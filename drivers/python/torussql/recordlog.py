# SPDX-License-Identifier: Apache-2.0
"""Append-only, checksummed, optionally sealed record log.

Properties (each one is tested):

* **Durable append** — a record batch is written with raw ``os.write`` and one
  ``fsync``. If the write fails part-way the file is truncated back to the
  pre-append offset, so a failed (and reported-as-failed) append can never
  reappear after recovery.
* **Torn tail vs corruption** — only a bad *final* record that lacks its
  trailing newline is a torn write and is dropped. A complete line that fails
  its check, or any bad record with data after it, is corruption: loading
  **refuses** (``LogCorrupt``) and never truncates, so valid later records are
  not destroyed.
* **Order / completeness** — every record carries a sequence number; deleted,
  duplicated or reordered records are detected.
* **Binding** — the header line (salt / key envelope / file id) is bound into
  every record: a sealed record carries it as AAD together with its sequence
  number, so records cannot be spliced between files or generations, and the
  header itself cannot be swapped without invalidating every record.
* **Sealing** — with a key every record is sealed (encrypt-then-MAC); an
  unsealed record in a sealed log is rejected. A wrong passphrase is reported as
  ``LogLocked`` and never modifies the file.
* **Atomic compaction / re-keying** — ``rewrite`` builds a new file and renames.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import zlib
from pathlib import Path
from typing import Iterable, Iterator

from . import seal as _seal
from .errors import CustodyError

_KEEP = object()


class LogCorrupt(CustodyError):
    pass


class LogLocked(CustodyError):
    pass


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
    except OSError:                                         # pragma: no cover
        return
    try:
        os.fsync(fd)
    except OSError:                                         # pragma: no cover
        pass
    finally:
        os.close(fd)


def _create_exclusive(path: str, mode: int = 0o600) -> int:
    """Create ``path`` fresh: refuse a pre-existing file / symlink (a planted
    ``.tmp`` would otherwise keep attacker-chosen permissions or redirect the
    write)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, mode)


class RecordLog:
    def __init__(self, path: str, magic: bytes, passphrase: str | None = None,
                 fsync: str = "always", *, key: int | None = None,
                 extra: bytes | None = None, label: bytes = b""):
        if fsync not in ("always", "never"):
            raise ValueError("fsync must be 'always' or 'never'")
        if passphrase and key is not None:
            raise ValueError("pass a passphrase or a key, not both")
        self.path, self.magic, self._pass, self._fsync = path, magic, passphrase, fsync
        self._label = label
        self._key: int | None = key
        self._extra = extra               # header suffix (salt / envelope / …)
        self._head = b""                  # full header line (without newline)
        self._aadbase = b""
        self._fd: int | None = None
        self._seq = 0
        self._size = 0
        self.records = 0

    # ── header helpers ───────────────────────────────────────────────────────
    @staticmethod
    def peek_header(path: str, magic: bytes) -> list[bytes] | None:
        """Tokens after the magic on the header line, or None if no such log."""
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return None
        with open(path, "rb") as f:
            line = f.readline().rstrip(b"\n")
        if not line.startswith(magic):
            raise LogCorrupt(f"{path}: not a {magic.decode()} file")
        return line[len(magic):].split()

    def _set_head(self, head: bytes) -> None:
        self._head = head
        self._aadbase = hashlib.sha256(b"torussql/recordlog/header\x00" + head).digest()[:16]

    def _aad(self, seq: int) -> bytes:
        return self._aadbase + struct.pack(">Q", seq)

    # ── codec ────────────────────────────────────────────────────────────────
    def _enc(self, rec: dict, seq: int) -> bytes:
        body = json.dumps(dict(rec, q=seq), separators=(",", ":")).encode()
        if self._key is not None:
            return b"S " + _seal.seal(self._key, body, self._aad(seq)).hex().encode() + b"\n"
        return b"P %08x " % zlib.crc32(self._aadbase + body) + body + b"\n"

    def _dec(self, line: bytes, seq: int) -> dict:
        if line.startswith(b"S "):
            if self._key is None:
                raise LogLocked("log is sealed — key/passphrase required")
            return json.loads(_seal.unseal(self._key, bytes.fromhex(line[2:].decode()),
                                           self._aad(seq)))
        if line.startswith(b"P "):
            if self._key is not None:
                raise ValueError("unsealed record in a sealed log")
            crc, _, body = line[2:].partition(b" ")
            if int(crc, 16) != zlib.crc32(self._aadbase + body):
                raise ValueError("crc")
            return json.loads(body)
        raise ValueError("unknown record")

    # ── open / replay ────────────────────────────────────────────────────────
    def open(self) -> Iterator[dict]:
        """Create the log if needed, then yield every valid record in order.
        Appending is possible once the iterator has been exhausted."""
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            self._create()
            return iter(())
        return self._replay()

    def _header_for_new(self) -> bytes:
        extra = self._extra
        if extra is None and self._pass:
            salt = os.urandom(16)
            self._key = _seal.passphrase_key(self._pass, salt, self._label)
            extra = salt.hex().encode()
        return self.magic + (b" " + extra if extra else b"")

    def _create(self) -> None:
        head = self._header_for_new()
        self._set_head(head)
        fd = _create_exclusive(self.path)
        try:
            os.write(fd, head + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self.path)
        self._open_append()

    def _replay(self) -> Iterator[dict]:
        with open(self.path, "rb") as f:
            raw = f.read()
        nl = raw.find(b"\n")
        if nl < 0 or not raw.startswith(self.magic):
            raise LogCorrupt(f"{self.path}: not a {self.magic.decode()} file")
        head = raw[:nl]
        toks = head[len(self.magic):].split()
        if self._extra is None:                         # key comes from a passphrase
            if toks:
                if not self._pass:
                    raise LogLocked(f"{self.path} is sealed — passphrase required")
                try:
                    salt = bytes.fromhex(toks[0].decode())
                except ValueError:
                    raise LogCorrupt(f"{self.path}: bad header") from None
                self._key = _seal.passphrase_key(self._pass, salt, self._label)
            elif self._pass:
                raise LogCorrupt(f"{self.path} is not sealed but a passphrase was given")
        elif head != self.magic + (b" " + self._extra if self._extra else b""):
            raise LogCorrupt(f"{self.path}: header does not match the expected key envelope")
        elif self._key is None and toks:
            raise LogLocked(f"{self.path} is sealed — key required")
        self._set_head(head)
        pos, good, expect, out = nl + 1, nl + 1, 0, []
        n = len(raw)
        while pos < n:
            end = raw.find(b"\n", pos)
            complete = end >= 0
            line = raw[pos:end] if complete else raw[pos:]
            try:
                rec = self._dec(line, expect)
                if not complete:
                    raise ValueError("no newline")
                if rec.get("q") != expect:
                    raise LogCorrupt(f"{self.path}: record out of sequence (expected "
                                     f"{expect}, got {rec.get('q')}) — deleted, "
                                     f"duplicated or reordered records")
            except (LogCorrupt, LogLocked):
                raise
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                if expect == 0 and self._key is not None:
                    raise LogLocked("wrong passphrase/key or corrupted log") from None
                if not complete:                      # torn final write → drop it
                    break
                raise LogCorrupt(
                    f"{self.path}: corrupt record at byte {pos} — refusing to load or "
                    f"truncate; restore from a backup") from None
            out.append(rec)
            expect += 1
            pos = end + 1
            good = pos
        if good < n:
            with open(self.path, "r+b") as f:
                f.truncate(good)
        self._seq, self._size, self.records = expect, good, expect
        self._open_append()
        return iter(out)

    def _open_append(self) -> None:
        self._fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        self._size = os.fstat(self._fd).st_size

    # ── appending ────────────────────────────────────────────────────────────
    def append(self, rec: dict) -> None:
        self.append_many([rec])

    def append_many(self, recs: Iterable[dict]) -> None:
        """Write all records, then one fsync. All-or-nothing: on any failure the
        file is truncated back and the sequence is unchanged."""
        if self._fd is None:
            raise CustodyError("log is closed or unusable after a failed write")
        seq, data = self._seq, bytearray()
        try:
            n = 0
            for rec in recs:
                data += self._enc(rec, seq + n)
                n += 1
            self._write_all(bytes(data))
            if self._fsync == "always":
                os.fsync(self._fd)
        except BaseException:
            self._rollback_to(self._size)
            raise
        self._seq = seq + n
        self._size += len(data)
        self.records += n

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            n = os.write(self._fd, view)
            view = view[n:]

    def _rollback_to(self, size: int) -> None:
        try:
            os.ftruncate(self._fd, size)
        except OSError:
            try:                                   # cannot restore a clean tail:
                os.close(self._fd)                 # refuse all further writes
            finally:
                self._fd = None

    # ── compaction / re-keying ───────────────────────────────────────────────
    def rewrite(self, records: Iterable[dict], *, key=_KEEP, extra=_KEEP) -> None:
        """Atomically replace the log with exactly ``records``.

        * default: keep the protection. A passphrase log gets a **fresh salt and
          key** every time (so records of an older generation can never be
          spliced into the new file);
        * ``key=…, extra=…``: switch to a new key / header (re-sealing, key
          rotation, threshold envelope).
        On any failure the old file and this object's state are untouched."""
        if key is _KEEP:
            if self._pass is not None and self._key is not None:
                salt = os.urandom(16)
                new_key = _seal.passphrase_key(self._pass, salt, self._label)
                head, new_extra = self.magic + b" " + salt.hex().encode(), None
            else:
                new_key, head, new_extra = self._key, self._head, self._extra
        else:
            new_key = key
            new_extra = None if extra is _KEEP else extra
            head = self.magic + (b" " + new_extra if new_extra else b"")
        tmp = self.path + ".tmp"
        old = (self._key, self._extra, self._head, self._aadbase, self._seq,
               self._size, self.records)
        fd = _create_exclusive(tmp)
        try:
            self._key = new_key
            self._set_head(head)
            os.write(fd, head + b"\n")
            seq, buf = 0, bytearray()
            for rec in records:
                buf += self._enc(rec, seq)
                seq += 1
                if len(buf) > (1 << 20):
                    os.write(fd, bytes(buf)); buf.clear()
            if buf:
                os.write(fd, bytes(buf))
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp, self.path)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            Path(tmp).unlink(missing_ok=True)
            (self._key, self._extra, head0, _a, self._seq, self._size, self.records) = old
            self._set_head(old[2])
            raise
        _fsync_dir(self.path)
        if self._fd is not None:
            os.close(self._fd)
        if key is not _KEEP:
            self._extra = new_extra
        self._seq = seq
        self._open_append()
        self.records = seq

    def sync(self) -> None:
        """fsync everything appended so far (for ``fsync='never'`` logs)."""
        if self._fd is not None:
            os.fsync(self._fd)

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.fsync(self._fd)
            finally:
                os.close(self._fd)
                self._fd = None
