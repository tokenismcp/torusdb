# SPDX-License-Identifier: Apache-2.0
"""Crash-safe durability for the keyless server: snapshot + write-ahead journal.

Layout for a database at ``PATH``:

    PATH            snapshot (JSON, sha256-checked, carries ``generation``)
    PATH.journal    JSONL write-ahead log; each line = one committed unit
    PATH.lock       advisory lock so two servers never open the same db

A journal line is ``{"g": generation, "ops": [[method, args], ...], "c": crc32}``.
One line is one atomic commit (a single statement, or a whole transaction), so
a crash mid-write leaves at most one torn trailing line, which recovery
discards. Records whose generation differs from the snapshot's are stale
(left over from before a checkpoint) and are ignored, which makes a crash
between "snapshot written" and "journal truncated" harmless.

Nothing here ever holds key material: the snapshot and journal contain only
schema, plaintext columns, and one-time-padded scalars (I(M;V_S)=0).
"""
from __future__ import annotations

import hashlib
import json
import os
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable

try:                                    # POSIX advisory locking
    import fcntl
except ImportError:                     # pragma: no cover  (Windows)
    fcntl = None                        # type: ignore[assignment]


class DatabaseLocked(RuntimeError):
    """Another process already has this database open."""


class CorruptDatabase(RuntimeError):
    """The snapshot failed its integrity check."""


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:                     # pragma: no cover
        return
    try:
        os.fsync(fd)
    except OSError:                     # pragma: no cover
        pass
    finally:
        os.close(fd)


def write_snapshot(path: str, body: dict, generation: int) -> None:
    """Atomically write ``body`` as generation ``generation`` with a checksum."""
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    doc = {"format": 2, "generation": generation,
           "sha256": hashlib.sha256(payload.encode()).hexdigest(),
           "snapshot": body}
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    _fsync_dir(p)


def read_snapshot(path: str) -> tuple[dict, int]:
    """-> (body, generation). Accepts the legacy un-checksummed format."""
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if "snapshot" not in doc:                       # legacy v1 file
        return doc, 0
    body = doc["snapshot"]
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(payload.encode()).hexdigest() != doc.get("sha256"):
        raise CorruptDatabase(f"{path}: snapshot checksum mismatch")
    return body, int(doc.get("generation", 0))


class Journal:
    """Append-only commit log with torn-tail recovery."""

    def __init__(self, path: str, generation: int, fsync: str = "always"):
        if fsync not in ("always", "never"):
            raise ValueError("fsync must be 'always' or 'never'")
        self.path = path
        self.generation = generation
        self._fsync = fsync
        self._f = None
        self.records = 0
        self.bytes = 0

    # — recovery —
    @staticmethod
    def replay(path: str, generation: int) -> Iterable[list]:
        """Yield each valid committed ``ops`` list of this generation."""
        if not os.path.exists(path):
            return
        good_end = 0
        with open(path, "rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                try:
                    rec = json.loads(line)
                    body = json.dumps([rec["g"], rec["ops"]],
                                      separators=(",", ":")).encode()
                    if zlib.crc32(body) != rec["c"]:
                        raise ValueError("crc")
                except (ValueError, KeyError, TypeError):
                    break                           # torn / corrupt tail
                good_end = f.tell()
                if rec["g"] == generation:
                    yield rec["ops"]
        # drop the torn tail so new appends start on a clean boundary
        if good_end < os.path.getsize(path):
            with open(path, "r+b") as f:
                f.truncate(good_end)

    def open(self) -> None:
        self._f = open(self.path, "ab")
        self.bytes = self._f.tell()

    def append(self, ops: list) -> None:
        body = json.dumps([self.generation, ops],
                          separators=(",", ":")).encode()
        rec = json.dumps({"g": self.generation, "ops": ops,
                          "c": zlib.crc32(body)},
                         separators=(",", ":")).encode() + b"\n"
        self._f.write(rec)
        self._f.flush()
        if self._fsync == "always":
            os.fsync(self._f.fileno())
        self.records += 1
        self.bytes += len(rec)

    def reset(self, generation: int) -> None:
        """Start a fresh, empty journal for ``generation`` (after a checkpoint)."""
        if self._f:
            self._f.close()
        with open(self.path, "wb") as f:
            f.flush()
            os.fsync(f.fileno())
        self.generation = generation
        self.records = 0
        self.open()

    def close(self) -> None:
        if self._f:
            try:
                self._f.flush()
                os.fsync(self._f.fileno())
            finally:
                self._f.close()
                self._f = None


class DbLock:
    """Advisory exclusive lock on ``PATH.lock`` (no-op where unsupported)."""

    def __init__(self, path: str):
        self._path = path + ".lock"
        self._fd = None

    def acquire(self) -> None:
        if fcntl is None:               # pragma: no cover
            return
        fd = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise DatabaseLocked(
                f"database is in use by another process ({self._path})")
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
