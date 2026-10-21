# SPDX-License-Identifier: Apache-2.0
"""Crash-safe durability for the keyless server: snapshot + write-ahead journal.

Layout for a database at ``PATH`` (all files ``0600``):

    PATH            snapshot (JSON, sha256-checked, carries ``generation``)
    PATH.journal    write-ahead log (a :class:`torussql.recordlog.RecordLog`)
    PATH.lock       advisory lock so two processes never open the same db

A journal record is ``{"g": generation, "ops": [[method, args], …], "tx": id?}``.
One record is one atomic commit (a single statement, or a whole transaction).
The journal inherits the RecordLog guarantees: an append that fails part-way is
truncated away (it can never reappear after recovery), a torn final record is
dropped, and **corruption anywhere else refuses to load** rather than silently
discarding the commits after it. Records whose generation differs from the
snapshot's are stale (left over from before a checkpoint) and are ignored, which
makes a crash between "snapshot written" and "journal truncated" harmless.

Nothing here ever holds key material: the snapshot and journal contain only
schema, plaintext columns, and one-time-padded scalars (I(M;V_S)=0).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from torussql.recordlog import LogCorrupt, RecordLog, _create_exclusive, _fsync_dir

try:                                    # POSIX advisory locking
    import fcntl
except ImportError:                     # pragma: no cover  (Windows)
    fcntl = None                        # type: ignore[assignment]

JOURNAL_MAGIC = b"TORUSJRN1"


class DatabaseLocked(RuntimeError):
    """Another process already has this database open."""


class CorruptDatabase(RuntimeError):
    """The snapshot or journal failed its integrity check."""


def write_snapshot(path: str, body: dict, generation: int, extra: dict | None = None) -> None:
    """Atomically write ``body`` as generation ``generation`` with a checksum.
    ``extra`` (e.g. the committed-transaction ring) is covered by the checksum."""
    inner = {"body": body, "extra": extra or {}}
    payload = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    doc = {"format": 3, "generation": generation,
           "sha256": hashlib.sha256(payload.encode()).hexdigest(), "snapshot": inner}
    tmp = path + ".tmp"
    fd = _create_exclusive(tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)       # never leave a stale temp behind
        raise
    _fsync_dir(path)


def read_snapshot(path: str) -> tuple[dict, int, dict]:
    """-> (body, generation, extra). Accepts the legacy formats."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (ValueError, OSError) as exc:
        raise CorruptDatabase(f"{path}: unreadable snapshot ({exc})") from exc
    if "snapshot" not in doc:                       # legacy v1 file (no checksum)
        return doc, 0, {}
    inner = doc["snapshot"]
    legacy = doc.get("format", 2) < 3
    payload = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(payload.encode()).hexdigest() != doc.get("sha256"):
        raise CorruptDatabase(f"{path}: snapshot checksum mismatch")
    if legacy:
        return inner, int(doc.get("generation", 0)), {}
    return inner["body"], int(doc.get("generation", 0)), inner.get("extra", {})


class Journal:
    """Write-ahead commit log (thin wrapper over :class:`RecordLog`)."""

    def __init__(self, path: str, generation: int, fsync: str = "always"):
        self.path = path
        self.generation = generation
        self._fsync_mode = fsync
        self._log = RecordLog(path, JOURNAL_MAGIC, fsync=fsync)
        self.records = 0                        # commits since the last checkpoint
        self.bytes = 0

    def open(self) -> list[dict]:
        """Open (creating if needed) and return every valid record of the
        CURRENT generation, in order."""
        try:
            recs = list(self._log.open())
        except LogCorrupt as exc:
            raise CorruptDatabase(str(exc)) from None
        out = [r for r in recs if r.get("g") == self.generation]
        self.records = len(out)
        self.bytes = self._log._size
        return out

    def append(self, ops: list, tx: str | None = None) -> None:
        rec = {"g": self.generation, "ops": ops}
        if tx:
            rec["tx"] = tx
        self._log.append(rec)                   # all-or-nothing; raises on failure
        self.records += 1
        self.bytes = self._log._size

    @property
    def usable(self) -> bool:
        return self._log._fd is not None

    def reset(self, generation: int) -> None:
        """Start a fresh, empty journal for ``generation`` (after a checkpoint).
        Atomic: on failure the old journal is untouched."""
        self._log.rewrite([])
        self.generation = generation
        self.records = 0
        self.bytes = self._log._size

    def close(self) -> None:
        self._log.close()


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


def restore_backup(db_path: str, backup_path: str) -> int:
    """Replace ``db_path`` with a backup. Holds the database lock (a running
    server makes this fail), verifies the backup's checksum first, and stamps the
    restored snapshot with a generation higher than any existing snapshot or
    journal so no stale record can ever be replayed on top of it."""
    lock = DbLock(db_path)
    lock.acquire()
    try:
        body, _gen, extra = read_snapshot(backup_path)          # verifies checksum
        old_gen = -1
        if os.path.exists(db_path):
            try:
                old_gen = read_snapshot(db_path)[1]
            except CorruptDatabase:
                old_gen = 0
        jp = db_path + ".journal"
        if os.path.exists(jp):
            try:
                recs = list(RecordLog(jp, JOURNAL_MAGIC).open())
                old_gen = max([old_gen] + [r.get("g", 0) for r in recs])
            except Exception:                                   # noqa: BLE001
                old_gen = max(old_gen, 1_000_000)               # unreadable: jump far ahead
        new_gen = old_gen + 1
        write_snapshot(db_path, body, new_gen, extra)
        Path(jp).unlink(missing_ok=True)
        return new_gen
    finally:
        lock.release()
