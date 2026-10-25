# SPDX-License-Identifier: Apache-2.0
"""Owner-trusted anchors for FHE tables: row-set integrity and freshness.

``authenticated=True`` FHE columns detect tampering of VALUES, but a lying server can still
lie about WHICH rows exist (row-id lists, COUNT/AVG denominators, dead flags) and can roll a
table back to an older, internally consistent state. Neither is detectable without a small
piece of state the server cannot forge. That state is the **anchor**: per table
``{epoch, root, count, pending}`` kept by the data owner.

* ``leaf(row) = PRF(K_anchor, "leaf", table, rowid, canonical(row material)) mod n`` where the
  material is every PLAIN column value (with a type tag), and for every FHE column the write
  nonce and SHA-256 of the cell and of the tag, plus a digest of the schema;
* ``root = Σ_{live rows} leaf  (mod n)``, ``count = number of live rows``.

Because the root is additive, INSERT adds a leaf, DELETE subtracts one and UPDATE does both.
The server cannot compute a leaf (PRF-keyed), so the only state it can present whose leaves sum
to ``root`` is exactly the anchored one (soundness ~ 1/n per attempt, see docs/fhe-columns.md).

This module holds the pieces that have no SQL in them: the :class:`Anchor` interface with a
file implementation (:class:`FileAnchor`) and an in-memory one (:class:`MemoryAnchor`), the
canonical row encoding, and the verified :class:`Snapshot`.

Anchor contract (what a future custodian-quorum implementation must provide): every change is
a compare-and-swap on the table's ``epoch``; ``begin_commit`` records the NEW state as
``pending`` BEFORE the owner asks the server to commit; ``finish_commit`` / ``abort`` settle it
afterwards; a reader must never be able to roll the anchor itself back (that is the point of
keeping it away from the server).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import secrets
import stat
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Callable, Iterable

from .errors import ExecError, IntegrityError, PlanError

try:                                             # advisory locks between owner PROCESSES
    import fcntl as _fcntl
except ImportError:                              # pragma: no cover  (Windows)
    _fcntl = None

N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001   # BN254 group order
FORMAT = "torussql-fhe-anchor"
FORMAT_VERSION = 1
HISTORY = 8                                      # past roots kept to tell "behind" from "forged"
MAX_FILE = 64 << 20


class AnchorFileError(ExecError):
    """The anchor file is unusable (symlink, lax permissions, corrupt, unknown version)."""


class AnchorConflict(ExecError):
    """A compare-and-swap on the anchor failed: another owner advanced the epoch, or a commit
    is already pending."""


class AnchorMissingError(ExecError):
    """The table has FHE columns but the anchor has no entry for it."""


class StaleServerError(IntegrityError):
    """The server presents an OLDER state of the table than the anchor records: a replica that
    lags behind, or a rollback. Never accepted silently."""


# ── anchor state ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Pending:
    epoch: int                  # the epoch the table gets when the commit succeeds
    root: int
    count: int
    txid: str | None = None     # the server transaction (lets another owner tell "in flight" from "dead")
    drop: bool = False          # the commit removes the table
    created: bool = False       # the entry itself was created by this pending commit


@dataclass(frozen=True)
class Entry:
    epoch: int
    root: int
    count: int
    pending: Pending | None = None
    history: tuple = ()         # ((epoch, root, count), ...) newest last


@dataclass(frozen=True)
class Change:
    """One table's part of a commit. ``expect_epoch`` is the epoch the owner's work is based
    on (None = the anchor must not know the table yet). ``root=None`` drops the table."""
    expect_epoch: int | None
    root: int | None
    count: int = 0


class Anchor:
    """Interface. All operations are atomic; ``expect_*`` arguments are compare-and-swap."""

    def get(self, table: str) -> Entry | None:
        raise NotImplementedError

    def tables(self) -> list[str]:
        raise NotImplementedError

    def begin_commit(self, changes: dict[str, Change], txid: str | None = None) -> None:
        """Record every change as ``pending`` (epoch+1), all or nothing. Raises
        :class:`AnchorConflict` when an epoch moved or a commit is already pending."""
        raise NotImplementedError

    def finish_commit(self, tables: Iterable[str], txid: str | None = None) -> None:
        """The server committed: promote ``pending`` to the state (epoch+1). Idempotent for a
        table whose pending commit was already settled; a pending commit of ANOTHER transaction
        is a conflict."""
        raise NotImplementedError

    def abort(self, tables: Iterable[str], txid: str | None = None) -> None:
        """The server did not commit: discard ``pending``."""
        raise NotImplementedError

    def set(self, table: str, root: int, count: int, expect_epoch: int | None) -> Entry:
        """Install a state directly (adopt a table). CAS on the epoch, refused while a commit
        is pending."""
        raise NotImplementedError

    def remove(self, table: str, expect_epoch: int | None = None) -> None:
        raise NotImplementedError


def _enc_entry(e: Entry) -> dict:
    d = {"epoch": e.epoch, "root": str(e.root), "count": e.count,
         "history": [[a, str(b), c] for a, b, c in e.history], "pending": None}
    if e.pending is not None:
        p = e.pending
        d["pending"] = {"epoch": p.epoch, "root": str(p.root), "count": p.count,
                        "txid": p.txid, "drop": p.drop, "created": p.created}
    return d


def _dec_entry(d: dict) -> Entry:
    try:
        p = d.get("pending")
        pend = None if p is None else Pending(int(p["epoch"]), int(p["root"]) % N, int(p["count"]),
                                              p.get("txid"), bool(p.get("drop")), bool(p.get("created")))
        hist = tuple((int(a), int(b) % N, int(c)) for a, b, c in d.get("history", []))
        return Entry(int(d["epoch"]), int(d["root"]) % N, int(d["count"]), pend, hist)
    except (KeyError, TypeError, ValueError) as exc:
        raise AnchorFileError(f"anchor entry is malformed ({exc})") from None


class _StateAnchor(Anchor):
    """Shared logic; subclasses provide ``_atomic(fn)`` — run ``fn(state_dict)`` as one
    read-modify-write — where ``state_dict`` maps table -> Entry."""

    def _atomic(self, fn: Callable[[dict], Any], write: bool = True):
        raise NotImplementedError

    def get(self, table):
        return self._atomic(lambda st: st.get(table), write=False)

    def tables(self):
        return self._atomic(lambda st: sorted(st), write=False)

    def begin_commit(self, changes, txid=None):
        if not changes:
            return

        def fn(st):
            for t, ch in changes.items():
                e = st.get(t)
                if e is None:
                    if ch.expect_epoch is not None:
                        raise AnchorConflict(f"anchor: {t!r} has no entry (expected epoch {ch.expect_epoch})")
                elif ch.expect_epoch != e.epoch:
                    raise AnchorConflict(f"anchor: {t!r} is at epoch {e.epoch}, the transaction was "
                                         f"based on {ch.expect_epoch} (another owner committed)")
                elif e.pending is not None:
                    raise AnchorConflict(f"anchor: {t!r} already has a pending commit")
            for t, ch in changes.items():
                e = st.get(t)
                created = e is None
                if created:
                    e = Entry(0, 0, 0)
                st[t] = dataclasses.replace(e, pending=Pending(
                    e.epoch + 1, (ch.root or 0) % N, ch.count, txid, ch.root is None, created))
        self._atomic(fn)

    def finish_commit(self, tables, txid=None):
        tables = list(tables)

        def fn(st):
            todo = []
            for t in tables:
                e = st.get(t)
                if e is None or e.pending is None:
                    continue            # already settled (by another owner that saw the commit land)
                if txid is not None and e.pending.txid != txid:
                    raise AnchorConflict(f"anchor: {t!r} has a pending commit of another transaction")
                todo.append(t)
            for t in todo:
                e = st[t]
                p = e.pending
                if p.drop:
                    del st[t]
                    continue
                hist = (e.history + ((e.epoch, e.root, e.count),))[-HISTORY:]
                st[t] = Entry(p.epoch, p.root, p.count, None, hist)
        self._atomic(fn)

    def abort(self, tables, txid=None):
        tables = list(tables)

        def fn(st):
            for t in tables:
                e = st.get(t)
                if e is None or e.pending is None or (txid is not None and e.pending.txid != txid):
                    continue                                   # nothing to abort: idempotent
                if e.pending.created:
                    del st[t]
                else:
                    st[t] = dataclasses.replace(e, pending=None)
        self._atomic(fn)

    def set(self, table, root, count, expect_epoch):
        def fn(st):
            e = st.get(table)
            if (e.epoch if e else None) != expect_epoch:
                raise AnchorConflict(f"anchor: {table!r} changed (expected epoch {expect_epoch})")
            if e is not None and e.pending is not None:
                raise AnchorConflict(f"anchor: {table!r} has a pending commit")
            hist = () if e is None else (e.history + ((e.epoch, e.root, e.count),))[-HISTORY:]
            st[table] = Entry(0 if e is None else e.epoch + 1, root % N, count, None, hist)
            return st[table]
        return self._atomic(fn)

    def remove(self, table, expect_epoch=None):
        def fn(st):
            e = st.get(table)
            if e is None:
                return
            if expect_epoch is not None and e.epoch != expect_epoch:
                raise AnchorConflict(f"anchor: {table!r} changed (expected epoch {expect_epoch})")
            del st[table]
        self._atomic(fn)


class MemoryAnchor(_StateAnchor):
    """In-memory anchor (tests, single-process experiments). Lost with the process."""

    def __init__(self) -> None:
        self._st: dict[str, Entry] = {}
        self._lock = threading.RLock()

    def _atomic(self, fn, write=True):
        with self._lock:
            work = dict(self._st)
            out = fn(work)
            if write:
                self._st = work
            return out


class FileAnchor(_StateAnchor):
    """JSON file, mode 0600, versioned. Writes are crash-safe (temporary file created with
    O_EXCL, fsync, atomic rename, fsync of the directory); several owner PROCESSES may share
    the file (an advisory ``flock`` on ``<path>.lock`` serialises read-modify-write). Refuses a
    symlink, a file that is not ours, lax permissions, malformed content and unknown versions —
    it never silently starts from an empty state when the file is damaged.

    Keep the file where the server cannot reach it, and back it up like the FHE key: losing it
    means losing row-set integrity (see docs/fhe-columns.md)."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(str(path)))
        self._lock = threading.RLock()
        self._check_dir()

    def __repr__(self) -> str:
        return f"<FileAnchor {self.path}>"

    def _check_dir(self) -> None:
        d = os.path.dirname(self.path)
        if not os.path.isdir(d):
            raise AnchorFileError(f"anchor directory {d} does not exist")

    @staticmethod
    def _check_fd(fd: int, what: str) -> os.stat_result:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AnchorFileError(f"{what} is not a regular file")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise AnchorFileError(f"{what} is owned by another user")
        if st.st_mode & 0o077:
            raise AnchorFileError(f"{what} has lax permissions ({stat.S_IMODE(st.st_mode):o}); "
                                  f"chmod 600 it (it is the owner's trust root)")
        return st

    def _read(self) -> dict[str, Entry]:
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return {}
        except OSError as exc:                         # ELOOP for a symlink, EACCES, ...
            raise AnchorFileError(f"cannot open the anchor file {self.path}: {exc}") from None
        try:
            st = self._check_fd(fd, f"anchor file {self.path}")
            if st.st_size > MAX_FILE:
                raise AnchorFileError("anchor file is implausibly large")
            raw = b""
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(fd)
        try:
            doc = json.loads(raw.decode("utf-8"))
            if doc.get("format") != FORMAT:
                raise ValueError("not an anchor file")
            if doc.get("v") != FORMAT_VERSION:
                raise AnchorFileError(f"anchor file version {doc.get('v')!r} is not supported "
                                      f"(this build reads version {FORMAT_VERSION})")
            return {t: _dec_entry(e) for t, e in doc["tables"].items()}
        except AnchorFileError:
            raise
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise AnchorFileError(f"anchor file {self.path} is corrupt ({exc}); restore it from a "
                                  f"backup — refusing to start from an empty state") from None

    def _write(self, st: dict[str, Entry]) -> None:
        body = json.dumps({"format": FORMAT, "v": FORMAT_VERSION,
                           "tables": {t: _enc_entry(e) for t, e in sorted(st.items())}},
                          sort_keys=True, indent=1).encode("utf-8")
        tmp = f"{self.path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        dfd = os.open(os.path.dirname(self.path), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def _atomic(self, fn, write=True):
        if not write:                                  # replace is atomic: a reader needs no lock
            with self._lock:
                return fn(dict(self._read()))
        with self._lock:
            lfd = None
            if _fcntl is not None:
                try:
                    lfd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT
                                  | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    self._check_fd(lfd, "anchor lock file")
                    _fcntl.flock(lfd, _fcntl.LOCK_EX)
                except OSError as exc:
                    if lfd is not None:
                        os.close(lfd)
                    raise AnchorFileError(f"cannot lock the anchor file: {exc}") from None
            try:
                st = self._read()
                work = dict(st)
                out = fn(work)
                if write and work != st:
                    self._write(work)
                return out
            finally:
                if lfd is not None:
                    os.close(lfd)                      # closing releases the flock


# ── canonical row material ───────────────────────────────────────────────────
def _field(tag: bytes, payload: bytes) -> bytes:
    return tag + len(payload).to_bytes(4, "big") + payload


def canon_value(v) -> bytes:
    """Unambiguous encoding of a PLAIN column value. bool and int share a form, and a Fraction
    with denominator 1 is the integer: they are the same SQL value."""
    if v is None:
        return _field(b"n", b"")
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int):
        return _field(b"i", str(v).encode())
    if isinstance(v, Fraction):
        if v.denominator == 1:
            return _field(b"i", str(v.numerator).encode())
        return _field(b"f", f"{v.numerator}/{v.denominator}".encode())
    if isinstance(v, str):
        return _field(b"s", v.encode("utf-8"))
    if isinstance(v, (bytes, bytearray)):
        return _field(b"x", bytes(v))
    raise IntegrityError(f"cannot anchor a value of type {type(v).__name__}")


def sha256(b) -> bytes | None:
    return hashlib.sha256(bytes(b)).digest() if isinstance(b, (bytes, bytearray)) else None


def schema_digest(table: str, cols) -> bytes:
    """Binds the leaf to the column names, types and policies (a server cannot relabel a
    column without invalidating every leaf)."""
    return hashlib.sha256(json.dumps([table, [list(c) for c in cols]],
                                     separators=(",", ":")).encode()).digest()


def row_material(sdig: bytes, plain_vals, fhe_parts) -> bytes:
    """``plain_vals``: values of the PLAIN columns in schema order; ``fhe_parts``: for each FHE
    column ``(nonce, sha256(cell), sha256(tag))`` (hashes may be None = absent)."""
    out = [b"torussql/anchor/row/v1", sdig]
    for v in plain_vals:
        out.append(canon_value(v))
    for nonce, hc, ht in fhe_parts:
        if nonce is not None and (isinstance(nonce, bool) or not isinstance(nonce, int)):
            raise IntegrityError("the server reported a malformed write nonce")
        out.append(canon_value(nonce))
        out.append(_field(b"c", hc or b""))
        out.append(_field(b"t", ht or b""))
    return b"".join(out)


# ── the verified snapshot ────────────────────────────────────────────────────
class RowRec:
    """One live row as verified against the anchor."""
    __slots__ = ("vals", "fhe", "leaf")

    def __init__(self, vals: tuple, fhe: tuple, leaf: int):
        self.vals = vals            # PLAIN column values, schema order
        self.fhe = fhe              # per FHE column: (nonce, sha256(cell), sha256(tag))
        self.leaf = leaf


class Snapshot:
    """The table as the anchor says it is. ``base_*`` is the committed state (matches the
    anchor at ``epoch``); ``root``/``count`` also contain the open transaction's changes."""

    def __init__(self, table: str, plain_cols: list[str], fhe_cols: list[str], sdig: bytes):
        self.table, self.plain_cols, self.fhe_cols, self.sdig = table, plain_cols, fhe_cols, sdig
        self.rows: dict[int, RowRec] = {}
        self.nslots = 0
        self.epoch: int | None = None
        self.base_root = self.base_count = 0
        self.root = self.count = 0
        self._pidx = {c: i for i, c in enumerate(plain_cols)}
        self._fidx = {c: i for i, c in enumerate(fhe_cols)}

    def row_dict(self, rid: int) -> dict:
        r = self.rows[rid]
        return {c: r.vals[i] for i, c in enumerate(self.plain_cols)}

    def live_ids(self) -> list[int]:
        return sorted(self.rows)

    def plain(self, col: str, ids: list[int]) -> list:
        i = self._pidx[col]
        try:
            return [self.rows[r].vals[i] for r in ids]
        except KeyError as exc:
            raise IntegrityError(f"row {exc.args[0]} of {self.table!r} is not part of the "
                                 f"anchored table state") from None

    def fhe_part(self, col: str, ids: list[int]) -> list:
        i = self._fidx[col]
        try:
            return [self.rows[r].fhe[i] for r in ids]
        except KeyError as exc:
            raise IntegrityError(f"row {exc.args[0]} of {self.table!r} is not part of the "
                                 f"anchored table state") from None


# ── the manager: verification, transaction deltas, commit protocol ───────────
class _TxT:
    """What an open transaction did to one table."""
    __slots__ = ("epoch", "droot", "dcount", "reset", "dropped")

    def __init__(self, epoch, reset=False):
        self.epoch, self.droot, self.dcount, self.reset, self.dropped = epoch, 0, 0, reset, False


class _Tx:
    def __init__(self, txid):
        self.txid = txid
        self.tables: dict[str, _TxT] = {}
        self.undo: list[Callable[[], None]] = []
        self.rescanned: set[str] = set()      # snapshots replaced mid-transaction (undo cannot reach them)


class AnchorManager:
    """Owner-side logic of the anchored table-state mode, driven by ``NoKeyClient``.

    Lifecycle of a write: ``snapshot(t)`` (verifies against the anchor, O(n) the first time or
    after another owner advanced the epoch) -> the server write -> ``record_*`` (leaf deltas)
    -> at COMMIT ``prepare()`` writes ``pending`` into the anchor, the server commits, then
    ``finish()`` (or ``abort()``). If the owner is driven without a transaction manager
    (``managed`` False) every statement is its own commit."""

    DEFAULT_MAX_ROWS = 1_000_000

    def __init__(self, client, anchor: Anchor, max_rows: int | None = None):
        if not isinstance(anchor, Anchor):
            raise TypeError("integrity_anchor must be an Anchor (or a file path)")
        self.c, self.anchor = client, anchor
        self.max_rows = int(max_rows or self.DEFAULT_MAX_ROWS)
        self.snaps: dict[str, Snapshot] = {}
        self.tx: _Tx | None = None
        self.auto = False                         # the open tx was started implicitly by a statement
        self.managed = False                      # a connection drives begin/commit
        self.tx_status: Callable[[str], str] | None = None
        self._pending: list[str] = []
        self._expect: dict = {}
        self._changes: dict[str, Change] = {}
        self.stats = {"scans": 0, "scan_rows": 0}

    # — which tables —
    def is_anchored(self, table: str) -> bool:
        cols = self.c._schema.get(table)
        return bool(self.c.authenticated and cols and any(p == "fhe" for (_c, _t, p) in cols))

    def _cols(self, table):
        cols = self.c._schema[table]
        return ([c for (c, _t, p) in cols if p == "plain"], [c for (c, _t, p) in cols if p == "fhe"],
                schema_digest(table, cols))

    # — scan + verify —
    def _rec(self, snap: Snapshot, rid, vals, fp) -> RowRec:
        if (not isinstance(vals, (list, tuple)) or len(vals) != len(snap.plain_cols)
                or not isinstance(fp, (list, tuple)) or len(fp) != len(snap.fhe_cols)):
            raise IntegrityError(f"{snap.table!r} row {rid}: the server's row has the wrong shape")
        parts = []
        for ent in fp:
            nonce, hc, ht = ent
            for h in (hc, ht):
                if h is not None and not (isinstance(h, (bytes, bytearray)) and len(h) == 32):
                    raise IntegrityError(f"{snap.table!r} row {rid}: malformed cell hash")
            parts.append((nonce, bytes(hc) if hc is not None else None, bytes(ht) if ht is not None else None))
        vals = tuple(vals)
        leaf = self.c._fhe_key().anchor_leaf(snap.table, rid, row_material(snap.sdig, vals, parts))
        return RowRec(vals, tuple(parts), leaf)

    def _scan(self, table: str) -> Snapshot:
        plain, fcols, sdig = self._cols(table)
        snap = Snapshot(table, plain, fcols, sdig)
        step = min(2000, int(self.c._fhe_limits().get("max_scan_rows") or 2000))
        start, root, count = 0, 0, 0
        while True:
            n, rows = self.c.server.fhe_rows(table, start, step)
            if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                raise IntegrityError("malformed slot count from the server")
            if n > self.max_rows:
                raise ExecError(f"{table!r} has {n} slots: more than the anchored-mode limit of "
                                f"{self.max_rows} rows (integrity_anchor_max_rows)")
            if start >= n:
                break
            if not rows or len(rows) > step:
                raise IntegrityError(f"{table!r}: the server's scan answer does not cover the "
                                     f"requested slots")
            for k, (rid, dead, vals, fp) in enumerate(rows):
                if rid != start + k:
                    raise IntegrityError(f"{table!r}: the server's scan skipped or repeated a slot")
                if dead:
                    continue
                rec = self._rec(snap, rid, vals, fp)
                snap.rows[rid] = rec
                root += rec.leaf
                count += 1
            start += len(rows)
        snap.nslots = n
        snap.root, snap.count = root % N, count
        snap.base_root, snap.base_count = snap.root, snap.count
        self.stats["scans"] += 1
        self.stats["scan_rows"] += n
        return snap

    def _missing(self, table):
        return AnchorMissingError(
            f"table {table!r} has FHE columns but the integrity anchor has no entry for it, so its "
            f"row set cannot be verified. If it was created before the anchor was configured, "
            f"call adopt_table({table!r}) once (trust on first use: only as honest as the server "
            f"at that moment); a table created through this connection is anchored automatically")

    def snapshot(self, table: str, *, force: bool = False, for_write: bool = False) -> Snapshot:
        """The verified table state (cached per anchor epoch)."""
        tt = self.tx.tables.get(table) if self.tx else None
        snap = self.snaps.get(table)
        if tt is not None and tt.reset and snap is not None:        # created inside this transaction
            return snap
        a = self.anchor.get(table)
        if a is None:
            raise self._missing(table)
        if (not force and snap is not None and snap.epoch == a.epoch and a.pending is None
                and snap.base_root == a.root and snap.base_count == a.count):
            return snap
        fresh = self._scan(table)
        dr, dc = (tt.droot, tt.dcount) if tt else (0, 0)
        got = ((fresh.root - dr) % N, fresh.count - dc)              # the committed part of what we see
        a = self._settle(table, a, got)
        if (tt is not None and tt.epoch is not None and a.epoch != tt.epoch):
            raise AnchorConflict(f"anchor: {table!r} moved from epoch {tt.epoch} to {a.epoch} "
                                 f"during the transaction (another owner committed)")
        fresh.epoch, fresh.base_root, fresh.base_count = a.epoch, got[0], got[1]
        volatile = a.pending is not None
        if volatile:
            fresh.epoch = None                                       # never cached while a commit is in flight
            if for_write:
                raise AnchorConflict(f"anchor: {table!r} has a commit in flight from another owner")
        self.snaps[table] = fresh
        if tt is not None:
            self.tx.rescanned.add(table)
            if tt.epoch is None and not volatile:
                tt.epoch = a.epoch
        return fresh

    def _settle(self, table: str, a: Entry, got: tuple) -> Entry:
        """Compare what the server presents (``got`` = root, count of the committed state) with
        the anchor; settle a pending commit; or refuse."""
        if got == (a.root, a.count):
            if a.pending is not None and not self._in_flight(a.pending):
                self.anchor.abort([table], a.pending.txid)
                a = self.anchor.get(table) or a
            return a
        p = a.pending
        if p is not None and not p.drop and got == (p.root, p.count):
            try:
                self.anchor.finish_commit([table], p.txid)
            except AnchorConflict:
                pass                                                  # another owner finished it first
            a2 = self.anchor.get(table)
            if a2 is not None and (a2.root, a2.count) == got:
                return a2
        if any((r, c) == got for (_e, r, c) in a.history):
            raise StaleServerError(
                f"{table!r}: the server is behind the anchor (its table state matches an older "
                f"epoch than {a.epoch}: a replica that has not caught up, or a rollback). Nothing "
                f"was accepted; retry once the server has caught up")
        raise IntegrityError(
            f"table state of {table!r} does not match the anchor: rows added, dropped, rolled "
            f"back or altered (server presents {got[1]} rows, the anchor records {a.count})")

    def _in_flight(self, p: Pending) -> bool:
        """Is another owner's commit still on its way? Only matters when the scan shows the OLD
        state; the scan itself, not this answer, decides what is accepted."""
        if self.tx_status is None or p.txid is None:
            return False
        try:
            # only "unknown" (rolled back / never begun) proves the commit is dead; "open" and
            # "committed" mean it is on its way — aborting then would race with the committer
            return self.tx_status(p.txid) != "unknown"
        except Exception:                                             # noqa: BLE001
            return True                                               # cannot tell: do not abort

    # — public read helpers —
    def match_ids(self, table: str, where) -> list[int]:
        from .nokey_engine import _match
        snap = self.snapshot(table)
        ids = snap.live_ids()
        if where is None:
            return ids
        return [i for i in ids if _match(snap.row_dict(i), where)]

    def plain(self, table: str, col: str, ids: list[int]) -> list:
        return self.snapshot(table).plain(col, ids)

    # — transaction state —
    def begin(self, txid: str | None = None) -> None:
        if self.tx is not None:
            raise PlanError("an anchor transaction is already open")
        self.tx, self.auto = _Tx(txid), False

    def ensure_tx(self) -> None:
        if self.tx is None:
            self.tx, self.auto = _Tx(None), True

    def _tt(self, table: str, snap: Snapshot | None = None) -> _TxT:
        tt = self.tx.tables.get(table)
        if tt is None:
            tt = self.tx.tables[table] = _TxT(snap.epoch if snap else None)
        return tt

    def _snap_for_write(self, table: str) -> Snapshot:
        self.ensure_tx()
        snap = self.snapshot(table, for_write=True)
        self._tt(table, snap)
        return snap

    def _apply(self, snap, tt, rid, new: RowRec | None, old: RowRec | None):
        saved = (snap.root, snap.count, snap.nslots, tt.droot, tt.dcount, old)
        d = ((new.leaf if new else 0) - (old.leaf if old else 0)) % N
        dn = (1 if new else 0) - (1 if old else 0)
        if new is not None:
            snap.rows[rid] = new
            snap.nslots = max(snap.nslots, rid + 1)
        else:
            snap.rows.pop(rid, None)
        snap.root, snap.count = (snap.root + d) % N, snap.count + dn
        tt.droot, tt.dcount = (tt.droot + d) % N, tt.dcount + dn

        def undo():
            snap.root, snap.count, snap.nslots, tt.droot, tt.dcount, o = saved
            if o is None:
                snap.rows.pop(rid, None)
            else:
                snap.rows[rid] = o
        self.tx.undo.append(undo)

    def record_insert(self, snap: Snapshot, rid: int, vals, fp) -> None:
        table = snap.table
        tt = self._tt(table, snap)
        if isinstance(rid, bool) or not isinstance(rid, int) or rid in snap.rows or rid < snap.nslots:
            raise IntegrityError(f"{table!r}: the server returned row id {rid!r}, which is already "
                                 f"in use or out of order")
        self._apply(snap, tt, rid, self._rec(snap, rid, vals, fp), None)

    def record_update(self, snap: Snapshot, rid: int, vals, fp) -> None:
        table = snap.table
        old = snap.rows.get(rid)
        if old is None:
            raise IntegrityError(f"row {rid} of {table!r} is not part of the anchored table state")
        self._apply(snap, self._tt(table, snap), rid, self._rec(snap, rid, vals, fp), old)

    def record_delete(self, snap: Snapshot, rid: int) -> None:
        table = snap.table
        old = snap.rows.get(rid)
        if old is None:
            raise IntegrityError(f"row {rid} of {table!r} is not part of the anchored table state")
        self._apply(snap, self._tt(table, snap), rid, None, old)

    def write_snapshot(self, table: str) -> Snapshot:
        return self._snap_for_write(table)

    # — DDL —
    def ddl_create(self, table: str) -> None:
        self.ensure_tx()
        plain, fcols, sdig = self._cols(table)
        a = self.anchor.get(table)
        had_tt = self.tx.tables.get(table)
        had_snap = self.snaps.get(table)
        tt = _TxT(a.epoch if a else None, reset=True)
        self.tx.tables[table] = tt
        self.snaps[table] = Snapshot(table, plain, fcols, sdig)

        tx = self.tx

        def undo():
            if had_tt is None:
                tx.tables.pop(table, None)
            else:
                tx.tables[table] = had_tt
            if had_snap is None:
                self.snaps.pop(table, None)
            else:
                self.snaps[table] = had_snap
        self.tx.undo.append(undo)

    def ddl_drop(self, table: str) -> None:
        self.ensure_tx()
        a = self.anchor.get(table)
        had_tt = self.tx.tables.get(table)
        tt = had_tt or _TxT(a.epoch if a else None)
        self.tx.tables[table] = tt
        was_dropped = tt.dropped
        tt.dropped = True
        had_snap = self.snaps.pop(table, None)

        tx = self.tx

        def undo():
            tt.dropped = was_dropped
            if had_tt is None:
                tx.tables.pop(table, None)
            if had_snap is not None:
                self.snaps[table] = had_snap
        self.tx.undo.append(undo)

    # — commit protocol —
    def prepare(self) -> bool:
        """Record ``pending`` in the anchor BEFORE the server is asked to commit. Returns False
        when the transaction changed nothing anchored."""
        tx = self.tx
        changes: dict[str, Change] = {}
        for t, tt in tx.tables.items():
            if tt.dropped:
                changes[t] = Change(tt.epoch, None, 0)
                continue
            if not (tt.droot or tt.dcount or tt.reset):
                continue
            snap = self.snaps[t]
            base_r, base_c = (0, 0) if tt.reset else (snap.base_root, snap.base_count)
            changes[t] = Change(tt.epoch, (base_r + tt.droot) % N, base_c + tt.dcount)
        if not changes:
            return False
        self.anchor.begin_commit(changes, tx.txid)
        self._pending = list(changes)
        self._changes = changes
        self._expect = {t: (None if ch.root is None else (ch.root, ch.count)) for t, ch in changes.items()}
        return True

    def finish(self) -> None:
        tx, pend = self.tx, self._pending
        self.tx, self.auto, self._pending = None, False, []
        if tx is None:
            return
        try:
            if pend:
                self.anchor.finish_commit(pend, tx.txid)
                self._repair_aborted(pend, tx.txid)
                for t in pend:                    # another owner may have settled it for us: check how
                    e, want = self.anchor.get(t), self._expect.get(t)
                    if (want is None) != (e is None) or (e is not None and (
                            e.pending is not None or (e.root, e.count) != want)):
                        raise AnchorConflict(f"{t!r} is not in the state this commit recorded")
        except AnchorConflict as exc:
            self.snaps.clear()
            raise IntegrityError(f"the anchor does not hold this transaction's commit: {exc}") from None
        for t, tt in tx.tables.items():
            snap = self.snaps.get(t)
            if tt.dropped:
                self.snaps.pop(t, None)
            elif snap is not None and t in pend:
                a = self.anchor.get(t)
                snap.epoch, snap.base_root, snap.base_count = a.epoch, snap.root, snap.count

    def _repair_aborted(self, pend: list[str], txid) -> None:
        """Our ``pending`` record was aborted behind our back (a reader that was told the commit
        is dead, e.g. by a lying ``tx_status``) although the server answered "committed": the
        anchor is still exactly at the state our transaction was based on, so record the commit
        again. If the server's "committed" was a lie, the next scan finds the old state and fails
        — a lie can only cause a failure, never an accepted wrong state."""
        redo = {}
        for t in pend:
            ch, e = self._changes[t], self.anchor.get(t)
            if (e is None and ch.expect_epoch is None) or (
                    e is not None and e.pending is None and e.epoch == ch.expect_epoch):
                redo[t] = ch
        if redo:
            self.anchor.begin_commit(redo, txid)
            self.anchor.finish_commit(list(redo), txid)

    def abort(self) -> None:
        """The transaction did not commit: discard its changes (and the pending record)."""
        tx, pend = self.tx, self._pending
        self.tx, self.auto, self._pending = None, False, []
        if tx is None:
            return
        try:
            if pend:
                self.anchor.abort(pend, tx.txid)
        finally:
            for u in reversed(tx.undo):
                u()
            for t in tx.rescanned:
                self.snaps.pop(t, None)               # replaced mid-transaction: rescan next time

    def detach(self) -> None:
        """The outcome is unknown (in doubt): leave the anchor's ``pending`` for the next
        connect to settle by scanning, and forget everything cached."""
        self.tx, self.auto, self._pending = None, False, []
        self.snaps.clear()

    def autocommit(self) -> None:
        try:
            self.prepare()
        except BaseException:
            self.abort()
            raise
        self.finish()

    # — tools —
    def adopt(self, table: str, replace: bool = False) -> dict:
        if self.tx is not None:
            raise PlanError("adopt_table: finish the transaction first")
        if not self.is_anchored(table):
            raise PlanError(f"{table!r} has no FHE columns (or the connection is not authenticated)")
        a = self.anchor.get(table)
        if a is not None and not replace:
            raise ExecError(f"{table!r} already has an anchor entry (epoch {a.epoch}); pass "
                            f"replace=True to adopt the server's current state instead")
        snap = self._scan(table)
        if a is not None:
            self.anchor.remove(table)
        e = self.anchor.set(table, snap.root, snap.count, None)
        snap.epoch = e.epoch
        self.snaps[table] = snap
        return {"table": table, "rows": snap.count, "slots": snap.nslots, "epoch": e.epoch}

    def verify(self, table: str) -> dict:
        if not self.is_anchored(table):
            raise PlanError(f"{table!r} has no FHE columns (or the connection is not authenticated)")
        snap = self.snapshot(table, force=True)
        return {"table": table, "rows": snap.count, "slots": snap.nslots, "epoch": snap.epoch}

    def settle_pending(self) -> None:
        """On connect: settle every pending commit the anchor holds by scanning the server."""
        on_server = None
        for t in self.anchor.tables():
            e = self.anchor.get(t)
            if e is None or e.pending is None:
                continue
            if t in self.c._schema:
                self.snapshot(t, force=True)
                continue
            if on_server is None:
                on_server = set(self.c.server.tables())
            if t in on_server:
                continue                                              # unknown schema: settled on first use
            p = e.pending
            if p.drop:
                self.anchor.finish_commit([t], p.txid)                # the table is gone: the drop committed
            elif p.created:
                self.anchor.abort([t], p.txid)                        # it was never created
            else:
                raise IntegrityError(f"table {t!r} is gone from the server but the anchor "
                                     f"records it (pending commit that is not a drop)")
