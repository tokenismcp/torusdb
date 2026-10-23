# SPDX-License-Identifier: Apache-2.0
"""Table storage for the keyless server: in-memory and disk-backed (paged heap).

A *table store* owns the rows of one table. Row ids ("slots") are stable forever:
DELETE only marks a slot dead, so the owner's masks (keyed by row id) never shift.
Stores hold only what the server may hold — plaintext columns and one-time-padded
scalars — never keys or masks.

Two implementations share one interface (:class:`TableStore`):

* :class:`MemoryTable` — a ``list`` of row dicts (what the server always used).
* :class:`PagedTable`  — an append-only **heap file** of checksummed row records,
  an in-memory array of 8-byte record offsets (one per slot), and an LRU row cache.
  Only offsets and the cache live in RAM, so the data set may be far larger than
  memory. UPDATE appends a new row version and repoints the slot; checkpoints
  record the heap length so recovery can discard anything newer and let the
  write-ahead journal replay it; ``compact`` rewrites the heap without the dead
  versions.

Both support secondary indexes on PLAIN columns (:meth:`TableStore.create_index`)
that accelerate ``=``, ``<``, ``<=``, ``>``, ``>=`` and ``IN`` predicates.

Every mutator returns an *undo* closure (or documents how to undo) so the server's
transaction machinery can roll back exactly; undo closures must run in reverse
order of the operations they undo.
"""
from __future__ import annotations

import bisect
import json
import os
import struct
import zlib
from array import array
from collections import OrderedDict
from fractions import Fraction
from typing import Any, Callable, Iterable, Iterator

MISSING = object()
_MAX_INT = 1 << 53


class StoreCorrupt(RuntimeError):
    """A heap record or index file failed its integrity check."""


# ── value codec (big-int exact, compact JSON) ───────────────────────────────
def _enc_val(v):
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, int):
        return v if -_MAX_INT < v < _MAX_INT else {"i": str(v)}
    if isinstance(v, Fraction):
        return {"f": [str(v.numerator), str(v.denominator)]}
    if isinstance(v, (bytes, bytearray)):
        import base64
        return {"x": base64.b64encode(bytes(v)).decode("ascii")}
    raise TypeError(f"cannot store {type(v).__name__}")


def _dec_val(v):
    if isinstance(v, dict):
        if "i" in v:
            return int(v["i"])
        if "x" in v:
            import base64
            return base64.b64decode(v["x"])
        return Fraction(int(v["f"][0]), int(v["f"][1]))
    return v


def encode_row(row: dict) -> bytes:
    return json.dumps({k: _enc_val(v) for k, v in row.items()},
                      separators=(",", ":")).encode()


def decode_row(buf: bytes) -> dict:
    return {k: _dec_val(v) for k, v in json.loads(buf).items()}


# ── secondary index ──────────────────────────────────────────────────────────
class _Index:
    """Sorted ``(key, rowid)`` pairs; NULL keys are not indexed."""
    __slots__ = ("col", "pairs")

    def __init__(self, col: str):
        self.col = col
        self.pairs: list[tuple] = []

    def add(self, key, rid: int) -> None:
        if key is not None:
            bisect.insort(self.pairs, (key, rid))

    def remove(self, key, rid: int) -> None:
        if key is None:
            return
        i = bisect.bisect_left(self.pairs, (key, rid))
        if i < len(self.pairs) and self.pairs[i] == (key, rid):
            del self.pairs[i]

    def bounds(self, op: str, val) -> tuple[int, int]:
        p = self.pairs
        if op == "=":
            return bisect.bisect_left(p, (val, -1)), bisect.bisect_right(p, (val, 1 << 62))
        if op == "<":
            return 0, bisect.bisect_left(p, (val, -1))
        if op == "<=":
            return 0, bisect.bisect_right(p, (val, 1 << 62))
        if op == ">":
            return bisect.bisect_right(p, (val, 1 << 62)), len(p)
        if op == ">=":
            return bisect.bisect_left(p, (val, -1)), len(p)
        raise ValueError(op)

    def ids(self, lo: int, hi: int) -> list[int]:
        return [r for _, r in self.pairs[lo:hi]]


_INDEXABLE = {"=", "<", "<=", ">", ">=", "in"}


class TableStore:
    """Interface + shared index machinery. Subclasses implement the storage."""

    def __init__(self) -> None:
        self._indexes: dict[str, _Index] = {}

    # — storage primitives (subclasses) —
    def __len__(self) -> int: raise NotImplementedError
    def row(self, i: int) -> dict: raise NotImplementedError
    def cell(self, i: int, col: str, default: Any = MISSING) -> Any:
        r = self.row(i)
        if col in r:
            return r[col]
        if default is MISSING:
            raise KeyError(col)
        return default
    def _append(self, row: dict) -> int: raise NotImplementedError
    def _truncate(self, n: int, mark: Any) -> None: raise NotImplementedError
    def _mark(self) -> Any: return None
    def _put_cell(self, i: int, col: str, val: Any) -> Callable[[], None]:
        raise NotImplementedError
    def _drop_cell(self, i: int, col: str) -> Callable[[], None]:
        raise NotImplementedError
    def is_dead(self, i: int) -> bool: raise NotImplementedError
    def _set_dead(self, i: int, dead: bool) -> None: raise NotImplementedError
    def dead_count(self) -> int: raise NotImplementedError
    def dead_ids(self) -> list[int]: raise NotImplementedError

    # — public mutators —
    def __getitem__(self, i: int) -> dict:
        return self.row(i)

    def append(self, row: dict) -> int:
        rid = self._append(row)
        for ix in self._indexes.values():
            ix.add(row.get(ix.col), rid)
        return rid

    def append_many(self, rows: list[dict]) -> list[int]:
        return [self.append(r) for r in rows]

    def rewind(self, n: int, mark: Any = None) -> None:
        """Undo appends: drop every slot >= ``n`` (``mark`` from :meth:`mark`)."""
        for ix in self._indexes.values():
            for i in range(len(self) - 1, n - 1, -1):
                if not self.is_dead(i):
                    ix.remove(self.row(i).get(ix.col), i)
        self._truncate(n, mark)

    def mark(self) -> tuple[int, Any]:
        return len(self), self._mark()

    def set_cell(self, i: int, col: str, val: Any) -> Callable[[], None]:
        """Set one cell; returns an undo closure."""
        ix = self._indexes.get(col)
        old = self.cell(i, col, MISSING)
        undo_store = self._put_cell(i, col, val)
        if ix is not None and not self.is_dead(i):
            if old is not MISSING:
                ix.remove(old, i)
            ix.add(val, i)

        def undo():
            undo_store()
            if ix is not None and not self.is_dead(i):
                ix.remove(val, i)
                if old is not MISSING:
                    ix.add(old, i)
        return undo

    def drop_cell(self, i: int, col: str) -> Callable[[], None]:
        ix = self._indexes.get(col)
        old = self.cell(i, col, MISSING)
        undo_store = self._drop_cell(i, col)
        if ix is not None and not self.is_dead(i) and old is not MISSING:
            ix.remove(old, i)

        def undo():
            undo_store()
            if ix is not None and not self.is_dead(i) and old is not MISSING:
                ix.add(old, i)
        return undo

    def kill(self, ids: Iterable[int]) -> list[int]:
        """Mark slots dead; returns the ones that were live."""
        newly = []
        for i in ids:
            if not self.is_dead(i):
                for ix in self._indexes.values():
                    ix.remove(self.cell(i, ix.col, None), i)
                self._set_dead(i, True)
                newly.append(i)
        return newly

    def revive(self, ids: Iterable[int]) -> None:
        for i in ids:
            if self.is_dead(i):
                self._set_dead(i, False)
                for ix in self._indexes.values():
                    ix.add(self.cell(i, ix.col, None), i)

    # — reading —
    def live_ids(self) -> Iterator[int]:
        for i in range(len(self)):
            if not self.is_dead(i):
                yield i

    def live_count(self) -> int:
        return len(self) - self.dead_count()

    def cells(self, col: str, ids: list[int]) -> list:
        return [self.row(i)[col] for i in ids]

    # — indexes —
    @property
    def indexed_columns(self) -> list[str]:
        return sorted(self._indexes)

    def create_index(self, col: str) -> None:
        if col in self._indexes:
            return
        ix = _Index(col)
        pairs = [(self.cell(i, col, None), i) for i in self.live_ids()]
        ix.pairs = sorted(p for p in pairs if p[0] is not None)
        self._indexes[col] = ix

    def drop_index(self, col: str) -> None:
        self._indexes.pop(col, None)

    def candidates(self, groups: list[list[tuple]]) -> list[int] | None:
        """Row ids that *may* satisfy an OR of AND-groups of ``(col, op, value)``
        atoms (op in ``= < <= > >= in``; ``in`` takes a list). Returns a sorted
        superset of the live matches, or ``None`` when some group has no usable
        index (the caller must scan). The caller still re-checks every atom."""
        if not self._indexes:
            return None
        out: set[int] = set()
        for group in groups:
            best = None                                  # (cost, index, [(lo,hi)…])
            for col, op, val in group:
                ix = self._indexes.get(col)
                if ix is None or op not in _INDEXABLE:
                    continue
                try:
                    if op == "in":
                        spans = [ix.bounds("=", v) for v in val if v is not None]
                    else:
                        if val is None:
                            continue
                        spans = [ix.bounds(op, val)]
                except TypeError:                        # incomparable literal
                    continue
                cost = sum(hi - lo for lo, hi in spans)
                if best is None or cost < best[0]:
                    best = (cost, ix, spans)
            if best is None:
                return None
            for lo, hi in best[2]:
                out.update(best[1].ids(lo, hi))
        return sorted(out)

    # — lifecycle —
    def close(self) -> None: ...


# ── in-memory ────────────────────────────────────────────────────────────────
class MemoryTable(TableStore):
    """List of row dicts + a dead set. ``store[i]`` is the live dict and iterating
    yields the row dicts, so it can stand in for the plain list it replaces."""

    def __init__(self, rows: Iterable[dict] = ()):
        super().__init__()
        self._rows: list[dict] = list(rows)
        self.dead: set[int] = set()

    def __len__(self): return len(self._rows)
    def __iter__(self): return iter(self._rows)
    def __getitem__(self, i): return self._rows[i]
    def row(self, i): return self._rows[i]
    def _append(self, row): self._rows.append(row); return len(self._rows) - 1
    def _truncate(self, n, mark):
        del self._rows[n:]
        self.dead = {i for i in self.dead if i < n}
    def _put_cell(self, i, col, val):
        r = self._rows[i]
        old = r.get(col, MISSING)
        r[col] = val

        def undo():
            if old is MISSING:
                r.pop(col, None)
            else:
                r[col] = old
        return undo
    def _drop_cell(self, i, col):
        r = self._rows[i]
        old = r.pop(col, MISSING)

        def undo():
            if old is not MISSING:
                r[col] = old
        return undo
    def is_dead(self, i): return i in self.dead
    def _set_dead(self, i, dead):
        (self.dead.add if dead else self.dead.discard)(i)
    def dead_count(self): return len(self.dead)
    def dead_ids(self): return sorted(self.dead)


# ── disk-backed paged heap ───────────────────────────────────────────────────
_HDR = struct.Struct("<II")                  # payload length, crc32
_IDX_MAGIC = b"TDBIDX1\n"


class PagedTable(TableStore):
    """Append-only heap of row records + offset array + LRU row cache.

    ``heap_path`` is created if missing. ``cache_rows`` bounds the decoded-row
    cache. The heap is only fsynced by :meth:`flush` (checkpoint); commit
    durability comes from the server's write-ahead journal.
    """

    def __init__(self, heap_path: str, cache_rows: int = 50_000):
        super().__init__()
        self.path = heap_path
        self.cache_rows = max(16, cache_rows)
        self._cache: OrderedDict[int, dict] = OrderedDict()
        self._offs = array("q")                       # record offset per slot
        self._dead = bytearray()
        self._ndead = 0
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(heap_path, flags, 0o600)
        self._end = os.fstat(self._fd).st_size
        self.garbage = 0                              # bytes of superseded versions

    # — record I/O —
    def _write_record(self, row: dict) -> int:
        payload = encode_row(row)
        rec = _HDR.pack(len(payload), zlib.crc32(payload)) + payload
        off = self._end
        n = os.pwrite(self._fd, rec, off)
        while n < len(rec):                           # short write
            n += os.pwrite(self._fd, rec[n:], off + n)
        self._end = off + len(rec)
        return off

    def _read_record(self, off: int) -> dict:
        hdr = os.pread(self._fd, _HDR.size, off)
        if len(hdr) < _HDR.size:
            raise StoreCorrupt(f"{self.path}: truncated record header at {off}")
        ln, crc = _HDR.unpack(hdr)
        payload = os.pread(self._fd, ln, off + _HDR.size)
        if len(payload) != ln or zlib.crc32(payload) != crc:
            raise StoreCorrupt(f"{self.path}: record at {off} failed its checksum")
        return decode_row(payload)

    def _remember(self, i: int, row: dict) -> None:
        c = self._cache
        c[i] = row
        c.move_to_end(i)
        if len(c) > self.cache_rows:
            c.popitem(last=False)

    # — interface —
    def __len__(self): return len(self._offs)

    def row(self, i):
        c = self._cache
        r = c.get(i)
        if r is None:
            if not 0 <= i < len(self._offs):
                raise IndexError(i)
            r = self._read_record(self._offs[i])
            self._remember(i, r)
        else:
            c.move_to_end(i)
        return r

    def _append(self, row):
        off = self._write_record(row)
        self._offs.append(off)
        self._dead.append(0)
        i = len(self._offs) - 1
        self._remember(i, dict(row))
        return i

    def _mark(self): return self._end

    def _truncate(self, n, mark):
        if mark is not None:
            os.ftruncate(self._fd, mark)
            self._end = mark
        for i in range(len(self._offs) - 1, n - 1, -1):
            if self._dead[i]:
                self._ndead -= 1
            self._cache.pop(i, None)
        del self._offs[n:]
        del self._dead[n:]

    def _put_cell(self, i, col, val):
        r = dict(self.row(i))
        r[col] = val
        return self._replace(i, r)

    def _drop_cell(self, i, col):
        r = dict(self.row(i))
        r.pop(col, None)
        return self._replace(i, r)

    def _replace(self, i, new_row):
        old_off, old_end, old_row = self._offs[i], self._end, self.row(i)
        off = self._write_record(new_row)
        wrote = self._end - off
        self.garbage += wrote
        self._offs[i] = off
        self._remember(i, new_row)

        def undo():
            self._offs[i] = old_off
            if self._end > old_end:                  # nothing newer remains (reverse order)
                os.ftruncate(self._fd, old_end)
                self._end = old_end
            self.garbage = max(0, self.garbage - wrote)
            self._remember(i, old_row)
        return undo

    def is_dead(self, i): return bool(self._dead[i])

    def _set_dead(self, i, dead):
        if bool(self._dead[i]) != dead:
            self._dead[i] = 1 if dead else 0
            self._ndead += 1 if dead else -1

    def dead_count(self): return self._ndead
    def dead_ids(self): return [i for i, d in enumerate(self._dead) if d]

    def cells(self, col, ids):
        return [self.row(i)[col] for i in ids]

    # — checkpoint / recovery —
    @property
    def heap_len(self) -> int:
        return self._end

    def flush(self) -> None:
        os.fsync(self._fd)

    def write_index_file(self, path: str) -> None:
        """Atomically persist offsets + dead flags (the slot table)."""
        tmp = path + ".tmp"
        n = len(self._offs)
        body = self._offs.tobytes()
        dead = bytes(self._dead)
        head = _IDX_MAGIC + struct.pack("<QQ", n, self._end)
        crc = zlib.crc32(body, zlib.crc32(dead, zlib.crc32(head)))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(head + struct.pack("<I", crc) + body + dead)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    def load_index_file(self, path: str, expect_slots: int, expect_end: int) -> None:
        """Adopt a persisted slot table and discard heap bytes newer than it."""
        with open(path, "rb") as f:
            data = f.read()
        hl = len(_IDX_MAGIC) + 16
        if len(data) < hl + 4 or not data.startswith(_IDX_MAGIC):
            raise StoreCorrupt(f"{path}: not a slot-table file")
        n, end = struct.unpack("<QQ", data[len(_IDX_MAGIC):hl])
        (crc,) = struct.unpack("<I", data[hl:hl + 4])
        body = data[hl + 4:hl + 4 + 8 * n]
        dead = data[hl + 4 + 8 * n:hl + 4 + 9 * n]
        if (len(body) != 8 * n or len(dead) != n
                or crc != zlib.crc32(body, zlib.crc32(dead, zlib.crc32(data[:hl])))):
            raise StoreCorrupt(f"{path}: slot table failed its checksum")
        if n != expect_slots or end != expect_end:
            raise StoreCorrupt(f"{path}: slot table does not match the checkpoint manifest")
        if os.fstat(self._fd).st_size < end:
            raise StoreCorrupt(f"{self.path}: heap is shorter ({os.fstat(self._fd).st_size}) "
                               f"than the checkpoint ({end}) — data files are damaged or "
                               f"were restored inconsistently")
        os.ftruncate(self._fd, end)               # drop post-checkpoint bytes; journal replays them
        self._end = end
        self._offs = array("q")
        self._offs.frombytes(body)
        self._dead = bytearray(dead)
        self._ndead = sum(self._dead)
        self._cache.clear()

    def compact(self, new_path: str) -> "PagedTable":
        """Write a fresh heap holding only current row versions (slot ids and
        dead flags preserved). The caller swaps the files after a checkpoint."""
        out = PagedTable(new_path, self.cache_rows)
        for i in range(len(self)):
            out._offs.append(out._write_record(self.row(i)))
            out._dead.append(self._dead[i])
        out._ndead = self._ndead
        out._indexes = self._indexes
        return out

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.fsync(self._fd)
            finally:
                os.close(self._fd)
                self._fd = None


# ── storage back ends (own the files of all tables of a database) ────────────
class MemoryStorage:
    """Tables live in RAM; durability is the server's snapshot + journal."""
    paged = False

    def new_table(self, name: str) -> TableStore:
        return MemoryTable()

    def close(self) -> None: ...


class DiskStorage:
    """Tables live in heap files under ``dirpath``:

        t<fid>.<epoch>.heap     row records (append-only; epoch bumps on compaction)
        t<fid>.<gen>.slots      slot table written by checkpoint ``gen``

    The checkpoint manifest (see :meth:`manifest`) names the live files; anything
    else is garbage from a crash or an old generation and is removed by
    :meth:`collect`. File names never contain user input.
    """
    paged = True

    def __init__(self, dirpath: str, cache_rows: int = 50_000,
                 compact_ratio: float = 0.5, compact_min_bytes: int = 1 << 20):
        self.dir = dirpath
        os.makedirs(dirpath, mode=0o700, exist_ok=True)
        self.cache_rows = cache_rows
        self.compact_ratio = compact_ratio
        self.compact_min_bytes = compact_min_bytes
        self.next_fid = 1
        self.fids: dict[int, tuple[str, int]] = {}      # id(store) -> (fid, epoch)
        self._meta: dict[str, dict] = {}                # table -> {fid, epoch, gen}
        self._graveyard: list[TableStore] = []

    # — helpers —
    def _heap(self, fid: int, epoch: int) -> str:
        return os.path.join(self.dir, f"t{fid}.{epoch}.heap")

    def _slots(self, fid: int, gen: int) -> str:
        return os.path.join(self.dir, f"t{fid}.{gen}.slots")

    def new_table(self, name: str) -> PagedTable:
        fid, self.next_fid = self.next_fid, self.next_fid + 1
        path = self._heap(fid, 0)
        for stale in (path, ):                           # leftovers of a crashed run
            try:
                os.unlink(stale)
            except FileNotFoundError:
                pass
        t = PagedTable(path, self.cache_rows)
        self._meta[name] = {"fid": fid, "epoch": 0, "gen": -1}
        return t

    def forget(self, name: str, store: TableStore) -> dict | None:
        """Table dropped (maybe to be restored by an undo): keep its files until
        the next collect()."""
        meta = self._meta.pop(name, None)
        self._graveyard.append(store)
        return meta

    def restore(self, name: str, store: TableStore, meta: dict | None) -> None:
        if meta is not None:
            self._meta[name] = meta
        if store in self._graveyard:
            self._graveyard.remove(store)

    def open_table(self, name: str, entry: dict) -> PagedTable:
        fid, epoch = entry["fid"], entry["epoch"]
        t = PagedTable(self._heap(fid, epoch), self.cache_rows)
        t.load_index_file(self._slots(fid, entry["gen"]), entry["slots"], entry["heap_len"])
        self._meta[name] = {"fid": fid, "epoch": epoch, "gen": entry["gen"]}
        self.next_fid = max(self.next_fid, fid + 1)
        return t

    # — checkpoint —
    def checkpoint_table(self, name: str, store: PagedTable, gen: int):
        """Make ``store`` durable as of ``gen``; returns (store, manifest entry)."""
        meta = self._meta[name]
        if (store.garbage >= self.compact_min_bytes
                and store.garbage > self.compact_ratio * max(1, store.heap_len)):
            new_epoch = meta["epoch"] + 1
            new = store.compact(self._heap(meta["fid"], new_epoch))
            new.flush()
            self._graveyard.append(store)
            store, meta["epoch"] = new, new_epoch
        store.flush()
        store.write_index_file(self._slots(meta["fid"], gen))
        meta["gen"] = gen
        return store, {"fid": meta["fid"], "epoch": meta["epoch"], "gen": gen,
                       "slots": len(store), "heap_len": store.heap_len,
                       "indexes": store.indexed_columns}

    def collect(self, manifest_tables: dict[str, dict]) -> None:
        """Delete every file the durable manifest does not reference."""
        keep = set()
        for e in manifest_tables.values():
            keep.add(os.path.basename(self._heap(e["fid"], e["epoch"])))
            keep.add(os.path.basename(self._slots(e["fid"], e["gen"])))
        for s in self._graveyard:
            try:
                s.close()
            except Exception:                            # noqa: BLE001
                pass
        self._graveyard.clear()
        for fn in os.listdir(self.dir):
            if fn not in keep and (fn.endswith(".heap") or fn.endswith(".slots")
                                   or fn.endswith(".tmp")):
                try:
                    os.unlink(os.path.join(self.dir, fn))
                except OSError:
                    pass

    def close(self) -> None:
        for s in self._graveyard:
            try:
                s.close()
            except Exception:                            # noqa: BLE001
                pass
        self._graveyard.clear()


# ── snapshot reads while a write transaction is open ─────────────────────────
class TxOverlay:
    """What one open (uncommitted) transaction changed, recorded *before* each
    change so other sessions can keep reading the last committed state instead
    of waiting for the writer. Only one write transaction exists at a time."""

    def __init__(self) -> None:
        self.base_len: dict[str, int] = {}               # table -> slot count at first write
        self.old_rows: dict[tuple[str, int], dict] = {}  # (table, slot) -> committed row
        self.killed: dict[str, set[int]] = {}            # slots deleted by the tx
        self.created: set[str] = set()                   # tables created by the tx
        self.dropped: dict[str, tuple] = {}              # table -> (schema, store) dropped by the tx

    def note_append(self, table: str, store: TableStore) -> None:
        self.base_len.setdefault(table, len(store))

    def note_update(self, table: str, store: TableStore, i: int) -> None:
        if i < self.base_len.get(table, len(store)):
            self.old_rows.setdefault((table, i), dict(store.row(i)))

    def note_kill(self, table: str, ids: Iterable[int]) -> None:
        self.killed.setdefault(table, set()).update(ids)


class StoreView(TableStore):
    """Read-only committed view of a store under a :class:`TxOverlay`."""

    def __init__(self, table: str, store: TableStore, ov: TxOverlay):
        super().__init__()
        self._t, self._s, self._ov = table, store, ov
        self._n = ov.base_len.get(table, len(store))
        self._killed = ov.killed.get(table, set())

    def __len__(self): return self._n
    def row(self, i):
        if not 0 <= i < self._n:
            raise IndexError(i)
        return self._ov.old_rows.get((self._t, i)) or self._s.row(i)
    def is_dead(self, i): return self._s.is_dead(i) and i not in self._killed
    def dead_ids(self):
        return sorted({i for i in self._s.dead_ids() if i < self._n and i not in self._killed})
    def dead_count(self): return len(self.dead_ids())
    @property
    def indexed_columns(self): return self._s.indexed_columns
    def candidates(self, groups): return None            # indexes describe the uncommitted state
    def close(self): ...
    # a view never mutates
    def _append(self, row): raise RuntimeError("read-only view")
