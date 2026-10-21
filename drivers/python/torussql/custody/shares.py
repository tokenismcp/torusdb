# SPDX-License-Identifier: Apache-2.0
"""A custodian's store of mask shares.

For every encrypted cell the data owner draws an independent uniform mask ``r``
and secret-shares it k-of-n among the custodians; this is the slice held by
*one* custodian. It is keyed by ``(generation, table, cid, col, version)`` where
``cid`` is a random id carried (as plaintext) on the server row and ``version``
is bumped on every UPDATE — so a share is never overwritten in place and a
crash cannot pair a new cell with an old mask.

A custodian can add up its shares over a set of cells (``sum``): because the
sharing is linear the owner combines the partial sums of k custodians into
Σ r without any individual mask being revealed to the querier.

Durable: sealed append-only :class:`RecordLog` with torn-write recovery.
"""
from __future__ import annotations

import threading
import time
from bisect import bisect_right

from .group import CustodyError
from .recordlog import RecordLog

Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254 order = the no-key scalar field


class ShareConflict(CustodyError):
    pass


class MissingShare(CustodyError):
    def __init__(self, n: int):
        super().__init__(f"{n} requested share(s) not held by this custodian")
        self.n = n


class Frozen(CustodyError):
    pass


class _Gen:
    __slots__ = ("x", "tables", "meta", "sorted_cache")

    def __init__(self) -> None:
        self.x: int | None = None
        self.tables: dict[str, dict[tuple, tuple[int, int]]] = {}
        self.meta: dict[str, object] = {}
        self.sorted_cache: dict[str, tuple[int, list]] = {}


class MaskShareStore:
    def __init__(self, path: str | None = None, passphrase: str | None = None,
                 fsync: str = "always", compact_factor: float = 3.0):
        self._lock = threading.RLock()
        self._gens: dict[int, _Gen] = {}
        self._version = 0
        self._log: RecordLog | None = None
        self._dead = 0                          # superseded/deleted records in the log
        self._compact_factor = compact_factor
        self.frozen: set[int] = set()            # generations closed to writes
        if path:
            self._log = RecordLog(path, b"TORUSMASKS1", passphrase, fsync)
            for rec in self._log.open():
                self._apply(rec)

    # ── state machine (also the replay path) ─────────────────────────────────
    def _g(self, gen: int) -> _Gen:
        return self._gens.setdefault(gen, _Gen())

    def _apply(self, r: dict) -> None:
        k = r["k"]
        g = self._g(r["g"]) if "g" in r else None
        if k == "x":
            g.x = r["x"]
        elif k == "p":
            for t, c, l, v, s, ts in r["e"]:
                g.tables.setdefault(t, {})[(c, l, v)] = (int(s, 16), ts)
        elif k == "d":
            for t, c, l, v in r["e"]:
                g.tables.get(t, {}).pop((c, l, v), None)
            self._dead += len(r["e"])
        elif k == "dt":
            self._dead += len(g.tables.pop(r["t"], {}))
        elif k == "dg":
            self._gens.pop(r["g"], None)
        elif k == "m":
            g.meta[r["key"]] = r["val"]
        elif k == "f":
            (self.frozen.add if r["v"] else self.frozen.discard)(r["g"])
        self._version += 1

    def _commit(self, recs: list[dict]) -> None:
        if self._log is not None:
            self._log.append_many(recs)         # raises → state unchanged below
        for r in recs:
            self._apply(r)
        if self._log is not None:
            self._maybe_compact()

    def _maybe_compact(self) -> None:
        live = sum(len(t) for g in self._gens.values() for t in g.tables.values())
        if self._dead > 10000 and self._dead > self._compact_factor * max(live, 1):
            self.compact()

    def compact(self) -> None:
        with self._lock:
            if self._log is None:
                return
            def records():
                for fg in self.frozen:
                    yield {"k": "f", "g": fg, "v": True}
                for gen, g in self._gens.items():
                    if g.x is not None:
                        yield {"k": "x", "g": gen, "x": g.x}
                    for key, val in g.meta.items():
                        yield {"k": "m", "g": gen, "key": key, "val": val}
                    for t, entries in g.tables.items():
                        items = list(entries.items())
                        for i in range(0, len(items), 2000):
                            yield {"k": "p", "g": gen, "e": [
                                [t, c, l, v, format(s, "x"), ts]
                                for (c, l, v), (s, ts) in items[i:i + 2000]]}
            self._log.rewrite(list(records()))
            self._dead = 0

    # ── operations ───────────────────────────────────────────────────────────
    def put(self, gen: int, x: int, entries: list) -> int:
        """entries = [(table, cid, col, ver, share_int)]. Idempotent for an
        identical share; a *different* share for an existing key is refused."""
        now = int(time.time())
        with self._lock:
            if gen in self.frozen:
                raise Frozen(f"generation {gen} is frozen (maintenance / being re-shared)")
            g = self._gens.get(gen)
            recs: list[dict] = []
            if g is None or g.x is None:
                recs.append({"k": "x", "g": gen, "x": x})
            elif g.x != x:
                raise ShareConflict(f"generation {gen} uses point x={g.x}, not {x}")
            new = []
            seen: dict[tuple, int] = {}
            for t, c, l, v, s in entries:
                if not 0 <= s < Q:
                    raise CustodyError("share out of range")
                key = (t, c, l, v)
                have = seen.get(key)
                if have is None and g is not None:
                    cur = g.tables.get(t, {}).get((c, l, v))
                    have = cur[0] if cur else None
                if have is not None:
                    if have != s:
                        raise ShareConflict(
                            f"refusing to overwrite an existing share ({t}.{l} v{v}); "
                            f"masks are never reused — masks are versioned")
                    continue
                seen[key] = s
                new.append([t, c, l, v, format(s, "x"), now])
            for i in range(0, len(new), 2000):
                recs.append({"k": "p", "g": gen, "e": new[i:i + 2000]})
            if recs:
                self._commit(recs)
            return len(new)

    def _items(self, gen: int, table: str):
        g = self._gens.get(gen)
        if g is None:
            raise MissingShare(1)
        return g.tables.get(table, {})

    def sum(self, gen: int, table: str, col: str, items: list) -> tuple[int, int]:
        """items = [(cid, ver, count)] → (Σ count·share mod Q, x)."""
        with self._lock:
            t = self._items(gen, table)
            acc, miss = 0, 0
            for c, v, n in items:
                e = t.get((c, col, v))
                if e is None:
                    miss += 1
                else:
                    acc += e[0] * n
            if miss:
                raise MissingShare(miss)
            return acc % Q, self._gens[gen].x

    def get(self, gen: int, table: str, col: str, items: list) -> tuple[list, int | None]:
        """items = [(cid, ver)] → ([share or None], x)."""
        with self._lock:
            g = self._gens.get(gen)
            if g is None:
                return [None] * len(items), None
            t = g.tables.get(table, {})
            return [(t[(c, col, v)][0] if (c, col, v) in t else None)
                    for c, v in items], g.x

    def has(self, gen: int, table: str, col: str, items: list) -> list[bool]:
        with self._lock:
            g = self._gens.get(gen)
            t = g.tables.get(table, {}) if g else {}
            return [(c, col, v) in t for c, v in items]

    def delete(self, gen: int, entries: list) -> int:
        with self._lock:
            g = self._gens.get(gen)
            if not g:
                return 0
            ex = [e for e in entries if (e[1], e[2], e[3]) in g.tables.get(e[0], {})]
            if ex:
                self._commit([{"k": "d", "g": gen, "e": [list(e) for e in ex]}])
            return len(ex)

    def drop_table(self, gen: int, table: str) -> int:
        with self._lock:
            g = self._gens.get(gen)
            n = len(g.tables.get(table, {})) if g else 0
            if n:
                self._commit([{"k": "dt", "g": gen, "t": table}])
            return n

    def drop_generation(self, gen: int) -> None:
        with self._lock:
            if gen in self._gens:
                self._commit([{"k": "dg", "g": gen}])
                self.compact()

    def list_page(self, gen: int, table: str, after: list | None, limit: int):
        """Stable paging over (cid, col, ver, ts) for GC / re-sharing."""
        with self._lock:
            g = self._gens.get(gen)
            if not g or table not in g.tables:
                return [], None
            cached = g.sorted_cache.get(table)
            if cached is None or cached[0] != self._version:
                cached = (self._version, sorted(g.tables[table]))
                g.sorted_cache[table] = cached
            keys = cached[1]
            start = bisect_right(keys, tuple(after)) if after else 0
            page = keys[start:start + limit]
            t = g.tables[table]
            out = [[c, l, v, t[(c, l, v)][1]] for (c, l, v) in page]
            return out, (list(page[-1]) if len(page) == limit else None)

    def tables(self, gen: int) -> list[str]:
        with self._lock:
            g = self._gens.get(gen)
            return sorted(g.tables) if g else []

    def meta_get(self, gen: int, key: str):
        with self._lock:
            g = self._gens.get(gen)
            return g.meta.get(key) if g else None

    def meta_put(self, gen: int, key: str, val, if_absent: bool = False) -> bool:
        with self._lock:
            g = self._gens.get(gen)
            if if_absent and g is not None and key in g.meta:
                return False
            self._commit([{"k": "m", "g": gen, "key": key, "val": val}])
            return True

    def set_frozen(self, gen: int, v: bool) -> None:
        with self._lock:
            self._commit([{"k": "f", "g": gen, "v": bool(v)}])

    def stats(self) -> dict:
        with self._lock:
            return {"generations": {
                        gen: {"x": g.x, "tables": {t: len(e) for t, e in g.tables.items()}}
                        for gen, g in self._gens.items()},
                    "dead_records": self._dead, "frozen": sorted(self.frozen),
                    "log_records": self._log.records if self._log else 0}

    def close(self) -> None:
        if self._log:
            self._log.close()
