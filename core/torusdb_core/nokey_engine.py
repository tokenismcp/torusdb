# SPDX-License-Identifier: Apache-2.0
"""No-key TorusSQL engine — the SQL surface over the no-key delegation
protocol Π (Lee, J1729 Labs).

This is the architecture the paper prescribes and the previous (trusted-
evaluator) engine violated:

  • The SERVER holds NO key material and NEVER decrypts. For an encrypted
    column it stores only a one-time-padded scalar in Z/nZ. Its whole view
    is uniform and independent of the plaintext (I(M;V_S)=0).
  • The CLIENT (data owner) holds the masks, blinds on INSERT, and unblinds
    + decodes results at its own guarded boundary.
  • Encrypted aggregation / scaling is Π_lin (non-interactive); encrypted
    products (DOT) are Π_mult (Beaver triples, one batched round). There is
    no decrypt-then-re-encrypt anywhere.

Trust boundary is explicit in the types: every `NoKeyServer` method takes
only blinded scalars and public circuit data; masks and decode live solely
on `NoKeyClient`.
"""
from __future__ import annotations

import dataclasses
import secrets
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Callable

from . import protocol as nokey
from .protocol import Owner, Server, decode, encode, gen_triple

from .errors import ExecError, IntegrityError, PlanError
from .maskstore import DictMaskStore, MaskStore
from torussql_parser.predicate import compare as _compare
from .store import MemoryStorage, StoreView, TableStore, TxOverlay
from .parser import parse
from .planner import (
    PAvg, PColRef, PCondition, PCountStar, PCtMul, PDot, PInList, PMax, PMin,
    PScalarMul, PScaledSum, PSum, PWhere, Plan, plan_query,
)

N = nokey.N


# ── plaintext predicate evaluation (server-side; plain columns only) ─────────
def _cmp(a, op: str, b) -> bool:
    try:
        return _compare(a, op, b)
    except TypeError as exc:
        raise ExecError(f"WHERE: cannot compare {a!r} {op} {b!r} ({exc})")
    except ValueError as exc:
        raise ExecError(f"WHERE: {exc}")


def _atom(row: dict, atom) -> bool:
    v = row.get(atom.column)
    if isinstance(atom, PInList):
        return v is not None and v in atom.values
    return _cmp(v, atom.op, atom.value)


def _atom_null_safe(row: dict, atom) -> bool:
    """Like _atom, but a NULL operand (LEFT JOIN null side / NULL cell) makes
    the comparison false, as in SQL."""
    v = row[atom.column]
    if v is None:
        return not isinstance(atom, PInList) and atom.op == "is_null"
    if isinstance(atom, PInList):
        return v in atom.values
    return _cmp(v, atom.op, atom.value)


def _match(row: dict, where) -> bool:
    return any(all(_atom(row, a) for a in group) for group in where.or_terms)


# ── The untrusted server: blinded scalars + plaintext columns, NO keys ───────
class NoKeyServer:
    """Holds schema, plaintext columns, and blinded scalars for encrypted
    columns. No secret key, no public key, no masks, no decode — ever.

    Rows live in per-table stores (:mod:`torusdb_core.store`): in memory by
    default, or in heap files on disk (``storage=DiskStorage(dir)``)."""

    def __init__(self, storage=None) -> None:
        self._storage = storage or MemoryStorage()
        self._schema: dict[str, list[tuple[str, str, str]]] = {}
        # table -> TableStore. Row ids are stable: DELETE marks a slot dead and
        # never reindexes (mask-vault keys must not shift).
        self._rows: dict[str, TableStore] = {}

    # — catalog / storage (server sees plaintext cols + blinded scalars) —
    def create(self, table: str, columns: list[tuple[str, str, str]],
               if_not_exists: bool = False) -> bool:
        """Create a table; returns False (and changes nothing) when it already
        exists and ``if_not_exists`` is set."""
        if table in self._schema:
            if if_not_exists:
                return False
            raise PlanError(f"table {table!r} already exists")
        self._schema[table] = columns
        self._rows[table] = self._storage.new_table(table)
        return True

    def drop(self, table: str):
        """Remove a table. Returns what :meth:`undrop` needs to bring it back."""
        saved = (self._schema.pop(table, None), self._rows.pop(table, None))
        meta = None
        if saved[1] is not None and getattr(self._storage, "paged", False):
            meta = self._storage.forget(table, saved[1])
        return saved + (meta,)

    def drop_if_exists(self, table: str) -> bool:
        if table not in self._schema:
            return False
        self.drop(table)
        return True

    def undrop(self, table: str, saved) -> None:
        schema, store, meta = saved
        if schema is not None:
            self._schema[table], self._rows[table] = schema, store
            if getattr(self._storage, "paged", False):
                self._storage.restore(table, store, meta)

    def tables(self) -> list[str]:
        return sorted(self._schema)

    def schema(self, table: str) -> list[tuple[str, str, str]]:
        if table not in self._schema:
            raise PlanError(f"no such table: {table}")
        return self._schema[table]

    def insert(self, table: str, row: dict) -> int:
        return self._rows[table].append(row)             # rowid

    def insert_many(self, table: str, rows: list[dict]) -> list[int]:
        return self._rows[table].append_many(rows)

    def update_cell(self, table: str, idx: int, col: str, value) -> None:
        self._rows[table].set_cell(idx, col, value)

    def delete_rows(self, table: str, idxs: list[int]) -> int:
        return len(self._rows[table].kill(idxs))

    def create_index(self, table: str, col: str) -> None:
        cols = {c[0]: c for c in self.schema(table)}
        if col not in cols:
            raise PlanError(f"no such column: {col}")
        if cols[col][2] != "plain":
            raise PlanError(f"cannot index {col!r}: only PLAIN columns can be indexed")
        self._rows[table].create_index(col)

    def drop_index(self, table: str, col: str) -> None:
        self.schema(table)
        self._rows[table].drop_index(col)

    def indexes(self, table: str) -> list[str]:
        self.schema(table)
        return self._rows[table].indexed_columns

    # — FHE columns: the server evaluates on ciphertexts using PUBLIC data only —
    def fhe_sum(self, table: str, col: str, idxs: list[int]) -> bytes:
        from . import fhe
        return fhe.sum_cells(self._rows[table].cells(col, idxs))

    def fhe_dot(self, ltable: str, lcol: str, lids: list[int],
                rtable: str, rcol: str, rids: list[int]) -> bytes:
        from . import fhe
        return fhe.dot_cells(self._rows[ltable].cells(lcol, lids),
                             self._rows[rtable].cells(rcol, rids))

    # — selection over the PLAINTEXT predicate (encrypted cols never tested) —
    def matching_rowids(self, table: str, where) -> list[int]:
        store = self._rows[table]
        if where is None:
            return list(store.live_ids())
        groups = [[(a.column, "in", list(a.values)) if isinstance(a, PInList)
                   else (a.column, _NORM_OP.get(a.op, ""), a.value) for a in g]
                  for g in where.or_terms]
        cand = store.candidates(groups)
        ids = cand if cand is not None else store.live_ids()
        return [i for i in ids if not store.is_dead(i) and _match(store.row(i), where)]

    def plain_cells(self, table: str, col: str, idxs: list[int]) -> list[Any]:
        store = self._rows[table]
        if col == "__cid__" or col.startswith("__mv__"):
            # owner bookkeeping columns may be absent on rows written by another
            # mask store; report None instead of failing the whole read
            return [store.cell(i, col, None) for i in idxs]
        return store.cells(col, idxs)

    def blinded_cell(self, table: str, col: str, idx: int) -> int:
        return self._rows[table].row(idx)[col]

    def blinded_cells(self, table: str, col: str, idxs: list[int]) -> list[int]:
        return self._rows[table].cells(col, idxs)

    # — Π_lin (Construction 16, step 2): affine form on blinded scalars —
    def blinded_sum(self, table: str, col: str, idxs: list[int]) -> int:
        return sum(self._rows[table].cells(col, idxs)) % N

    def blinded_scaled_sum(self, table: str, col: str, idxs: list[int],
                           k: int) -> int:
        return k * sum(self._rows[table].cells(col, idxs)) % N

    def blinded_per_row_scaled(self, table: str, col: str, idxs: list[int],
                               k: int) -> list[int]:
        return [k * v % N for v in self._rows[table].cells(col, idxs)]

    # — Π_mult (Construction 18, step 2): combine opened operands —
    @staticmethod
    def mult_combine_batch(openings: list[tuple[int, int]]) -> list[int]:
        return [e * g % N for (e, g) in openings]

    # — durable storage of the (keyless) blinded database ——————————————
    def to_body(self) -> dict:
        """JSON-safe LOGICAL image of the whole database (no keys, no masks).
        Works for every storage back end; used for backups and migration."""
        return {"schema": {t: [list(c) for c in cols]
                           for t, cols in self._schema.items()},
                "rows": {t: [{k: _pv(v) for k, v in store.row(i).items()}
                             for i in range(len(store))]
                         for t, store in self._rows.items()},
                "deleted": {t: store.dead_ids() for t, store in self._rows.items()},
                "indexes": {t: store.indexed_columns for t, store in self._rows.items()
                            if store.indexed_columns}}

    def body_chunks(self, extra: dict, rows_per_chunk: int = 2000):
        """Yield the *canonical* JSON text of ``{"body": to_body(), "extra": extra}``
        piece by piece (keys sorted, compact separators — byte-identical to
        ``json.dumps(..., sort_keys=True, separators=(",", ":"))``) so a snapshot
        of a huge database never has to exist in memory at once."""
        import json
        dumps = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"))   # noqa: E731
        tables = sorted(self._schema)
        yield '{"body":{"deleted":{'
        yield ",".join(f"{dumps(t)}:{dumps(self._rows[t].dead_ids())}" for t in tables)
        yield '},"indexes":{'
        yield ",".join(f"{dumps(t)}:{dumps(self._rows[t].indexed_columns)}" for t in tables
                       if self._rows[t].indexed_columns)
        yield '},"rows":{'
        for n, t in enumerate(tables):
            store = self._rows[t]
            yield ("," if n else "") + dumps(t) + ":["
            buf: list[str] = []
            for i in range(len(store)):
                buf.append(dumps({k: _pv(v) for k, v in store.row(i).items()}))
                if len(buf) >= rows_per_chunk:
                    yield ("," if i >= rows_per_chunk else "") + ",".join(buf)
                    buf = []
            if buf:
                yield ("," if len(store) > len(buf) else "") + ",".join(buf)
            yield "]"
        yield '},"schema":{'
        yield ",".join(f"{dumps(t)}:{dumps([list(c) for c in self._schema[t]])}" for t in tables)
        yield '}},"extra":' + dumps(extra) + "}"

    def checkpoint_body(self, gen: int) -> dict:
        """Snapshot body for generation ``gen``. For disk storage this flushes the
        heaps and writes slot tables, returning a small manifest; the caller must
        call :meth:`checkpoint_done` once the manifest is durably in place."""
        if not getattr(self._storage, "paged", False):
            return self.to_body()
        tables = {}
        for t in list(self._rows):
            self._rows[t], tables[t] = self._storage.checkpoint_table(t, self._rows[t], gen)
        self._manifest_tables = tables
        return {"paged": 1, "next_fid": self._storage.next_fid,
                "schema": {t: [list(c) for c in cols] for t, cols in self._schema.items()},
                "tables": tables}

    def checkpoint_done(self) -> None:
        if getattr(self._storage, "paged", False):
            self._storage.collect(self._manifest_tables)

    def stats(self) -> dict:
        return {t: {"rows": len(s), "deleted": s.dead_count(), "indexes": s.indexed_columns}
                for t, s in self._rows.items()}

    def close(self) -> None:
        for s in self._rows.values():
            s.close()
        self._storage.close()

    @classmethod
    def from_body(cls, snap: dict, storage=None) -> "NoKeyServer":
        paged_snap = bool(snap.get("paged"))
        if paged_snap and not (storage is not None and getattr(storage, "paged", False)):
            raise ValueError("this snapshot is a disk-storage manifest; open it with "
                             "DiskStorage (or restore a logical backup)")
        srv = cls(storage)
        srv._schema = {t: [tuple(c) for c in cols] for t, cols in snap["schema"].items()}
        if paged_snap:
            storage.next_fid = max(storage.next_fid, snap.get("next_fid", 1))
            for t, entry in snap["tables"].items():
                store = storage.open_table(t, entry)
                for col in entry.get("indexes", []):
                    store.create_index(col)
                srv._rows[t] = store
            srv._manifest_tables = dict(snap["tables"])
            storage.collect(srv._manifest_tables)          # drop crash leftovers
            return srv
        for t in srv._schema:                               # logical image: import
            store = srv._rows[t] = storage.new_table(t) if storage else MemoryStorage().new_table(t)
            for row in snap["rows"].get(t, []):
                store.append({k: _upv(v) for k, v in row.items()})
            store.kill(snap.get("deleted", {}).get(t, []))
            for col in snap.get("indexes", {}).get(t, []):
                store.create_index(col)
        return srv

    def save(self, path: str) -> None:
        """Persist schema + blinded/plaintext rows. Contains NO key material
        and NO masks — a stolen snapshot is a one-time pad."""
        _atomic_write_json(path, self.to_body())

    @classmethod
    def open(cls, path: str) -> "NoKeyServer":
        import json
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_body(json.load(f))


class CommittedView(NoKeyServer):
    """Read-only :class:`NoKeyServer` showing the last committed state while a
    write transaction (described by ``ov``) is open."""

    def __init__(self, srv: NoKeyServer, ov: TxOverlay) -> None:
        self._storage = srv._storage
        self._schema, self._rows = {}, {}
        for t, cols in srv._schema.items():
            if t in ov.created and t not in ov.dropped:
                continue
            if t in ov.dropped:                    # dropped then re-created in the tx
                cols, store = ov.dropped[t]
            else:
                store = srv._rows[t]
            self._schema[t] = cols
            self._rows[t] = StoreView(t, store, ov)
        for t, (cols, store) in ov.dropped.items():
            if t not in self._schema and cols is not None:
                self._schema[t] = cols
                self._rows[t] = StoreView(t, store, ov)


_NORM_OP = {"=": "=", "==": "=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}


# ── The owner/client: masks + encode/decode, drives the protocol ─────────────
def _mac_col(col: str) -> str:
    return "__mac__" + col


@dataclass
class NoKeyClient:
    server: NoKeyServer
    _owner: Owner = field(default_factory=Owner)
    # mask vault: (table, rowid, col) -> r   (NEVER leaves the client)
    _masks: dict[tuple[str, int, str], int] = field(default_factory=dict)
    _coltype: dict[tuple[str, str], str] = field(default_factory=dict)
    _colpolicy: dict[tuple[str, str], str] = field(default_factory=dict)
    # the owner's own copy of the schema (so planning never depends on the
    # server — the server may be a remote, schema-opaque proxy)
    _schema: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)
    # Integrity (no-key paper §IX): when authenticated, each encrypted cell s
    # carries a one-time-padded SPDZ-style MAC m = α·s (α secret to the owner);
    # the owner verifies the MAC of every affine result, catching a cheating
    # server except w.p. 1/n. α and the MAC masks live in the vault, so key
    # custody protects them too.
    authenticated: bool = False
    _alpha: int = 0
    # where the masks live (see maskstore.py); default = this process
    maskstore: MaskStore | None = None
    # secret key of the FHE columns (torusdb_core.fhe.FheKey); None = no FHE columns
    fhe: Any = None
    # Tables whose column policies were learned from the (untrusted) server
    # rather than created/vaulted by this owner. A malicious server could relabel
    # an encrypted column "plain" and receive plaintext, so writes to such
    # tables are refused unless the caller vouches for the schema.
    _untrusted: set = field(default_factory=set)

    def _require_trusted(self, table: str) -> None:
        if table in self._untrusted:
            raise PlanError(
                f"table {table!r}: its schema was learned from the server, which could "
                f"mislabel an encrypted column as plain; refusing to write. Create the "
                f"table through this vault, or pass trust_server_schema=True after "
                f"verifying the schema yourself")

    def __post_init__(self):
        if self.maskstore is None:
            self.maskstore = DictMaskStore()
        self.maskstore.bind(self)
        cfg = self.maskstore.config()          # a shared mask cluster dictates these
        if cfg is not None:
            self.authenticated = bool(cfg["authenticated"])
            self._alpha = int(cfg["alpha"])
        if self.authenticated and self._alpha == 0:
            self._alpha = secrets.randbelow(N - 1) + 1

    # — entry point —
    def execute(self, sql: str) -> Any:
        plan = plan_query(parse(sql), _CatalogView(self._schema))
        if plan.kind == "noop":                  # IF [NOT] EXISTS that has nothing to do
            return 0
        if plan.kind == "drop_if_exists":        # unknown to this client: ask the server
            if self.server.drop_if_exists(plan.table):
                self._forget_table(plan.table)
            return 0
        if plan.kind == "create":
            return self._create(plan)
        if plan.kind == "drop":
            self.server.drop(plan.table)
            self._forget_table(plan.table)
            return 0
        if plan.kind == "create_index":
            self.server.create_index(plan.table, plan.raw.column)
            return 0
        if plan.kind == "drop_index":
            self.server.drop_index(plan.table, plan.raw.column)
            return 0
        if plan.kind == "insert":
            return self._insert(plan)
        if plan.kind == "update":
            return self._update(plan)
        if plan.kind == "delete":
            return self._delete(plan)
        if plan.kind == "select":
            return self._select(plan)
        raise PlanError(f"unsupported: {plan.kind}")

    # — DDL —
    def _create(self, plan: Plan) -> int:
        q = plan.raw
        cols = [(c.name, c.type, c.policy) for c in
                _spec_columns(q)]
        if not self.server.create(q.name, cols, q.if_not_exists):
            # it exists on the server but this client did not know it: adopt the
            # server's schema, read-only until the caller vouches for it
            cols = [tuple(c) for c in self.server.schema(q.name)]
            self._untrusted.add(q.name)
        self._schema[q.name] = cols
        for (name, typ, pol) in cols:
            self._coltype[(q.name, name)] = typ
            self._colpolicy[(q.name, name)] = pol
        return 0

    # — INSERT: blind encrypted cells, keep masks, send only blinded —
    def _blind_row(self, q) -> tuple[dict, dict]:
        table = q.table
        row: dict[str, Any] = {}
        pending_masks: dict[str, int] = {}
        for cname, raw in zip(q.columns, q.values):
            policy = self._colpolicy[(table, cname)]
            value = _literal_to_value(raw, self._coltype[(table, cname)])
            if policy == "plain":
                row[cname] = value
            elif policy == "fhe":
                row[cname] = self._fhe_key().encrypt(self._fhe_int(value, cname))
            else:
                s = encode(value)
                blinded, r = self._owner.blind(s)
                row[cname] = blinded
                pending_masks[cname] = r
                if self.authenticated:
                    mac = self._alpha * s % N           # SPDZ MAC m = α·s
                    mblind, mr = self._owner.blind(mac)
                    row[_mac_col(cname)] = mblind
                    pending_masks[_mac_col(cname)] = mr
        return row, pending_masks

    def _insert(self, plan: Plan) -> int:
        q = plan.raw
        self._require_trusted(q.table)
        row, masks = self._blind_row(q)
        # masks first, row second: a crash in between leaves an orphan MASK
        # (harmless), never a server cell with no mask (unreadable forever)
        extras = self.maskstore.stage_insert(q.table, [masks])[0]
        row.update(extras)
        rowid = self.server.insert(q.table, row)
        self.maskstore.commit_insert(q.table, [rowid], [masks], [extras])
        return 1

    def insert_many(self, sqls: list[str]) -> int:
        """Bulk-load: every statement must be an INSERT into one table. The
        rows are blinded locally and sent in a single round trip."""
        plans = [plan_query(parse(s), _CatalogView(self._schema)) for s in sqls]
        if not plans:
            return 0
        table = plans[0].table
        if any(p.kind != "insert" or p.table != table for p in plans):
            raise PlanError("insert_many requires INSERTs into a single table")
        self._require_trusted(table)
        blinded = [self._blind_row(p.raw) for p in plans]
        all_masks = [m for _, m in blinded]
        extras = self.maskstore.stage_insert(table, all_masks)
        rows = []
        for (row, _m), ex in zip(blinded, extras):
            row.update(ex)
            rows.append(row)
        rowids = self.server.insert_many(table, rows)
        self.maskstore.commit_insert(table, rowids, all_masks, extras)
        return len(rowids)

    def _forget_table(self, table: str) -> None:
        self._schema.pop(table, None)
        for d in (self._coltype, self._colpolicy):
            for k in [k for k in d if k[0] == table]:
                del d[k]
        self.maskstore.forget_table(table)

    # — UPDATE: re-blind changed encrypted cells, refresh their masks —
    def _update(self, plan: Plan) -> int:
        q = plan.raw
        table = q.table
        self._require_trusted(table)
        idxs = self.server.matching_rowids(table, plan.where)
        per_row = []                                  # (rowid, masks, [(col, cell)])
        for i in idxs:
            masks: dict[str, int] = {}
            cells: list[tuple[str, Any]] = []
            for (col, raw) in q.assignments:
                value = _literal_to_value(raw, self._coltype[(table, col)])
                if self._colpolicy[(table, col)] == "plain":
                    cells.append((col, value))
                elif self._colpolicy[(table, col)] == "fhe":
                    cells.append((col, self._fhe_key().encrypt(self._fhe_int(value, col))))
                else:
                    s = encode(value)
                    blinded, r = self._owner.blind(s)
                    cells.append((col, blinded))
                    masks[col] = r
                    if self.authenticated:
                        mblind, mr = self._owner.blind(self._alpha * s % N)
                        cells.append((_mac_col(col), mblind))
                        masks[_mac_col(col)] = mr
            per_row.append((i, masks, cells))
        items = [(i, m) for i, m, _ in per_row if m]
        # new masks are persisted (under a new version) BEFORE any cell changes
        extras = self.maskstore.stage_update(table, items) if items else []
        extra_by_row = {i: e for (i, _m), e in zip(items, extras)}
        for i, _masks, cells in per_row:
            for col, v in cells:
                self.server.update_cell(table, i, col, v)
            for col, v in extra_by_row.get(i, {}).items():
                self.server.update_cell(table, i, col, v)
        if items:
            self.maskstore.commit_update(table, items, extras)
        return len(idxs)

    # — DELETE: tombstone the matched rows (rowids/masks stay stable) —
    def _delete(self, plan: Plan) -> int:
        idxs = self.server.matching_rowids(plan.table, plan.where)
        return self.server.delete_rows(plan.table, idxs)

    # — SELECT —
    #
    # One pipeline for single-table and join queries. A "tuple" holds one
    # rowid per table instance (None for the null side of a LEFT JOIN); a
    # single-table query is simply 1-tuples. Plain columns are evaluated at
    # the owner on plaintext cells; encrypted columns only ever leave the
    # server as blinded scalars (Π_lin / Π_mult), never decrypted there.
    def _select(self, plan: Plan) -> "ResultSet":
        qualified = plan.instances is not None
        inst = plan.instances or {plan.table: plan.table}
        names = list(inst)

        def loc(col_name: str) -> tuple[str, str]:
            """Plan column name -> (instance, bare column)."""
            if qualified:
                a, c = col_name.split(".", 1)
                return a, c
            return names[0], col_name

        tuples = self._base_tuples(plan, inst, names, loc, qualified)

        # ORDER BY a column that is not selected: sort on a hidden trailing
        # column, then drop it (not meaningful for a single aggregate row).
        ob = plan.order_by
        hidden = (ob is not None
                  and ob.column not in [self._proj_name(p)
                                        for p in plan.projections]
                  and (bool(plan.group_by)
                       or not any(isinstance(p, self._AGG)
                                  for p in plan.projections)))
        if hidden:
            plan = dataclasses.replace(
                plan, projections=list(plan.projections)
                + [PColRef(name=ob.column, policy="plain")])

        if plan.group_by:
            rs = self._grouped(plan, inst, names, loc, tuples)
        else:
            rs = self._project(plan, inst, names, loc, tuples)
        rs = self._finish(rs, plan)
        if hidden:
            rs.columns = rs.columns[:-1]
            rs.rows = [r[:-1] for r in rs.rows]
        return rs

    # — row sources: FROM table (+ WHERE pushdown), then each join step —
    def _base_tuples(self, plan, inst, names, loc, qualified):
        first = names[0]
        push, post = self._split_where(plan.where, first, qualified)
        left_ids = self.server.matching_rowids(inst[first], push)
        tuples: list[tuple] = [(i,) for i in left_ids]
        pos = {a: k for k, a in enumerate(names)}

        for j in plan.joins or []:
            right_ids = self.server.matching_rowids(j.table, None)
            right_keys = self.server.plain_cells(j.table, j.right_col, right_ids)
            right_map: dict = {}
            for ridx, rkey in zip(right_ids, right_keys):
                if rkey is not None:                # NULL never equals NULL
                    right_map.setdefault(rkey, []).append(ridx)
            lkeys = self._ids_to_cells(
                inst[j.left_alias], j.left_col,
                [t[pos[j.left_alias]] for t in tuples])
            stepped: list[tuple] = []
            for t, lk in zip(tuples, lkeys):
                matches = right_map.get(lk, ()) if lk is not None else ()
                if matches:
                    stepped.extend(t + (m,) for m in matches)
                elif j.kind == "left":
                    stepped.append(t + (None,))
            tuples = stepped

        if post is not None:
            tuples = self._post_filter(post, inst, names, loc, tuples)
        return tuples

    @staticmethod
    def _split_where(where, first: str, qualified: bool):
        """(pushdown, post): predicates touching only the FROM table run at
        the server's plaintext index; anything else filters the joined rows."""
        if where is None:
            return None, None
        if not qualified:
            return where, None
        pre = first + "."
        atoms = [a for g in where.or_terms for a in g]
        if all(a.column.startswith(pre) for a in atoms):
            stripped = []
            for g in where.or_terms:
                ng = []
                for a in g:
                    bare = a.column[len(pre):]
                    ng.append(PInList(column=bare, values=a.values)
                              if isinstance(a, PInList)
                              else PCondition(column=bare, op=a.op,
                                              value=a.value))
                stripped.append(ng)
            return PWhere(or_terms=stripped), None
        return None, where

    def _post_filter(self, where, inst, names, loc, tuples):
        pos = {a: k for k, a in enumerate(names)}
        cols = {a.column for g in where.or_terms for a in g}
        vals = {}
        for c in cols:
            alias, bare = loc(c)
            vals[c] = self._ids_to_cells(
                inst[alias], bare, [t[pos[alias]] for t in tuples])
        keep = []
        for k, t in enumerate(tuples):
            row = {c: v[k] for c, v in vals.items()}
            if any(all(_atom_null_safe(row, a) for a in g)
                   for g in where.or_terms):
                keep.append(t)
        return keep

    # — fetch a plain column for (possibly None) rowids, batched + deduped —
    def _ids_to_cells(self, table: str, col: str, ids: list) -> list:
        uniq = sorted({i for i in ids if i is not None})
        got = dict(zip(uniq, self.server.plain_cells(table, col, uniq))) \
            if uniq else {}
        return [got.get(i) if i is not None else None for i in ids]

    # — owner-side reveal of a column for each tuple (None rowid -> None) —
    def _reveal_col(self, table: str, col: str, ids: list) -> list:
        uniq = sorted({i for i in ids if i is not None})
        if not uniq:
            return [None] * len(ids)
        vals = self._reveal_many(table, col, uniq)
        got = dict(zip(uniq, vals))
        return [got.get(i) if i is not None else None for i in ids]

    def _reveal_many(self, table: str, col: str, idxs: list[int]) -> list:
        policy = self._colpolicy[(table, col)]
        if policy == "plain":
            return self.server.plain_cells(table, col, idxs)
        if policy == "fhe":
            key = self._fhe_key()
            return [key.decrypt_cell(c) for c in self.server.plain_cells(table, col, idxs)]
        return [decode(s) for s in self._read_verified_scalars(table, col, idxs)]

    _AGG = (PSum, PAvg, PCountStar, PScaledSum, PDot, PScalarMul, PCtMul,
            PMin, PMax)

    def _project(self, plan, inst, names, loc, tuples) -> "ResultSet":
        pos = {a: k for k, a in enumerate(names)}
        out_cols = [self._proj_name(p) for p in plan.projections]
        agg = any(isinstance(p, self._AGG) for p in plan.projections)
        if not agg:
            vecs = []
            for p in plan.projections:
                alias, bare = loc(p.name)
                vecs.append(self._reveal_col(
                    inst[alias], bare, [t[pos[alias]] for t in tuples]))
            rows = [list(r) for r in zip(*vecs)] if vecs else [[] for _ in tuples]
            return ResultSet(out_cols, rows)
        cells = [self._eval_agg(p, inst, names, loc, tuples)
                 for p in plan.projections]
        return ResultSet(out_cols, [cells])

    def _grouped(self, plan, inst, names, loc, tuples) -> "ResultSet":
        pos = {a: k for k, a in enumerate(names)}
        gcols = plan.group_by
        keyvecs = []
        for g in gcols:
            alias, bare = loc(g)
            keyvecs.append(self._ids_to_cells(
                inst[alias], bare, [t[pos[alias]] for t in tuples]))
        groups: dict[tuple, list[tuple]] = {}
        for k, t in enumerate(tuples):
            groups.setdefault(tuple(v[k] for v in keyvecs), []).append(t)

        out_cols = [self._proj_name(p) for p in plan.projections]
        rows = []
        for key, gtuples in groups.items():
            if plan.having and not _cmp(len(gtuples), plan.having[0],
                                        plan.having[1]):
                continue
            cells = []
            for p in plan.projections:
                if isinstance(p, PColRef):
                    cells.append(key[gcols.index(p.name)])
                else:
                    cells.append(self._eval_agg(p, inst, names, loc, gtuples))
            rows.append(cells)
        return ResultSet(out_cols, rows)

    @staticmethod
    def _proj_name(p) -> str:
        if isinstance(p, PColRef):
            return p.name
        if isinstance(p, PSum):
            return f"sum({p.column})"
        if isinstance(p, PAvg):
            return f"avg({p.column})"
        if isinstance(p, PMin):
            return f"min({p.column})"
        if isinstance(p, PMax):
            return f"max({p.column})"
        if isinstance(p, PCountStar):
            return "count(*)"
        if isinstance(p, PScaledSum):
            return f"{p.scalar}*sum({p.column})"
        if isinstance(p, PScalarMul):
            return f"{p.scalar}*{p.column}"
        if isinstance(p, PDot):
            return f"dot({p.left},{p.right})"
        if isinstance(p, PCtMul):
            return f"{p.left}*{p.right}"
        return "expr"

    # — evaluate one (aggregate / per-row encrypted) projection over tuples —
    def _eval_agg(self, p, inst, names, loc, tuples):
        pos = {a: k for k, a in enumerate(names)}

        def ids(col_name):
            alias, bare = loc(col_name)
            return inst[alias], bare, [t[pos[alias]] for t in tuples]

        def live(col_name):
            table, bare, all_ids = ids(col_name)
            return table, bare, [i for i in all_ids if i is not None]

        if isinstance(p, PCountStar):
            return len(tuples)
        if isinstance(p, PColRef):
            table, bare, all_ids = ids(p.name)
            return self._reveal_col(table, bare, all_ids)
        if isinstance(p, (PMin, PMax)):
            table, bare, lv = live(p.column)
            vals = [v for v in self.server.plain_cells(table, bare, lv)
                    if v is not None] if lv else []
            if not vals:
                return None
            return min(vals) if isinstance(p, PMin) else max(vals)
        if isinstance(p, PSum):
            table, bare, lv = live(p.column)
            if self._colpolicy[(table, bare)] == "fhe":
                return self._fhe_sum(table, bare, lv)
            return self._pi_lin_sum(table, bare, lv)
        if isinstance(p, PAvg):
            table, bare, lv = live(p.column)
            if self._colpolicy[(table, bare)] == "fhe":
                return Fraction(self._fhe_sum(table, bare, lv), len(lv)) if lv else None
            if self._colpolicy[(table, bare)] == "plain":
                vals = [v for v in self.server.plain_cells(table, bare, lv)
                        if v is not None] if lv else []
                if not vals:
                    return None
                return Fraction(sum(vals)) / len(vals)      # NULLs are skipped
            if not lv:
                return None
            total = self._pi_lin_sum(table, bare, lv)
            n = len(lv)
            return total / n if isinstance(total, Fraction) else Fraction(total, n)
        if isinstance(p, PScaledSum):
            table, bare, lv = live(p.column)
            return self._pi_lin_scaled_sum(table, bare, lv, p.scalar)
        if isinstance(p, PScalarMul):
            table, bare, all_ids = ids(p.column)
            lv = [i for i in all_ids if i is not None]
            done = iter(self._pi_lin_per_row(table, bare, lv, p.scalar)
                        if lv else [])
            return [next(done) if i is not None else None for i in all_ids]
        if isinstance(p, (PDot, PCtMul)):
            lt, lc, lids = ids(p.left)
            rt, rc, rids = ids(p.right)
            both = [(a, b) for a, b in zip(lids, rids)
                    if a is not None and b is not None]
            if isinstance(p, PDot) and p.fhe:
                return self._fhe_dot(lt, lc, [a for a, _ in both], rt, rc, [b for _, b in both])
            prods = self._pi_mult_products(
                lt, lc, [a for a, _ in both], rt, rc, [b for _, b in both]) \
                if both else []
            if isinstance(p, PDot):
                return sum(prods) if prods else 0
            done = iter(prods)
            return [next(done) if (a is not None and b is not None) else None
                    for a, b in zip(lids, rids)]
        raise PlanError(f"unsupported projection {p}")

    # — FHE columns —
    _FHE_SUM_CHUNK = 2000
    _FHE_DOT_CHUNK = 100               # ~0.2 s per row in pure Python: keep calls well under the timeout

    def _fhe_key(self):
        if self.fhe is None:
            raise ExecError("this table has FHE columns but no FHE key is loaded "
                            "(connect with fhe_key=…)")
        return self.fhe

    @staticmethod
    def _fhe_int(value, col: str) -> int:
        if isinstance(value, Fraction):
            if value.denominator != 1:
                raise ExecError(f"FHE column {col!r} holds integers only")
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExecError(f"FHE column {col!r} holds integers only")
        return value

    def _fhe_sum(self, table: str, col: str, idxs: list[int]) -> int:
        from . import fhe
        key = self._fhe_key()
        if not idxs:
            return 0
        total = None
        for i in range(0, len(idxs), self._FHE_SUM_CHUNK):
            part = self.server.fhe_sum(table, col, idxs[i:i + self._FHE_SUM_CHUNK])
            total = part if total is None else fhe.add_sums(total, part)
        return key.decrypt_sum(total)

    def _fhe_dot(self, lt, lc, lids, rt, rc, rids) -> int:
        from . import fhe
        key = self._fhe_key()
        if not lids:
            return 0
        total = None
        for i in range(0, len(lids), self._FHE_DOT_CHUNK):
            part = self.server.fhe_dot(lt, lc, lids[i:i + self._FHE_DOT_CHUNK],
                                       rt, rc, rids[i:i + self._FHE_DOT_CHUNK])
            total = part if total is None else fhe.mul_dots(total, part)
        return key.decrypt_dot(total)

    # — Π_lin: SUM = Σ s̃ᵢ on the server, minus Σ rᵢ at the owner —
    def _pi_lin_sum(self, table: str, col: str, idxs: list[int]):
        blinded = self.server.blinded_sum(table, col, idxs)
        mask = self.maskstore.sum(table, col, idxs)
        y = self._owner.unblind_affine(blinded, [1], [mask])
        if self.authenticated:
            self._verify_mac(table, col, idxs, y, scale=1, per_row=False)
        return decode(y)

    def _pi_lin_scaled_sum(self, table: str, col: str, idxs: list[int], k: int):
        blinded = self.server.blinded_scaled_sum(table, col, idxs, k)
        mask = self.maskstore.sum(table, col, idxs)
        y = self._owner.unblind_affine(blinded, [k], [mask])
        if self.authenticated:
            self._verify_mac(table, col, idxs, y, scale=k, per_row=False)
        return decode(y)

    def _pi_lin_per_row(self, table: str, col: str, idxs: list[int], k: int):
        blinded = self.server.blinded_per_row_scaled(table, col, idxs, k)
        masks = self.maskstore.get(table, col, idxs) if idxs else []
        ys = [self._owner.unblind_affine(bi, [k], [m])
              for bi, m in zip(blinded, masks)]
        if self.authenticated:
            self._verify_mac(table, col, idxs, ys, scale=k, per_row=True)
        return [decode(y) for y in ys]

    # — verify the SPDZ MAC of an affine result (no-key paper §IX) —
    def _verify_mac(self, table, col, idxs, y, *, scale, per_row):
        mcol = _mac_col(col)
        if per_row:
            mblind = self.server.blinded_per_row_scaled(table, mcol, idxs, scale)
            mmasks = self.maskstore.get(table, mcol, idxs) if idxs else []
            for bi, i, yi, mm in zip(mblind, idxs, y, mmasks):
                M = self._owner.unblind_affine(bi, [scale], [mm])
                if M != self._alpha * yi % N:
                    raise IntegrityError(
                        f"MAC check failed on per-row {scale}*{col} (row {i}) — "
                        f"server returned a forged value")
        else:
            mblind = self.server.blinded_scaled_sum(table, mcol, idxs, scale)
            mmask = self.maskstore.sum(table, mcol, idxs)
            M = self._owner.unblind_affine(mblind, [scale], [mmask])
            if M != self._alpha * y % N:
                raise IntegrityError(
                    f"MAC check failed on {scale}*sum({col}) — server returned "
                    f"a forged/incorrect aggregate")

    # — Π_mult: per-row products via Beaver triples, one batched round —
    # The operands may live in different tables (a join pairs row i of the
    # left table with row j of the right); lids[k] and rids[k] are the
    # operands of product k.
    def _pi_mult_products(self, ltable: str, left: str, lids: list[int],
                          rtable: str, right: str, rids: list[int]) -> list:
        triples, openings = [], []
        # owner reconstructs (and, when authenticated, MAC-verifies) its own
        # encoded operands — a server that tampered with a stored operand is
        # caught here before the product is formed. Fetched in two batches.
        sls = self._read_verified_scalars(ltable, left, lids)
        srs = self._read_verified_scalars(rtable, right, rids)
        for sl, sr in zip(sls, srs):
            t = gen_triple()
            e, g = self._owner.mult_open(sl, sr, t)
            triples.append(t); openings.append((e, g))
        egs = self.server.mult_combine_batch(openings)        # server: no key
        prods = []
        for (e, g), eg, t in zip(openings, egs, triples):
            if self.authenticated and eg != e * g % N:
                raise IntegrityError(
                    "server returned a forged product term in DOT/× "
                    "(e·g mismatch)")
            prods.append(decode(self._owner.mult_reconstruct(e, g, eg, t)))
        return prods

    # — batch form: one round trip for the values (+ one for their MACs) —
    def _read_verified_scalars(self, table: str, col: str,
                               ids: list[int]) -> list[int]:
        if not ids:
            return []
        blinded = self.server.blinded_cells(table, col, ids)
        masks = self.maskstore.get(table, col, ids)
        ss = [(b - r) % N for b, r in zip(blinded, masks)]
        if self.authenticated:
            mb = self.server.blinded_cells(table, _mac_col(col), ids)
            mmasks = self.maskstore.get(table, _mac_col(col), ids)
            for m, i, s, mr in zip(mb, ids, ss, mmasks):
                mm = (m - mr) % N
                if mm != self._alpha * s % N:
                    raise IntegrityError(
                        f"MAC check failed reading {col} (row {i}) — the "
                        f"stored encrypted value was tampered with")
        return ss

    # — read one encrypted cell to its scalar, verifying its MAC if on —
    def _read_verified_scalar(self, table: str, col: str, i: int) -> int:
        s = (self.server.blinded_cell(table, col, i)
             - self.maskstore.get(table, col, [i])[0]) % N
        if self.authenticated:
            m = (self.server.blinded_cell(table, _mac_col(col), i)
                 - self.maskstore.get(table, _mac_col(col), [i])[0]) % N
            if m != self._alpha * s % N:
                raise IntegrityError(
                    f"MAC check failed reading {col} (row {i}) — the stored "
                    f"encrypted value was tampered with")
        return s

    # — reveal a single stored cell at the owner boundary —
    def _reveal(self, table: str, col: str, idx: int):
        policy = self._colpolicy[(table, col)]
        if policy == "plain":
            return self.server.blinded_cell(table, col, idx)
        return decode(self._read_verified_scalar(table, col, idx))

    def _mask(self, table: str, rowid: int, col: str) -> int:
        return self.maskstore.get(table, col, [rowid])[0]

    # — the mask vault (CLIENT-side only; never sent to the server) —
    def masks_blob(self) -> bytes:
        """Serialize the entire mask vault + schema to bytes (the single
        long-lived owner secret; protect it with key custody, see keymgmt)."""
        import json
        if not self.maskstore.local:
            raise ExecError("masks are held by a threshold mask cluster; there is "
                            "no local vault to export")
        snap = {
            "masks": [[t, i, c, str(r)] for (t, i, c), r in self._masks.items()],
            "coltype": [[t, c, v] for (t, c), v in self._coltype.items()],
            "colpolicy": [[t, c, v] for (t, c), v in self._colpolicy.items()],
            "authenticated": self.authenticated,
            "alpha": str(self._alpha),
        }
        return json.dumps(snap).encode("utf-8")

    def restore_masks_blob(self, data: bytes) -> None:
        import json
        snap = json.loads(data.decode("utf-8"))
        self._masks = {(t, i, c): int(r) for (t, i, c, r) in snap["masks"]}
        self._coltype = {(t, c): v for (t, c, v) in snap["coltype"]}
        self._colpolicy = {(t, c): v for (t, c, v) in snap["colpolicy"]}
        self.authenticated = bool(snap.get("authenticated", False))
        self._alpha = int(snap.get("alpha", "0"))
        self._schema = {}
        for (t, c), typ in self._coltype.items():
            self._schema.setdefault(t, [])
            self._schema[t].append((c, typ, self._colpolicy[(t, c)]))

    def save_masks(self, path: str) -> None:
        import os
        tmp = f"{path}.tmp"
        with open(tmp, "wb") as f:
            f.write(self.masks_blob()); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)

    def load_masks(self, path: str) -> None:
        with open(path, "rb") as f:
            self.restore_masks_blob(f.read())

    # — DISTINCT / ORDER BY / LIMIT / aliases (presentation, at the owner) —
    def _finish(self, rs: "ResultSet", plan: Plan) -> "ResultSet":
        if plan.distinct:                        # dedupe output rows, order-stable
            seen, deduped = set(), []
            for row in rs.rows:
                key = tuple(repr(c) for c in row)
                if key not in seen:
                    seen.add(key); deduped.append(row)
            rs.rows = deduped
        if plan.order_by is not None and plan.order_by.column in rs.columns:
            j = rs.columns.index(plan.order_by.column)
            try:
                # NULLs (from a LEFT JOIN) sort last ascending, first descending
                rs.rows.sort(key=lambda r: (r[j] is None, r[j]),
                             reverse=plan.order_by.descending)
            except TypeError as exc:
                raise ExecError(f"ORDER BY: cannot compare values ({exc})")
        if plan.offset:
            rs.rows = rs.rows[plan.offset:]
        if plan.limit is not None:
            rs.rows = rs.rows[:plan.limit]
        if plan.out_aliases:
            for k, a in enumerate(plan.out_aliases):
                if a and k < len(rs.columns):
                    rs.columns[k] = a
        return rs


@dataclass
class ResultSet:
    columns: list[str]
    rows: list[list[Any]]


# ── glue: let the existing planner type-check against the server's schema ────
class _CatalogView:
    """Adapts the owner's schema to the planner's catalog interface so we
    reuse the exact same policy/type validation (the open/closed agreement
    rules) without duplicating them — and without consulting the server."""
    def __init__(self, schema: dict[str, list[tuple[str, str, str]]]):
        from .catalog import ColumnSpec, TableSpec
        self.tables = {}
        for name, cols in schema.items():
            self.tables[name] = TableSpec(
                name=name,
                columns=tuple(ColumnSpec(n, t, p) for (n, t, p) in cols))

    def get(self, name: str):
        return self.tables[name]


def _spec_columns(create_q):
    from .catalog import ColumnSpec
    return [ColumnSpec(n, t, p) for (n, t, p) in create_q.columns]


def _literal_to_value(raw, coltype: str | None = None):
    if isinstance(raw, tuple) and raw and raw[0] == "frac":
        f = Fraction(raw[1], raw[2])
        if f.denominator == 1:
            return int(f)                       # one canonical form: 5, never Fraction(5,1)
        return f
    return raw


# ── persistence value codec (big-int-exact, JSON-safe) ───────────────────────
def _pv(v):
    if v is None:
        return {"t": "n"}
    if isinstance(v, bool):
        return {"t": "b", "v": v}
    if isinstance(v, int):
        return {"t": "i", "v": str(v)}
    if isinstance(v, str):
        return {"t": "s", "v": v}
    if isinstance(v, Fraction):
        return {"t": "f", "n": str(v.numerator), "d": str(v.denominator)}
    if isinstance(v, (bytes, bytearray)):
        import base64
        return {"t": "x", "v": base64.b64encode(bytes(v)).decode("ascii")}
    raise TypeError(f"cannot persist {type(v).__name__}")


def _upv(d):
    t = d["t"]
    if t == "n":
        return None
    if t == "b":
        return bool(d["v"])
    if t == "i":
        return int(d["v"])
    if t == "s":
        return d["v"]
    if t == "f":
        return Fraction(int(d["n"]), int(d["d"]))
    if t == "x":
        import base64
        return base64.b64decode(d["v"])
    raise ValueError(f"unknown persisted tag {t!r}")


def _atomic_write_json(path: str, obj) -> None:
    import json
    import os
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
