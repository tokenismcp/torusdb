# SPDX-License-Identifier: Apache-2.0
"""Threshold mask cluster: the data owner's masks, secret-shared k-of-n.

Every encrypted cell on the server is ``encode(v) + r``. Here ``r`` is drawn
independently and uniformly per cell (a *shared* secret x with public per-cell
scalars would let the server eliminate x and learn linear combinations of
plaintexts — so it is deliberately NOT done) and secret-shared with a Laurent
series among the custodians. Consequences:

* no process, host or administrator holds the vault; the owner machine is
  stateless (schema is re-learned from the server);
* an aggregate (``SUM``/``AVG``/…) is unblinded by combining the custodians'
  **partial sums** — the querier learns Σr over the rows it asked about, never
  an individual mask; only reading a cell back (``SELECT enc_col``) or an
  operand of DOT/× necessarily reveals that cell's mask to the querier;
* custodian answers are cross-checked: with more than k answers a faulty or
  malicious custodian is detected and outvoted (authenticated mode additionally
  protects against a malicious *server* via the MAC, whose key α lives in the
  cluster config, shared the same way).

Crash safety without two-phase commit: masks are stored **before** the server
row exists and old versions are never deleted before the new cell is committed
(``__cid__`` / ``__mv__<col>`` hidden plaintext columns tie a row to its mask
version). A crash leaves harmless orphan masks (collected by ``gc``), never a
cell without its mask.
"""
from __future__ import annotations

import concurrent.futures as cf
import secrets
import time
from collections import Counter

from ecfhe_query.errors import ExecError
from ecfhe_query.maskstore import MaskStore

from . import laurent
from .group import CustodyError
from .net import QuorumError
from .shares import Q

CID, MV = "__cid__", "__mv__"


def _new_version() -> int:
    """A fresh, unpredictable mask version (< 2^53, JSON/JS safe). Never derived
    from the server's value: after a rolled-back transaction the server's
    counter goes back while a stray newer mask may still exist — reusing its
    number would be (correctly) refused as mask reuse and wedge the cell."""
    return secrets.randbits(52) + 1


class MaskClusterError(CustodyError):
    pass


class MaskUnavailable(MaskClusterError):
    """Fewer than k custodians could answer (or hold the requested shares)."""
    def __init__(self, need, have, problems):
        self.problems = problems
        super().__init__(f"need {need} custodians, got {have} usable answers; {problems}")


class MaskWriteError(MaskClusterError):
    pass


class ThresholdMaskStore(MaskStore):
    local = False

    def __init__(self, nodes: list, k: int, *, xs: list[int] | None = None,
                 gen: int | None = None, write_quorum: int | None = None,
                 read_grace: float = 0.2, timeout: float = 60.0, chunk: int = 20000,
                 auto_init: bool = False):
        n = len(nodes)
        self.xs = list(xs) if xs else list(range(1, n + 1))
        if len(set(self.xs)) != n or any(x < 1 for x in self.xs):
            raise MaskClusterError("custodian points must be distinct positive integers")
        self.p = laurent.Params(k, n, Q)
        self.nodes = list(nodes)
        self.k, self.n = k, n
        self.write_quorum = write_quorum if write_quorum is not None else n
        if not k <= self.write_quorum <= n:
            raise MaskClusterError("write_quorum must satisfy k ≤ write_quorum ≤ n")
        self.read_grace, self.timeout, self.chunk = read_grace, timeout, chunk
        self.gen = gen
        self._auto_init = auto_init
        self._cfg: dict | None = None
        self._pool = cf.ThreadPoolExecutor(max_workers=max(4, n * 2))
        self._weights = {x: laurent.commit_check_weights(x, self.p.t, Q) for x in self.xs}
        self.client = None
        self.server = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def bind(self, client) -> None:
        self.client = client
        self.server = client.server

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        for nd in self.nodes:
            try:
                nd.close()
            except Exception:                                      # noqa: BLE001
                pass

    # ── fan-out ──────────────────────────────────────────────────────────────
    def _fanout(self, method: str, args_for, *, min_ok: int | None = None, indexes=None):
        """Call the chosen nodes in parallel. Returns (results{i: value}, errors{i: str}).
        Waits for every node, or — once ``min_ok`` succeeded — only ``read_grace``
        longer for the stragglers (a dead custodian never delays a read)."""
        idx = list(range(self.n)) if indexes is None else list(indexes)
        futs = {self._pool.submit(self.nodes[i].call, method, args_for(i)): i for i in idx}
        res, err = {}, {}
        deadline = time.monotonic() + self.timeout
        grace_at = None
        pending = set(futs)
        while pending:
            now = time.monotonic()
            if now >= deadline or (grace_at is not None and now >= grace_at):
                break
            timeout = (deadline if grace_at is None else min(deadline, grace_at)) - now
            done, pending = cf.wait(pending, timeout=timeout, return_when=cf.FIRST_COMPLETED)
            for f in done:
                i = futs[f]
                try:
                    res[i] = f.result()
                except Exception as exc:                           # noqa: BLE001
                    err[i] = f"{type(exc).__name__}: {exc}"
            if min_ok is not None and grace_at is None and len(res) >= min_ok:
                grace_at = time.monotonic() + self.read_grace
        for f in pending:
            f.cancel()
            err.setdefault(futs[f], "no answer in time")
        return res, err

    # ── cluster configuration (shared by every client) ───────────────────────
    def _current_gen(self) -> int | None:
        res, err = self._fanout("mask_meta_get", lambda i: [0, "current_gen"], min_ok=self.k)
        votes = Counter(v for v in res.values() if v is not None)
        if not votes:
            if len(res) >= self.k:
                return None                                       # nobody has one: uninitialised
            raise MaskUnavailable(self.k, len(res), err)
        gen, cnt = votes.most_common(1)[0]
        if cnt < min(self.k, len(res)):
            raise MaskClusterError(f"custodians disagree about the current generation: {dict(votes)}")
        return int(gen)

    def config(self) -> dict | None:
        if self._cfg is None:
            self._load_config()
        return self._cfg

    def _load_config(self) -> None:
        gen = self.gen if self.gen is not None else self._current_gen()
        if gen is None:
            if self._auto_init:
                self.initialize(authenticated=False)
                gen = self.gen
            else:
                raise MaskClusterError(
                    "the mask cluster is not initialised — run "
                    "`python -m torussql.custody mask-init` (or ThresholdMaskStore.initialize())")
        self.gen = gen
        res, err = self._fanout("mask_meta_get", lambda i: [gen, "config"], min_ok=self.k)
        cfgs = {i: c for i, c in res.items() if c}
        if len(cfgs) < self.k:
            raise MaskUnavailable(self.k, len(cfgs), err)
        any_cfg = next(iter(cfgs.values()))
        if (any_cfg["k"], any_cfg["n"]) != (self.k, self.n) or list(any_cfg["xs"]) != self.xs:
            raise MaskClusterError(
                f"cluster is configured k={any_cfg['k']} n={any_cfg['n']} xs={any_cfg['xs']}, "
                f"this client was given k={self.k} n={self.n} xs={self.xs}")
        alpha = 0
        if any_cfg["authenticated"]:
            pts = [(self.xs[i], int(c["alpha"], 16)) for i, c in cfgs.items()]
            try:
                alpha, _bad = laurent.robust_reconstruct(pts, self.k, Q)
            except laurent.InconsistentShares as exc:
                raise MaskClusterError(f"cannot recover the integrity key: {exc}") from None
        self._cfg = {"authenticated": bool(any_cfg["authenticated"]), "alpha": alpha}

    def initialize(self, authenticated: bool = False, force: bool = False) -> None:
        """One-time (administrator) setup: record the cluster parameters and, for
        authenticated mode, secret-share the integrity key α. Requires the
        ``mask_admin`` permission. Refuses to run twice unless ``force``."""
        gen0 = self.gen if self.gen is not None else 0
        res, err = self._fanout("mask_meta_get", lambda i: [0, "current_gen"])
        if err:
            raise MaskClusterError(f"all custodians must be reachable to initialise: {err}")
        if any(v is not None for v in res.values()) and not force:
            raise MaskClusterError("the cluster is already initialised (use force=True to overwrite)")
        alpha = secrets.randbelow(Q - 1) + 1 if authenticated else 0
        a_shares = dict(laurent.split(alpha, self.p)) if authenticated else {}
        base = {"authenticated": bool(authenticated), "k": self.k, "n": self.n, "xs": self.xs}

        def cfg_for(i):
            c = dict(base)
            c["alpha"] = format(laurent.evaluate(self._coeffs_alpha[0], self.xs[i], Q), "x") \
                if authenticated else None
            return c
        if authenticated:
            self._coeffs_alpha = (laurent.new_coeffs(alpha, self.p),)
        res, err = self._fanout("mask_meta_put",
                                lambda i: [gen0, "config", cfg_for(i), not force])
        if err:
            raise MaskClusterError(f"initialisation incomplete, re-run with force=True: {err}")
        res, err = self._fanout("mask_meta_put",
                                lambda i: [0, "current_gen", gen0, not force])
        if err:
            raise MaskClusterError(f"initialisation incomplete, re-run with force=True: {err}")
        self._coeffs_alpha = None
        self.gen, self._cfg = gen0, {"authenticated": bool(authenticated), "alpha": alpha}

    # ── writing ──────────────────────────────────────────────────────────────
    def _put(self, table: str, items: list) -> None:
        """items = [(cid, col, ver, mask)] → shared to every custodian."""
        if self.gen is None:
            self.config()
        p, q = self.p, Q
        per_node: list[list] = [[] for _ in range(self.n)]
        for cid, col, ver, r in items:
            coeffs = laurent.new_coeffs(r, p)
            for j, x in enumerate(self.xs):
                w = self._weights[x]
                s = sum(c * wi for c, wi in zip(coeffs, w)) % q
                per_node[j].append([table, cid, col, ver, format(s, "x")])
        ok = set(range(self.n))
        errors: dict[int, str] = {}
        for lo in range(0, max(len(items), 1), self.chunk):
            alive = sorted(ok)
            res, err = self._fanout(
                "mask_put", lambda i: [self.gen, self.xs[i], per_node[i][lo:lo + self.chunk]],
                indexes=alive)
            for i, e in err.items():
                ok.discard(i)
                errors[i] = e
            if len(ok) < self.write_quorum:
                raise MaskWriteError(
                    f"only {len(ok)} of {self.n} custodians accepted the masks "
                    f"(write quorum {self.write_quorum}); the row was NOT written. {errors}")

    def stage_insert(self, table, rows_masks):
        items, extras = [], []
        for masks in rows_masks:
            cid = secrets.token_hex(16)
            ex = {CID: cid}
            for col, r in masks.items():
                ver = _new_version()
                items.append((cid, col, ver, r))
                ex[MV + col] = ver
            extras.append(ex)
        if items:
            self._put(table, items)
        return extras

    def commit_insert(self, table, rowids, rows_masks, extras):
        pass

    def stage_update(self, table, items):
        rowids = [i for i, _ in items]
        cids = self._server_col(table, CID, rowids)
        puts, extras = [], []
        for pos, (rid, masks) in enumerate(items):
            cid = cids[pos]
            if not isinstance(cid, str):
                raise ExecError(f"row {rid} of {table!r} has no mask-cluster id")
            ex = {}
            for col, r in masks.items():
                new = _new_version()
                puts.append((cid, col, new, r))
                ex[MV + col] = new
            extras.append(ex)
        self._put(table, puts)
        return extras

    def commit_update(self, table, items, extras):
        pass                      # old versions are kept until `gc` (a server tx may still roll back)

    # ── reading ──────────────────────────────────────────────────────────────
    def _server_col(self, table, col, rowids):
        return self.server.plain_cells(table, col, rowids)

    def _lookup(self, table: str, col: str, rowids: list[int], strict: bool = True):
        """(cid, version) per row. ``strict=False`` yields None for a row that
        carries no reference instead of failing the whole batch."""
        uniq = sorted(set(rowids))
        if not uniq:
            return []
        cids = self._server_col(table, CID, uniq)
        vers = self._server_col(table, MV + col, uniq)
        m = {}
        for rid, cid, ver in zip(uniq, cids, vers):
            if not isinstance(cid, str) or not isinstance(ver, int) or isinstance(ver, bool):
                if strict:
                    raise ExecError(
                        f"{table}.{col} row {rid} carries no mask-cluster reference — it was "
                        f"not written through this mask cluster (or the server altered it)")
                m[rid] = None
            else:
                m[rid] = (cid, ver)
        return [m[r] for r in rowids]

    def sum(self, table, col, rowids):
        if not rowids:
            return 0
        if self.gen is None:
            self.config()
        refs = self._lookup(table, col, rowids)
        counts = Counter(refs)
        uniq = list(counts)
        total = 0
        for lo in range(0, len(uniq), self.chunk):
            part = uniq[lo:lo + self.chunk]
            args = [[c, v, counts[(c, v)]] for c, v in part]
            res, err = self._fanout("mask_sum", lambda i: [self.gen, table, col, args],
                                    min_ok=self.k)
            pts = []
            for i, r in res.items():
                if r.get("x") != self.xs[i]:
                    err[i] = f"answered for point {r.get('x')}, expected {self.xs[i]}"
                else:
                    pts.append((self.xs[i], int(r["s"], 16)))
            if len(pts) < self.k:
                raise MaskUnavailable(self.k, len(pts), err)
            try:
                s, bad = laurent.robust_reconstruct(pts, self.k, Q)
            except laurent.InconsistentShares as exc:
                raise MaskClusterError(f"custodians returned inconsistent partial sums: {exc}") from None
            if bad:
                self._report_faulty(bad)
            total += s
        return total % Q

    def get(self, table, col, rowids):
        if not rowids:
            return []
        if self.gen is None:
            self.config()
        refs = self._lookup(table, col, rowids)
        uniq = list(dict.fromkeys(refs))
        got: dict[tuple, int] = {}
        for lo in range(0, len(uniq), self.chunk):
            part = uniq[lo:lo + self.chunk]
            args = [[c, v] for c, v in part]
            res, err = self._fanout("mask_get", lambda i: [self.gen, table, col, args],
                                    min_ok=self.k)
            rows = {i: r["s"] for i, r in res.items() if r.get("x") == self.xs[i]}
            for i, r in res.items():
                if r.get("x") != self.xs[i]:
                    err[i] = f"answered for point {r.get('x')}, expected {self.xs[i]}"
            if len(rows) < self.k:
                raise MaskUnavailable(self.k, len(rows), err)
            got.update(self._combine_items(part, rows))
        return [got[r] for r in refs]

    def _combine_items(self, part, rows: dict[int, list]) -> dict:
        """Reconstruct many secrets from per-custodian share lists. Fast path:
        interpolate from the k lowest points and verify the others against it;
        any mismatch falls back to per-item majority reconstruction."""
        idx = sorted(rows, key=lambda i: self.xs[i])
        out: dict = {}
        lam_cache: dict[tuple, dict] = {}
        for pos, key in enumerate(part):
            pts = [(self.xs[i], int(rows[i][pos], 16)) for i in idx if rows[i][pos] is not None]
            if len(pts) < self.k:
                raise MaskUnavailable(self.k, len(pts),
                                      f"cell {key[0][:8]}… held by only {len(pts)} custodian(s)")
            xs_t = tuple(x for x, _ in pts[:self.k])
            lam = lam_cache.get(xs_t)
            if lam is None:
                lam = lam_cache[xs_t] = laurent.lambdas(list(xs_t), Q)
            secret = sum(lam[x] * y for x, y in pts[:self.k]) % Q
            consistent = True
            for x, y in pts[self.k:]:
                mu_key = (xs_t, x)
                mu = lam_cache.get(mu_key)
                if mu is None:
                    mu = lam_cache[mu_key] = laurent.eval_coeffs(list(xs_t), x, Q)
                if sum(c * yy for c, (_, yy) in zip(mu, pts[:self.k])) % Q != y % Q:
                    consistent = False
                    break
            if not consistent:
                try:
                    secret, bad = laurent.robust_reconstruct(pts, self.k, Q)
                except laurent.InconsistentShares as exc:
                    raise MaskClusterError(f"custodians disagree about a mask: {exc}") from None
                self._report_faulty(bad)
            out[key] = secret
        return out

    def _report_faulty(self, bad_xs: list[int]) -> None:
        import logging
        names = [getattr(self.nodes[self.xs.index(x)], "label", x) for x in bad_xs]
        logging.getLogger("torusdb.masks").error(
            "custodian(s) returned inconsistent shares and were outvoted: %s", names)
        self.faulty = set(getattr(self, "faulty", set())) | set(names)

    def available(self, table, col, rowids):
        if not rowids:
            return []
        if self.gen is None:
            self.config()
        refs = self._lookup(table, col, rowids, strict=False)
        uniq = [r for r in dict.fromkeys(refs) if r is not None]
        have = {u: 0 for u in uniq}
        for lo in range(0, len(uniq), self.chunk):
            part = uniq[lo:lo + self.chunk]
            args = [[c, v] for c, v in part]
            res, err = self._fanout("mask_has", lambda i: [self.gen, table, col, args])
            if len(res) < self.k:       # unreachable ≠ missing: never report cells as lost
                raise MaskUnavailable(self.k, len(res), err)
            for flags in res.values():
                for key, f in zip(part, flags):
                    have[key] += bool(f)
        return [r is not None and have[r] >= self.k for r in refs]

    def forget_table(self, table):
        res, err = self._fanout("mask_drop_table", lambda i: [self.gen, table]) \
            if self.gen is not None else ({}, {})
        # best effort: a token without mask_admin simply leaves garbage for `gc`

    # ── operator tools ───────────────────────────────────────────────────────
    def _live_refs(self, table: str) -> dict:
        """(cid, col) -> committed version, for every live server row."""
        s = self.server
        ids = s.matching_rowids(table, None)
        if not ids:
            return {}
        cids = s.plain_cells(table, CID, ids)
        schema = s.schema(table)
        enc = [c for (c, _t, pol) in schema if pol != "plain"]
        cols = enc + ["__mac__" + c for c in enc]
        live = {}
        for col in cols:
            try:
                vers = s.plain_cells(table, MV + col, ids)
            except Exception:                                      # noqa: BLE001
                continue
            for cid, v in zip(cids, vers):
                if isinstance(cid, str) and isinstance(v, int):
                    live[(cid, col)] = v
        return live

    def _node_entries(self, i: int, table: str, page: int = 20000):
        after = None
        while True:
            entries, after = self.nodes[i].call("mask_list", [self.gen, table, after, page])
            yield from entries
            if after is None:
                return

    def gc(self, tables: list[str] | None = None, *, min_age: int = 3600,
           dry_run: bool = False) -> dict:
        """Delete masks no committed row refers to: orphans left by crashes or
        rolled-back transactions, versions superseded by an UPDATE, and masks of
        deleted rows. Entries younger than ``min_age`` seconds are kept (an
        insert may be in flight). Needs ``mask_admin``."""
        report = {"deleted": 0, "kept_young": 0, "live": 0}
        tabs = tables or sorted({t for nd in range(self.n)
                                 for t in self.nodes[nd].call("mask_tables", [self.gen])})
        now = int(time.time())
        for table in tabs:
            live = self._live_refs(table) if table in self._server_tables() else {}
            report["live"] += len(live)
            for i in range(self.n):
                doomed = []
                for cid, col, ver, ts in self._node_entries(i, table):
                    if live.get((cid, col)) == ver:
                        continue
                    if now - ts < min_age:
                        report["kept_young"] += 1
                        continue
                    doomed.append([table, cid, col, ver])
                    if len(doomed) >= 20000 and not dry_run:
                        report["deleted"] += self.nodes[i].call("mask_delete", [self.gen, doomed])
                        doomed = []
                if doomed:
                    if dry_run:
                        report["deleted"] += len(doomed)
                    else:
                        report["deleted"] += self.nodes[i].call("mask_delete", [self.gen, doomed])
        return report

    def _server_tables(self) -> set:
        try:
            return set(self.server.tables())
        except Exception:                                          # noqa: BLE001
            return set()

    def repair(self, tables: list[str] | None = None, batch: int = 5000) -> dict:
        """Restore shares a custodian is missing (it was down during a write).
        Each missing share is recomputed by interpolation from k holders and
        pushed to the custodian that lacks it. Needs ``mask_admin``/``mask_read``
        and ``mask_write``; the operator process handles shares only (no database
        access is needed)."""
        fixed = 0
        tabs = tables or sorted({t for i in range(self.n)
                                 for t in self.nodes[i].call("mask_tables", [self.gen])})
        for table in tabs:
            keys: dict = {}
            for i in range(self.n):
                for cid, col, ver, _ts in self._node_entries(i, table):
                    keys.setdefault((cid, col, ver), set()).add(i)
            todo = [(k, h) for k, h in keys.items() if len(h) < self.n]
            for lo in range(0, len(todo), batch):
                part = todo[lo:lo + batch]
                by_col: dict[str, list] = {}
                for (cid, col, ver), holders in part:
                    by_col.setdefault(col, []).append((cid, ver, holders))
                for col, ents in by_col.items():
                    args = [[c, v] for c, v, _ in ents]
                    res, err = self._fanout("mask_get", lambda i: [self.gen, table, col, args])
                    puts: dict[int, list] = {}
                    for pos, (cid, ver, holders) in enumerate(ents):
                        pts = [(self.xs[i], int(r["s"][pos], 16)) for i, r in res.items()
                               if r["s"][pos] is not None]
                        if len(pts) < self.k:
                            continue                             # unrecoverable here
                        base = pts[:self.k]
                        for j in range(self.n):
                            if j in holders:
                                continue
                            mu = laurent.eval_coeffs([x for x, _ in base], self.xs[j], Q)
                            s = sum(c * y for c, (_, y) in zip(mu, base)) % Q
                            puts.setdefault(j, []).append([table, cid, col, ver, format(s, "x")])
                    for j, ents_j in puts.items():
                        self.nodes[j].call("mask_put", [self.gen, self.xs[j], ents_j])
                        fixed += len(ents_j)
        return {"restored_shares": fixed}


def reshare_masks(old: ThresholdMaskStore, new_nodes: list, new_k: int, *,
                  new_xs: list[int] | None = None, tables: list[str] | None = None,
                  batch: int = 5000) -> ThresholdMaskStore:
    """Move every mask to a new committee (refresh, replace a custodian, change
    k or n). Streaming and restartable; run it in a maintenance window.

    The operator process handles shares and reconstructs each mask transiently —
    but it never touches the database, and a mask is useless without the server's
    blinded cell (it is a uniformly random number). The old generation is frozen
    first so no write can be lost; clients re-read the current generation when
    they next connect. Old shares remain until ``mask_drop_gen``.
    """
    old.config()
    new_gen = old.gen + 1
    new = ThresholdMaskStore(new_nodes, new_k, xs=new_xs, gen=new_gen,
                             timeout=old.timeout, chunk=old.chunk)
    # quiesce the old generation
    res, err = old._fanout("mask_freeze", lambda i: [old.gen, True])
    if len(res) < old.k:
        raise MaskUnavailable(old.k, len(res), err)
    cfg = old.config()
    tabs = tables or sorted({t for i in range(old.n) for t in old.nodes[i].call("mask_tables", [old.gen])})
    for table in tabs:
        keys = {}
        for i in range(old.n):
            try:
                for cid, col, ver, _ts in old._node_entries(i, table):
                    keys.setdefault(col, set()).add((cid, ver))
            except QuorumError:
                continue
        for col, vals in keys.items():
            vals = sorted(vals)
            for lo in range(0, len(vals), batch):
                part = vals[lo:lo + batch]
                res, err = old._fanout("mask_get", lambda i: [old.gen, table, col,
                                                              [[c, v] for c, v in part]])
                rows = {i: r["s"] for i, r in res.items() if r.get("x") == old.xs[i]}
                if len(rows) < old.k:
                    raise MaskUnavailable(old.k, len(rows), err)
                secrets_ = old._combine_items(part, rows)
                new._put(table, [(c, col, v, secrets_[(c, v)]) for c, v in part])
    # config: re-share the integrity key under the new parameters
    alpha = cfg["alpha"] if cfg["authenticated"] else 0
    coeffs = laurent.new_coeffs(alpha, new.p)
    base = {"authenticated": cfg["authenticated"], "k": new.k, "n": new.n, "xs": new.xs}
    res, err = new._fanout("mask_meta_put", lambda i: [new_gen, "config", dict(
        base, alpha=format(laurent.evaluate(coeffs, new.xs[i], Q), "x")
        if cfg["authenticated"] else None), False])
    if err:
        raise MaskClusterError(f"could not install the new configuration: {err}")
    # flip the pointer on every custodian that took part
    for nodes in (old, new):
        nodes._fanout("mask_meta_put", lambda i: [0, "current_gen", new_gen, False])
    new._cfg = {"authenticated": cfg["authenticated"], "alpha": alpha}
    return new
