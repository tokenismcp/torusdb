# SPDX-License-Identifier: Apache-2.0
"""Evaluation of v0.6.1 / v0.6.2 expressions over FHE columns (the owner side).

v0.6.2 additionally accepts the SAME product shapes **un-aggregated**, as a per-row projection
(``SELECT L*R FROM t``, including the bare ``SELECT a*b FROM t``): the server finalises each row's
pairing on its own (one GT ciphertext PER ROW, never folded together) and the owner decrypts each
individually — ``FheExpr.level == "row"``, handled by ``_run_row`` / ``_term_row`` / ``_delegated_row``
below, which share every cap, cost field and ``fhe_dot_mode`` rule with the aggregate path.

WHO COMPUTES WHAT
=================

An FHE column holds EC-FHE ciphertexts ``(C1, C2 | D1, D2)``. The statements this module runs are the
shapes accepted by ``torussql_parser.fhe_expr``: public affine combinations of TERMS, each term being

* ``SUM(L*R)``   Σ_i L_i·R_i            ("sumprod": row by row products of two integer-linear forms)
* ``AL*AR``      (Σ_i L_i)(Σ_j R_j)     ("aggprod": product of two aggregate linear forms)
* ``SUM(L)``     plain linear sums      ("sum": the existing ``fhe_sum``)

**The server** (holds NO key, no mask, receives NO ciphertext from the owner) performs, in the default
*delegated* mode, only PUBLIC curve and pairing arithmetic on cells it already stores:

1. the operand ciphertexts ``Enc(L)`` and ``Enc(R)`` by linear combination with the PUBLIC integer
   coefficients (and constant) of the query: ``Σ k·D1``, ``Σ k·D2 + c·G2`` for the G2 half of the left
   operand, the same on the G1 half for the right one;
2. the pairings of the G2 half of ``Enc(L)`` with the G1 half of ``Enc(R)`` (4 per row for ``SUM(L*R)``;
   4 in total for ``AL*AR``), the Miller loops multiplied before one final exponentiation;
3. nothing else. The answer is a GT ciphertext that only the owner can open.

Nothing at the server is decrypted, nothing is re-encrypted, and the server never sees a value, a
secret, a mask, a tag key or any ciphertext that the owner produced for the query: what travels is
table / column names, row ids, small integers (the literals of the query) and the back end's name.

**The owner** (this process, holding the FHE key or a quorum of custodians) opens each GT result
with ``decrypt_dot`` (one bounded discrete log in GT per term; out of range -> ``FheError``, never
a wrapped value), then applies the PUBLIC affine part (scalars, additions, ``/ literal``, AVG's 1/n)
in exact rational arithmetic.

**Authenticated connections.** A ciphertext product cannot be tag-checked (the tag is linear in the
value), so ``fhe_dot_mode`` decides exactly as it does for ``DOT``: ``auto`` + authenticated means
``local``: the owner reads the operand cells (each verified against its row-bound tag, and against the
anchored table state when an anchor is configured) or the verified aggregate SUMs, and multiplies the
plaintexts itself; the server only serves cells / sums. Only an explicit
``fhe_dot_mode="delegated"`` (or ``fhe_allow_unverified_dot``) lets an authenticated connection
accept a server-computed product, with no integrity for that product — as documented for ``DOT``.

Range: every term's exact integer must lie in ``[-range, range]`` of the key (<= 2^40), in BOTH modes;
the bounds on coefficients (2^40) and operand width (16 columns) keep every true product far below the
group order, so a residue inside the range is the true integer and a result outside it raises instead
of wrapping.
"""
from __future__ import annotations

from fractions import Fraction
from types import SimpleNamespace

from . import fhe
from .errors import ExecError, IntegrityError
from torussql_parser.expr import _fold
from torussql_parser.fhe_expr import MAX_COEF, analyze, peval


class FheExprRunner:
    def __init__(self, client, pexpr, inst, names, loc, tuples) -> None:
        self.c = client
        self.p = pexpr
        self.loc = loc
        if len(names) != 1:
            raise ExecError("FHE expressions cannot be used in a join query")
        self.table = inst[names[0]]
        self.ids = [t[0] for t in tuples]
        self.n = len(self.ids)
        self._sums: dict[str, int] = {}
        self._cols: dict[str, list[int]] = {}
        self.cost = {"server_products": 0, "pairings": 0, "decrypted_cells": 0, "gt_results": 0}

    # ── resolution ───────────────────────────────────────────────────────────
    def _resolve(self, name):
        alias, bare = self.loc(name)
        pol = self.c._colpolicy[(self.table, bare)]
        return alias, SimpleNamespace(name=bare, policy=pol, type=self.c._coltype[(self.table, bare)])

    # ── leaves ───────────────────────────────────────────────────────────────
    def _sum(self, col: str) -> int:
        if col not in self._sums:
            self._sums[col] = self.c._fhe_sum(self.table, col, self.ids)
        return self._sums[col]

    def _col(self, col: str) -> list[int]:
        if col not in self._cols:
            vals = self.c._reveal_many(self.table, col, self.ids)
            self._cols[col] = [self.c._fhe_int(v, col) for v in vals]
            self.cost["decrypted_cells"] += len(vals)
        return self._cols[col]

    def _operand(self, lin):
        """-> ([(column, int k)], int constant) of a validated operand (the constant of an aggregate
        operand depends on the number of rows: c0 + c1·n)."""
        c = peval(lin.c, self.n)
        if c is None or c.denominator != 1 or abs(int(c)) > MAX_COEF:
            raise ExecError("an operand constant of an FHE product exceeds 2^40 for this many rows")
        return [(col, int(k)) for col, k in lin.coefs.items()], int(c)

    # ── row-level terms (v0.6.2: un-aggregated products, one value per row) ────
    def _term_row(self, term, mode: str) -> list[int]:
        """-> one value per row for a ROW-level term (``("prod", L, R)`` or ``("lin", L)``)."""
        key = self.c._fhe_key()
        kind = term[0]
        if kind == "lin":
            lin = term[1]
            c = peval(lin.c, self.n)
            if c is None or c.denominator != 1 or abs(int(c)) > MAX_COEF:
                raise ExecError("a per-row term constant of an FHE expression exceeds 2^40")
            c = int(c)
            coefs = list(lin.coefs.items())
            return [key._in_range(c + sum(k * self._col(col)[i] for col, k in coefs))
                    for i in range(self.n)]
        if kind != "prod":
            raise ExecError(f"unsupported row-level FHE term: {kind}")
        lt, lc = self._operand(term[1])
        rt, rc = self._operand(term[2])
        if mode == "local":
            a = [lc + sum(k * self._col(col)[i] for col, k in lt) for i in range(self.n)]
            b = [rc + sum(k * self._col(col)[i] for col, k in rt) for i in range(self.n)]
            return [key._in_range(x * y) for x, y in zip(a, b)]
        blobs = self._delegated_row(lt, lc, rt, rc)
        self.cost["server_products"] += 1
        self.cost["gt_results"] += len(blobs)
        return [key.decrypt_dot(blob) for blob in blobs]

    def _delegated_row(self, lt, lc: int, rt, rc: int) -> list[bytes]:
        """Server-delegated per-row product: shares the chunking / cap logic of ``_delegated``'s
        ``"sum"`` path (same per-row pairing cost), but every chunk's blobs come back un-summed."""
        c, key, table = self.c, self.c._fhe_key(), self.table
        lim = c._fhe_limits()
        be = key.backend
        sb = lim.get("default_backend")
        if sb in ("pyecc", "mcl"):
            sb_ = sb
        elif sb == "auto":
            sb_ = "mcl" if "mcl" in (lim.get("backends") or []) else "pyecc"
        else:
            sb_ = be
        lterms, rterms = [list(t) for t in lt], [list(t) for t in rt]
        cap = int((lim.get("recommended_dot_rows") or {}).get(sb_)
                  or (c._FHE_DOT_CHUNK_NATIVE if sb_ == "mcl" else c._FHE_DOT_CHUNK))
        cap = max(1, min(cap, int((lim.get("max_dot_rows") or {}).get(sb_) or cap)))
        work = int((lim.get("max_mul_work") or {}).get(sb_) or 0)
        if work:
            cap = max(1, min(cap, work // max(1, len(lt) + len(rt))))
        out: list[bytes] = []
        for i in range(0, self.n, cap):
            part = c._guard(table, lambda i=i: c.server.fhe_mul(
                table, "row", self.ids[i:i + cap], None, lterms, lc, rterms, rc, be))
            out.extend(part)
            self.cost["pairings"] += 4 * len(self.ids[i:i + cap])
        return out

    def _run_row(self, fx, mode: str):
        """A row-level FheExpr (v0.6.2): one value per row (never a single scalar). Mirrors the
        aggregate path's affine combination, applied independently to each row's term values."""
        n = self.n
        const = peval(fx.const, n)
        if const is None:
            raise ExecError("a row-level FHE expression cannot depend on AVG's 1/n")
        totals = [const] * n
        for coef, term in fx.terms:
            f = peval(coef, n)
            if f is None:
                raise ExecError("a row-level FHE expression cannot depend on AVG's 1/n")
            if n == 0:
                continue
            vals = self._term_row(term, mode)
            totals = [t + f * v for t, v in zip(totals, vals)]
        return [int(t) if t.denominator == 1 else Fraction(t) for t in totals]

    # ── terms ────────────────────────────────────────────────────────────────
    def _term(self, term, mode: str) -> int:
        kind = term[0]
        if kind == "sum":
            return self._sum(term[1])
        key = self.c._fhe_key()
        lt, lc = self._operand(term[1])
        rt, rc = self._operand(term[2])
        if mode == "local":
            if kind == "sumprod":
                a = [lc + sum(k * self._col(col)[i] for col, k in lt) for i in range(self.n)]
                b = [rc + sum(k * self._col(col)[i] for col, k in rt) for i in range(self.n)]
                v = sum(x * y for x, y in zip(a, b))
            else:
                v = (lc + sum(k * self._sum(col) for col, k in lt)) * (rc + sum(k * self._sum(col) for col, k in rt))
            return key._in_range(v)
        blob = self._delegated(kind, lt, lc, rt, rc)
        self.cost["server_products"] += 1
        self.cost["gt_results"] += 1
        return key.decrypt_dot(blob)

    def _delegated(self, kind: str, lt, lc: int, rt, rc: int) -> bytes:
        c, key, table = self.c, self.c._fhe_key(), self.table
        lim = c._fhe_limits()
        be = key.backend                                     # the back end we ASK for (a hint)
        sb = lim.get("default_backend")                     # the one the server really uses sizes the calls
        if sb in ("pyecc", "mcl"):
            sb_ = sb
        elif sb == "auto":
            sb_ = "mcl" if "mcl" in (lim.get("backends") or []) else "pyecc"
        else:
            sb_ = be
        lterms, rterms = [list(t) for t in lt], [list(t) for t in rt]
        total = None
        if kind == "sumprod":
            cap = int((lim.get("recommended_dot_rows") or {}).get(sb_)
                      or (c._FHE_DOT_CHUNK_NATIVE if sb_ == "mcl" else c._FHE_DOT_CHUNK))
            cap = max(1, min(cap, int((lim.get("max_dot_rows") or {}).get(sb_) or cap)))
            work = int((lim.get("max_mul_work") or {}).get(sb_) or 0)
            if work:
                cap = max(1, min(cap, work // max(1, len(lt) + len(rt))))
            for i in range(0, self.n, cap):
                part = c._guard(table, lambda: c.server.fhe_mul(
                    table, "sum", self.ids[i:i + cap], None, lterms, lc, rterms, rc, be))
                total = part if total is None else fhe.mul_dots(total, part)
                self.cost["pairings"] += 4 * len(self.ids[i:i + cap])
            return total
        # aggregate x aggregate: (Σ_u L_u)(Σ_v R_v) = Π_{u,v} pair(L_u, R_v); the constants ride on chunk 0
        step = int((lim.get("max_mul_agg_rows") or {}).get(sb_) or 0) or min(
            c._FHE_SUM_CHUNK, int(lim.get("max_sum_rows") or 10 ** 9))
        chunks = [self.ids[i:i + step] for i in range(0, self.n, step)]
        for u, cu in enumerate(chunks):
            for v, cv in enumerate(chunks):
                part = c._guard(table, lambda: c.server.fhe_mul(
                    table, "agg", cu, cv, lterms, lc if u == 0 else 0, rterms, rc if v == 0 else 0, be))
                total = part if total is None else fhe.mul_dots(total, part)
                self.cost["pairings"] += 4
        return total

    # ── run ──────────────────────────────────────────────────────────────────
    def run(self):
        c = self.c
        fx, _tree = analyze(self.p.expr, self._resolve, _fold, allow_row=True)
        mode = c._fhe_mode()
        c._fhe_key()
        n = self.n
        result = None
        dead = False
        if fx.level == "row":
            result = self._run_row(fx, mode)
        else:
            total = peval(fx.const, n)
            dead = total is None
            if not dead:
                for coef, term in fx.terms:
                    f = peval(coef, n)
                    if f is None:                              # AVG over no rows: the result is NULL
                        dead = True
                        break
                    if n == 0:
                        continue
                    total += f * self._term(term, mode)
            if not dead:
                result = int(total) if total.denominator == 1 else Fraction(total)
        prev = c.last_expr_cost or {}
        cost = dict(self.cost, depth=0, mult_rounds=0, products=fx.products, inversions=0, linear_sums=0)
        c.last_expr_cost = {k: prev.get(k, 0) + v for k, v in cost.items() if k != "depth"}
        c.last_expr_cost["depth"] = prev.get("depth", 0)
        if dead:
            return None
        return result
