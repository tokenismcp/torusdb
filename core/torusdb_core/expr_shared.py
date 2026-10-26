# SPDX-License-Identifier: Apache-2.0
"""Shared-wire evaluation of v0.6 arithmetic expressions: the paper's circuit composition Π_C
(Lee, "No-Key Delegation of EC-FHE", Construction 20) with every wire held as a TWO-PARTY ADDITIVE
SHARING over Z/nZ -- the owner's half of the protocol (the server's half is ``wires.py``).

WHO COMPUTES WHAT
=================

Every wire X (a column, a literal-scaled sum, a product, a quotient...) is X = X_S + X_O (mod n).
A stored cell is x~ = x + r, so a *loaded* wire has X_S = x~ (the server's own stored value) and
X_O = -r (the mask the owner already holds). Nothing else is ever sent about a loaded column.

* SERVER (``wires.WireStore``, session-scoped): applies every linear gate to ITS share (add, sub,
  public scalar/vector multiply, public add, SUM over rows, broadcast), computes ITS share of every
  Beaver product, and keeps the result as a NEW server-resident wire. It never receives a key, a
  mask, a MAC key or anything derived from a plaintext except uniform shares and openings; it never
  decodes; it never learns a product, quotient or the final result (it only SENDS its share of the
  result wire(s) to the owner).
* OWNER (this module): applies the same linear gates to ITS shares (local arithmetic, no
  communication), deals one Beaver triple (u, v, w=uv) per product element -- the server gets only
  its additive SHARES of it -- computes ITS share of each product, and finally adds the server's
  share of the result wire to its own and decodes (strict: OutOfBudget exactly as before). The owner
  does O(rows) local ring arithmetic per level and exchanges O(rows) openings per level; it fetches
  no operand cell and unmasks no operand or intermediate. (This O(rows) owner work is inherent to
  unconditionally secure two-party computation -- see docs/crypto-review-packet.md §3.3.)

Ciphertext x ciphertext product Z = X*Y (one request/response per multiplicative level, batched over
all products and rows of the level):

    e = X - u, g = Y - v are opened: each party contributes its share (the owner sends e_O = X_O - u_O,
    the server answers e_S = X_S - u_S); both learn e and g, which are uniform and independent of
    X, Y because u_O, v_O are fresh uniform and unknown to the server.
    Z_S = w_S + e v_S + g u_S + e g        (server, stored as a new wire)
    Z_O = w_O + e v_O + g u_O              (owner)

Division by a public k multiplies both shares by k^-1. Division by an ENCRYPTED y never decrypts y:
a fresh uniform non-zero rho is dealt as a sharing, [t] = [rho]*[y] is formed by a Beaver product and
t = rho*y is opened (uniform on non-zero values whatever y is: it reveals nothing about y), then
[1/y] = t^-1 * [rho] is a local public-scalar multiplication, and x/y = x * [1/y] one more product.
A zero denominator makes t = 0: the owner then substitutes a fresh random non-zero dummy for t
before sending anything back, so the server's view (and the sequence of requests) is identical
whether or not a denominator was zero, and raises DivisionByZero only after the final reveal.

Authenticated mode: every wire carries a share of its SPDZ tag alpha*X (alpha known only to the owner);
every opening is MAC-checked by the owner, and the revealed result is MAC-checked before it is
decoded. See ``docs/crypto-review-packet.md`` §3.3 for the argument and its limits.

WHAT THE OWNER LEARNS: the owner is the DEALER of the triples (u, v) and of rho, so the openings
e = X - u and g = Y - v, together with the values it dealt, determine the operand wires X, Y -- and
t = rho*y determines y -- for any owner willing to compute them. This implementation never does (no
operand cell is fetched, no intermediate is formed, one value is decoded: the result), but that is
a property of this code, not a cryptographic guarantee against a curious owner process; in the
single-owner model the owner holds all the data anyway. Making the owner blind to intermediates needs
a third party or a computational assumption (OT/HE triple generation); see the review packet.
"""
from __future__ import annotations

import secrets
from fractions import Fraction

from . import protocol as nokey
from .errors import DivisionByZero, ExecError, IntegrityError
from .expr_eval import ExprRunner, _ring
from .protocol import Owner, decode, encode

N = nokey.N


class _V:
    """A node's value. Public (``wid is None``): ``pub`` is a list of ring elements / None (dead).
    Shared: ``wid`` is the server wire, ``own`` the owner's value shares and ``ownm`` its tag shares
    (authenticated mode), ``live`` the positions that exist (None = all)."""
    __slots__ = ("pub", "wid", "own", "ownm", "live", "w")

    def __init__(self, w, pub=None, wid=None, own=None, ownm=None, live=None):
        self.w, self.pub, self.wid, self.own, self.ownm, self.live = w, pub, wid, own, ownm, live

    @property
    def shared(self) -> bool:
        return self.wid is not None


def _and(a, b, wa, wb, w):
    """Liveness of a binary result at width ``w``."""
    if a is None and b is None:
        return None
    a = [True] * w if a is None else (a if len(a) == w else a * w)
    b = [True] * w if b is None else (b if len(b) == w else b * w)
    return [x and y for x, y in zip(a, b)]


class SharedExprRunner(ExprRunner):
    """Evaluate one ``PExpr`` with shared wires (see the module docstring)."""

    INV_LEVELS = 1            # dividing by an encrypted value costs one extra product level

    def __init__(self, client, pexpr, inst, names, loc, tuples) -> None:
        super().__init__(client, pexpr, inst, names, loc, tuples)
        self.cost.update({"openings": 0, "wires": 0, "requests": 0, "reveals": 0})
        self.auth = bool(client.authenticated)
        self.alpha = client._alpha if self.auth else 0
        self._qid = secrets.token_hex(6)
        self._seq = 0
        self._pending: list = []          # (op, cost, handler)
        self._post: list = []             # callbacks run after the pending ops were answered
        self._tofree: list = []           # wires to drop at the end of the next flush
        self._live_ids: set = set()
        self._mask_cache: dict = {}
        self._inv: dict = {}              # node index -> (rho V, t^-1 vector)
        self._budget = 100_000
        self._max_ops = 10_000

    # ── plumbing ─────────────────────────────────────────────────────────────
    def _setup_limits(self) -> None:
        srv = self.c.server
        lim = {}
        try:
            lim = (srv.limits() or {}).get("wires") or {}
        except Exception:                                              # noqa: BLE001
            pass
        supports = getattr(srv, "supports_wires", None)
        if not hasattr(srv, "wire_exec") or (supports is not None and not supports()):
            raise ExecError(
                "this server does not offer the shared-wire RPCs (wire_exec); connect with "
                "expr_mode='owner' to evaluate expressions the v0.6 way (the owner unmasks the "
                "operand cells), or upgrade the server")
        self._budget = int(lim.get("max_request_elements") or self._budget)
        self._max_ops = int(lim.get("max_ops") or self._max_ops)
        self._chunk = max(1, self._budget // 9)

    def _new(self) -> str:
        self._seq += 1
        wid = f"{self._qid}.{self._seq}"
        self._live_ids.add(wid)
        self.cost["wires"] += 1
        return wid

    def _emit(self, op, cost=0, handler=None) -> None:
        self._pending.append((op, cost, handler))

    def _free_after(self, wid) -> None:
        if wid is not None:
            self._tofree.append(wid)

    def _flush(self) -> None:
        pend, self._pending = self._pending, []
        freed: list = []
        if self._tofree:
            freed, self._tofree = self._tofree, []
            for k in range(0, len(freed), 2000):
                pend.append((["free", freed[k:k + 2000]], 0, None))
        groups, cur, used = [], [], 0
        for ent in pend:
            if cur and (used + ent[1] > self._budget or len(cur) >= self._max_ops):
                groups.append(cur)
                cur, used = [], 0
            cur.append(ent)
            used += ent[1]
        if cur:
            groups.append(cur)
        for grp in groups:
            res = self.c.server.wire_exec([e[0] for e in grp])
            self.cost["requests"] += 1
            if not isinstance(res, list) or len(res) != len(grp):
                raise IntegrityError("server answered the wrong number of wire operations")
            for ent, r in zip(grp, res):
                if ent[2] is not None:
                    ent[2](r)
        self._live_ids.difference_update(freed)          # only now: a failed flush must still free them
        post, self._post = self._post, []
        for fn in post:
            fn()

    def _cleanup(self) -> None:
        """Drop whatever this query still holds on the server (best effort, never raises)."""
        self._pending, self._post = [], []
        ids = list(self._live_ids | set(self._tofree))
        self._live_ids.clear()
        self._tofree = []
        for k in range(0, len(ids), 2000):
            try:
                self.c.server.wire_free(ids[k:k + 2000])
            except Exception:                                          # noqa: BLE001
                return

    def _vec_ok(self, x, k, what="reply"):
        if (not isinstance(x, list) or len(x) != k
                or any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < N for v in x)):
            raise IntegrityError(f"server returned a malformed {what}")
        return x

    # ── public-value helpers ─────────────────────────────────────────────────
    def _span_ops(self, name, out, a, vec, w):
        """Emit a (chunked) vector-carrying op; ``vec`` are ring elements."""
        if not vec:
            self._emit([name, out, a, [], 0, w])
            return
        for lo in range(0, len(vec), self._chunk):
            part = vec[lo:lo + self._chunk]
            self._emit([name, out, a, part, lo, w], len(part))

    def _bcast(self, v: _V, w: int) -> _V:
        if v.w == w:
            return v
        if v.w != 1:
            raise ExecError("internal: operand widths are neither equal nor scalar")
        if not v.shared:
            return _V(w, pub=v.pub * w)
        out = self._new()
        self._emit(["bc", out, v.wid, w])
        self._free_after(out)
        return _V(w, wid=out, own=v.own * w,
                  ownm=None if v.ownm is None else v.ownm * w,
                  live=None if v.live is None else v.live * w)

    @staticmethod
    def _wd(a: _V, b: _V) -> int:
        return 0 if 0 in (a.w, b.w) else max(a.w, b.w)

    # ── gates on shared values (owner shares + server ops) ───────────────────
    def _g_neg(self, a: _V) -> _V:
        out = self._new()
        self._emit(["neg", out, a.wid])
        return _V(a.w, wid=out, own=[(-x) % N for x in a.own],
                  ownm=None if a.ownm is None else [(-x) % N for x in a.ownm], live=a.live)

    def _g_mulc(self, a: _V, k: int, live="keep") -> _V:
        out = self._new()
        k %= N
        self._emit(["mulc", out, a.wid, k])
        return _V(a.w, wid=out, own=[x * k % N for x in a.own],
                  ownm=None if a.ownm is None else [x * k % N for x in a.ownm],
                  live=a.live if live == "keep" else live)

    def _g_mulv(self, a: _V, vec: list, live) -> _V:
        out = self._new()
        self._span_ops("mulv", out, a.wid, vec, a.w)
        return _V(a.w, wid=out, own=[x * y % N for x, y in zip(a.own, vec)],
                  ownm=None if a.ownm is None else [x * y % N for x, y in zip(a.ownm, vec)],
                  live=live)

    def _g_addc(self, a: _V, c: int, live) -> _V:
        out = self._new()
        c %= N
        self._emit(["addc", out, a.wid, c])
        ownm = None if a.ownm is None else [(x + self.alpha * c) % N for x in a.ownm]
        return _V(a.w, wid=out, own=list(a.own), ownm=ownm, live=live)

    def _g_addv(self, a: _V, vec: list, live) -> _V:
        out = self._new()
        self._span_ops("addv", out, a.wid, vec, a.w)
        ownm = None if a.ownm is None else [(x + self.alpha * y) % N for x, y in zip(a.ownm, vec)]
        return _V(a.w, wid=out, own=list(a.own), ownm=ownm, live=live)

    def _g_addsub(self, op: str, a: _V, b: _V) -> _V:
        w = self._wd(a, b)
        a, b = self._bcast(a, w), self._bcast(b, w)
        out = self._new()
        self._emit([op, out, a.wid, b.wid])
        f = (lambda x, y: (x + y) % N) if op == "add" else (lambda x, y: (x - y) % N)
        return _V(w, wid=out, own=[f(x, y) for x, y in zip(a.own, b.own)],
                  ownm=None if a.ownm is None else [f(x, y) for x, y in zip(a.ownm, b.ownm)],
                  live=_and(a.live, b.live, a.w, b.w, w))

    def _pub_parts(self, p: _V):
        """(scalar or None, vector or None, live) of a public operand; dead -> 0."""
        if p.w == 1:
            x = p.pub[0]
            return (0 if x is None else x), None, ([False] if x is None else None)
        vals = [0 if x is None else x for x in p.pub]
        dead = [x is not None for x in p.pub]
        return None, vals, (None if all(dead) else dead)

    def _g_pub(self, op: str, s: _V, p: _V, flip: bool = False) -> _V:
        """Shared ``s`` with public ``p``: op in add / sub / smul (``flip``: p - s)."""
        sc, vec, plive = self._pub_parts(p)
        if vec is not None and s.w != p.w:
            s = self._bcast(s, p.w)
        live = s.live
        if plive is not None:
            if vec is None:                           # a dead scalar kills every position
                live = [False] * s.w
            else:
                live = plive if live is None else [x and y for x, y in zip(live, plive)]
        if op == "smul":
            return self._g_mulc(s, sc, live) if vec is None else self._g_mulv(s, vec, live)
        if flip:
            s = self._g_neg(s)                        # p - s = (-s) + p
            self._free_after(s.wid)
        elif op == "sub":
            sc = None if sc is None else (-sc) % N
            vec = None if vec is None else [(-x) % N for x in vec]
        return self._g_addc(s, sc, live) if vec is None else self._g_addv(s, vec, live)

    def _g_sum(self, a: _V) -> _V:
        if a.live is not None and not all(a.live):       # dead positions must not contribute
            a = self._g_mulv(a, [1 if x else 0 for x in a.live], None)
            self._free_after(a.wid)
        out = self._new()
        self._emit(["sum", out, a.wid])
        ownm = None if a.ownm is None else [sum(a.ownm) % N]
        return _V(1, wid=out, own=[sum(a.own) % N], ownm=ownm, live=None)

    # ── leaves ───────────────────────────────────────────────────────────────
    def _masks(self, table: str, col: str, uniq: list) -> dict:
        key = (table, col, tuple(uniq))
        got = self._mask_cache.get(key)
        if got is None:
            got = dict(zip(uniq, self.c.maskstore.get(table, col, uniq))) if uniq else {}
            self._mask_cache[key] = got
        return got

    def _load(self, name: str) -> _V:
        alias, bare = self.loc(name)
        table = self.inst[alias]
        ids = [t[self.pos[alias]] for t in self.tuples]
        uniq = sorted({i for i in ids if i is not None})
        mm = self._masks(table, bare, uniq)
        own = [0 if i is None else (-mm[i]) % N for i in ids]
        ownm = None
        if self.auth:
            mk = self._masks(table, "__mac__" + bare, uniq)
            ownm = [0 if i is None else (-mk[i]) % N for i in ids]
        out = self._new()
        if not ids:
            self._emit(["load", out, table, bare, [], self.auth, 0, 0])
        for lo in range(0, len(ids), self._chunk):
            part = ids[lo:lo + self._chunk]
            self._emit(["load", out, table, bare, part, self.auth, lo, len(ids)], len(part))
        live = None if all(i is not None for i in ids) else [i is not None for i in ids]
        return _V(len(ids), wid=out, own=own, ownm=ownm, live=live)

    def _linsum(self, node) -> _V:
        fn, (coef, const) = node.data
        valid = self._valid_ids(list(coef))
        cnt = len(valid)
        acc = None
        for name, k in coef.items():
            if k == 0:
                continue
            alias, bare = self.loc(name)
            table = self.inst[alias]
            ids = [t[self.pos[alias]] for t in valid]
            self.cost["linear_sums"] += 1
            if not ids:
                continue
            out = self._new()
            for lo in range(0, len(ids), self._chunk):
                part = ids[lo:lo + self._chunk]
                self._emit(["loadsum", out, table, bare, part, self.auth, lo > 0], len(part))
            ownm = ([(-self.c.maskstore.sum(table, "__mac__" + bare, ids)) % N] if self.auth else None)
            v = _V(1, wid=out, own=[(-self.c.maskstore.sum(table, bare, ids)) % N], ownm=ownm)
            v = self._g_mulc(v, _ring(k))
            self._free_after(out)
            if acc is None:
                acc = v
            else:
                new = self._g_addsub("add", acc, v)
                self._free_after(acc.wid)
                self._free_after(v.wid)
                acc = new
        c0 = (_ring(const) * cnt) % N if const != 0 else 0
        if acc is None:
            total = _V(1, pub=[c0])
        elif c0:
            total = self._g_addc(acc, c0, None)
            self._free_after(acc.wid)
        else:
            total = acc
        if fn == "AVG":
            if not valid:
                return _V(1, pub=[None])
            inv = Owner.invert(cnt)
            if not total.shared:
                return _V(1, pub=[total.pub[0] * inv % N])
            out = self._g_mulc(total, inv)
            self._free_after(total.wid)
            return out
        return total

    # ── the pass over the DAG ────────────────────────────────────────────────
    def _compute(self, i: int, vals: dict) -> None:
        node = self.nodes[i]
        op = node.op
        if i in self._inv:                                 # an inversion started one level earlier
            vals[i] = self._inv_finish(i)
            return
        args = [vals[a] for a in node.args]
        if not node.enc or (args and not any(v.shared for v in args)):
            # public subtree: plain list arithmetic at the owner (both parties know it)
            pubvals = {a: vals[a].pub for a in node.args}
            lst = ExprRunner._local(self, node, pubvals)
            vals[i] = _V(len(lst), pub=lst)
            return
        if op == "col":
            vals[i] = self._load(node.data)
        elif op == "linsum":
            vals[i] = self._linsum(node)
        elif op == "neg":
            vals[i] = self._g_neg(args[0])
        elif op == "sum":
            vals[i] = self._g_sum(args[0])
        elif op == "avg":
            a = args[0]
            live = a.w if a.live is None else sum(a.live)
            if live == 0:
                vals[i] = _V(1, pub=[None])
            else:
                s = self._g_sum(a)
                vals[i] = self._g_mulc(s, Owner.invert(live))
                self._free_after(s.wid)
        elif op in ("add", "sub", "smul"):
            a, b = args
            if a.shared and b.shared:
                if op == "smul":
                    raise ExecError("internal: a product of two shared wires must be a Beaver gate")
                vals[i] = self._g_addsub(op, a, b)
            elif a.shared:
                vals[i] = self._g_pub(op, a, b)
            else:
                vals[i] = self._g_pub(op, b, a, flip=(op == "sub"))
        else:
            raise ExecError(f"internal: unknown operator {op}")                 # pragma: no cover

    # — Beaver gate: Z = X*Y -------------------------------------------------
    def _deal(self, k: int):
        """k fresh triples, additively shared: server shares and owner shares."""
        al = self.alpha
        S = {"u": [], "v": [], "w": []}
        O = {"u": [], "v": [], "w": []}
        if self.auth:
            S.update(mu=[], mv=[], mw=[])
            O.update(mu=[], mv=[], mw=[])
        rb = secrets.randbelow
        for _ in range(k):
            uS, uO, vS, vO, wS = rb(N), rb(N), rb(N), rb(N), rb(N)
            u, v = (uS + uO) % N, (vS + vO) % N
            w = u * v % N
            S["u"].append(uS); O["u"].append(uO)
            S["v"].append(vS); O["v"].append(vO)
            S["w"].append(wS); O["w"].append((w - wS) % N)
            if self.auth:
                muS, mvS, mwS = rb(N), rb(N), rb(N)
                S["mu"].append(muS); O["mu"].append((al * u - muS) % N)
                S["mv"].append(mvS); O["mv"].append((al * v - mvS) % N)
                S["mw"].append(mwS); O["mw"].append((al * w - mwS) % N)
        return S, O

    def _emit_mul(self, a: _V, b: _V) -> _V:
        w = self._wd(a, b)
        a, b = self._bcast(a, w), self._bcast(b, w)
        out = self._new()
        res = _V(w, wid=out, own=[0] * w, ownm=[0] * w if self.auth else None,
                 live=_and(a.live, b.live, a.w, b.w, w))
        per = 8 if self.auth else 5
        for lo in range(0, max(w, 1), self._chunk):
            k = min(self._chunk, w - lo)
            S, O = self._deal(k)
            eo = [(x - u) % N for x, u in zip(a.own[lo:lo + k], O["u"])]
            go = [(y - v) % N for y, v in zip(b.own[lo:lo + k], O["v"])]
            tri = dict(S, eo=eo, go=go)
            self._emit(["mul", out, a.wid, b.wid, tri, lo, w], k * per,
                       lambda r, a=a, b=b, res=res, lo=lo, k=k, eo=eo, go=go, O=O:
                       self._on_mul(r, a, b, res, lo, k, eo, go, O))
        self.cost["products"] += w
        return res

    def _on_mul(self, r, a, b, res, lo, k, eo, go, O) -> None:
        if not isinstance(r, list) or len(r) != 4:
            raise IntegrityError("server returned a malformed product reply")
        eS, gS = self._vec_ok(r[0], k), self._vec_ok(r[1], k)
        al = self.alpha
        if self.auth:
            meS, mgS = self._vec_ok(r[2], k), self._vec_ok(r[3], k)
        for j in range(k):
            e, g = (eS[j] + eo[j]) % N, (gS[j] + go[j]) % N
            if self.auth:
                # MAC-check both openings: the server's reported tag share of e (resp. g) plus the
                # owner's must equal alpha*e (resp. alpha*g)
                if ((meS[j] + a.ownm[lo + j] - O["mu"][j]) - al * e) % N or \
                   ((mgS[j] + b.ownm[lo + j] - O["mv"][j]) - al * g) % N:
                    raise IntegrityError("MAC check failed on a multiplication opening -- the "
                                         "server tampered with a wire share")
            res.own[lo + j] = (O["w"][j] + e * O["v"][j] + g * O["u"][j]) % N
            if self.auth:
                res.ownm[lo + j] = (O["mw"][j] + e * O["mv"][j] + g * O["mu"][j]
                                    + al * e % N * g) % N
        self.cost["openings"] += 2 * k

    def _public_mul(self, a: _V, b: _V) -> _V:
        if not a.shared and not b.shared:
            w = self._wd(a, b)
            a, b = self._bcast(a, w), self._bcast(b, w)
            return _V(w, pub=[None if x is None or y is None else x * y % N
                              for x, y in zip(a.pub, b.pub)])
        return self._g_pub("smul", a, b) if a.shared else self._g_pub("smul", b, a)

    # — reveal (the only thing the server ever sends back about a result) —
    def _emit_reveal(self, v: _V, sink: dict) -> None:
        sink["z"], sink["m"] = [0] * v.w, [0] * v.w
        for lo in range(0, v.w, self._chunk):
            k = min(self._chunk, v.w - lo)
            self._emit(["reveal", v.wid, lo, k], k * (2 if self.auth else 1),
                       lambda r, lo=lo, k=k: self._on_reveal(r, sink, lo, k))
        self.cost["reveals"] += 1

    def _on_reveal(self, r, sink, lo, k) -> None:
        if not isinstance(r, list) or len(r) != 2:
            raise IntegrityError("server returned a malformed reveal reply")
        sink["z"][lo:lo + k] = self._vec_ok(r[0], k)
        if self.auth:
            sink["m"][lo:lo + k] = self._vec_ok(r[1], k)

    def _open(self, v: _V, sink: dict) -> list:
        """z = server share + owner share per position, MAC-checked on live positions."""
        out = []
        for j in range(v.w):
            z = (sink["z"][j] + v.own[j]) % N
            if self.auth and (v.live is None or v.live[j]):
                if (sink["m"][j] + v.ownm[j] - self.alpha * z) % N:
                    raise IntegrityError("MAC check failed on the revealed result -- the "
                                         "server returned a forged or inconsistent share")
            out.append(z)
        return out

    # — division by an encrypted y: [t] = [rho]*[y], open t, [1/y] = t^-1 [rho] —
    def _inv_start(self, i: int, y: _V) -> None:
        rb = secrets.randbelow
        w = y.w
        rho = [rb(N - 1) + 1 for _ in range(w)]                 # uniform NON-ZERO
        rS = [rb(N) for _ in range(w)]
        rO = [(r - s) % N for r, s in zip(rho, rS)]
        mS = mO = None
        if self.auth:
            mS = [rb(N) for _ in range(w)]
            mO = [(self.alpha * r - s) % N for r, s in zip(rho, mS)]
        wid = self._new()
        step = self._chunk
        if w == 0:
            self._emit(["put", wid, [], [] if self.auth else None, 0, 0])
        for lo in range(0, w, step):
            part = rS[lo:lo + step]
            self._emit(["put", wid, part, None if mS is None else mS[lo:lo + step], lo, w],
                       len(part) * (2 if self.auth else 1))
        rhoV = _V(w, wid=wid, own=rO, ownm=mO)
        prod = self._emit_mul(rhoV, y)
        sink: dict = {}
        self._emit_reveal(prod, sink)
        self._free_after(prod.wid)

        def finish() -> None:
            ts = self._open(prod, sink)                      # t = rho*y, MAC-checked
            tinv = []
            for j, t in enumerate(ts):
                if t == 0:
                    if y.live is None or y.live[j]:
                        if self.zero is None:
                            self.zero = f" (result row {j})" if self.nodes[i].shape == "row" else ""
                    t = rb(N - 1) + 1                        # dummy: the server must not learn it
                else:
                    self.cost["inversions"] += 1
                tinv.append(pow(t, -1, N))
            self.cost["openings"] += len(ts)
            self._inv[i] = (rhoV, tinv, y.live)
        self._post.append(finish)

    def _inv_finish(self, i: int) -> _V:
        rhoV, tinv, live = self._inv.pop(i)
        out = self._new()
        self._span_ops("mulv", out, rhoV.wid, tinv, rhoV.w)
        self._free_after(rhoV.wid)
        return _V(rhoV.w, wid=out, own=[x * y % N for x, y in zip(rhoV.own, tinv)],
                  ownm=None if rhoV.ownm is None else [x * y % N for x, y in zip(rhoV.ownm, tinv)],
                  live=live)

    # ── run ──────────────────────────────────────────────────────────────────
    def depth(self) -> int:
        return max((n.level for n in self.nodes), default=0)

    def run(self):
        root = self._compile(self.p.expr)
        depth = self.depth()
        self._setup_limits()
        refs = [0] * len(self.nodes)
        for n in self.nodes:
            for a in n.args:
                refs[a] += 1
        refs[root] += 1
        vals: dict[int, _V] = {}

        def consume(i: int) -> None:
            """The node ``i`` was used once more; drop its wire after the last use."""
            for a in self.nodes[i].args:
                refs[a] -= 1
                if refs[a] == 0 and vals[a].shared:
                    self._free_after(vals[a].wid)
                    vals[a] = None                           # the owner's share is dead too

        try:
            for lvl in range(depth + 1):
                for i, n in enumerate(self.nodes):
                    if n.level == lvl and n.op != "cmul":
                        started = i in self._inv
                        self._compute(i, vals)
                        if not started:                      # an inversion consumed its argument at its start
                            consume(i)
                muls = 0
                for i, n in enumerate(self.nodes):
                    if n.level != lvl + 1:
                        continue
                    if n.op == "cmul":
                        a, b = vals[n.args[0]], vals[n.args[1]]
                        if a.shared and b.shared:
                            vals[i] = self._emit_mul(a, b)
                            muls += 1
                        else:                              # an operand turned out public (empty AVG)
                            vals[i] = self._public_mul(a, b)
                        consume(i)
                    elif n.op == "inv" and n.enc and vals[n.args[0]].shared:
                        self._inv_start(i, vals[n.args[0]])
                        consume(i)
                        muls += 1
                if muls:
                    self.cost["mult_rounds"] += 1
                if lvl == depth:
                    rootv = vals[root]
                    sink: dict = {}
                    if rootv.shared:
                        self._emit_reveal(rootv, sink)
                    # the last request also drops everything the query still holds (after the reveal)
                    self._tofree = list(set(self._tofree) | self._live_ids)
                self._flush()
            rootv = vals[root]
            if rootv.shared:
                zs = self._open(rootv, sink)
                outv = [z if (rootv.live is None or rootv.live[j]) else None for j, z in enumerate(zs)]
            else:
                outv = rootv.pub
            if self.zero is not None:
                raise DivisionByZero(f"division by zero: a denominator is 0{self.zero}")
            prev = self.c.last_expr_cost or {}
            self.c.last_expr_cost = {k: prev.get(k, 0) + v for k, v in self.cost.items()}
            self.c.last_expr_cost["depth"] = max(prev.get("depth", 0), depth)
            self.c.last_expr_cost["mode"] = "shared"
            if self.p.kind == "row":
                outv = self._bc(outv, self.R) if self.R else []
                return [None if v is None else decode(v) for v in outv]
            v = outv[0]
            return None if v is None else decode(v)
        finally:
            self._cleanup()
