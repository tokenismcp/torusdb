# SPDX-License-Identifier: Apache-2.0
"""Server side of the shared-wire protocol (wire RPCs ``wire_exec`` / ``wire_free``).

This is the SERVER half of the paper's circuit composition Π_C (Lee, "No-Key Delegation of
EC-FHE", Construction 20) as it is realised in TorusSQL >= 0.6.1 for arithmetic expressions
(spec §5.10, docs/crypto-review-packet.md §3.3, proto/torussql-wire-v2.md §9).

Every wire X of the circuit is held as a TWO-PARTY ADDITIVE SHARING over Z/nZ:

    X = X_S + X_O (mod n)            X_S lives here, in a session-scoped store;
                                     X_O lives only at the data owner.

A stored cell is x~ = x + r, i.e. ``X_S = x~`` and ``X_O = -r``. This module only ever holds
the ``X_S`` side. It has no key, no mask, no MAC key and never decodes anything: every value
it receives from the owner is a uniform share or a public constant, and every value it
returns is its own share (uniform, because the owner's share is a fresh one-time pad).

When the owner runs in authenticated mode every wire additionally carries a share of its SPDZ
tag ``alpha * X`` (``macs``); the server treats it exactly like the value (linear gates apply
to both, the Beaver combination applies to both) and never learns alpha.

Gates (all ring arithmetic mod n, elementwise over the wire):

    linear      add / sub / neg / mulc / mulv (public scalar / vector) / addc / addv / bc / sum
                -- local, no communication
    mul         Beaver product of two wires: one request/response exchange per multiplicative
                level, batched over every product of the level
    reveal      return THIS side's share of a wire (the owner adds its own and decodes; the
                server never receives the result)

The store enforces strict per-session caps (wire count, total elements, request size, TTL) and
a server-wide element cap, and reports every violation as a clear :class:`WireError`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .errors import ExecError
from .protocol import N


class WireError(ExecError):
    """A wire request was malformed, referred to an unknown/expired wire, or exceeded a cap."""


@dataclass
class WireLimits:
    max_wires: int = 4096                 # live wires per session
    max_elements: int = 4_000_000         # ring elements held per session (a tagged wire counts twice)
    ttl: float = 120.0                    # seconds a wire may sit unused before it is dropped
    max_ops: int = 20_000                 # operations per wire_exec request
    max_request_elements: int = 150_000   # ring elements (vectors + reveal counts) per request

    def as_dict(self) -> dict:
        return {"version": 1, "max_wires": self.max_wires, "max_elements": self.max_elements,
                "ttl": self.ttl, "max_ops": self.max_ops,
                "max_request_elements": self.max_request_elements}


class WireBudget:
    """A server-wide cap shared by every session's store."""

    def __init__(self, max_elements: int) -> None:
        self.max, self.used = max_elements, 0
        self._lock = threading.Lock()

    def reserve(self, n: int) -> None:
        with self._lock:
            if self.used + n > self.max:
                raise WireError(f"server-wide wire memory cap reached ({self.max} elements); "
                                f"retry later or evaluate over fewer rows")
            self.used += n

    def release(self, n: int) -> None:
        with self._lock:
            self.used = max(0, self.used - n)


class _Wire:
    __slots__ = ("vals", "macs", "width", "filled", "touched")

    def __init__(self, width: int, tagged: bool, now: float) -> None:
        self.vals = [0] * width
        self.macs = [0] * width if tagged else None
        self.width = width
        self.filled = 0
        self.touched = now

    @property
    def cost(self) -> int:
        return self.width * (2 if self.macs is not None else 1)

    @property
    def complete(self) -> bool:
        return self.filled == self.width


def ring(x, what: str = "value") -> int:
    """A ring element from the wire: an int or its decimal string, 0 <= x < n."""
    if isinstance(x, bool):
        raise WireError(f"{what}: not a ring element")
    if isinstance(x, str):
        if not 0 < len(x) <= 80 or not (x.isascii() and x.isdecimal()):
            raise WireError(f"{what}: not a ring element")
        x = int(x)
    if not isinstance(x, int) or not 0 <= x < N:
        raise WireError(f"{what}: not a ring element in [0, n)")
    return x


def _vec(v, what: str, limit: int, opt: bool = False):
    if v is None and opt:
        return None
    if not isinstance(v, list) or len(v) > limit:
        raise WireError(f"{what}: expected a list of at most {limit} ring elements")
    return [ring(x, what) for x in v]


def _int(x, what: str, lo: int = 0, hi: int = 1 << 40) -> int:
    if isinstance(x, bool) or not isinstance(x, int) or not lo <= x <= hi:
        raise WireError(f"{what}: expected an integer in [{lo}, {hi}]")
    return x


def _wid(x) -> str:
    if not isinstance(x, str) or not 0 < len(x) <= 64:
        raise WireError("wire id must be a string of 1-64 characters")
    return x


class WireStore:
    """One session's wires. NOT thread-safe by itself: a session issues one request at a time;
    cross-session expiry uses :meth:`expire` under the engine's wire lock."""

    def __init__(self, limits: WireLimits | None = None, budget: WireBudget | None = None,
                 clock=time.monotonic) -> None:
        self.limits = limits or WireLimits()
        self.budget = budget
        self.clock = clock
        self.wires: dict[str, _Wire] = {}
        self.elements = 0
        self.lock = threading.RLock()
        self._clear = False               # another thread asked for everything to be dropped

    # ── accounting ──────────────────────────────────────────────────────────
    def _alloc(self, wid: str, width: int, tagged: bool) -> _Wire:
        lim = self.limits
        if wid in self.wires:
            raise WireError(f"wire {wid!r} already exists")
        if len(self.wires) >= lim.max_wires:
            raise WireError(f"too many live wires in this session (max {lim.max_wires}); "
                            f"the expression is too large")
        cost = width * (2 if tagged else 1)
        if self.elements + cost > lim.max_elements:
            raise WireError(f"session wire memory cap reached ({lim.max_elements} elements): "
                            f"the expression over this many rows needs too much server-side "
                            f"state; evaluate over fewer rows (WHERE / GROUP BY) or raise "
                            f"the server's --wire-max-elements")
        if self.budget is not None:
            self.budget.reserve(cost)
        w = _Wire(width, tagged, self.clock())
        self.wires[wid] = w
        self.elements += cost
        return w

    def _drop(self, wid: str) -> None:
        w = self.wires.pop(wid, None)
        if w is not None:
            self.elements -= w.cost
            if self.budget is not None:
                self.budget.release(w.cost)

    def free(self, ids=None) -> int:
        """Drop the named wires (unknown ids are ignored), or every wire when ``ids`` is None."""
        with self.lock:
            names = list(self.wires) if ids is None else [i for i in ids if i in self.wires]
            for i in names:
                self._drop(i)
            return len(names)

    def expire(self, now: float | None = None) -> int:
        """Drop wires unused for longer than the TTL."""
        now = self.clock() if now is None else now
        with self.lock:
            old = [k for k, w in self.wires.items() if now - w.touched > self.limits.ttl]
            for k in old:
                self._drop(k)
            return len(old)

    def request_clear(self) -> None:
        """Drop everything -- never blocks: if a request is running (it holds the lock and may be
        waiting for the database lock, which the caller may hold) the drop happens at the start of
        the next request or the next sweep."""
        self._clear = True
        self.sweep()

    def sweep(self) -> None:
        """Called from other threads (TTL sweeper, end of a transaction): non-blocking."""
        if self.lock.acquire(blocking=False):
            try:
                if self._clear:
                    self._clear = False
                    self.free(None)
                else:
                    self.expire()
            finally:
                self.lock.release()

    def stats(self) -> dict:
        return {"wires": len(self.wires), "elements": self.elements}

    def _get(self, wid, need_complete: bool = True) -> _Wire:
        wid = _wid(wid)
        w = self.wires.get(wid)
        if w is None:
            raise WireError(f"unknown wire {wid!r} (never created, already freed, or expired "
                            f"after {self.limits.ttl:g} s)")
        if need_complete and not w.complete:
            raise WireError(f"wire {wid!r} is still being filled")
        w.touched = self.clock()
        return w

    def _target(self, out, width: int, lo: int, k: int, tagged: bool) -> _Wire:
        """The output wire of a span-writing op: created at ``lo == 0``, then filled in order."""
        out = _wid(out)
        if lo == 0 and out not in self.wires:
            w = self._alloc(out, width, tagged)
        else:
            w = self._get(out, need_complete=False)
            if w.width != width or (w.macs is not None) != tagged:
                raise WireError(f"wire {out!r}: inconsistent span (width/tag)")
        if lo != w.filled or lo + k > width or w.complete and k:
            raise WireError(f"wire {out!r}: spans must be written in order and not overflow "
                            f"(at {lo}, filled {w.filled}, width {width})")
        return w

    # ── execution ───────────────────────────────────────────────────────────
    def exec(self, ops, read_cells) -> list:
        """Run a batch of operations in order; return one result per operation (``None`` for
        operations that return nothing). ``read_cells(table, col, rows)`` returns the stored
        ring elements of the given rows (``None`` rows yield 0) -- the only access to the
        database."""
        lim = self.limits
        if not isinstance(ops, list) or len(ops) > lim.max_ops:
            raise WireError(f"at most {lim.max_ops} operations per request")
        with self.lock:
            if self._clear:
                self._clear = False
                self.free(None)
            self.expire()
            budget = [0]
            out = []
            for op in ops:
                if not isinstance(op, list) or not op or not isinstance(op[0], str):
                    raise WireError("each operation must be a list starting with its name")
                fn = _OPS.get(op[0])
                if fn is None:
                    raise WireError(f"unknown wire operation {op[0]!r}")
                try:
                    out.append(fn(self, read_cells, budget, *op[1:]))
                except TypeError as exc:
                    raise WireError(f"bad arguments for wire operation {op[0]!r}: {exc}") from None
            return out

    def _charge(self, budget: list, n: int) -> None:
        budget[0] += n
        if budget[0] > self.limits.max_request_elements:
            raise WireError(f"request too large: more than {self.limits.max_request_elements} "
                            f"ring elements; split it")

    # — leaves —
    def _op_load(self, read_cells, budget, out, table, col, rows, with_mac=False, lo=0, width=None):
        """Load stored cells as a wire (``X_S = x~``); spans let a long row list arrive in pieces."""
        rows = self._rows(rows, budget)
        lo = _int(lo, "lo")
        width = len(rows) if width is None else _int(width, "width")
        tagged = bool(with_mac)
        w = self._target(out, width, lo, len(rows), tagged)
        try:
            vals = self._cells(read_cells(table, col, rows), len(rows))
            macs = (self._cells(read_cells(table, "__mac__" + col, rows), len(rows))
                    if tagged else None)
        except BaseException:
            self._drop(out)
            raise
        w.vals[lo:lo + len(rows)] = vals
        if tagged:
            w.macs[lo:lo + len(rows)] = macs
        w.filled += len(rows)
        return None

    def _op_loadsum(self, read_cells, budget, out, table, col, rows, with_mac=False, more=False):
        """Width-1 wire holding the SUM of the stored cells (Π_lin on the server side); ``more``
        adds another batch of rows into the existing wire."""
        rows = self._rows(rows, budget)
        tagged = bool(with_mac)
        if more:
            w = self._get(out)
            if w.width != 1 or (w.macs is not None) != tagged:
                raise WireError("loadsum: cannot accumulate into this wire")
        else:
            w = self._alloc(_wid(out), 1, tagged)
        try:
            vals = self._cells(read_cells(table, col, rows), len(rows))
            macs = (self._cells(read_cells(table, "__mac__" + col, rows), len(rows))
                    if tagged else None)
        except BaseException:
            self._drop(out)
            raise
        w.vals[0] = (w.vals[0] + sum(vals)) % N
        if macs is not None:
            w.macs[0] = (w.macs[0] + sum(macs)) % N
        w.filled = 1
        return None

    @staticmethod
    def _cells(cells, n: int) -> list:
        if not isinstance(cells, list) or len(cells) != n:
            raise WireError("internal: cell read returned the wrong number of cells")
        for c in cells:
            if isinstance(c, bool) or not isinstance(c, int) or not 0 <= c < N:
                raise WireError("the column does not hold ring elements (is it an encrypted "
                                "column?)")
        return cells

    def _rows(self, rows, budget) -> list:
        if not isinstance(rows, list):
            raise WireError("rows must be a list of row ids")
        self._charge(budget, len(rows))
        for r in rows:
            if r is not None and (isinstance(r, bool) or not isinstance(r, int) or r < 0):
                raise WireError("row ids must be non-negative integers (or null)")
        return rows

    def _op_put(self, read_cells, budget, out, vec, mac, lo, width):
        lo, width = _int(lo, "lo"), _int(width, "width")
        vec = _vec(vec, "put", self.limits.max_request_elements)
        mac = _vec(mac, "put (tag)", self.limits.max_request_elements, opt=True)
        if mac is not None and len(mac) != len(vec):
            raise WireError("put: value and tag vectors differ in length")
        self._charge(budget, len(vec) * (2 if mac is not None else 1))
        w = self._target(out, width, lo, len(vec), mac is not None)
        w.vals[lo:lo + len(vec)] = vec
        if mac is not None:
            w.macs[lo:lo + len(vec)] = mac
        w.filled += len(vec)
        return None

    # — linear gates —
    def _unary(self, out, a):
        wa = self._get(a)
        wo = self._alloc(_wid(out), wa.width, wa.macs is not None)
        wo.filled = wa.width
        return wa, wo

    def _op_neg(self, read_cells, budget, out, a):
        wa, wo = self._unary(out, a)
        wo.vals = [(-x) % N for x in wa.vals]
        if wa.macs is not None:
            wo.macs = [(-x) % N for x in wa.macs]
        return None

    def _op_mulc(self, read_cells, budget, out, a, k):
        k = ring(k, "mulc")
        wa, wo = self._unary(out, a)
        wo.vals = [x * k % N for x in wa.vals]
        if wa.macs is not None:
            wo.macs = [x * k % N for x in wa.macs]
        return None

    def _op_addc(self, read_cells, budget, out, a, c):
        c = ring(c, "addc")
        wa, wo = self._unary(out, a)
        wo.vals = [(x + c) % N for x in wa.vals]
        if wa.macs is not None:
            wo.macs = list(wa.macs)                 # the owner adds alpha*c to ITS tag share
        return None

    def _span_unary(self, budget, out, a, vec, lo, width, what):
        lo, width = _int(lo, "lo"), _int(width, "width")
        vec = _vec(vec, what, self.limits.max_request_elements)
        self._charge(budget, len(vec))
        wa = self._get(a)
        if wa.width != width or lo + len(vec) > width:
            raise WireError(f"{what}: vector does not fit the wire")
        wo = self._target(out, width, lo, len(vec), wa.macs is not None)
        return wa, wo, vec, lo

    def _op_mulv(self, read_cells, budget, out, a, vec, lo, width):
        wa, wo, vec, lo = self._span_unary(budget, out, a, vec, lo, width, "mulv")
        k = len(vec)
        wo.vals[lo:lo + k] = [x * y % N for x, y in zip(wa.vals[lo:lo + k], vec)]
        if wa.macs is not None:
            wo.macs[lo:lo + k] = [x * y % N for x, y in zip(wa.macs[lo:lo + k], vec)]
        wo.filled += k
        return None

    def _op_addv(self, read_cells, budget, out, a, vec, lo, width):
        wa, wo, vec, lo = self._span_unary(budget, out, a, vec, lo, width, "addv")
        k = len(vec)
        wo.vals[lo:lo + k] = [(x + y) % N for x, y in zip(wa.vals[lo:lo + k], vec)]
        if wa.macs is not None:
            wo.macs[lo:lo + k] = wa.macs[lo:lo + k]
        wo.filled += k
        return None

    def _binary(self, out, a, b):
        wa, wb = self._get(a), self._get(b)
        if wa.width != wb.width:
            raise WireError("operand wires differ in width (broadcast first)")
        if (wa.macs is None) != (wb.macs is None):
            raise WireError("operand wires differ in tagging")
        wo = self._alloc(_wid(out), wa.width, wa.macs is not None)
        wo.filled = wa.width
        return wa, wb, wo

    def _op_add(self, read_cells, budget, out, a, b):
        wa, wb, wo = self._binary(out, a, b)
        wo.vals = [(x + y) % N for x, y in zip(wa.vals, wb.vals)]
        if wa.macs is not None:
            wo.macs = [(x + y) % N for x, y in zip(wa.macs, wb.macs)]
        return None

    def _op_sub(self, read_cells, budget, out, a, b):
        wa, wb, wo = self._binary(out, a, b)
        wo.vals = [(x - y) % N for x, y in zip(wa.vals, wb.vals)]
        if wa.macs is not None:
            wo.macs = [(x - y) % N for x, y in zip(wa.macs, wb.macs)]
        return None

    def _op_bc(self, read_cells, budget, out, a, width):
        width = _int(width, "width")
        wa = self._get(a)
        if wa.width != 1:
            raise WireError("bc: only a width-1 wire can be broadcast")
        wo = self._alloc(_wid(out), width, wa.macs is not None)
        wo.vals = wa.vals * width
        if wa.macs is not None:
            wo.macs = wa.macs * width
        wo.filled = width
        return None

    def _op_sum(self, read_cells, budget, out, a):
        wa = self._get(a)
        wo = self._alloc(_wid(out), 1, wa.macs is not None)
        wo.vals[0] = sum(wa.vals) % N
        if wa.macs is not None:
            wo.macs[0] = sum(wa.macs) % N
        wo.filled = 1
        return None

    # — Beaver product: Z = X*Y from a triple (u, v, w=uv), additively shared —
    def _op_mul(self, read_cells, budget, out, a, b, tri, lo, width):
        lo, width = _int(lo, "lo"), _int(width, "width")
        wa, wb = self._get(a), self._get(b)
        if wa.width != width or wb.width != width:
            raise WireError("mul: operand wires differ in width (broadcast first)")
        tagged = wa.macs is not None
        if tagged != (wb.macs is not None):
            raise WireError("mul: operand wires differ in tagging")
        if not isinstance(tri, dict):
            raise WireError("mul: triple shares missing")
        lim = self.limits.max_request_elements
        want = ("u", "v", "w", "eo", "go") + (("mu", "mv", "mw") if tagged else ())
        if set(tri) != set(want):
            raise WireError(f"mul: triple fields must be exactly {sorted(want)}")
        t = {k: _vec(tri[k], f"mul.{k}", lim) for k in want}
        k = len(t["u"])
        if any(len(v) != k for v in t.values()) or lo + k > width:
            raise WireError("mul: triple vectors must all have the span's length")
        self._charge(budget, k * len(want))
        wo = self._target(out, width, lo, k, tagged)
        sl = slice(lo, lo + k)
        xs, ys = wa.vals[sl], wb.vals[sl]
        u, v, w_, eo, go = t["u"], t["v"], t["w"], t["eo"], t["go"]
        eS = [(x - ui) % N for x, ui in zip(xs, u)]           # this side's share of e = X - u
        gS = [(y - vi) % N for y, vi in zip(ys, v)]           # ... and of g = Y - v
        zs = []
        for j in range(k):
            e = (eS[j] + eo[j]) % N                           # e, g are public to both parties
            g = (gS[j] + go[j]) % N
            zs.append((w_[j] + e * v[j] + g * u[j] + e * g) % N)
        wo.vals[lo:lo + k] = zs
        meS = mgS = None
        if tagged:
            mu, mv, mw = t["mu"], t["mv"], t["mw"]
            meS = [(m - mui) % N for m, mui in zip(wa.macs[sl], mu)]
            mgS = [(m - mvi) % N for m, mvi in zip(wb.macs[sl], mv)]
            ms = []
            for j in range(k):
                e = (eS[j] + eo[j]) % N
                g = (gS[j] + go[j]) % N
                ms.append((mw[j] + e * mv[j] + g * mu[j]) % N)  # the owner adds alpha*e*g
            wo.macs[lo:lo + k] = ms
        wo.filled += k
        return [eS, gS, meS, mgS]

    # — reveal: hand back THIS side's share (never the result) —
    def _op_reveal(self, read_cells, budget, a, lo, count):
        lo, count = _int(lo, "lo"), _int(count, "count")
        wa = self._get(a)
        if lo + count > wa.width:
            raise WireError("reveal: span outside the wire")
        self._charge(budget, count * (2 if wa.macs is not None else 1))
        return [wa.vals[lo:lo + count],
                None if wa.macs is None else wa.macs[lo:lo + count]]

    def _op_free(self, read_cells, budget, ids):
        if not isinstance(ids, list) or len(ids) > self.limits.max_request_elements:
            raise WireError("free: expected a list of wire ids")
        for i in ids:
            _wid(i)
        self.free(ids)
        return None


_OPS = {
    "load": WireStore._op_load, "loadsum": WireStore._op_loadsum, "put": WireStore._op_put,
    "neg": WireStore._op_neg, "mulc": WireStore._op_mulc, "addc": WireStore._op_addc,
    "mulv": WireStore._op_mulv, "addv": WireStore._op_addv, "add": WireStore._op_add,
    "sub": WireStore._op_sub, "bc": WireStore._op_bc, "sum": WireStore._op_sum,
    "mul": WireStore._op_mul, "reveal": WireStore._op_reveal, "free": WireStore._op_free,
}

# ── wire (JSON) encoding of requests and replies ─────────────────────────────
# Ring elements travel as decimal strings (exact for 254-bit values in every language); row ids,
# widths and spans are small JSON integers. The server accepts either form for a ring element.
def _s(v):
    return None if v is None else [str(x) for x in v]


def ops_to_wire(ops: list) -> list:
    out = []
    for op in ops:
        name = op[0]
        if name in ("mulc", "addc"):
            op = [name, op[1], op[2], str(op[3])]
        elif name in ("put",):
            op = [name, op[1], _s(op[2]), _s(op[3]), op[4], op[5]]
        elif name in ("mulv", "addv"):
            op = [name, op[1], op[2], _s(op[3]), op[4], op[5]]
        elif name == "mul":
            op = [name, op[1], op[2], op[3], {k: _s(v) for k, v in op[4].items()}, op[5], op[6]]
        out.append(op)
    return out


def results_to_wire(ops: list, res: list) -> list:
    return [[_s(r[0]), _s(r[1]), _s(r[2]), _s(r[3])] if op[0] == "mul"
            else [_s(r[0]), _s(r[1])] if op[0] == "reveal" else r
            for op, r in zip(ops, res)]


def _i(v):
    return None if v is None else [int(x) for x in v]


def results_from_wire(ops: list, res: list) -> list:
    if not isinstance(res, list) or len(res) != len(ops):
        raise WireError("malformed wire reply")
    out = []
    for op, r in zip(ops, res):
        if op[0] == "mul":
            out.append([_i(r[0]), _i(r[1]), _i(r[2]), _i(r[3])])
        elif op[0] == "reveal":
            out.append([_i(r[0]), _i(r[1])])
        else:
            out.append(r)
    return out
