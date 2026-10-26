# SPDX-License-Identifier: Apache-2.0
"""Owner-side evaluation of v0.6 arithmetic expressions: the paper's circuit
composition Π_C (Lee, "No-Key Delegation of EC-FHE", Construction 20) over the
blinded database.

WHO COMPUTES WHAT (read this before trusting any claim about "offloading")
=========================================================================

* The **server** stores blinded scalars  s̃ = s + r  (r uniform, held only in the
  owner's vault) and plaintext columns. It performs exactly two kinds of
  arithmetic here, both on values that are uniform and independent of the data:

  - Π_lin:  sums of stored blinded cells (``blinded_sum``) — only for
    *linear* ``SUM(...)`` arguments, see :func:`_linear`;
  - Π_mult: the step ``e·g mod n`` of a Beaver multiplication, where
    ``e = s − u`` and ``g = s' − v`` are the operands opened against a FRESH
    random triple (u, v, w=uv).

* The **owner** (this process, the guarded boundary) does everything else: it
  removes the masks of the cells it reads (it holds them), applies every
  linear gate (``+``, ``−``, public scalar multiples, division by a public
  value) to unmasked values, draws the triples, reconstructs each product
  ``s·s' = w + e·v + g·u + e·g``, and inverts denominators.

* Because the owner reconstructs both operands of a product before opening
  them, the product itself is **not offloaded**: the server's ``e·g`` is a
  product of two numbers the owner already knows (review packet, finding F-3).
  Every ciphertext x ciphertext level nevertheless costs exactly one batched
  owner round trip, as in the paper (Proposition 21: δ rounds for
  multiplicative depth δ), and the server's view of it is uniform.

* An **intermediate** (a product, a quotient) lives only in this process. It is
  never sent to the server except inside the next level's Beaver opening
  ``e = x − u`` with a fresh uniform ``u``; that opening is the Π_boot re-mask
  (remove the old mask — here the owner already holds the value — and re-mask
  with a fresh one before the server sees it). The server therefore never holds
  an intermediate, never decrypts one, and never receives a mask.

* **Division.** ``x / k`` for a public ``k`` is multiplication by ``k⁻¹ mod n``
  (a public-scalar operation, no round). ``x / y`` for an encrypted ``y`` is
  owner-assisted: additive masking does not commute with inversion, so the
  owner unmasks ``y`` (or holds it as an intermediate), computes ``y⁻¹ mod n``
  (Π_boot with Boot := inversion), and then multiplies ``x · y⁻¹`` — a
  public-scalar multiplication if ``x`` is public, otherwise one more Beaver
  level. ``y = 0`` raises :class:`DivisionByZero` at the owner — but only after the
  protocol has run to its last round with a dummy inverse, so that the sequence of
  requests the server sees does not reveal that a zero occurred. The owner learns
  the denominator (it is the data owner); the server learns nothing new.

* **Exactness.** Everything is ring/field arithmetic in Z/nZ, which is exact;
  only the final decode (Wang rational reconstruction, strict) can fail, and it
  raises ``OutOfBudget`` rather than return a wrong value. Intermediates may
  leave the representable range as long as the final result is back inside it.
"""
from __future__ import annotations

from fractions import Fraction

from . import protocol as nokey
from .errors import DivisionByZero, ExecError, IntegrityError
from .protocol import Owner, decode, encode, gen_triple
from torussql_parser.ast import AggCall, BinOp, ColRef, Lit, Neg

N = nokey.N
_MAX_BATCH = 100_000                # openings per request (server default limit is 200 000)


class _Node:
    __slots__ = ("op", "args", "level", "enc", "shape", "data")

    def __init__(self, op, args=(), level=0, enc=False, shape="scalar", data=None):
        self.op, self.args, self.level = op, list(args), level
        self.enc, self.shape, self.data = enc, shape, data


def _linear(e, is_enc_col):
    """If ``e`` is a linear form  Σ κ_c·c + κ₀  over ENCRYPTED columns only
    (no product of two columns, no division by a column, no PLAIN column) return
    ``({column: Fraction κ_c}, Fraction κ₀)``, else None. Such a SUM is a Π_lin
    aggregate: the server sums each column's blinded cells, the owner combines."""
    if isinstance(e, Lit):
        return {}, Fraction(e.value)
    if isinstance(e, ColRef):
        return ({e.name: Fraction(1)}, Fraction(0)) if is_enc_col(e.name) else None
    if isinstance(e, Neg):
        r = _linear(e.operand, is_enc_col)
        return None if r is None else ({k: -v for k, v in r[0].items()}, -r[1])
    if isinstance(e, BinOp):
        l = _linear(e.left, is_enc_col)
        r = _linear(e.right, is_enc_col)
        if l is None or r is None:
            return None
        if e.op in "+-":
            sg = 1 if e.op == "+" else -1
            co = dict(l[0])
            for k, v in r[0].items():
                co[k] = co.get(k, 0) + sg * v
            return co, l[1] + sg * r[1]
        if e.op == "*":
            if not l[0]:
                return {k: l[1] * v for k, v in r[0].items()}, l[1] * r[1]
            if not r[0]:
                return {k: r[1] * v for k, v in l[0].items()}, l[1] * r[1]
            return None
        if e.op == "/" and not r[0] and r[1] != 0:
            return {k: v / r[1] for k, v in l[0].items()}, l[1] / r[1]
    return None


def expr_rounds(client, pexpr, inst, names, loc) -> int:
    """Sequential ciphertext x ciphertext product levels the expression needs under the client's
    ``expr_mode`` (``shared``: a division by an ENCRYPTED value costs one extra level, the product
    rho*y that is opened). Pure compilation -- no request is sent."""
    if getattr(client, "expr_mode", "shared") == "shared":
        from .expr_shared import SharedExprRunner as cls
    else:
        cls = ExprRunner
    r = cls(client, pexpr, inst, names, loc, [])
    r._compile(pexpr.expr)
    return max((n.level for n in r.nodes), default=0)


class ExprRunner:
    """Evaluate one ``PExpr`` over a list of row tuples (expr_mode="owner": the v0.6 behaviour)."""

    INV_LEVELS = 0            # extra product levels per division by an encrypted value

    def __init__(self, client, pexpr, inst, names, loc, tuples) -> None:
        self.c = client
        self.p = pexpr
        self.inst = inst
        self.loc = loc
        self.pos = {a: k for k, a in enumerate(names)}
        self.tuples = tuples
        self.R = len(tuples)
        self.nodes: list[_Node] = []
        self._colcache: dict[str, list] = {}
        self.cost = {"mult_rounds": 0, "products": 0, "inversions": 0, "linear_sums": 0}
        self.zero: str | None = None          # set when a denominator was 0 (raised after the last round)

    # ── compile the tree into a DAG with multiplicative levels ───────────────
    def _add(self, node: _Node) -> int:
        self.nodes.append(node)
        return len(self.nodes) - 1

    def _is_enc_col(self, name: str) -> bool:
        alias, bare = self.loc(name)
        return self.c._colpolicy[(self.inst[alias], bare)] != "plain"

    def _compile(self, e) -> int:
        add = self._add
        if isinstance(e, Lit):
            return add(_Node("lit", data=e.value))
        if isinstance(e, ColRef):
            return add(_Node("col", enc=self._is_enc_col(e.name), shape="row", data=e.name))
        if isinstance(e, Neg):
            a = self._compile(e.operand)
            n = self.nodes[a]
            return add(_Node("neg", [a], n.level, n.enc, n.shape))
        if isinstance(e, AggCall):
            if e.fn == "COUNT":
                return add(_Node("count"))
            lin = _linear(e.arg, self._is_enc_col)
            if lin is not None and lin[0]:
                return add(_Node("linsum", level=0, enc=True, data=(e.fn, lin)))
            a = self._compile(e.arg)
            return add(_Node("sum" if e.fn == "SUM" else "avg", [a], self.nodes[a].level,
                             self.nodes[a].enc, "scalar"))
        if isinstance(e, BinOp):
            a = self._compile(e.left)
            b = self._compile(e.right)
            if e.op == "/" and isinstance(e.right, Lit):
                # x / k, k public: multiply by k⁻¹ mod n (= encode(1/k)); no inversion step
                f = 1 / Fraction(e.right.value)
                self.nodes.pop()                                    # drop the literal's own node
                b = add(_Node("lit", data=int(f) if f.denominator == 1 else f))
                op = "*"
            elif e.op == "/":
                nb = self.nodes[b]
                b = add(_Node("inv", [b], nb.level + (self.INV_LEVELS if nb.enc else 0),
                              nb.enc, nb.shape))
                op = "*"
            else:
                op = e.op
            na, nb = self.nodes[a], self.nodes[b]
            shape = "row" if "row" in (na.shape, nb.shape) else "scalar"
            enc = na.enc or nb.enc
            if op == "*":
                if na.enc and nb.enc:
                    return add(_Node("cmul", [a, b], max(na.level, nb.level) + 1, True, shape))
                return add(_Node("smul", [a, b], max(na.level, nb.level), enc, shape))
            return add(_Node("add" if op == "+" else "sub", [a, b],
                             max(na.level, nb.level), enc, shape))
        raise ExecError(f"cannot evaluate expression node {type(e).__name__}")

    # ── leaves ───────────────────────────────────────────────────────────────
    def _col_vector(self, name: str) -> list:
        got = self._colcache.get(name)
        if got is not None:
            return got
        alias, bare = self.loc(name)
        table = self.inst[alias]
        ids = [t[self.pos[alias]] for t in self.tuples]
        if self.c._colpolicy[(table, bare)] == "plain":
            cells = self.c._ids_to_cells(table, bare, ids)
            out = [None if v is None else encode(_numeric(v, name)) for v in cells]
        else:
            uniq = sorted({i for i in ids if i is not None})
            got_ = dict(zip(uniq, self.c._read_verified_scalars(table, bare, uniq))) if uniq else {}
            out = [None if i is None else got_[i] for i in ids]
        self._colcache[name] = out
        return out

    def _valid_ids(self, names: list[str]) -> list[tuple]:
        """Tuples whose rows exist for every referenced column's instance."""
        aliases = sorted({self.loc(n)[0] for n in names})
        return [t for t in self.tuples if all(t[self.pos[a]] is not None for a in aliases)]

    def _linsum(self, node: _Node):
        fn, (coef, const) = node.data
        valid = self._valid_ids(list(coef))
        total = (_ring(const) * len(valid)) % N if const != 0 else 0
        for name, k in coef.items():
            if k == 0:
                continue
            alias, bare = self.loc(name)
            ids = [t[self.pos[alias]] for t in valid]
            s = self.c._pi_lin_sum_raw(self.inst[alias], bare, ids) if ids else 0
            total = (total + _ring(k) * s) % N
            self.cost["linear_sums"] += 1
        if fn == "AVG":
            if not valid:
                return [None]
            return [total * Owner.invert(len(valid)) % N]
        return [total]

    # ── operators ────────────────────────────────────────────────────────────
    @staticmethod
    def _bc(v: list, n: int) -> list:
        return v if len(v) == n else v * n

    def _width(self, *vs) -> int:
        return max(len(v) for v in vs)

    def _local(self, node: _Node, vals) -> list:
        op = node.op
        if op == "lit":
            return [encode(node.data)]
        if op == "col":
            return self._col_vector(node.data)
        if op == "count":
            return [len(self.tuples)]
        if op == "linsum":
            return self._linsum(node)
        a = vals[node.args[0]]
        if op == "neg":
            return [None if x is None else (-x) % N for x in a]
        if op == "sum":
            return [sum(x for x in a if x is not None) % N]
        if op == "avg":
            live = [x for x in a if x is not None]
            return [sum(live) * Owner.invert(len(live)) % N] if live else [None]
        if op == "inv":
            out = []
            for k, x in enumerate(a):
                if x is None:
                    out.append(None)
                    continue
                try:
                    out.append(Owner.invert(x))
                except ZeroDivisionError:
                    # Do NOT stop here: aborting would show the server (as a missing
                    # request) that a denominator was zero. Carry on with a dummy 0 so the
                    # request sequence is independent of the data, and raise at the end.
                    if self.zero is None:
                        self.zero = f" (result row {k})" if node.shape == "row" else ""
                    out.append(0)
                    continue
                self.cost["inversions"] += 1
            return out
        b = vals[node.args[1]]
        w = self._width(a, b)
        a, b = self._bc(a, w), self._bc(b, w)
        if op == "add":
            return [None if x is None or y is None else (x + y) % N for x, y in zip(a, b)]
        if op == "sub":
            return [None if x is None or y is None else (x - y) % N for x, y in zip(a, b)]
        if op == "smul":                          # public scalar x value: NOT a ciphertext product
            return [None if x is None or y is None else x * y % N for x, y in zip(a, b)]
        raise ExecError(f"internal: unknown operator {op}")                 # pragma: no cover

    def _mult_round(self, level_nodes: list[int], vals: dict) -> None:
        """ONE owner round for every ciphertext x ciphertext product of a level
        (Π_mult, Construction 18, batched as in Construction 20)."""
        owner = self.c._owner
        ops = []                                  # (node idx, position)
        triples, openings = [], []
        shapes = {}
        for i in level_nodes:
            node = self.nodes[i]
            a, b = vals[node.args[0]], vals[node.args[1]]
            w = self._width(a, b)
            a, b = self._bc(a, w), self._bc(b, w)
            shapes[i] = w
            for k, (x, y) in enumerate(zip(a, b)):
                if x is None or y is None:
                    continue
                t = gen_triple()                  # fresh triple per product, never reused
                openings.append(owner.mult_open(x, y, t))
                triples.append(t)
                ops.append((i, k))
        egs: list[int] = []
        step = _MAX_BATCH
        try:
            step = max(1, min(step, int((self.c.server.limits() or {}).get("max_items") or step)))
        except Exception:                                     # noqa: BLE001
            pass
        for s in range(0, len(openings), step):
            egs += self.c.server.mult_combine_batch(openings[s:s + step])
        if len(egs) != len(openings):
            raise IntegrityError("server returned the wrong number of product terms")
        for i in level_nodes:
            vals[i] = [None] * shapes[i]
        for (i, k), (e, g), eg, t in zip(ops, openings, egs, triples):
            if self.c.authenticated and eg != e * g % N:
                raise IntegrityError("server returned a forged product term in an expression (e·g mismatch)")
            vals[i][k] = owner.mult_reconstruct(e, g, eg, t)
        self.cost["mult_rounds"] += 1
        self.cost["products"] += len(openings)

    # ── run ──────────────────────────────────────────────────────────────────
    def run(self):
        root = self._compile(self.p.expr)
        depth = max((n.level for n in self.nodes), default=0)
        if depth != self.p.depth:                              # planner/engine disagree: never guess
            raise ExecError(f"internal: planned multiplicative depth {self.p.depth} "
                            f"!= compiled depth {depth}")
        vals: dict[int, list] = {}
        for lvl in range(depth + 1):
            if lvl > 0:
                muls = [i for i, n in enumerate(self.nodes) if n.op == "cmul" and n.level == lvl]
                if muls:
                    self._mult_round(muls, vals)
            for i, n in enumerate(self.nodes):
                if n.level == lvl and n.op != "cmul":
                    vals[i] = self._local(n, vals)
        if self.zero is not None:
            raise DivisionByZero(f"division by zero: a denominator is 0{self.zero}")
        out = vals[root]
        prev = self.c.last_expr_cost or {}
        self.c.last_expr_cost = {k: prev.get(k, 0) + v for k, v in self.cost.items()}
        self.c.last_expr_cost["depth"] = max(prev.get("depth", 0), depth)
        if self.p.kind == "row":
            out = self._bc(out, self.R) if self.R else []
            return [None if v is None else decode(v) for v in out]
        v = out[0]
        return None if v is None else decode(v)


def _ring(k: Fraction) -> int:
    """A folded public coefficient as a ring element, WITHOUT the representability check of
    ``encode``: the coefficient of a linear form may be a product of literals that is not
    representable on its own (only the final result has to be). ``den`` is invertible mod n
    because it is a product of integers below n and n is prime."""
    return (k.numerator % N) * pow(k.denominator % N, -1, N) % N


def _numeric(v, name: str):
    if isinstance(v, bool) or not isinstance(v, (int, Fraction)):
        raise ExecError(f"column {name!r} holds a non-numeric value in an expression")
    return v
