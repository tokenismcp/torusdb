# SPDX-License-Identifier: Apache-2.0
"""Static analysis of expressions over FHE columns (v0.6.1) — engine-free.

FHE columns are EC-FHE ciphertexts. The keyless server can add ciphertexts (G1 side) and pair the G2
half of one ciphertext with the G1 half of another (GT side); a GT element cannot be paired again.
So exactly ONE ciphertext x ciphertext product level exists, and nothing is ever decrypted or
re-encrypted at the server or in between. What this module accepts is the set of shapes for which
that is enough:

    expression  ::=  public affine combination of TERMS
    TERM        ::=  SUM(P)                 P a per-row product  L * R
                  |  AL * AR                AL, AR aggregate linear forms (products of SUMs)
                  |  SUM(L) / AVG(...)      a plain linear sum (needs at least one product elsewhere)
    L, R        ::=  integer-linear forms   k1*col1 + k2*col2 + ... + c      over FHE columns
    AL, AR      ::=  k1*SUM(col1) + ... + c     (SUM(L) is the aggregate of a linear form)
    public      ::=  literals, + - between terms, * and / by a literal, unary minus, AVG's 1/n

* Every product has TWO integer-linear operands: ``(a + 2*b) * (c - d)``, ``a * a``, ``(a+1)*(b-3)``.
  Coefficients and the constant are integers of magnitude <= 2^40, at most 16 columns per operand.
* The product is aggregated: ``SUM(L*R)`` (row by row) or ``SUM(..)*SUM(..)`` (aggregates). A per-row
  product is not offered.
* Public scaling, addition and division by a literal happen at the owner AFTER decryption of the GT
  result(s): ``2*SUM(a*b) - SUM(c*d) / 4 + 7``, ``AVG(a*b)``.
* Rejected, with a precise message: a product of a product (depth > 1), a division by anything that is
  not a literal, FHE mixed with PLAIN / ENC / PAIRED columns, a per-row (non-aggregated) FHE value,
  non-integer operand coefficients, operands wider than the bounds above.

The result of the analysis, :class:`FheExpr`, is also what the engine evaluates, so the open
validator, the planner and the evaluator agree by construction.
"""
from __future__ import annotations

from fractions import Fraction

from .ast import AggCall, BinOp, ColRef, Lit, Neg
from .errors import ValidationError

REJECT_BARE_COLUMN_PRODUCT = True   # see analyze(): SUM(x*y) of two bare FHE columns is spelled DOT(x, y)
MAX_COEF = 1 << 40            # |k| of an operand coefficient / |c| of its constant (= the dlog bound)
MAX_COLS = 16                 # distinct columns in one operand
MAX_PRODUCTS = 16             # product terms in one expression


def old_message(name: str) -> str:
    return (f"FHE column {name!r} cannot be used inside an arithmetic expression "
            f"(FHE columns support SUM, AVG, k*SUM and DOT only)")


class _Reject(ValidationError):
    pass


# ── polynomials in n (the number of rows): exponent -> Fraction, exponents in {-1, 0, 1} ────────────
def _padd(a: dict, b: dict, sg: int = 1) -> dict:
    out = dict(a)
    for e, v in b.items():
        out[e] = out.get(e, Fraction(0)) + sg * v
    return {e: v for e, v in out.items() if v != 0}


def _pscale(a: dict, f: Fraction) -> dict:
    return {e: v * f for e, v in a.items() if v * f != 0}


def _pshift(a: dict, d: int) -> dict:
    return {e + d: v for e, v in a.items()}


def peval(a: dict, n: int) -> Fraction | None:
    """The value of a polynomial at ``n`` rows; None when it has an n^-1 term and n == 0."""
    tot = Fraction(0)
    for e, v in a.items():
        if e < 0 and n == 0:
            return None
        tot += v * Fraction(n) ** e
    return tot


class Lin:
    """``Σ coefs[col]·col + c`` over FHE columns. ``level`` "row": a value per row (``c`` is a constant
    polynomial); "agg": ``col`` stands for SUM(col) and ``c`` is a polynomial in n (SUM(a+1) = SUM(a) + n)."""
    __slots__ = ("level", "coefs", "c")

    def __init__(self, level, coefs, c):
        self.level, self.coefs, self.c = level, coefs, c


class Res:
    """A public affine combination of terms. ``terms``: ``[(poly coefficient, term)]`` with term
    ``("prod", L, R)`` (per row, row level), ``("lin", L)`` (row level), ``("sumprod", L, R)`` (Σ_i L_i·R_i),
    ``("aggprod", AL, AR)`` ((Σ L)(Σ R)) or ``("sum", col)`` (agg level)."""
    __slots__ = ("level", "terms", "const")

    def __init__(self, level, terms, const):
        self.level, self.terms, self.const = level, terms, const


class FheExpr:
    """A validated FHE expression: an aggregate public-affine combination with >= 1 product term."""
    __slots__ = ("terms", "const", "products")

    def __init__(self, res: Res):
        self.terms, self.const = res.terms, res.const
        self.products = sum(1 for _c, t in res.terms if t[0] in ("sumprod", "aggprod"))


def _fail(msg: str):
    raise _Reject(f"FHE expression: {msg}")


_DEPTH = ("a product of products (or of a product and anything else) is not available: the server pairs "
          "two ciphertexts once, a pairing result cannot be paired again, and no intermediate is ever "
          "decrypted or re-encrypted. Use products of integer-linear forms: SUM(a*b), "
          "SUM((a+2*b)*(c-d)), SUM(a)*SUM(b)")


def _lin_clean(level, coefs, c):
    return Lin(level, {k: v for k, v in coefs.items() if v != 0}, c)


def _lin_add(x: Lin, y: Lin, sg: int) -> Lin:
    if x.level != y.level:
        _fail(_MIX)
    co = dict(x.coefs)
    for k, v in y.coefs.items():
        co[k] = co.get(k, Fraction(0)) + sg * v
    return _lin_clean(x.level, co, _padd(x.c, y.c, sg))


def _lin_scale(x: Lin, f: Fraction) -> Lin:
    return _lin_clean(x.level, {k: v * f for k, v in x.coefs.items()}, _pscale(x.c, f))


_MIX = "per-row columns and aggregates cannot be mixed; wrap the columns in SUM(...)"


def _lin_to_res(x: Lin) -> Res:
    if x.level == "row":
        return Res("row", [({0: Fraction(1)}, ("lin", x))], {})
    return Res("agg", [({0: v}, ("sum", k)) for k, v in x.coefs.items()], dict(x.c))


def _res_add(x: Res, y: Res, sg: int) -> Res:
    if x.level != y.level:
        _fail(_MIX)
    return Res(x.level, x.terms + [(_pscale(c, Fraction(sg)), t) for c, t in y.terms],
               _padd(x.const, y.const, sg))


def _res_scale(x: Res, f: Fraction) -> Res:
    return Res(x.level, [(_pscale(c, f), t) for c, t in x.terms], _pscale(x.const, f))


def _check_operand(x: Lin, which: str) -> None:
    """An operand of a product: integer coefficients, bounded; becomes a ciphertext on the server."""
    if not x.coefs:
        _fail(f"the {which} operand of a product has no FHE column (a constant factor is a scalar: "
              f"write k * ...)")
    if len(x.coefs) > MAX_COLS:
        _fail(f"an operand of a product combines at most {MAX_COLS} columns")
    for k, v in x.coefs.items():
        if v.denominator != 1:
            _fail(f"the coefficient of {k!r} in the {which} operand of a product is not an integer; "
                  f"a ciphertext cannot be divided: scale outside, e.g. (a+b)*c/2 instead of ((a+b)/2)*c")
        if abs(v.numerator) > MAX_COEF:
            _fail(f"the coefficient of {k!r} exceeds 2^40 in absolute value")
    for e, v in x.c.items():
        if e < 0 or v.denominator != 1 or abs(v.numerator) > MAX_COEF:
            _fail(f"the constant of the {which} operand of a product must be an integer of magnitude "
                  f"<= 2^40 (and not depend on AVG)")


def _mul(x, y):
    if isinstance(x, Fraction) and isinstance(y, Fraction):
        return x * y
    if isinstance(x, Fraction):
        x, y = y, x
    if isinstance(y, Fraction):
        return _lin_scale(x, y) if isinstance(x, Lin) else _res_scale(x, y)
    if isinstance(x, Lin) and isinstance(y, Lin):
        if x.level != y.level:
            _fail(_MIX)
        _check_operand(x, "left")
        _check_operand(y, "right")
        if x.level == "row":
            return Res("row", [({0: Fraction(1)}, ("prod", x, y))], {})
        return Res("agg", [({0: Fraction(1)}, ("aggprod", x, y))], {})
    if any(t[0] in ("prod", "sumprod", "aggprod") for r in (x, y) if isinstance(r, Res) for _c, t in r.terms):
        _fail(_DEPTH)
    _fail("a factor of a product must be an integer-linear form of FHE columns (or of their SUMs); "
          "AVG(...) and sums of terms are not")


def _add(x, y, sg: int):
    """x + sg*y for constants, linear forms and results (a linear form next to a result becomes a term)."""
    if isinstance(x, Fraction) and isinstance(y, Fraction):
        return x + sg * y
    if isinstance(x, Fraction):
        return _add_const(y if sg == 1 else _neg(y), x)
    if isinstance(y, Fraction):
        return _add_const(x, sg * y)
    if isinstance(x, Lin) and isinstance(y, Lin):
        return _lin_add(x, y, sg)
    if isinstance(x, Lin):
        x = _lin_to_res(x)
    if isinstance(y, Lin):
        y = _lin_to_res(y)
    return _res_add(x, y, sg)


def _add_const(x, c: Fraction):
    if isinstance(x, Lin):
        return _lin_clean(x.level, dict(x.coefs), _padd(x.c, {0: c} if c else {}))
    return Res(x.level, list(x.terms), _padd(x.const, {0: c} if c else {}))


def _neg(x):
    if isinstance(x, Fraction):
        return -x
    return _lin_scale(x, Fraction(-1)) if isinstance(x, Lin) else _res_scale(x, Fraction(-1))


def _sum(x):
    """SUM over the rows of a per-row linear form or result."""
    if isinstance(x, Fraction) or x.level != "row":
        _fail("SUM(...) needs an argument that contains an FHE column and no aggregate")
    if isinstance(x, Lin):
        return Lin("agg", dict(x.coefs), _pshift(x.c, 1))
    terms, const = [], _pshift(x.const, 1)
    for c, t in x.terms:
        if t[0] == "prod":
            terms.append((c, ("sumprod", t[1], t[2])))
        else:                                                 # a linear row term: Σ k·SUM(col) + const·n
            lin = t[1]
            for col, k in lin.coefs.items():
                terms.append((_pscale(c, k), ("sum", col)))
            const = _padd(const, _pshift(_pscale(c, lin.c.get(0, Fraction(0))), 1))
    return Res("agg", terms, const)


def _avg(x):
    s = _sum(x)
    if isinstance(s, Lin):
        s = _lin_to_res(s)
    return Res(s.level, [(_pshift(c, -1), t) for c, t in s.terms], _pshift(s.const, -1))


def analyze(expr, resolve, fold) -> tuple[FheExpr, object]:
    """Validate ``expr`` (the unfolded tree) and return ``(FheExpr, folded_tree)``.
    ``resolve(name) -> (instance, column)``; ``fold`` folds constant subtrees (``expr._fold``)."""
    tree = fold(expr)
    seen: list = []
    if (REJECT_BARE_COLUMN_PRODUCT and isinstance(tree, AggCall) and tree.fn == "SUM"
            and isinstance(tree.arg, BinOp) and tree.arg.op == "*"
            and isinstance(tree.arg.left, ColRef) and isinstance(tree.arg.right, ColRef)):
        # `SUM(x * y)` over two bare FHE columns IS `DOT(x, y)`; the v0.5/v0.6 conformance suite
        # (spec/conformance, test_v06_fhe_columns_stay_depth_one_with_a_clear_error) pins it as rejected
        # with the pre-v0.6.1 text, so the spelling stays rejected. Every other product (a coefficient, a
        # constant, a second column in an operand, an aggregate factor) is accepted.
        # Set to False to accept it (one line; update that conformance test and drivers/expr_vectors.json).
        c = resolve(tree.arg.left.name)[1]
        if c.policy == "fhe":
            raise _Reject(old_message(c.name))

    def ev(e):
        if isinstance(e, Lit):
            if isinstance(e.value, bool):
                raise ValidationError("boolean literal in arithmetic expression")
            return Fraction(e.value)
        if isinstance(e, ColRef):
            _inst, col = resolve(e.name)
            if col.policy != "fhe":
                raise _Reject(old_message(seen[0] if seen else col.name))
            return Lin("row", {col.name: Fraction(1)}, {})
        if isinstance(e, Neg):
            return _neg(ev(e.operand))
        if isinstance(e, AggCall):
            if e.fn == "COUNT":
                raise _Reject(old_message(seen[0]))
            a = ev(e.arg)
            if isinstance(a, Fraction):
                _fail(f"{e.fn}(...) needs an argument that contains an FHE column")
            return _sum(a) if e.fn == "SUM" else _avg(a)
        if isinstance(e, BinOp):
            a, b = ev(e.left), ev(e.right)
            if e.op == "+":
                return _add(a, b, 1)
            if e.op == "-":
                return _add(a, b, -1)
            if e.op == "*":
                return _mul(a, b)
            if e.op == "/":
                if not isinstance(b, Fraction):
                    raise _Reject(old_message(seen[0]))
                if b == 0:
                    raise ValidationError("division by zero")
                return _mul(a, 1 / b)
        raise ValidationError(f"unsupported expression node: {type(e).__name__}")

    cols = _columns(tree)
    for name in cols:
        _inst, col = resolve(name)
        if col.policy == "fhe":
            seen.append(col.name)
    if not seen:
        raise AssertionError("analyze() is for expressions with FHE columns")
    for name in cols:
        _inst, col = resolve(name)
        if col.policy != "fhe":
            raise _Reject(old_message(seen[0]))
    v = ev(tree)
    if isinstance(v, Fraction):
        raise ValidationError("expression contains no column or aggregate (a constant is not a result)")
    if isinstance(v, Lin):
        if v.level == "row":
            raise _Reject(old_message(seen[0]))
        v = _lin_to_res(v)
    if v.level == "row":
        if any(t[0] == "prod" for _c, t in v.terms):
            _fail("a per-row product of FHE columns is not supported; aggregate it: SUM(a*b)")
        raise _Reject(old_message(seen[0]))
    prods = [t for _c, t in v.terms if t[0] in ("sumprod", "aggprod")]
    if not prods:
        raise _Reject(old_message(seen[0]))
    if len(prods) > MAX_PRODUCTS:
        _fail(f"at most {MAX_PRODUCTS} products per expression")
    return FheExpr(v), tree


def _columns(e) -> list[str]:
    out: list[str] = []

    def walk(n):
        if isinstance(n, ColRef):
            if n.name not in out:
                out.append(n.name)
        elif isinstance(n, Neg):
            walk(n.operand)
        elif isinstance(n, BinOp):
            walk(n.left); walk(n.right)
        elif isinstance(n, AggCall) and n.arg is not None:
            walk(n.arg)
    walk(e)
    return out
