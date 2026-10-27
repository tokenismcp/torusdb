# SPDX-License-Identifier: Apache-2.0
"""Static analysis of TorusSQL v0.6 arithmetic expressions — engine-free.

The single source of truth for *what an expression may contain*. The open
validator (``validate.py``) and the engine's planner both call
:func:`analyze_expr`, so they accept and reject exactly the same expressions.

An expression is a tree of ``Lit`` / ``ColRef`` / ``Neg`` / ``BinOp`` /
``AggCall`` nodes (``ast.py``). Analysis

* folds constant sub-expressions exactly (``Fraction`` arithmetic) and rejects a
  constant division by zero or an out-of-range constant;
* classifies the result as **row** (a value per row: contains bare columns) or
  **agg** (one value per query/group: contains aggregates), and rejects
  mixing the two or an expression with neither;
* tracks which operands are *encrypted* (depend on an ENC/PAIRED column) and
  enforces the policy rules (below);
* computes the **multiplicative depth** (number of sequential ciphertext x
  ciphertext product levels = owner rounds, see spec v0.6 section 3).

Policy rules (v0.6):

* STR columns cannot appear in an expression. FHE columns appear only in the shapes of
  ``fhe_expr`` (integer-linear operands, ONE server-side product level, aggregated; v0.6.1) and never
  next to PLAIN / ENC / PAIRED columns; otherwise they keep their dedicated SUM / AVG / k*SUM / DOT forms.
* A product of two encrypted operands (ciphertext x ciphertext) and a division
  whose denominator is encrypted require every ENC/PAIRED column inside the
  operands involved to be PAIRED (an ENC column is additive-only). Linear
  positions (``+``, ``-``, public scalar multiples, division by a public
  value) accept ENC columns too.
* PLAIN numeric columns and literals are *public* operands: product with an
  encrypted operand is a public-scalar multiplication, not a ciphertext product.
* ``SUM(expr)`` needs an encrypted expression; a per-row expression needs at
  least one encrypted column.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from .ast import AggCall, BinOp, ColRef, Lit, Neg
from .errors import ValidationError

MAX_SCALAR = 1 << 126          # |k| / numerator / denominator bound of a constant


@dataclass(frozen=True)
class ExprInfo:
    kind: str          # "row" (one value per row) | "agg" (one value per query/group)
    enc: bool          # depends on at least one ENC/PAIRED column
    depth: int         # multiplicative depth = ciphertext x ciphertext levels
    ct_muls: int       # number of ciphertext x ciphertext products
    inversions: int    # number of owner-assisted inversions (non-constant denominators)
    fhe: bool = False  # an FHE expression (v0.6.1): products are paired BY THE SERVER, depth/rounds are 0


# internal per-node summary: (kind, enc_columns, depth, ct_muls, inversions)
#   kind: "const" | "row" | "agg"


def _check_const(v) -> None:
    n, d = (v.numerator, v.denominator) if isinstance(v, Fraction) else (int(v), 1)
    if abs(n) > MAX_SCALAR or d > MAX_SCALAR:
        raise ValidationError(
            f"constant {v} is out of range (|numerator|, denominator <= 2^126): a larger "
            f"constant could wrap around the modulus and return a wrong value")


def _norm(f: Fraction):
    return int(f) if f.denominator == 1 else f


def _pol(col) -> str:
    return col.policy.upper() if col.policy != "encrypted" else "ENC"


def _require_paired(cols, why: str) -> None:
    for c in cols:
        if c.policy != "paired":
            raise ValidationError(
                f"{why} requires PAIRED columns (column {c.name!r} is {_pol(c)}); "
                f"an ENC column is additive-only")


def _merge_kind(a: str, b: str) -> str:
    if a == "const":
        return b
    if b == "const" or a == b:
        return a
    raise ValidationError(
        "an expression cannot mix per-row columns and aggregates; wrap the columns "
        "in SUM(...) / AVG(...) or select the aggregate on its own")


def _an(e, resolve) -> tuple:
    """Return (folded node, summary) for ``e``."""
    if isinstance(e, Lit):
        if isinstance(e.value, bool):
            raise ValidationError("boolean literal in arithmetic expression")
        _check_const(e.value)
        return e, ("const", (), 0, 0, 0)

    if isinstance(e, ColRef):
        _inst, col = resolve(e.name)
        if col.type == "str":
            raise ValidationError(
                f"STR column {col.name!r} cannot be used in an arithmetic expression")
        if col.policy == "fhe":
            raise ValidationError(
                f"FHE column {col.name!r} cannot be used inside an arithmetic expression "
                f"(FHE columns support SUM, AVG, k*SUM and DOT only)")
        cols = () if col.policy == "plain" else (col,)
        return e, ("row", cols, 0, 0, 0)

    if isinstance(e, Neg):
        o, s = _an(e.operand, resolve)
        if isinstance(o, Lit):
            v = _norm(Fraction(-o.value))
            _check_const(v)
            return Lit(value=v), ("const", (), 0, 0, 0)
        return Neg(operand=o), s

    if isinstance(e, AggCall):
        if e.fn == "COUNT":
            return e, ("agg", (), 0, 0, 0)
        arg, s = _an(e.arg, resolve)
        if s[0] != "row":
            raise ValidationError(
                f"{e.fn}(...) needs an argument that contains a column "
                f"(not a constant or another aggregate)")
        if e.fn == "SUM" and not s[1]:
            raise ValidationError(
                "SUM requires an encrypted expression (an ENC/PAIRED column); "
                "the argument depends only on PLAIN columns")
        return AggCall(fn=e.fn, arg=arg), ("agg", s[1], s[2], s[3], s[4])

    if isinstance(e, BinOp):
        l, ls = _an(e.left, resolve)
        r, rs = _an(e.right, resolve)
        kind = _merge_kind(ls[0], rs[0])
        enc_l, enc_r = bool(ls[1]), bool(rs[1])
        cols = ls[1] + rs[1]
        depth = max(ls[2], rs[2])
        muls = ls[3] + rs[3]
        invs = ls[4] + rs[4]
        if e.op in ("+", "-"):
            pass
        elif e.op == "*":
            if enc_l and enc_r:
                _require_paired(cols, "a ciphertext x ciphertext product")
                depth += 1
                muls += 1
        elif e.op == "/":
            if isinstance(r, Lit):
                if r.value == 0:
                    raise ValidationError("division by zero")
            else:
                invs += 1
                if enc_r:
                    _require_paired(rs[1] + (ls[1] if enc_l else ()),
                                    "division by an encrypted denominator")
                    if enc_l:
                        depth = max(ls[2], rs[2]) + 1
                        muls += 1
                    else:
                        depth = rs[2]
        else:                                                    # pragma: no cover
            raise ValidationError(f"unsupported operator {e.op!r}")
        if isinstance(l, Lit) and isinstance(r, Lit):            # exact constant folding
            a, b = Fraction(l.value), Fraction(r.value)
            v = a + b if e.op == "+" else a - b if e.op == "-" else a * b if e.op == "*" else a / b
            v = _norm(v)
            _check_const(v)
            return Lit(value=v), ("const", (), 0, 0, 0)
        return BinOp(op=e.op, left=l, right=r), (kind, cols, depth, muls, invs)

    raise ValidationError(f"unsupported expression node: {type(e).__name__}")


def _fold(e):
    """Fold constant subtrees exactly (Fraction arithmetic), as ``_an`` does."""
    if isinstance(e, Lit):
        if isinstance(e.value, bool):
            raise ValidationError("boolean literal in arithmetic expression")
        _check_const(e.value)
        return e
    if isinstance(e, Neg):
        o = _fold(e.operand)
        if isinstance(o, Lit):
            v = _norm(Fraction(-o.value))
            _check_const(v)
            return Lit(value=v)
        return Neg(operand=o)
    if isinstance(e, AggCall):
        return e if e.arg is None else AggCall(fn=e.fn, arg=_fold(e.arg))
    if isinstance(e, BinOp):
        l, r = _fold(e.left), _fold(e.right)
        if e.op == "/" and isinstance(r, Lit) and r.value == 0:
            raise ValidationError("division by zero")
        if isinstance(l, Lit) and isinstance(r, Lit):
            a, b = Fraction(l.value), Fraction(r.value)
            v = a + b if e.op == "+" else a - b if e.op == "-" else a * b if e.op == "*" else a / b
            v = _norm(v)
            _check_const(v)
            return Lit(value=v)
        return BinOp(op=e.op, left=l, right=r)
    return e


def analyze_expr(expr, resolve, *, top: bool = True, fhe_ok: bool = True) -> tuple:
    """Check ``expr`` and return ``(folded_expr, ExprInfo)``.

    ``resolve(name) -> (instance, column)`` looks a (possibly qualified) column
    up and raises the caller's own error type for an unknown column; ``column``
    only needs ``name``, ``type`` and ``policy``. Raises
    :class:`ValidationError` for every rule violation. ``fhe_ok=False`` (a join: FHE columns
    cannot be joined) keeps the pre-v0.6.1 rule that FHE columns are rejected."""
    from . import fhe_expr
    cols_ = [resolve(n)[1] for n in fhe_expr._columns(expr)]       # an unknown column raises here
    fcols = [c.name for c in cols_ if c.policy == "fhe"]
    if fcols:
        if not fhe_ok:
            raise ValidationError(fhe_expr.old_message(fcols[0]))
        # allow_row=True: a bare per-row product projection (SELECT a*b FROM t, SELECT (a+b)*c FROM t)
        # is accepted here too (v0.6.2); the aggregated shapes (SUM(a*b), SUM(a)*SUM(b), ...) are
        # unaffected — fhe_expr.analyze rejects a pure per-row LINEAR form (no product) exactly as before.
        fx, folded = fhe_expr.analyze(expr, resolve, _fold, allow_row=True)
        return folded, ExprInfo(kind=fx.level, enc=True, depth=0, ct_muls=fx.products, inversions=0,
                                fhe=True)
    node, (kind, cols, depth, muls, invs) = _an(expr, resolve)
    if kind == "const":
        raise ValidationError(
            "expression contains no column or aggregate (a constant is not a result)")
    if kind == "row" and not cols:
        raise ValidationError(
            "a per-row expression needs at least one ENC/PAIRED column; an expression "
            "over PLAIN columns only is not supported (select the columns and compute "
            "it client-side)")
    return node, ExprInfo(kind=kind, enc=bool(cols), depth=depth, ct_muls=muls,
                          inversions=invs)


# ── canonical text (default output-column name) ──────────────────────────────
_PREC = {"+": 1, "-": 1, "*": 2, "/": 2}


def render(e, parent: int = 0, right: bool = False) -> str:
    """Canonical, minimally parenthesised text of an expression."""
    if isinstance(e, Lit):
        v = e.value
        s = str(v) if not isinstance(v, Fraction) else f"FRAC({v.numerator},{v.denominator})"
        return f"({s})" if (isinstance(v, int) and v < 0 and parent) else s
    if isinstance(e, ColRef):
        return e.name
    if isinstance(e, Neg):
        inner = f"-{render(e.operand, 3)}"
        return f"({inner})" if parent else inner       # never emit `--` (a comment)
    if isinstance(e, AggCall):
        return "count(*)" if e.fn == "COUNT" else f"{e.fn.lower()}({render(e.arg)})"
    if isinstance(e, BinOp):
        p = _PREC[e.op]
        s = f"{render(e.left, p)}{e.op}{render(e.right, p, True)}"
        return f"({s})" if (p < parent or (p == parent and right)) else s
    return "expr"


def columns_of(e) -> list[str]:
    """Column names referenced by an expression, in first-use order."""
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
