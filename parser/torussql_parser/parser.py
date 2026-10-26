# SPDX-License-Identifier: Apache-2.0
"""TorusSQL parser — hand-rolled, dependency-free.

Grammar (case-insensitive keywords); see ../../spec/TorusSQL-Spec-v0.1.md:

    CREATE TABLE <name> ( <col> <type> <policy>, ... )
        type   ::= INT | STR | RATIONAL
        policy ::= PLAIN | ENC | PAIRED

    INSERT INTO <name> ( <col>, ... ) VALUES ( <lit>, ... )
        lit ::= int | str | NULL | FRAC( int , int )

    SELECT <proj_list> FROM <name> [ WHERE <plain_col> = <lit> ]
        proj_list ::= * | <proj> ( , <proj> )*
        proj      ::= <col>
                    | SUM( <col> )
                    | DOT( <col>, <col> )
                    | <int> * <col>
                    | <col> * <col>

    DROP TABLE <name>

    CREATE INDEX ON <name> ( <plain_col> )      -- accelerates = < <= > >= IN
    DROP INDEX ON <name> ( <col> )
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Sequence

from .ast import (
    AggCall, AvgExpr, BinOp, ColRef, ExprProj, Lit, Neg, Condition, CountStar, CreateTable, CtMulExpr, Delete,
    DotExpr, DropTable, CreateIndex, DropIndex, Having, InList, Insert, Join, MaxExpr, MinExpr, OrderBy,
    POLICY_KEYWORDS, Proj, Query, ScalarMulExpr, ScaledSumExpr, Select, SumExpr,
    TYPE_KEYWORDS, Update, Where, WHERE_OPS,
)
from .errors import ParseError


# ── Tokeniser ────────────────────────────────────────────────────────────────
_TOK_RE = re.compile(r"""
    \s+                         |
    --[^\n]*                    |
    /\*.*?\*/                   |
    (?P<num>-?[0-9]+)           |
    (?P<str>'(?:[^']|'')*')     |
    (?P<id>[A-Za-z_][A-Za-z_0-9]*) |
    (?P<sym>==|!=|<>|<=|>=|[(),*=<>?.;+\-/])
""", re.VERBOSE | re.DOTALL)


@dataclass
class Tok:
    kind: str
    value: Any
    pos: int


def _tokenise(sql: str) -> list[Tok]:
    toks: list[Tok] = []
    i = 0
    while i < len(sql):
        m = _TOK_RE.match(sql, i)
        if not m:
            raise ParseError(f"unexpected char at {i}: {sql[i:i+10]!r}")
        if m.group("num"):
            try:
                toks.append(Tok("num", int(m.group("num")), i))
            except ValueError:
                raise ParseError(f"integer literal at {i} is too long") from None
        elif m.group("str"):
            s = m.group("str")[1:-1].replace("''", "'")
            toks.append(Tok("str", s, i))
        elif m.group("id"):
            toks.append(Tok("id", m.group("id"), i))
        elif m.group("sym"):
            toks.append(Tok("sym", m.group("sym"), i))
        i = m.end()
    return toks


class _P:
    def __init__(self, toks: Sequence[Tok]):
        self.toks = list(toks)
        self.i = 0
        self.nest = 0           # open parentheses / unary minus signs (bounds recursion)

    def peek(self, *, kind: str | None = None, value: Any = None) -> Tok | None:
        if self.i >= len(self.toks):
            return None
        t = self.toks[self.i]
        if kind and t.kind != kind:
            return None
        if value is not None:
            cmp = t.value.upper() if isinstance(t.value, str) else t.value
            want = value.upper() if isinstance(value, str) else value
            if cmp != want:
                return None
        return t

    def eat(self, *, kind: str | None = None, value: Any = None) -> Tok:
        t = self.peek(kind=kind, value=value)
        if t is None:
            cur = self.toks[self.i] if self.i < len(self.toks) else None
            raise ParseError(f"expected kind={kind} value={value} got {cur}")
        self.i += 1
        return t

    def eof(self) -> bool:
        return self.i >= len(self.toks)

    def split_neg(self) -> None:
        """In operator position the tokeniser's negative literal (`a-1` lexes as
        `a`, `-1`) is really a binary minus: split it into `-` and `1`."""
        t = self.toks[self.i] if self.i < len(self.toks) else None
        if t is not None and t.kind == "num" and t.value < 0:
            self.toks[self.i:self.i + 1] = [Tok("sym", "-", t.pos), Tok("num", -t.value, t.pos)]


def parse(sql: str) -> Query:
    """Parse one TorusSQL statement into an AST node."""
    toks = _tokenise(sql)
    if toks and toks[-1].kind == "sym" and toks[-1].value == ";":
        toks.pop()                                   # one optional trailing ';'
    if any(t.kind == "sym" and t.value == ";" for t in toks):
        raise ParseError("only one statement per call (found ';' inside the statement)")
    if not toks:
        raise ParseError("empty SQL")
    p = _P(toks)
    head = p.eat(kind="id").value.upper()
    if head == "CREATE":
        return _parse_create(p)
    if head == "DROP":
        return _parse_drop(p)
    if head == "INSERT":
        return _parse_insert(p)
    if head == "UPDATE":
        return _parse_update(p)
    if head == "DELETE":
        return _parse_delete(p)
    if head == "SELECT":
        return _parse_select(p)
    raise ParseError(f"unknown statement: {head}")


def _parse_index(p: _P, cls):
    p.eat(kind="id", value="ON")
    table = p.eat(kind="id").value
    p.eat(kind="sym", value="(")
    col = p.eat(kind="id").value
    p.eat(kind="sym", value=")")
    if not p.eof():
        raise ParseError("trailing tokens after INDEX definition")
    return cls(table=table, column=col)


def _parse_create(p: _P):
    if p.peek(kind="id", value="INDEX"):
        p.eat()
        return _parse_index(p, CreateIndex)
    p.eat(kind="id", value="TABLE")
    if_not_exists = False
    if p.peek(kind="id", value="IF"):
        p.eat(); p.eat(kind="id", value="NOT"); p.eat(kind="id", value="EXISTS")
        if_not_exists = True
    name = p.eat(kind="id").value
    p.eat(kind="sym", value="(")
    cols: list[tuple[str, str, str]] = []
    while True:
        cname = p.eat(kind="id").value
        ctype = p.eat(kind="id").value.upper()
        cpolicy = p.eat(kind="id").value.upper()
        if ctype not in TYPE_KEYWORDS:
            raise ParseError(f"bad type {ctype}")
        if cpolicy not in POLICY_KEYWORDS:
            raise ParseError(f"bad policy {cpolicy}")
        cols.append((cname, TYPE_KEYWORDS[ctype], POLICY_KEYWORDS[cpolicy]))
        if p.peek(kind="sym", value=","):
            p.eat(); continue
        break
    p.eat(kind="sym", value=")")
    if not p.eof():
        raise ParseError("trailing tokens after CREATE TABLE")
    return CreateTable(name=name, columns=cols, if_not_exists=if_not_exists)


def _parse_drop(p: _P):
    if p.peek(kind="id", value="INDEX"):
        p.eat()
        return _parse_index(p, DropIndex)
    p.eat(kind="id", value="TABLE")
    if_exists = False
    if p.peek(kind="id", value="IF"):
        p.eat(); p.eat(kind="id", value="EXISTS")
        if_exists = True
    name = p.eat(kind="id").value
    if not p.eof():
        raise ParseError("trailing tokens after DROP TABLE")
    return DropTable(name=name, if_exists=if_exists)


def _parse_insert(p: _P) -> Insert:
    p.eat(kind="id", value="INTO")
    table = p.eat(kind="id").value
    p.eat(kind="sym", value="(")
    cols: list[str] = []
    while True:
        cols.append(p.eat(kind="id").value)
        if p.peek(kind="sym", value=","):
            p.eat(); continue
        break
    p.eat(kind="sym", value=")")
    p.eat(kind="id", value="VALUES")
    p.eat(kind="sym", value="(")
    vals: list[Any] = []
    while True:
        vals.append(_parse_literal(p))
        if p.peek(kind="sym", value=","):
            p.eat(); continue
        break
    p.eat(kind="sym", value=")")
    if len(cols) != len(vals):
        raise ParseError("column/value count mismatch")
    if len(set(cols)) != len(cols):
        raise ParseError("duplicate column in INSERT")
    if not p.eof():
        raise ParseError("trailing tokens after INSERT")
    return Insert(table=table, columns=cols, values=vals)


def _parse_update(p: _P) -> Update:
    table = p.eat(kind="id").value
    p.eat(kind="id", value="SET")
    assignments: list[tuple[str, object]] = []
    while True:
        col = p.eat(kind="id").value
        p.eat(kind="sym", value="=")
        assignments.append((col, _parse_literal(p)))
        if p.peek(kind="sym", value=","):
            p.eat(); continue
        break
    where = None
    if p.peek(kind="id", value="WHERE"):
        p.eat()
        where = _parse_where(p)
    if not p.eof():
        raise ParseError("trailing tokens in UPDATE")
    if len({c for c, _ in assignments}) != len(assignments):
        raise ParseError("duplicate column in UPDATE SET")
    return Update(table=table, assignments=assignments, where=where)


def _parse_delete(p: _P) -> Delete:
    p.eat(kind="id", value="FROM")
    table = p.eat(kind="id").value
    where = None
    if p.peek(kind="id", value="WHERE"):
        p.eat()
        where = _parse_where(p)
    if not p.eof():
        raise ParseError("trailing tokens in DELETE")
    return Delete(table=table, where=where)


_RESERVED = frozenset({
    "JOIN", "INNER", "LEFT", "OUTER", "ON", "WHERE", "GROUP", "ORDER",
    "HAVING", "LIMIT", "OFFSET", "AS", "FROM", "SELECT", "AND", "OR", "IN", "BY",
    "LIKE", "IS", "BETWEEN", "NOT",
})


def _parse_table_alias(p: _P) -> str | None:
    """Optional `[AS] alias` after a table name (never a reserved word)."""
    if p.peek(kind="id", value="AS"):
        p.eat()
        t = p.eat(kind="id")
        if t.value.upper() in _RESERVED:
            raise ParseError(f"reserved word {t.value!r} cannot be an alias")
        return t.value
    t = p.peek(kind="id")
    if t is not None and t.value.upper() not in _RESERVED:
        p.eat()
        return t.value
    return None


def _parse_col_ref(p: _P) -> str:
    """Parse `table.col` (table-qualified) or bare `col`. Returns dotted or plain string."""
    name = p.eat(kind="id").value
    if p.peek(kind="sym", value="."):
        p.eat()
        col = p.eat(kind="id").value
        return f"{name}.{col}"
    return name


def _parse_literal(p: _P):
    """literal ::= int | str | NULL | FRAC( int , int )"""
    if p.peek(kind="id", value="FRAC"):
        p.eat()
        p.eat(kind="sym", value="(")
        n_tok = p.eat()
        if n_tok.kind != "num":
            raise ParseError(f"FRAC numerator must be integer, got {n_tok}")
        p.eat(kind="sym", value=",")
        d_tok = p.eat()
        if d_tok.kind != "num":
            raise ParseError(f"FRAC denominator must be integer, got {d_tok}")
        p.eat(kind="sym", value=")")
        if d_tok.value == 0:
            raise ParseError("FRAC denominator must be nonzero")
        return ("frac", n_tok.value, d_tok.value)

    t = p.eat()
    if t.kind == "num":
        return t.value
    if t.kind == "str":
        return t.value
    if t.kind == "id" and t.value.upper() == "NULL":
        return None
    raise ParseError(f"bad VALUE {t}")


def _parse_select(p: _P) -> Select:
    sel = Select(table="")
    if p.peek(kind="id", value="DISTINCT"):
        p.eat()
        sel.distinct = True
    if p.peek(kind="sym", value="*"):
        p.eat()
        sel.star = True
    else:
        while True:
            sel.projections.append(_parse_proj(p))
            if p.peek(kind="id", value="AS"):       # optional column alias
                p.eat()
                sel.aliases.append(p.eat(kind="id").value)
            else:
                sel.aliases.append(None)
            if p.peek(kind="sym", value=","):
                p.eat(); continue
            break

    p.eat(kind="id", value="FROM")
    sel.table = p.eat(kind="id").value
    sel.table_alias = _parse_table_alias(p)

    # Optional [INNER | LEFT [OUTER]] JOIN <t> [[AS] alias] ON … clauses
    while True:
        kind = "inner"
        if p.peek(kind="id", value="INNER"):
            p.eat()
            p.eat(kind="id", value="JOIN")
        elif p.peek(kind="id", value="LEFT"):
            p.eat()
            if p.peek(kind="id", value="OUTER"):
                p.eat()
            p.eat(kind="id", value="JOIN")
            kind = "left"
        elif p.peek(kind="id", value="JOIN"):
            p.eat()
        else:
            break
        join_table = p.eat(kind="id").value
        join_alias = _parse_table_alias(p)
        p.eat(kind="id", value="ON")
        left_ref = _parse_col_ref(p)
        p.eat(kind="sym", value="=")
        right_ref = _parse_col_ref(p)
        sel.joins.append(Join(table=join_table, on_left=left_ref,
                              on_right=right_ref, alias=join_alias, kind=kind))

    if p.peek(kind="id", value="WHERE"):
        p.eat()
        sel.where = _parse_where(p)

    if p.peek(kind="id", value="GROUP"):
        p.eat()
        p.eat(kind="id", value="BY")
        while True:
            sel.group_by.append(_parse_col_ref(p))
            if p.peek(kind="sym", value=","):
                p.eat(); continue
            break

    if p.peek(kind="id", value="HAVING"):
        p.eat()
        p.eat(kind="id", value="COUNT")
        p.eat(kind="sym", value="(")
        p.eat(kind="sym", value="*")
        p.eat(kind="sym", value=")")
        op = p.eat(kind="sym").value
        if op not in WHERE_OPS:
            raise ParseError(f"unsupported HAVING operator {op!r}")
        sel.having = Having(op=op, value=p.eat(kind="num").value)

    if p.peek(kind="id", value="ORDER"):
        p.eat()
        p.eat(kind="id", value="BY")
        col = _parse_col_ref(p)
        desc = False
        if p.peek(kind="id", value="ASC"):
            p.eat()
        elif p.peek(kind="id", value="DESC"):
            p.eat(); desc = True
        sel.order_by = OrderBy(column=col, descending=desc)

    if p.peek(kind="id", value="LIMIT"):
        p.eat()
        n = p.eat(kind="num").value
        if n < 0:
            raise ParseError("LIMIT must be non-negative")
        sel.limit = n

    if p.peek(kind="id", value="OFFSET"):
        p.eat()
        n = p.eat(kind="num").value
        if n < 0:
            raise ParseError("OFFSET must be non-negative")
        sel.offset = n

    if not p.eof():
        raise ParseError("trailing tokens in SELECT")
    return sel


def _parse_where(p: _P) -> Where:
    """predicate ::= and_group ( OR and_group )*
       and_group ::= atom ( AND atom )*   — DNF, AND binds tighter than OR."""
    or_terms: list[list] = []
    while True:
        group: list = []
        while True:
            group.extend(_parse_atom(p))
            if p.peek(kind="id", value="AND"):
                p.eat(); continue
            break
        or_terms.append(group)
        if p.peek(kind="id", value="OR"):
            p.eat(); continue
        break
    return Where(or_terms=or_terms)


def _literal(p: _P, what: str):
    v = p.eat()
    if v.kind not in ("num", "str"):
        raise ParseError(f"{what} must be a literal")
    return v.value


def _parse_in_list(p: _P) -> list:
    p.eat(kind="sym", value="(")
    values: list = []
    while True:
        v = p.eat()
        if v.kind not in ("num", "str"):
            raise ParseError("IN list values must be literals")
        values.append(v.value)
        if p.peek(kind="sym", value=","):
            p.eat(); continue
        break
    p.eat(kind="sym", value=")")
    if not values:
        raise ParseError("IN list must be non-empty")
    return values


def _parse_atom(p: _P) -> list:
    """One predicate atom, returned as the list of primitive atoms it stands for
    (BETWEEN and NOT IN desugar into AND-ed comparisons)."""
    col = _parse_col_ref(p)
    if p.peek(kind="id", value="IN"):
        p.eat()
        return [InList(column=col, values=_parse_in_list(p))]
    if p.peek(kind="id", value="BETWEEN"):
        p.eat()
        lo = _literal(p, "BETWEEN bound")
        p.eat(kind="id", value="AND")
        hi = _literal(p, "BETWEEN bound")
        return [Condition(column=col, op=">=", value=lo),
                Condition(column=col, op="<=", value=hi)]
    if p.peek(kind="id", value="IS"):
        p.eat()
        neg = False
        if p.peek(kind="id", value="NOT"):
            p.eat(); neg = True
        p.eat(kind="id", value="NULL")
        return [Condition(column=col, op="not_null" if neg else "is_null", value=None)]
    if p.peek(kind="id", value="NOT"):
        p.eat()
        if p.peek(kind="id", value="IN"):
            p.eat()
            return [Condition(column=col, op="!=", value=v) for v in _parse_in_list(p)]
        p.eat(kind="id", value="LIKE")
        return [Condition(column=col, op="not_like", value=_literal(p, "LIKE pattern"))]
    if p.peek(kind="id", value="LIKE"):
        p.eat()
        return [Condition(column=col, op="like", value=_literal(p, "LIKE pattern"))]
    op_tok = p.eat(kind="sym")
    if op_tok.value not in WHERE_OPS:
        raise ParseError(f"unsupported WHERE operator {op_tok.value!r}")
    return [Condition(column=col, op=op_tok.value, value=_literal(p, "WHERE value"))]


# ── projections and arithmetic expressions (v0.6) ────────────────────────────
#
#   expr    ::= term { ('+' | '-') term }
#   term    ::= unary { ('*' | '/') unary }
#   unary   ::= '-' unary | primary
#   primary ::= int | FRAC(int, int) | colref | '(' expr ')'
#             | SUM(expr) | AVG(expr) | COUNT(*)
#   proj    ::= expr | MIN(colref) | MAX(colref) | DOT(colref, colref)
#
# The pre-v0.6 projection shapes (col, SUM(col), AVG(col), k*col, k*SUM(col),
# col*col, COUNT(*)) are still returned as their own AST nodes (_classify);
# anything else becomes an ExprProj.

MAX_EXPR_HEIGHT = 100     # tree height limit (bounds recursion in every consumer)


def _too_deep() -> ParseError:
    return ParseError(f"expression is nested too deeply (tree height limit {MAX_EXPR_HEIGHT})")


def _is_op(p: _P, *ops: str) -> bool:
    t = p.peek(kind="sym")
    return t is not None and t.value in ops


def _parse_expr(p: _P) -> tuple[Any, int]:
    left, h = _parse_term(p)
    while True:
        p.split_neg()
        if not _is_op(p, "+", "-"):
            return left, h
        op = p.eat().value
        right, h2 = _parse_term(p)
        h = max(h, h2) + 1
        if h > MAX_EXPR_HEIGHT:
            raise _too_deep()
        left = BinOp(op=op, left=left, right=right)


def _parse_term(p: _P) -> tuple[Any, int]:
    left, h = _parse_unary(p)
    while _is_op(p, "*", "/"):
        op = p.eat().value
        right, h2 = _parse_unary(p)
        h = max(h, h2) + 1
        if h > MAX_EXPR_HEIGHT:
            raise _too_deep()
        left = BinOp(op=op, left=left, right=right)
    return left, h


def _enter(p: _P) -> None:
    p.nest += 1
    if p.nest > MAX_EXPR_HEIGHT:
        raise _too_deep()


def _parse_unary(p: _P) -> tuple[Any, int]:
    if _is_op(p, "-"):
        p.eat()
        _enter(p)
        operand, h = _parse_unary(p)
        p.nest -= 1
        if isinstance(operand, Lit):
            return Lit(value=-operand.value), h
        if h + 1 > MAX_EXPR_HEIGHT:
            raise _too_deep()
        return Neg(operand=operand), h + 1
    return _parse_primary(p)


def _contains_agg(e) -> bool:
    if isinstance(e, AggCall):
        return True
    if isinstance(e, BinOp):
        return _contains_agg(e.left) or _contains_agg(e.right)
    if isinstance(e, Neg):
        return _contains_agg(e.operand)
    return False


def _parse_primary(p: _P) -> tuple[Any, int]:
    if p.peek(kind="num"):
        return Lit(value=p.eat().value), 0
    if _is_op(p, "("):
        p.eat()
        _enter(p)
        e, h = _parse_expr(p)
        p.eat(kind="sym", value=")")
        p.nest -= 1
        return e, h
    t = p.peek(kind="id")
    if t is None:
        raise ParseError(f"could not parse an expression at token {p.peek()}")
    nxt = p.toks[p.i + 1] if p.i + 1 < len(p.toks) else None
    is_call = nxt is not None and nxt.kind == "sym" and nxt.value == "("
    kw = t.value.upper()
    if kw == "FRAC" and is_call:
        n, d = _parse_literal(p)[1:]
        f = Fraction(n, d)
        return Lit(value=int(f) if f.denominator == 1 else f), 0
    if is_call:
        if kw == "COUNT":
            p.eat(); p.eat(kind="sym", value="(")
            p.eat(kind="sym", value="*")
            p.eat(kind="sym", value=")")
            return AggCall(fn="COUNT"), 0
        if kw in ("SUM", "AVG"):
            p.eat(); p.eat(kind="sym", value="(")
            _enter(p)
            arg, h = _parse_expr(p)
            p.nest -= 1
            p.eat(kind="sym", value=")")
            if _contains_agg(arg):
                raise ParseError(f"{kw}(...) cannot contain another aggregate")
            if h + 1 > MAX_EXPR_HEIGHT:
                raise _too_deep()
            return AggCall(fn=kw, arg=arg), h + 1
        if kw in ("MIN", "MAX", "DOT"):
            raise ParseError(f"{kw}(...) cannot be used inside an arithmetic expression")
        raise ParseError(f"unknown function {t.value!r}")
    if kw in _CLAUSE_WORDS:
        raise ParseError(f"expected an expression, got keyword {t.value.upper()}")
    return ColRef(name=_parse_col_ref(p)), 0


_CLAUSE_WORDS = frozenset({"FROM", "AS", "WHERE", "GROUP", "HAVING", "LIMIT", "OFFSET",
                           "JOIN", "ON", "AND", "OR", "SELECT"})


def _is_int_lit(e) -> bool:
    return isinstance(e, Lit) and isinstance(e.value, int) and not isinstance(e.value, bool)


def _classify(e) -> Proj:
    """Map an expression tree back to the pre-v0.6 node types where one exists."""
    if isinstance(e, ColRef):
        return e
    if isinstance(e, AggCall):
        if e.fn == "COUNT":
            return CountStar()
        if isinstance(e.arg, ColRef):
            return (SumExpr if e.fn == "SUM" else AvgExpr)(column=e.arg.name)
    if isinstance(e, BinOp) and e.op == "*":
        if _is_int_lit(e.left):
            if isinstance(e.right, ColRef):
                return ScalarMulExpr(scalar=e.left.value, column=e.right.name)
            if (isinstance(e.right, AggCall) and e.right.fn == "SUM"
                    and isinstance(e.right.arg, ColRef)):
                return ScaledSumExpr(scalar=e.left.value, column=e.right.arg.name)
        if isinstance(e.left, ColRef) and isinstance(e.right, ColRef):
            return CtMulExpr(left=e.left.name, right=e.right.name)
    return ExprProj(expr=e)


def _parse_proj(p: _P) -> Proj:
    t = p.peek(kind="id")
    nxt = p.toks[p.i + 1] if p.i + 1 < len(p.toks) else None
    if t is not None and nxt is not None and nxt.kind == "sym" and nxt.value == "(":
        kw = t.value.upper()
        node = None
        if kw in ("MIN", "MAX"):
            p.eat(); p.eat(kind="sym", value="(")
            col = _parse_col_ref(p)
            p.eat(kind="sym", value=")")
            node = (MinExpr if kw == "MIN" else MaxExpr)(column=col)
        elif kw == "DOT":
            p.eat(); p.eat(kind="sym", value="(")
            a = _parse_col_ref(p)
            p.eat(kind="sym", value=",")
            b = _parse_col_ref(p)
            p.eat(kind="sym", value=")")
            node = DotExpr(left=a, right=b)
        if node is not None:
            p.split_neg()
            if _is_op(p, "+", "-", "*", "/"):
                raise ParseError(f"{kw}(...) cannot be used inside an arithmetic expression")
            return node
    e, _h = _parse_expr(p)
    return _classify(e)
