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
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from .ast import (
    AvgExpr, ColRef, Condition, CountStar, CreateTable, CtMulExpr, Delete,
    DotExpr, DropTable, Having, InList, Insert, Join, MaxExpr, MinExpr, OrderBy,
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
    (?P<sym>==|!=|<>|<=|>=|[(),*=<>?.;])
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


def _parse_create(p: _P) -> CreateTable:
    p.eat(kind="id", value="TABLE")
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
    return CreateTable(name=name, columns=cols)


def _parse_drop(p: _P) -> DropTable:
    p.eat(kind="id", value="TABLE")
    name = p.eat(kind="id").value
    if not p.eof():
        raise ParseError("trailing tokens after DROP TABLE")
    return DropTable(name=name)


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
    "HAVING", "LIMIT", "AS", "FROM", "SELECT", "AND", "OR", "IN", "BY",
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
            group.append(_parse_atom(p))
            if p.peek(kind="id", value="AND"):
                p.eat(); continue
            break
        or_terms.append(group)
        if p.peek(kind="id", value="OR"):
            p.eat(); continue
        break
    return Where(or_terms=or_terms)


def _parse_atom(p: _P):
    col = _parse_col_ref(p)
    if p.peek(kind="id", value="IN"):
        p.eat()
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
        return InList(column=col, values=values)
    op_tok = p.eat(kind="sym")
    if op_tok.value not in WHERE_OPS:
        raise ParseError(f"unsupported WHERE operator {op_tok.value!r}")
    v = p.eat()
    if v.kind not in ("num", "str"):
        raise ParseError("WHERE value must be a literal")
    return Condition(column=col, op=op_tok.value, value=v.value)


def _parse_proj(p: _P) -> Proj:
    if p.peek(kind="id", value="COUNT"):
        p.eat()
        p.eat(kind="sym", value="(")
        p.eat(kind="sym", value="*")
        p.eat(kind="sym", value=")")
        return CountStar()
    for kw, node in (("SUM", SumExpr), ("AVG", AvgExpr),
                     ("MIN", MinExpr), ("MAX", MaxExpr)):
        if p.peek(kind="id", value=kw):
            p.eat()
            p.eat(kind="sym", value="(")
            col = _parse_col_ref(p)
            p.eat(kind="sym", value=")")
            return node(column=col)
    if p.peek(kind="id", value="DOT"):
        p.eat()
        p.eat(kind="sym", value="(")
        a = _parse_col_ref(p)
        p.eat(kind="sym", value=",")
        b = _parse_col_ref(p)
        p.eat(kind="sym", value=")")
        return DotExpr(left=a, right=b)
    if p.peek(kind="num"):
        n = p.eat().value
        p.eat(kind="sym", value="*")
        if p.peek(kind="id", value="SUM"):           # k * SUM(col)  — aggregate
            p.eat()
            p.eat(kind="sym", value="(")
            col = _parse_col_ref(p)
            p.eat(kind="sym", value=")")
            return ScaledSumExpr(scalar=n, column=col)
        col = _parse_col_ref(p)                      # k * col       — per-row
        return ScalarMulExpr(scalar=n, column=col)
    if p.peek(kind="id"):
        first = p.eat(kind="id").value
        # table-qualified ref: t.col [* t2.col2]
        if p.peek(kind="sym", value="."):
            p.eat()
            first_col = p.eat(kind="id").value
            first = f"{first}.{first_col}"
        if p.peek(kind="sym", value="*"):
            p.eat()
            second = p.eat(kind="id").value
            if p.peek(kind="sym", value="."):
                p.eat()
                second_col = p.eat(kind="id").value
                second = f"{second}.{second_col}"
            return CtMulExpr(left=first, right=second)
        return ColRef(name=first)
    raise ParseError(f"could not parse projection at token {p.peek()}")
