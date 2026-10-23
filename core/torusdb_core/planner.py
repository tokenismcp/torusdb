# SPDX-License-Identifier: Apache-2.0
"""Planner: AST → typed plan with policy/type checks.

Encrypted-column compatibility rules:
    SUM(c)            : c must be policy=encrypted or paired
    DOT(a, b)         : both must be policy=paired  (★_ct needs G1+G2)
    col1 * col2       : same as DOT
    k * c             : c must be encrypted or paired; k is plain int
    WHERE c = lit     : c must be policy=plain  (no encrypted equality
                        circuit in this engine — that needs FHE bootstrap
                        of an equality predicate)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from .catalog import Catalog
from .errors import PlanError
from .parser import (
    ColRef, CreateIndex, CreateTable, CtMulExpr, Delete, DotExpr, DropIndex, DropTable, Insert, Join,
    Query, ScalarMulExpr, Select, SumExpr, Update,
)
from torussql_parser.ast import (
    AvgExpr, CountStar, InList, MaxExpr, MinExpr, ScaledSumExpr,
)
from torussql_parser.errors import ValidationError as _OpenValidationError
from torussql_parser.predicate import LIKE_OPS, NULL_OPS
from torussql_parser.validate import MAX_SCALAR, check_literal, check_predicate_literal


def _typed(fn, *args):
    """Run an open-validator literal check, reporting it as a PlanError so the
    closed planner rejects exactly what the open validator rejects."""
    try:
        fn(*args)
    except _OpenValidationError as exc:
        raise PlanError(str(exc)) from None


@dataclass
class PColRef:
    name: str
    policy: str


@dataclass
class PSum:
    column: str
    policy: str


@dataclass
class PDot:
    left: str
    right: str


@dataclass
class PCtMul:
    left: str
    right: str


@dataclass
class PScalarMul:
    """k * col — per-row scalar multiply."""
    scalar: int
    column: str
    policy: str


@dataclass
class PScaledSum:
    """k * SUM(col) — scaled aggregate."""
    scalar: int
    column: str
    policy: str


@dataclass
class PCountStar:
    pass


@dataclass
class PAvg:
    column: str
    policy: str


@dataclass
class PMin:
    column: str


@dataclass
class PMax:
    column: str


@dataclass
class PJoin:
    """Planned join step. The joined (right) instance is always `alias`; the
    ON column of the other side belongs to the earlier instance `left_alias`.
    Both ON columns are PLAIN (equality is evaluated on plaintext keys)."""
    table: str          # physical right table
    alias: str          # right instance name (alias, else the table name)
    left_alias: str     # earlier instance the ON refers to
    left_col: str       # bare ON column on left_alias
    right_col: str      # bare ON column on the right instance
    kind: str = "inner" # "inner" | "left"


PProj = Union[PColRef, PSum, PDot, PCtMul, PScalarMul, PScaledSum, PCountStar,
              PAvg, PMin, PMax]


@dataclass
class PCondition:
    column: str
    op: str
    value: object


@dataclass
class PInList:
    column: str
    values: list


@dataclass
class PWhere:
    """DNF predicate: OR of AND-groups of atoms (PCondition | PInList)."""
    or_terms: list[list]


@dataclass
class POrderBy:
    column: str
    descending: bool


@dataclass
class Plan:
    kind: str
    raw: Query
    table: str = ""
    projections: list[PProj] | None = None
    star: bool = False
    where: PWhere | None = None
    order_by: POrderBy | None = None
    limit: int | None = None
    offset: int | None = None
    out_aliases: list | None = None   # AS names, aligned with projections
    distinct: bool = False
    group_by: list[str] | None = None
    having: tuple | None = None       # (op, value) on COUNT(*) per group
    pairing_ops: int = 0          # number of ★_ct operations this plan uses
    joins: list[PJoin] | None = None  # join steps, in order
    # instance name -> physical table, FROM table first (self-joins map two
    # instance names to one table). None for single-table queries.
    instances: dict | None = None


class _Scope:
    """Table instances visible to a statement, keyed by instance name."""

    def __init__(self) -> None:
        self.specs: dict = {}

    def add(self, name: str, spec) -> None:
        if name in self.specs:
            raise PlanError(
                f"duplicate table name {name!r} in FROM/JOIN — give each "
                f"occurrence a distinct alias")
        self.specs[name] = spec

    def resolve(self, ref: str):
        """'inst.col' or bare 'col' -> (instance, ColumnSpec)."""
        if "." in ref:
            inst, cname = ref.split(".", 1)
            if inst not in self.specs:
                raise PlanError(f"unknown table {inst!r} in column ref {ref!r}")
            return inst, self._col(inst, cname)
        owners = [i for i, sp in self.specs.items() if sp.has(ref)]
        if len(owners) == 1:
            return owners[0], self.specs[owners[0]].column(ref)
        if len(owners) > 1:
            raise PlanError(
                f"column {ref!r} is ambiguous in join — qualify as table.col")
        raise PlanError(f"no such column: {ref!r}")

    def _col(self, inst: str, cname: str):
        try:
            return self.specs[inst].column(cname)
        except KeyError:
            raise PlanError(f"no such column: {cname!r} in table {inst!r}")


def plan_query(q: Query, catalog: Catalog) -> Plan:
    if isinstance(q, CreateTable):
        return _plan_create(q, catalog)
    if isinstance(q, DropTable):
        if q.name not in catalog.tables:
            if q.if_exists:
                return Plan(kind="drop_if_exists", raw=q, table=q.name)
            raise PlanError(f"no such table: {q.name}")
        return Plan(kind="drop", raw=q, table=q.name)
    if isinstance(q, (CreateIndex, DropIndex)):
        spec = catalog.tables.get(q.table)
        if spec is None:
            raise PlanError(f"no such table: {q.table}")
        if not spec.has(q.column):
            raise PlanError(f"no such column: {q.column!r} in table {q.table!r}")
        if spec.column(q.column).policy != "plain":
            raise PlanError(f"cannot index {q.column!r}: only PLAIN columns can be indexed")
        return Plan(kind="create_index" if isinstance(q, CreateIndex) else "drop_index",
                    raw=q, table=q.table)
    if isinstance(q, Insert):
        return _plan_insert(q, catalog)
    if isinstance(q, Update):
        return _plan_update(q, catalog)
    if isinstance(q, Delete):
        return _plan_delete(q, catalog)
    if isinstance(q, Select):
        return _plan_select(q, catalog)
    raise PlanError(f"unknown query type: {type(q).__name__}")


def _plan_create(q: CreateTable, cat: Catalog) -> Plan:
    """Same rules as the open validator (_validate_create): the engine must
    reject exactly what the dialect rejects."""
    if q.name.startswith("__"):
        raise PlanError(f"table names starting with '__' are reserved ({q.name!r})")
    if q.name in cat.tables:
        if q.if_not_exists:
            return Plan(kind="noop", raw=q, table=q.name)
        raise PlanError(f"table {q.name!r} already exists")
    if not q.columns:
        raise PlanError("a table must declare at least one column")
    seen: set[str] = set()
    for (n, t, p) in q.columns:
        if n.startswith("__"):
            raise PlanError(
                f"column names starting with '__' are reserved (column {n!r})")
        if n in seen:
            raise PlanError(f"duplicate column {n!r}")
        seen.add(n)
        if p != "plain" and t == "str":
            raise PlanError(f"STR columns must be PLAIN (column {n!r})")
    return Plan(kind="create", raw=q, table=q.name)


def _plan_where(q_where, scope: "_Scope", qualify: bool) -> "PWhere | None":
    """Plan a predicate. Columns must be PLAIN. With qualify=True (joins) the
    atom column is stored as 'instance.col'; otherwise as the bare name."""
    if q_where is None:
        return None
    or_terms = []
    for grp in q_where.or_terms:
        atoms = []
        for atom in grp:
            inst, col = scope.resolve(atom.column)
            if col.policy != "plain":
                raise PlanError(
                    "WHERE on encrypted columns is not supported (encrypted "
                    f"predicate circuit needed); use a plain column "
                    f"(column {col.name!r} is {col.policy})")
            if isinstance(atom, InList):
                _typed(check_predicate_literal, col, atom.values)
            elif atom.op in NULL_OPS:
                pass
            elif atom.op in LIKE_OPS:
                if col.type != "str" or not isinstance(atom.value, str):
                    raise PlanError(f"LIKE needs a STR column and a string pattern "
                                    f"(column {col.name!r} is {col.type.upper()})")
            else:
                _typed(check_predicate_literal, col, [atom.value])
            name = f"{inst}.{col.name}" if qualify else col.name
            if isinstance(atom, InList):
                atoms.append(PInList(column=name, values=list(atom.values)))
            else:
                atoms.append(PCondition(column=name, op=atom.op,
                                        value=atom.value))
        or_terms.append(atoms)
    return PWhere(or_terms=or_terms)


def _single_scope(cat: Catalog, table: str) -> "_Scope":
    sc = _Scope()
    sc.add(table, cat.get(table))
    return sc


def _plan_update(q: Update, cat: Catalog) -> Plan:
    if q.table not in cat.tables:
        raise PlanError(f"no such table: {q.table}")
    spec = cat.get(q.table)
    for (col, val) in q.assignments:
        if not spec.has(col):
            raise PlanError(f"no such column: {col!r} in table {q.table!r}")
        _typed(check_literal, spec.column(col), val)
    return Plan(kind="update", raw=q, table=q.table,
                where=_plan_where(q.where, _single_scope(cat, q.table), False))


def _plan_delete(q: Delete, cat: Catalog) -> Plan:
    if q.table not in cat.tables:
        raise PlanError(f"no such table: {q.table}")
    return Plan(kind="delete", raw=q, table=q.table,
                where=_plan_where(q.where, _single_scope(cat, q.table), False))


def _plan_insert(q: Insert, cat: Catalog) -> Plan:
    if q.table not in cat.tables:
        raise PlanError(f"no such table: {q.table}")
    spec = cat.get(q.table)
    required = {c.name for c in spec.columns}
    given = set(q.columns)
    if given != required:
        raise PlanError(f"INSERT must list every column (table has {required}, got {given})")
    for cname, lit in zip(q.columns, q.values):
        _typed(check_literal, spec.column(cname), lit)
    return Plan(kind="insert", raw=q, table=q.table)




def _plan_select(q: Select, cat: Catalog) -> Plan:
    if q.table not in cat.tables:
        raise PlanError(f"no such table: {q.table}")

    # ── instances: the FROM table and every JOIN, keyed by alias ─────────────
    scope = _Scope()
    scope.add(q.name, cat.get(q.table))
    instances: dict[str, str] = {q.name: q.table}
    is_join = bool(q.joins)
    planned_joins: list[PJoin] = []
    for j in q.joins:
        if j.table not in cat.tables:
            raise PlanError(f"no such table: {j.table!r}")
        scope.add(j.name, cat.get(j.table))
        instances[j.name] = j.table

        li, lc = scope.resolve(j.on_left)
        ri, rc = scope.resolve(j.on_right)
        if li == j.name and ri != j.name:            # orient: new table right
            li, lc, ri, rc = ri, rc, li, lc
        if ri != j.name:
            raise PlanError(
                f"JOIN ON must reference the joined table {j.name!r}")
        if li == ri:
            raise PlanError(
                f"JOIN ON must relate two different tables (both sides are "
                f"{li!r})")
        for col in (lc, rc):
            if col.policy != "plain":
                raise PlanError(
                    f"JOIN ON column {col.name!r} must be PLAIN "
                    f"(is {col.policy})")
        if (lc.type == "str") != (rc.type == "str"):
            raise PlanError(
                f"JOIN ON compares incompatible types "
                f"({lc.name!r} is {lc.type}, {rc.name!r} is {rc.type})")
        planned_joins.append(PJoin(table=j.table, alias=j.name, left_alias=li,
                                   left_col=lc.name, right_col=rc.name,
                                   kind=j.kind))

    def qn(inst: str, col: str) -> str:
        """Name used in the plan: 'inst.col' in a join, bare otherwise."""
        return f"{inst}.{col}" if is_join else col

    def _rcol(ref: str):
        inst, col = scope.resolve(ref)
        return qn(inst, col.name), col

    projs: list[PProj] = []
    pairings = 0

    if q.star:
        for inst, tname in instances.items():
            for c in cat.get(tname).columns:
                projs.append(PColRef(name=qn(inst, c.name), policy=c.policy))
    else:
        for proj in q.projections:
            if isinstance(proj, ColRef):
                qname, col = _rcol(proj.name)
                projs.append(PColRef(name=qname, policy=col.policy))
            elif isinstance(proj, SumExpr):
                qname, col = _rcol(proj.column)
                if col.policy == "plain":
                    raise PlanError(f"SUM requires encrypted/paired column, got plain (column {col.name!r})")
                projs.append(PSum(column=qname, policy=col.policy))
            elif isinstance(proj, DotExpr):
                qname_a, a = _rcol(proj.left)
                qname_b, b = _rcol(proj.right)
                if a.policy != "paired":
                    raise PlanError(f"DOT requires `paired` policy on column {a.name!r} (need both G1 & G2 sides)")
                if b.policy != "paired":
                    raise PlanError(f"DOT requires `paired` policy on column {b.name!r}")
                # TorusSQL v0.1: DOT is INT-only. Rational inner products
                # collapse under GT aggregation — the denominator slot sums
                # to Σ(bᵢ·dᵢ) instead of a common denominator, so an N-row
                # rational DOT would decode to (Σ num)/(Σ den), which equals
                # Σ(aᵢ·bᵢ) only for N=1. Reject rather than return a wrong
                # value. (Spec §4.5; rational DOT is roadmap.)
                if a.type != "int" or b.type != "int":
                    bad = a.name if a.type != "int" else b.name
                    raise PlanError(
                        f"DOT requires INT columns in v0.1 (column {bad!r} is "
                        f"{(a if a.type != 'int' else b).type}); rational inner "
                        f"product collapses the denominator under GT "
                        f"aggregation. Use per-row `a * b` for rational "
                        f"products, or sum INT-typed columns.")
                pairings += 1
                projs.append(PDot(left=qname_a, right=qname_b))
            elif isinstance(proj, CtMulExpr):
                qname_a, a = _rcol(proj.left)
                qname_b, b = _rcol(proj.right)
                if a.policy != "paired" or b.policy != "paired":
                    raise PlanError(f"ciphertext × ciphertext ({a.name} * {b.name}) "
                                    f"requires both columns to be `paired`")
                pairings += 1
                projs.append(PCtMul(left=qname_a, right=qname_b))
            elif isinstance(proj, ScalarMulExpr):
                if abs(proj.scalar) > MAX_SCALAR:
                    raise PlanError(f"scalar {proj.scalar} is out of range (|k| ≤ 2^126)")
                qname, col = _rcol(proj.column)
                if col.policy == "plain":
                    raise PlanError(f"k*col requires encrypted/paired, got plain (column {col.name!r})")
                projs.append(PScalarMul(scalar=proj.scalar, column=qname,
                                        policy=col.policy))
            elif isinstance(proj, ScaledSumExpr):
                if abs(proj.scalar) > MAX_SCALAR:
                    raise PlanError(f"scalar {proj.scalar} is out of range (|k| ≤ 2^126)")
                qname, col = _rcol(proj.column)
                if col.policy == "plain":
                    raise PlanError(f"k*SUM(col) requires encrypted/paired, got plain (column {col.name!r})")
                projs.append(PScaledSum(scalar=proj.scalar, column=qname,
                                        policy=col.policy))
            elif isinstance(proj, CountStar):
                projs.append(PCountStar())
            elif isinstance(proj, AvgExpr):
                qname, col = _rcol(proj.column)
                if col.type == "str":
                    raise PlanError(f"AVG requires a numeric column "
                                    f"(column {col.name!r} is str)")
                projs.append(PAvg(column=qname, policy=col.policy))
            elif isinstance(proj, (MinExpr, MaxExpr)):
                qname, col = _rcol(proj.column)
                fn = "MIN" if isinstance(proj, MinExpr) else "MAX"
                if col.policy != "plain":
                    raise PlanError(
                        f"{fn} requires a plain column (ordering over "
                        f"ciphertext is unavailable); column {col.name!r} "
                        f"is {col.policy}")
                if col.type == "str":
                    raise PlanError(f"{fn} requires a numeric column "
                                    f"(column {col.name!r} is str)")
                projs.append(PMin(column=qname) if isinstance(proj, MinExpr)
                             else PMax(column=qname))
            else:
                raise PlanError(f"unsupported projection {proj}")

    where = _plan_where(q.where, scope, is_join)

    if q.star and q.group_by:
        raise PlanError("SELECT * cannot be combined with GROUP BY — list the grouped "
                        "columns and aggregates explicitly")
    agg_like = (not q.star and not q.group_by and any(
        isinstance(p, (PSum, PAvg, PMin, PMax, PCountStar, PDot, PScaledSum,
                       PScalarMul, PCtMul)) for p in projs))
    if agg_like and q.order_by is not None:
        raise PlanError("ORDER BY has no effect on an aggregate result — use GROUP BY "
                        "or select plain rows")
    if (not q.group_by and (q.limit is not None or q.offset is not None)
            and any(isinstance(p, (PScalarMul, PCtMul)) for p in projs)):
        raise PlanError("LIMIT/OFFSET do not apply to per-row encrypted expressions "
                        "(k*col, a*b), which are returned as one list")

    group_by: list[str] = []
    for gcol in q.group_by:
        inst, col = scope.resolve(gcol)
        if col.policy != "plain":
            raise PlanError(f"GROUP BY requires a plain column (column "
                            f"{col.name!r} is not plain)")
        group_by.append(qn(inst, col.name))
    if group_by:
        for p in projs:
            if isinstance(p, PColRef) and p.name not in group_by:
                raise PlanError(
                    f"column {p.name!r} must appear in GROUP BY or be used in "
                    f"an aggregate")

    order_by = None
    if q.order_by:
        inst, col = scope.resolve(q.order_by.column)
        if col.policy != "plain":
            raise PlanError(f"ORDER BY requires a plain column "
                            f"(column {col.name!r} is {col.policy})")
        order_by = POrderBy(column=qn(inst, col.name),
                            descending=q.order_by.descending)

    if order_by is not None and not any(
            isinstance(p, PColRef) and p.name == order_by.column for p in projs):
        if q.distinct:
            raise PlanError(
                "for SELECT DISTINCT, ORDER BY column must appear in the "
                "select list")
        if group_by and order_by.column not in group_by:
            raise PlanError(
                "ORDER BY column must appear in GROUP BY or the select list")

    if q.having and not group_by:
        raise PlanError("HAVING requires GROUP BY")
    having = (q.having.op, q.having.value) if q.having else None
    return Plan(kind="select", raw=q, table=q.table, projections=projs,
                star=q.star, where=where, order_by=order_by, limit=q.limit, offset=q.offset,
                out_aliases=list(q.aliases) if q.aliases else None,
                distinct=q.distinct,
                group_by=group_by or None,
                having=having, pairing_ops=pairings,
                joins=planned_joins or None,
                instances=instances if is_join else None)
