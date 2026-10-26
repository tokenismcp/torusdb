# SPDX-License-Identifier: Apache-2.0
"""Static capability/policy/type validation for TorusSQL — engine-free.

This is the OPEN half of the dialect: the rules for *what is allowed*, with
no execution and no crypto. A driver runs this client-side to reject illegal
queries before they touch the engine, and the engine's planner
enforces the same rules server-side. The two MUST agree; this module is the
canonical statement of the rules (spec §2, §4).

Usage:
    schema = Schema()
    schema.apply(parse("CREATE TABLE t (id INT PLAIN, x INT PAIRED)"))
    schema.validate(parse("SELECT DOT(x, x) FROM t"))     # ok
    schema.validate(parse("SELECT DOT(id, x) FROM t"))    # ValidationError
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ast import (
    AvgExpr, BinOp, ColRef, CountStar, CreateTable, CtMulExpr, Delete, DotExpr, ExprProj,
    DropTable, CreateIndex, DropIndex, InList, Insert, Join, MaxExpr, MinExpr, Query, ScalarMulExpr,
    ScaledSumExpr, Select, SumExpr, Update,
)
from .expr import MAX_SCALAR, analyze_expr
from .predicate import LIKE_OPS, NULL_OPS
from .errors import ValidationError



def _describe(lit) -> str:
    if lit is None:
        return "NULL"
    if isinstance(lit, tuple):
        return f"fraction {lit[1]}/{lit[2]}"
    return "string" if isinstance(lit, str) else "integer"


def check_literal(col, lit) -> None:
    """Reject a literal that cannot be stored in ``col`` (duck-typed: any object
    with ``name``, ``type`` and ``policy``). NULL is allowed only in PLAIN
    columns; STR takes strings; INT takes integers (or an integral FRAC);
    RATIONAL takes integers and FRAC."""
    if lit is None:
        if col.policy != "plain":
            raise ValidationError(
                f"NULL is not allowed in {col.policy.upper()} column "
                f"{col.name!r} (encrypted cells always hold a value)")
        return
    if col.type == "str":
        if not isinstance(lit, str):
            raise ValidationError(
                f"column {col.name!r} is STR; cannot store {_describe(lit)}")
        return
    if isinstance(lit, str):
        raise ValidationError(
            f"column {col.name!r} is {col.type.upper()}; cannot store a string")
    if col.type == "int" and isinstance(lit, tuple) and lit[1] % lit[2] != 0:
        raise ValidationError(
            f"column {col.name!r} is INT; cannot store {_describe(lit)}")


def check_predicate_literal(col, atom_values) -> None:
    """A WHERE comparison must pit like with like (string vs STR, number vs
    numeric column)."""
    for v in atom_values:
        if (col.type == "str") != isinstance(v, str):
            raise ValidationError(
                f"WHERE: cannot compare {col.type.upper()} column "
                f"{col.name!r} with a {_describe(v)}")


@dataclass(frozen=True)
class Column:
    name: str
    type: str       # 'int' | 'str' | 'rational'
    policy: str     # 'plain' | 'encrypted' | 'paired'


@dataclass
class Table:
    name: str
    columns: list[Column]

    def column(self, name: str) -> Column:
        for c in self.columns:
            if c.name == name:
                return c
        raise ValidationError(f"no such column: {name!r} in table {self.name!r}")

    def has(self, name: str) -> bool:
        return any(c.name == name for c in self.columns)


@dataclass
class Schema:
    """Tracks declared tables and validates statements against them."""
    tables: dict[str, Table] = field(default_factory=dict)

    # ── mutate the schema ────────────────────────────────────────────────
    def apply(self, q: Query) -> None:
        """Apply a DDL statement (CREATE/DROP) to the schema, after
        validating it. DML is validated but does not change the schema."""
        self.validate(q)
        if isinstance(q, CreateTable) and q.name in self.tables:
            return                                      # IF NOT EXISTS on an existing table
        if isinstance(q, CreateTable):
            self.tables[q.name] = Table(
                name=q.name,
                columns=[Column(n, t, p) for (n, t, p) in q.columns])
        elif isinstance(q, DropTable):
            self.tables.pop(q.name, None)

    # ── validate without mutating ────────────────────────────────────────
    def validate(self, q: Query) -> None:
        if isinstance(q, CreateTable):
            self._validate_create(q)
        elif isinstance(q, DropTable):
            if not (q.if_exists and q.name not in self.tables):
                self._require_table(q.name)
        elif isinstance(q, (CreateIndex, DropIndex)):
            self._validate_index(q)
        elif isinstance(q, Insert):
            self._validate_insert(q)
        elif isinstance(q, Update):
            self._validate_update(q)
        elif isinstance(q, Delete):
            self._validate_delete(q)
        elif isinstance(q, Select):
            self._validate_select(q)
        else:
            raise ValidationError(f"unknown statement: {type(q).__name__}")

    # ── helpers ──────────────────────────────────────────────────────────
    def _require_table(self, name: str) -> Table:
        if name not in self.tables:
            raise ValidationError(f"no such table: {name}")
        return self.tables[name]

    def _validate_index(self, q) -> None:
        table = self._require_table(q.table)
        cols = {c.name: c for c in table.columns}
        if q.column not in cols:
            raise ValidationError(f"no such column: {q.column!r} in table {q.table!r}")
        if cols[q.column].policy != "plain":
            raise ValidationError(f"cannot index {q.column!r}: only PLAIN columns can be indexed")

    def _validate_create(self, q: CreateTable) -> None:
        if q.name.startswith("__"):
            raise ValidationError(
                f"table names starting with '__' are reserved ({q.name!r})")
        if q.name in self.tables and not q.if_not_exists:
            raise ValidationError(f"table {q.name!r} already exists")
        seen: set[str] = set()
        for (n, t, p) in q.columns:
            if n.startswith("__"):
                raise ValidationError(
                    f"column names starting with '__' are reserved (column {n!r})")
            if n in seen:
                raise ValidationError(f"duplicate column {n!r}")
            seen.add(n)
            if p == "fhe" and t != "int":
                raise ValidationError(f"FHE columns must be INT (column {n!r})")
            # string columns can't be encrypted in v0.1 (spec §2.2)
            if p != "plain" and t == "str":
                raise ValidationError(
                    f"STR columns must be PLAIN (column {n!r})")

    def _validate_insert(self, q: Insert) -> None:
        table = self._require_table(q.table)
        required = {c.name for c in table.columns}
        given = set(q.columns)
        if given != required:
            raise ValidationError(
                f"INSERT must list every column (table has {required}, "
                f"got {given})")
        if len(q.columns) != len(q.values):
            raise ValidationError("column/value count mismatch")
        for cname, lit in zip(q.columns, q.values):
            check_literal(table.column(cname), lit)

    def _validate_select(self, q: Select) -> None:
        # instances are introduced left to right so ON can only see the past
        scope = _Scope()
        scope.add(q.name, self._require_table(q.table))
        for j in q.joins:
            scope.add(j.name, self._require_table(j.table))
            self._validate_on(scope, j)

        if not q.star:
            for proj in q.projections:
                self._validate_proj(scope, proj)
        agg_like = (not q.star and not q.group_by and any(
            isinstance(p, (SumExpr, AvgExpr, MinExpr, MaxExpr, CountStar, DotExpr,
                           ScaledSumExpr, ScalarMulExpr, CtMulExpr, ExprProj))
            for p in q.projections))
        if agg_like and q.order_by is not None:
            raise ValidationError(
                "ORDER BY has no effect on an aggregate result — use GROUP BY or "
                "select plain rows")
        if (not q.star and not q.group_by and (q.limit is not None or q.offset is not None) and any(
                isinstance(p, (ScalarMulExpr, CtMulExpr))
                or (isinstance(p, ExprProj) and self._expr_info(scope, p).kind == "row")
                for p in q.projections)):
            raise ValidationError(
                "LIMIT/OFFSET do not apply to per-row encrypted expressions (k*col, a*b), "
                "which are returned as one list")

        self._validate_where(scope, q.where)

        group_keys: list[tuple[str, str]] = []
        for gcol in q.group_by:
            inst, col = scope.resolve(gcol, "GROUP BY")
            if col.policy != "plain":
                raise ValidationError(
                    f"GROUP BY requires a PLAIN column (column {col.name!r} is "
                    f"{col.policy}) — grouping on encrypted keys is not "
                    f"supported")
            group_keys.append((inst, col.name))
        if q.group_by:
            if q.star:
                raise ValidationError(
                    "SELECT * cannot be combined with GROUP BY — list the "
                    "grouped columns and aggregates explicitly")
            for proj in q.projections:
                if isinstance(proj, ColRef):
                    inst, col = scope.resolve(proj.name, "projection")
                    if (inst, col.name) not in group_keys:
                        raise ValidationError(
                            f"column {proj.name!r} must appear in GROUP BY or "
                            f"be used in an aggregate")
        if q.having is not None and not q.group_by:
            raise ValidationError("HAVING requires GROUP BY")

        if q.order_by is not None:
            inst, col = scope.resolve(q.order_by.column, "ORDER BY")
            if col.policy != "plain":
                raise ValidationError(
                    "ORDER BY requires a PLAIN column (column "
                    f"{col.name!r} is {col.policy})")
            projected = q.star or any(
                isinstance(p, ColRef)
                and scope.resolve(p.name, "projection")[0] == inst
                and scope.resolve(p.name, "projection")[1].name == col.name
                for p in q.projections)
            if not projected:
                if q.distinct:
                    raise ValidationError(
                        "for SELECT DISTINCT, ORDER BY column must appear in "
                        "the select list")
                if q.group_by and (inst, col.name) not in group_keys:
                    raise ValidationError(
                        "ORDER BY column must appear in GROUP BY or the "
                        "select list")

    def _expr_info(self, scope: "_Scope", proj: ExprProj):
        """Analyse a general expression projection (v0.6): (folded, ExprInfo)."""
        return analyze_expr(proj.expr, lambda ref: scope.resolve(ref, "expression"))[1]

    def _validate_on(self, scope: "_Scope", j: Join) -> None:
        li, lc = scope.resolve(j.on_left, "ON")
        ri, rc = scope.resolve(j.on_right, "ON")
        if j.name not in (li, ri):
            raise ValidationError(
                f"JOIN ON must reference the joined table {j.name!r}")
        if li == ri:
            raise ValidationError(
                f"JOIN ON must relate two different tables (both sides are "
                f"{li!r})")
        for (inst, col) in ((li, lc), (ri, rc)):
            if col.policy != "plain":
                raise ValidationError(
                    f"JOIN ON column {col.name!r} must be PLAIN "
                    f"(is {col.policy})")
        if (lc.type == "str") != (rc.type == "str"):
            raise ValidationError(
                f"JOIN ON compares incompatible types "
                f"({lc.name!r} is {lc.type}, {rc.name!r} is {rc.type})")

    def _validate_where(self, scope: "_Scope", where) -> None:
        if where is None:
            return
        for group in where.or_terms:
            for atom in group:
                _inst, col = scope.resolve(atom.column, "WHERE")
                if col.policy != "plain":
                    raise ValidationError(
                        "WHERE on encrypted columns is not supported; use a "
                        f"PLAIN column for predicates (column {col.name!r} is "
                        f"{col.policy})")
                if isinstance(atom, InList):
                    check_predicate_literal(col, atom.values)
                elif atom.op in NULL_OPS:
                    pass                                   # IS [NOT] NULL has no literal
                elif atom.op in LIKE_OPS:
                    if col.type != "str" or not isinstance(atom.value, str):
                        raise ValidationError(
                            f"LIKE needs a STR column and a string pattern "
                            f"(column {col.name!r} is {col.type.upper()})")
                else:
                    check_predicate_literal(col, [atom.value])

    def _validate_update(self, q: Update) -> None:
        table = self._require_table(q.table)
        for (col, val) in q.assignments:
            check_literal(table.column(col), val)        # exists + type fits
        scope = _Scope()
        scope.add(q.table, table)
        self._validate_where(scope, q.where)

    def _validate_delete(self, q: Delete) -> None:
        table = self._require_table(q.table)
        scope = _Scope()
        scope.add(q.table, table)
        self._validate_where(scope, q.where)

    def _validate_proj(self, scope: "_Scope", proj) -> None:
        if isinstance(proj, CountStar):
            return                              # COUNT(*) is always valid

        if isinstance(proj, ColRef):
            _i, col = scope.resolve(proj.name, "projection")
            _no_fhe_in_join(scope, col)

        elif isinstance(proj, SumExpr):
            _i, col = scope.resolve(proj.column, "SUM")
            if col.policy == "plain":
                raise ValidationError(
                    f"SUM requires an ENC/PAIRED/FHE column, got PLAIN "
                    f"(column {col.name!r})")
            _no_fhe_in_join(scope, col)

        elif isinstance(proj, AvgExpr):
            _i, col = scope.resolve(proj.column, "AVG")
            if col.type == "str":
                raise ValidationError(
                    f"AVG requires a numeric column (column {col.name!r} is str)")
            _no_fhe_in_join(scope, col)

        elif isinstance(proj, (MinExpr, MaxExpr)):
            fn = "MIN" if isinstance(proj, MinExpr) else "MAX"
            _i, col = scope.resolve(proj.column, fn)
            if col.policy != "plain":
                raise ValidationError(
                    f"{fn} requires a PLAIN column (ordering over ciphertext "
                    f"is not available); column {col.name!r} is {col.policy}")
            if col.type == "str":
                raise ValidationError(
                    f"{fn} requires a numeric column (column {col.name!r} is str)")

        elif isinstance(proj, (ScalarMulExpr, ScaledSumExpr)):
            if abs(proj.scalar) > MAX_SCALAR:
                raise ValidationError(
                    f"scalar {proj.scalar} is out of range (|k| ≤ 2^126): a larger "
                    f"multiplier could wrap around the modulus and return a wrong value")
            _i, col = scope.resolve(proj.column, "k * col")
            if col.policy == "plain":
                raise ValidationError(
                    f"k * col requires an ENC/PAIRED column, got PLAIN "
                    f"(column {col.name!r})")
            if col.policy == "fhe" and isinstance(proj, ScalarMulExpr):
                raise ValidationError(
                    f"k * col (per row) is not supported on FHE columns (column {col.name!r}); "
                    f"k * SUM(col) is")

        elif isinstance(proj, CtMulExpr):
            _i, a = scope.resolve(proj.left, "col * col")
            _j, b = scope.resolve(proj.right, "col * col")
            if "plain" in (a.policy, b.policy):
                # v0.6: a PLAIN factor makes it a public-scalar product (an expression)
                self._expr_info(scope, ExprProj(expr=BinOp(
                    op="*", left=ColRef(name=proj.left), right=ColRef(name=proj.right))))
            elif a.policy != "paired" or b.policy != "paired":
                raise ValidationError(
                    f"ciphertext × ciphertext ({a.name} * {b.name}) requires "
                    f"both columns to be PAIRED")

        elif isinstance(proj, DotExpr):
            _i, a = scope.resolve(proj.left, "DOT")
            _j, b = scope.resolve(proj.right, "DOT")
            if a.policy == "fhe" and b.policy == "fhe":
                _no_fhe_in_join(scope, a)
                return
            if a.policy == "fhe" or b.policy == "fhe":
                raise ValidationError(
                    "DOT cannot mix FHE and PAIRED columns — use two FHE columns "
                    "or two PAIRED columns")
            if a.policy != "paired" or b.policy != "paired":
                bad = a.name if a.policy != "paired" else b.name
                raise ValidationError(
                    f"DOT requires PAIRED or FHE columns (column {bad!r})")
            # v0.1: DOT is INT-only — rational inner products collapse the
            # denominator under aggregation (spec §4.5).
            if a.type != "int" or b.type != "int":
                bad = a.name if a.type != "int" else b.name
                raise ValidationError(
                    f"DOT requires INT columns in v0.1 (column {bad!r} is "
                    f"{(a if a.type != 'int' else b).type}); use per-row "
                    f"`a * b` for rational products")

        elif isinstance(proj, ExprProj):
            self._expr_info(scope, proj)

        else:
            raise ValidationError(f"unsupported projection: {proj}")


def _no_fhe_in_join(scope, col) -> None:
    if col.policy == "fhe" and len(scope.instances) > 1:
        raise ValidationError(
            f"FHE column {col.name!r} cannot be used in a join query yet")


class _Scope:
    """The table instances visible to a statement, keyed by instance name
    (the alias if given, else the table name). Two instances may be the same
    physical table (self-join) — they are distinguished by their alias."""

    def __init__(self) -> None:
        self.instances: dict[str, Table] = {}

    def add(self, name: str, table: Table) -> None:
        if name in self.instances:
            raise ValidationError(
                f"duplicate table name {name!r} in FROM/JOIN — give each "
                f"occurrence a distinct alias")
        self.instances[name] = table

    def resolve(self, ref: str, where: str) -> tuple[str, Column]:
        """'inst.col' or bare 'col' → (instance, Column). A bare name must be
        unambiguous across the instances in scope."""
        if "." in ref:
            inst, cname = ref.split(".", 1)
            if inst not in self.instances:
                raise ValidationError(f"{where}: unknown table {inst!r} in {ref!r}")
            return inst, self.instances[inst].column(cname)
        owners = [i for i, t in self.instances.items() if t.has(ref)]
        if len(owners) == 1:
            return owners[0], self.instances[owners[0]].column(ref)
        if len(owners) > 1:
            raise ValidationError(
                f"column {ref!r} is ambiguous — qualify as table.col")
        if len(self.instances) == 1:
            # single-table: keep the classic "no such column … in table" text
            only = next(iter(self.instances.values()))
            only.column(ref)                     # raises ValidationError
        raise ValidationError(f"no such column: {ref!r}")


def validate_script(statements: list[Query]) -> None:
    """Validate a sequence of statements as one session (CREATEs first build
    the schema). Raises on the first offending statement."""
    schema = Schema()
    for q in statements:
        schema.apply(q)
