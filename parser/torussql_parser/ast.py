# SPDX-License-Identifier: Apache-2.0
"""TorusSQL abstract syntax tree.

Pure data — no engine, no crypto, no I/O. These nodes are the public AST a
driver inspects after parsing and before sending a query over the wire.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union


# ── DDL / DML statements ─────────────────────────────────────────────────────
@dataclass
class CreateTable:
    name: str
    columns: list[tuple[str, str, str]]   # (name, type, policy), normalized
    if_not_exists: bool = False


@dataclass
class DropTable:
    name: str
    if_exists: bool = False


@dataclass
class CreateIndex:
    table: str
    column: str


@dataclass
class DropIndex:
    table: str
    column: str


@dataclass
class Insert:
    table: str
    columns: list[str]
    values: list[Any]                     # int | str | None | ("frac", n, d)


@dataclass
class Update:
    table: str
    assignments: list[tuple[str, Any]]    # (column, literal)
    where: "Where | None" = None


@dataclass
class Delete:
    table: str
    where: "Where | None" = None


# ── SELECT projections ───────────────────────────────────────────────────────
@dataclass
class ColRef:
    name: str


@dataclass
class SumExpr:
    column: str


@dataclass
class DotExpr:
    left: str
    right: str


@dataclass
class ScalarMulExpr:
    """k * col — per-row scalar multiply (one scaled value per row)."""
    scalar: int
    column: str


@dataclass
class ScaledSumExpr:
    """k * SUM(col) — scale the encrypted aggregate."""
    scalar: int
    column: str


@dataclass
class CtMulExpr:
    """col1 * col2 — formal ciphertext × ciphertext multiplication."""
    left: str
    right: str


@dataclass
class CountStar:
    """COUNT(*) — plaintext count of the selected rows."""


@dataclass
class AvgExpr:
    column: str


@dataclass
class MinExpr:
    column: str


@dataclass
class MaxExpr:
    column: str


# ── v0.6 expression grammar ──────────────────────────────────────────────────
# A general arithmetic expression over columns, literals and aggregates.
# `ColRef` (above) is also the column leaf of an expression tree.
@dataclass
class Lit:
    """A numeric constant (an int, or a Fraction for `FRAC(n, d)` / folded
    constants)."""
    value: Any                            # int | fractions.Fraction


@dataclass
class Neg:
    """Unary minus."""
    operand: Any


@dataclass
class BinOp:
    """`left op right` with op in + - * /."""
    op: str
    left: Any
    right: Any


@dataclass
class AggCall:
    """An aggregate inside an expression: SUM(expr), AVG(expr) or COUNT(*)
    (``arg`` is None for COUNT(*))."""
    fn: str                               # "SUM" | "AVG" | "COUNT"
    arg: Any = None


@dataclass
class ExprProj:
    """A projection that is a general arithmetic expression (v0.6). The legacy
    shapes (`col`, `SUM(col)`, `k*col`, `k*SUM(col)`, `a*b`, ...) keep their
    own node types; ExprProj is produced only for what they cannot express."""
    expr: Any


Proj = Union[ColRef, SumExpr, DotExpr, ScalarMulExpr, ScaledSumExpr, CtMulExpr,
             CountStar, AvgExpr, MinExpr, MaxExpr, ExprProj]

# Comparison operators allowed in WHERE (plaintext columns only).
WHERE_OPS = ("=", "!=", "<>", "<", ">", "<=", ">=")


@dataclass
class Condition:
    """A comparison atom: `column op literal`."""
    column: str
    op: str
    value: Any


@dataclass
class InList:
    """An `column IN (lit, ...)` atom."""
    column: str
    values: list[Any]


Atom = Union[Condition, InList]


@dataclass
class Where:
    """Predicate in disjunctive normal form: an OR of AND-groups of atoms.
    Without parentheses, `AND` binds tighter than `OR`, so
    `a AND b OR c` parses to or_terms = [[a, b], [c]]."""
    or_terms: list[list] = field(default_factory=list)


@dataclass
class OrderBy:
    column: str
    descending: bool = False


@dataclass
class Having:
    """A HAVING predicate on COUNT(*) of each group: COUNT(*) op <int>."""
    op: str
    value: int


@dataclass
class Join:
    """JOIN clause: [INNER|LEFT [OUTER]] JOIN <table> [[AS] alias]
    ON <left_col> = <right_col>.
    Column refs may be qualified ('alias.col') or bare ('col')."""
    table: str
    on_left: str
    on_right: str
    alias: str | None = None
    kind: str = "inner"               # "inner" | "left"

    @property
    def name(self) -> str:
        """The instance name this join introduces (alias, else the table)."""
        return self.alias or self.table


@dataclass
class Select:
    table: str
    projections: list[Proj] = field(default_factory=list)
    star: bool = False
    where: Where | None = None
    order_by: OrderBy | None = None
    limit: int | None = None
    offset: int | None = None
    # Output-column aliases (from `AS`), aligned 1:1 with `projections`;
    # an entry is None when that projection has no alias. Empty for `*`.
    aliases: list = field(default_factory=list)
    distinct: bool = False
    group_by: list[str] = field(default_factory=list)   # plaintext columns
    having: Having | None = None
    joins: list["Join"] = field(default_factory=list)
    table_alias: str | None = None

    @property
    def name(self) -> str:
        """The instance name of the FROM table (alias, else the table)."""
        return self.table_alias or self.table


Query = Union[CreateTable, DropTable, CreateIndex, DropIndex, Insert, Update, Delete, Select]


# ── Normalized vocabularies (the dialect's closed sets) ──────────────────────
TYPES = ("int", "str", "rational")
POLICIES = ("plain", "encrypted", "paired", "fhe")

TYPE_KEYWORDS = {"INT": "int", "STR": "str", "RATIONAL": "rational"}
POLICY_KEYWORDS = {"PLAIN": "plain", "ENC": "encrypted", "PAIRED": "paired", "FHE": "fhe"}
