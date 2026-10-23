# SPDX-License-Identifier: Apache-2.0
"""torussql-parser — the open TorusSQL dialect parser and static validator.

Engine-free and dependency-free. Parses TorusSQL text into an AST and
statically validates capability/policy/type rules (spec §2, §4), so a client
can reject illegal queries before they reach the closed TorusDB engine.

    from torussql_parser import parse, Schema

    schema = Schema()
    schema.apply(parse("CREATE TABLE t (id INT PLAIN, x INT PAIRED)"))
    schema.validate(parse("SELECT DOT(x, x) FROM t"))
"""
from __future__ import annotations

from .ast import (
    AvgExpr, ColRef, Condition, CountStar, CreateIndex, CreateTable, CtMulExpr, Delete,
    DotExpr, DropIndex, DropTable, Having, InList, Insert, MaxExpr, MinExpr, OrderBy,
    Query, ScalarMulExpr, ScaledSumExpr, Select, SumExpr, Update, Where,
    POLICIES, TYPES, WHERE_OPS,
)
from .errors import ParseError, TorusSQLError, ValidationError
from .parser import parse
from .validate import Column, Schema, Table, validate_script

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "parse",
    "Schema", "Table", "Column", "validate_script",
    "ParseError", "ValidationError", "TorusSQLError",
    "CreateTable", "DropTable", "CreateIndex", "DropIndex", "Insert", "Update", "Delete", "Select",
    "Having", "Query",
    "ColRef", "SumExpr", "DotExpr", "ScalarMulExpr", "ScaledSumExpr",
    "CtMulExpr", "CountStar", "AvgExpr", "MinExpr", "MaxExpr",
    "Where", "Condition", "InList", "OrderBy",
    "TYPES", "POLICIES", "WHERE_OPS",
]
