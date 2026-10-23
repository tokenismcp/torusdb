# SPDX-License-Identifier: Apache-2.0
"""Engine parser — a thin adapter over the open `torussql-parser`.

The TorusSQL grammar and AST live in ONE place: the open, engine-free
`torussql_parser` package (torussql/parser/). This module re-exports that AST
so the planner/executor keep importing AST nodes from `.parser`, and wraps
`parse` so parse failures surface as the engine's own `ParseError`
(`torusdb_core.errors.ParseError`) for stable exception handling.

Validation (policy/type rules) is NOT here — it stays in planner.py
(server-side enforcement). The open package's validator mirrors those rules
client-side; the conformance suite checks the two agree.
"""
from __future__ import annotations

from torussql_parser.ast import (                       # noqa: F401  (re-export)
    ColRef, CreateTable, CtMulExpr, Delete, DotExpr, DropTable, Insert, Join,
    Query, ScalarMulExpr, Select, SumExpr, Update, Where,
)
from torussql_parser.errors import ParseError as _OpenParseError
from torussql_parser.parser import parse as _open_parse

from .errors import ParseError


def parse(sql: str) -> Query:
    try:
        return _open_parse(sql)
    except _OpenParseError as exc:
        raise ParseError(str(exc)) from exc
