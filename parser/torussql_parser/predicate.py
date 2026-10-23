# SPDX-License-Identifier: Apache-2.0
"""Single definition of WHERE-atom semantics, shared by the validator, the engine
and the wire layer so they can never disagree.

Operators: ``= != <> < > <= >=``, ``is_null``, ``not_null``, ``like``,
``not_like``. A NULL operand makes every comparison false (SQL three-valued logic
folded to false); ``is_null`` / ``not_null`` are the only atoms that match NULL.
``LIKE`` supports ``%`` (any run) and ``_`` (any one character), case-sensitive.
"""
from __future__ import annotations

import re
from functools import lru_cache

from .ast import WHERE_OPS

NULL_OPS = ("is_null", "not_null")
LIKE_OPS = ("like", "not_like")
PRED_OPS = WHERE_OPS + NULL_OPS + LIKE_OPS


@lru_cache(maxsize=256)
def _like_regex(pattern: str):
    out = []
    for ch in pattern:
        out.append(".*" if ch == "%" else "." if ch == "_" else re.escape(ch))
    return re.compile("".join(out), re.DOTALL)


def like(value: str, pattern: str) -> bool:
    return _like_regex(pattern).fullmatch(value) is not None


def compare(a, op: str, b) -> bool:
    """Evaluate one atom. Raises TypeError for incomparable operands and
    ValueError for an unknown operator."""
    if op == "is_null":
        return a is None
    if op == "not_null":
        return a is not None
    if a is None or b is None:
        return False
    if op == "like":
        return isinstance(a, str) and like(a, b)
    if op == "not_like":
        return isinstance(a, str) and not like(a, b)
    if op == "=":
        return a == b
    if op in ("!=", "<>"):
        return a != b
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == ">=":
        return a >= b
    raise ValueError(f"unsupported operator {op!r}")
