# SPDX-License-Identifier: Apache-2.0
"""Wire codec for the no-key delegation RPC.

The no-key server exposes its (key-free) operations as RPCs; the driver holds
the mask vault and drives the protocol. Every value that crosses the wire is
either a public plaintext cell, a one-time-padded scalar, or a Beaver opening
— never a key, never an unblinded encrypted value.

Big integers (blinded scalars, openings) travel as decimal strings so the
encoding is exact and language-portable. One newline-delimited JSON object
per message: request {"m": method, "a": [...]}, response {"ok": ...} | {"err": ...}.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Any


# ── plaintext / scalar values ────────────────────────────────────────────────
def wv(v: Any) -> dict:
    """python value → wire form (JSON-safe, big-int-exact)."""
    if v is None:
        return {"t": "n"}
    if isinstance(v, bool):
        return {"t": "b", "v": v}
    if isinstance(v, int):
        return {"t": "i", "v": str(v)}
    if isinstance(v, str):
        return {"t": "s", "v": v}
    if isinstance(v, Fraction):
        return {"t": "f", "n": str(v.numerator), "d": str(v.denominator)}
    raise TypeError(f"cannot wire-encode {type(v).__name__}")


def uwv(d: dict) -> Any:
    """wire form → python value. Strict: a malformed or non-scalar value is a
    ValueError (never stored, never reaches the snapshot)."""
    if not isinstance(d, dict) or "t" not in d:
        raise ValueError("malformed wire value")
    t = d["t"]
    if t == "n":
        return None
    if t == "b":
        if not isinstance(d.get("v"), bool):
            raise ValueError("boolean wire value must be true/false")
        return d["v"]
    if t == "i":
        v = d.get("v")
        if not isinstance(v, (str, int)) or isinstance(v, bool):
            raise ValueError("integer wire value must be a decimal string")
        return int(v)
    if t == "s":
        if not isinstance(d.get("v"), str):
            raise ValueError("string wire value must be a string")
        return d["v"]
    if t == "f":
        if not all(isinstance(d.get(k), (str, int)) and not isinstance(d.get(k), bool)
                   for k in ("n", "d")):
            raise ValueError("fraction wire value needs decimal n and d")
        den = int(d["d"])
        if den == 0:
            raise ValueError("fraction denominator must be non-zero")
        return Fraction(int(d["n"]), den)
    raise ValueError(f"unknown wire value tag {t!r}")


# ── WHERE predicate (plaintext, DNF) — server-evaluable form ──────────────────
def where_to_wire(pwhere) -> dict | None:
    """Serialize a planner PWhere (DNF of PCondition / PInList atoms)."""
    if pwhere is None:
        return None
    groups = []
    for grp in pwhere.or_terms:
        atoms = []
        for a in grp:
            if hasattr(a, "values"):                 # PInList
                atoms.append({"c": a.column,
                              "in": [wv(x) for x in a.values]})
            else:                                    # PCondition
                atoms.append({"c": a.column, "op": a.op, "v": wv(a.value)})
        groups.append(atoms)
    return {"or": groups}


def _cmp(a, op: str, b) -> bool:
    """SQL comparison: a NULL operand makes the atom false (never an error)."""
    from torussql_parser.predicate import compare
    try:
        return compare(a, op, b)
    except TypeError:
        raise ValueError(f"cannot compare {type(a).__name__} with {type(b).__name__}") from None


def match_wire(row: dict, pred: dict | None) -> bool:
    """Evaluate a wire predicate against a stored row's PLAINTEXT columns."""
    if pred is None:
        return True
    for group in pred["or"]:
        if all(_atom(row, a) for a in group):
            return True
    return False


def _atom(row: dict, a: dict) -> bool:
    val = row.get(a["c"])
    if "in" in a:
        return val is not None and val in [uwv(x) for x in a["in"]]
    return _cmp(val, a["op"], uwv(a["v"]))
