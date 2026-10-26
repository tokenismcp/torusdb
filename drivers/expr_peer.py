#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Python reference peer for the cross-implementation expression tests (TypeScript and Rust drivers).

usage: expr_peer.py HOST PORT JSON
  JSON = {"auth": bool, "tables": [{"name", "columns": [[n, type, policy]...], "rows": [["1", "3/4", null]...]}],
          "queries": [{"table", "expr", "where"?: {"col","op","val"}, "max_depth"?: int}]}

Connects to the SAME real server as the other driver with the Python engine (a separate owner with its own
masks, so it works on its own copy of the tables), runs every query through the expression path and prints
a JSON list: {"value": ..., "cost": {...}} or {"error": ClassName} per query. Integers and fractions are
strings "n" / "n/d"; NULL is null; a per-row expression is a list.
"""
import json
import sys
from fractions import Fraction

import torussql
from torussql_parser import parser as _pp
from torussql_parser.ast import ExprProj

_pp._classify = lambda e: ExprProj(expr=e)       # the expression path for every shape (as the other drivers)

from torusdb_core.errors import DepthLimitExceeded, DivisionByZero, IntegrityError, PlanError  # noqa: E402
from torusdb_core.protocol import OutOfBudget                                              # noqa: E402


def sval(v):
    if v is None:
        return None
    if isinstance(v, Fraction) and v.denominator != 1:
        return f"{v.numerator}/{v.denominator}"
    return str(int(v))


def lit(s):
    if s is None:
        return "NULL"
    if "/" in s:
        n, d = s.split("/")
        return f"FRAC({n},{d})"
    return s


def cls(exc):
    for c, n in ((DepthLimitExceeded, "DepthLimitExceeded"), (DivisionByZero, "DivisionByZero"),
                 (OutOfBudget, "OutOfBudget"), (IntegrityError, "IntegrityError"), (PlanError, "PlanError")):
        if isinstance(exc, c):
            return n
    return type(exc).__name__


def main():
    host, port, spec = sys.argv[1], int(sys.argv[2]), json.loads(sys.argv[3])
    conn = torussql.connect(host, port, authenticated=bool(spec.get("auth")), timeout=240.0)
    cli = conn.client
    if hasattr(cli, "expr_mode"):
        cli.expr_mode = "owner"                  # the owner-computed evaluation the drivers implement
    out = []
    try:
        for t in spec["tables"]:
            cols = ", ".join(f"{n} {ty.upper()} {'ENC' if p == 'encrypted' else p.upper()}" for n, ty, p in t["columns"])
            cli.execute(f"CREATE TABLE {t['name']} ({cols})")
            for row in t["rows"]:
                cli.execute(f"INSERT INTO {t['name']} ({', '.join(c[0] for c in t['columns'])}) "
                            f"VALUES ({', '.join(lit(v) for v in row)})")
        for q in spec["queries"]:
            where = ""
            w = q.get("where")
            if w:
                val = "(" + ", ".join(map(str, w["val"])) + ")" if w["op"] == "IN" else w["val"]
                where = f" WHERE {w['col']} {w['op']} {val}"
            cli.max_mult_depth = q.get("max_depth", 8)
            try:
                rs = cli.execute(f"SELECT {q['expr']} FROM {q['table']}{where}")
            except Exception as exc:                    # noqa: BLE001
                out.append({"error": cls(exc)})
                continue
            v = rs.rows[0][0]
            res = {"value": [sval(x) for x in v] if isinstance(v, list) else sval(v)}
            c = cli.last_expr_cost
            if c is not None:
                res["cost"] = {"depth": c["depth"], "mult_rounds": c["mult_rounds"], "products": c["products"],
                               "inversions": c["inversions"], "linear_sums": c["linear_sums"]}
            out.append(res)
    finally:
        conn.close()
    print(json.dumps(out))


main()
