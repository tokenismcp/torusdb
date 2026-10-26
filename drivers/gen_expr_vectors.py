#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate drivers/expr_vectors.json: cross-language vectors for TorusSQL dialect v0.6 expressions.

The Python parser/engine is the reference. For every expression text this records

  * `static`  : what parsing + the shared policy analysis (`torussql_parser.analyze_expr`, the code
                both the open validator and the engine planner call) say: the folded canonical text,
                kind, depth, ciphertext products, inversions - or the error class and message;
  * `exec`    : the exact result the real engine returns over fixed datasets (ints and fractions as
                strings "n" / "n/d", NULL as null, a per-row expression as a list), the cost the owner
                spent (rounds == depth) - or the error class.

The TypeScript and Rust drivers re-run every case and must agree exactly (drivers/typescript/test/
expr.test.ts, drivers/rust/tests/expr.rs). Re-generate with:

    PYTHONPATH=core:parser python drivers/gen_expr_vectors.py > drivers/expr_vectors.json

The engine is driven through the *expression path* for every shape: `_classify` is patched to return an
ExprProj, so a legacy-shaped projection such as `a*b` or `3*SUM(a)` is evaluated as the general
expression it also is (the drivers have no separate legacy forms). MIN / MAX / DOT are whole
projections, not expressions, and are not part of the vectors.
"""
from __future__ import annotations

import json
import random
import sys
from fractions import Fraction

from torussql_parser import parser as _pp
from torussql_parser.ast import ExprProj
from torussql_parser.errors import ParseError as OpenParseError
from torussql_parser.errors import ValidationError
from torussql_parser.expr import analyze_expr, render

_pp._classify = lambda e: ExprProj(expr=e)          # the expression path for every shape

from torusdb_core.errors import DepthLimitExceeded, DivisionByZero, ExecError, IntegrityError, PlanError  # noqa: E402
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer  # noqa: E402
from torusdb_core.planner import _Scope                          # noqa: E402
from torusdb_core.catalog import ColumnSpec, TableSpec          # noqa: E402
from torusdb_core.protocol import OutOfBudget                    # noqa: E402

F = Fraction


def sval(v):
    if v is None:
        return None
    if isinstance(v, Fraction) and v.denominator != 1:
        return f"{v.numerator}/{v.denominator}"
    return str(int(v))


def cls(exc) -> str:
    for c, n in ((DepthLimitExceeded, "DepthLimitExceeded"), (DivisionByZero, "DivisionByZero"),
                 (OutOfBudget, "OutOfBudget"), (IntegrityError, "IntegrityError"),
                 (PlanError, "PlanError"), (ValidationError, "PlanError"), (OpenParseError, "ParseError")):
        if isinstance(exc, c):
            return n
    if type(exc).__name__ == "ParseError":
        return "ParseError"
    return type(exc).__name__


# ── static analysis ─────────────────────────────────────────────────────────
SCOPES = {
    # single table t
    "t": [["t", [["id", "int", "plain"], ["name", "str", "plain"], ["e", "rational", "encrypted"],
                 ["p", "int", "paired"], ["q", "int", "paired"], ["f", "int", "fhe"],
                 ["w", "rational", "plain"]]]],
    # a join: emp e, dept d (and e2: the same table again)
    "j": [["e", [["eid", "int", "plain"], ["did", "int", "plain"], ["sal", "int", "paired"],
                 ["bon", "rational", "encrypted"]]],
          ["d", [["did", "int", "plain"], ["fx", "rational", "paired"], ["m", "int", "paired"]]]],
}

STATIC_T = [
    # precedence, associativity, unary minus, literals
    "p+q*p", "p-q-p", "p/q/p", "p*q/p", "(p+q)*p", "p*q*p", "-p", "-(p+q)", "p * -q", "p - -1", "p*-2",
    "-(-p)", "- 3 * p + q", "p-1", "p -1", "p - 1", "p-1*q", "q*p-2", "(p)-1", "p-2*q",
    "p / FRAC(2, 3)", "p + FRAC(4, 2)", "p + FRAC(1, 0)", "FRAC(-1,3)*p", "p*FRAC(3,-6)", "frac(1,2)*p",
    "SUM(p*q)/COUNT(*)", "AVG(p+1)*2", "sum(p)", "Sum(p*q)", "COUNT(*)*2", "count( * )", "SUM(p)*SUM(q)",
    "SUM(p*q*p)/COUNT(*)", "SUM(e+p*2)/COUNT(*)", "AVG(p/q)", "SUM(p)/SUM(q)+1", "AVG(id*2)",
    # comments and whitespace
    "p /* c */ * q", "p -- x\n * q", "p--1", "p - -1", "p\t*\nq", "p/*", "p /* unterminated",
    # valid shapes
    "p*q*p", "p*q+e", "e/2+e", "p/q", "p*id", "e*id*id", "100/p", "-p*q", "p*q+0", "2*p*q*3", "p*w",
    "p/id", "s", "(p*q)*(p*q)", "p*q*p*q", "p/4", "p / (1/3 + FRAC(1,6))", "p/(2-2+1)",
    "id*2+p", "p+SUM(p)*0", "t.p*t.q", "t.p+q",
    # policy errors
    "e*p", "e*p*q", "(e+p)*q", "p/e", "e/e", "5/e", "p/0", "p/(3-3)", "p/(FRAC(1,2)-FRAC(1,2))",
    "id*2+id", "id/id", "SUM(id*2)", "SUM(5)", "1+2", "p+SUM(q)", "name*2+p", "f*2+p", "SUM(f)/COUNT(*)",
    "f", "f+1", "p*q*f", "SUM(f*f)", f"p/{2**127}", f"p*{2**127}+p", f"p+{2**126}", f"p+{2**126 + 1}",
    f"p*FRAC(1,{2**127})", "nope*p*q", "x.p+q", "t.nope+p", "SUM(COUNT(*))", "COUNT(*)+p", "p+COUNT(*)",
    "SUM(p)+p", "AVG(5)", "SUM(SUM(p))", "SUM(p+COUNT(*))", "name", "name+p", "id", "id+id", "w+w",
    "w*p", "w/p",
    # parse errors
    "p+", "(p", "p q", "p+*q", "sqrt(p)", "MIN(p)+1", "1+DOT(p,q)", "DOT(p,q)*2", "MAX(p)",
    "COUNT(p)", "SUM()", "p/", "", "   ", ")", "p)", "p;", ";", "'a'", "p+'a'", "p % q", "p ^ q",
    "p == q", "p != q", "p ? q", "[p]", "p,q", "FROM", "p FROM", "SELECT", "p AS x", "NULL", "p+NULL",
    "FRAC(1)", "FRAC(1,2,3)", "FRAC(p,2)", "FRAC(1.5,2)", "1.5*p", "p*1e3", "0x10*p", "p.q.r", "t.", ".p",
    "p¹", "p * q", "p﻿*q", "p\u001c*q", "p \u0085* q",
    "9" * 4301 + "+p", "9" * 40 + "*p",
]
# the edges of the tree-height limit (100): 99 / 100 / 101 levels of every kind of nesting
for _k in (99, 100, 101):
    STATIC_T += ["p" + "+q" * _k, "p" + "*q" * _k, "(" * _k + "p+q" + ")" * _k, "- " * _k + "p", "-" * _k + "p",
                 "SUM(" + "p+" * _k + "q)", "p" + "/q" * _k, "(" * _k + "p" + ")" * _k + "+q"]

STATIC_J = [
    "e.sal*d.m", "sal*m", "sal*d.m*fx", "e.sal*d.fx/d.m", "did*sal", "e.did*sal", "d.did+sal", "e.nope+sal",
    "x.sal+m", "e.sal*e.bon", "bon*sal", "bon+sal*m", "SUM(e.sal*d.m*d.fx)", "SUM(sal*m)/COUNT(*)",
    "SUM(bon)/SUM(m)", "sal/m", "bon/m", "m/bon", "eid*did", "e.eid+e.sal", "sal+m",
]


def column_specs(scope):
    return {alias: TableSpec(name=alias, columns=tuple(ColumnSpec(n, t, p) for n, t, p in cols))
            for alias, cols in scope}


def parse_expr_only(text: str):
    toks = _pp._tokenise(text)
    p = _pp._P(toks)
    e, _h = _pp._parse_expr(p)
    if not p.eof():
        raise OpenParseError(f"unexpected token after the expression: {p.peek()}")
    return e


def static_case(scope_name, text):
    scope = _Scope()
    for alias, spec in column_specs(SCOPES[scope_name]).items():
        scope.add(alias, spec)
    out = {"scope": scope_name, "expr": text}
    # MIN / MAX / DOT heads are whole projections in SQL; the drivers' expression entry points reject them
    head = text.lstrip()[:4].upper()
    if head[:3] in ("MIN", "MAX", "DOT") and text.lstrip()[3:].lstrip().startswith("("):
        out["error"] = "ParseError"
        out["message"] = "whole projection"
        return out
    try:
        tree = parse_expr_only(text)
    except Exception as exc:                                     # noqa: BLE001
        if type(exc).__name__ not in ("ParseError",):
            raise
        out["error"] = "ParseError"
        out["message"] = str(exc)
        return out
    try:
        folded, info = analyze_expr(tree, scope.resolve)
    except (ValidationError, PlanError) as exc:
        out["error"] = "PlanError"
        out["message"] = str(exc)
        return out
    out.update(ok=True, text=render(folded), kind=info.kind, enc=info.enc, depth=info.depth,
               ct_muls=info.ct_muls, inversions=info.inversions)
    return out


# ── execution datasets ──────────────────────────────────────────────────────
T_SCHEMA = [["id", "int", "plain"], ["dept", "int", "plain"], ["q", "int", "plain"], ["a", "int", "paired"],
            ["b", "int", "paired"], ["c", "int", "paired"], ["d", "int", "paired"], ["r", "rational", "paired"],
            ["s", "rational", "encrypted"], ["e", "int", "paired"]]
T_ROWS = [
    (1, 5, 5, 2, 3, 4, 5, F(1, 2), 10, 7),
    (2, 5, 2, -5, 7, 2, -1, F(-3, 4), -3, -2),
    (3, 9, 1, 6, -4, 3, 8, F(2, 3), F(7, 3), 9),
    (4, 9, -3, 0, 11, -6, 2, F(5), 0, 1),
    (5, 9, 4, 13, -2, 5, -7, F(-1, 7), F(1, 2), -8),
]
N_SCHEMA = [["id", "int", "plain"], ["w", "int", "plain"], ["a", "int", "paired"], ["b", "int", "paired"]]
N_ROWS = [(1, 2, 3, 4), (2, None, 5, 6), (3, 3, 7, 8)]
BIG_SCHEMA = [["id", "int", "plain"], ["a", "int", "paired"], ["b", "int", "paired"], ["c", "int", "paired"]]
BIG_ROWS = [(1, 2 ** 60, 2 ** 60, 3), (2, 2 ** 100 + 3, 2 ** 100 + 7, 5)]
EMP_SCHEMA = [["eid", "int", "plain"], ["did", "int", "plain"], ["sal", "int", "paired"]]
EMP_ROWS = [(1, 10, 100), (2, 10, 200), (3, 20, 300), (4, 30, 400)]
DEPT_SCHEMA = [["did", "int", "plain"], ["bonus", "int", "paired"], ["fx", "rational", "paired"]]
DEPT_ROWS = [(10, 3, F(1, 2)), (20, 5, F(2, 3))]
EMPTY_SCHEMA = [["id", "int", "plain"], ["a", "int", "paired"], ["b", "int", "paired"]]

TABLES = [("t", T_SCHEMA, T_ROWS), ("n", N_SCHEMA, N_ROWS), ("big", BIG_SCHEMA, BIG_ROWS),
          ("emp", EMP_SCHEMA, EMP_ROWS), ("dept", DEPT_SCHEMA, DEPT_ROWS), ("em", EMPTY_SCHEMA, [])]


def lit(v):
    if v is None:
        return "NULL"
    if isinstance(v, Fraction) and v.denominator != 1:
        return f"FRAC({v.numerator},{v.denominator})"
    return str(int(v))


def make_client(auth=False):
    cli = NoKeyClient(NoKeyServer(), authenticated=auth)
    if hasattr(cli, "expr_mode"):
        cli.expr_mode = "owner"          # the owner-computed evaluation the TypeScript / Rust drivers implement
    for name, schema, rows in TABLES:
        cols = ", ".join(f"{n} {t.upper()} {'ENC' if p == 'encrypted' else p.upper()}" for n, t, p in schema)
        cli.execute(f"CREATE TABLE {name} ({cols})")
        for row in rows:
            cli.execute(f"INSERT INTO {name} ({', '.join(c[0] for c in schema)}) VALUES "
                        f"({', '.join(lit(v) for v in row)})")
    return cli


def run_query(cli, case):
    """-> result dict for one exec case"""
    where = ""
    w = case.get("where")
    if w:
        val = "(" + ", ".join(map(str, w["val"])) + ")" if w["op"] == "IN" else w["val"]
        where = f" WHERE {w['col']} {w['op']} {val}"
    if "join" in case:
        j = case["join"]
        frm = f"{j['left'][0]} {j['left'][1]}"
        for st in j["steps"]:
            kw = "LEFT JOIN" if st["kind"] == "left" else "JOIN"
            frm += f" {kw} {st['table']} {st['alias']} ON {st['left_alias']}.{st['left_col']} = {st['alias']}.{st['right_col']}"
    else:
        frm = case["table"]
    sql = f"SELECT {case['expr']} FROM {frm}{where}"
    cli.max_mult_depth = case.get("max_depth", 8)
    try:
        rs = cli.execute(sql)
    except Exception as exc:                                    # noqa: BLE001
        return {"error": cls(exc), "message": str(exc)}
    v = rs.rows[0][0]
    cost = cli.last_expr_cost
    res = {"value": [sval(x) for x in v] if isinstance(v, list) else sval(v)}
    if cost is not None:
        res["cost"] = {"depth": cost["depth"], "mult_rounds": cost["mult_rounds"], "products": cost["products"],
                       "inversions": cost["inversions"], "linear_sums": cost["linear_sums"]}
    return res


T_EXPRS = [
    "a*b+0", "a*b*c", "a*b*c*d", "a*b*c*d*a", "(a*b)*(c*d)", "r*r*r", "a*b+c", "c+a*b", "a*b-c*d",
    "(a+b)*(c-d)", "(a+b)*(c-d)*a", "-(a*b)*c+7", "2*a*b*3", "a*q", "a*b*q", "s+s*2", "a*b+s",
    "(a*b+c)*(c-d)*r", "a*b + c*d + a*d", "a*b", "a*e", "s*e", "3*a", "-3*a", "12*s", "a", "s", "-a",
    "SUM(a*b)", "SUM(a*b*c)", "SUM(a*b*c*d)", "SUM(a*b-c)", "SUM(r*r)", "SUM(a+b)", "SUM(2*a-b+3)",
    "SUM(s/4)", "SUM(a)/COUNT(*)", "SUM(a*b)/COUNT(*)", "AVG(a*b)", "AVG(a+b)", "SUM(a)*SUM(b)",
    "SUM(a*b)/SUM(c)", "SUM(a*b)*2+COUNT(*)", "SUM(e)/SUM(a*b)", "SUM(a)", "AVG(a)", "COUNT(*)",
    "3*SUM(a)", "SUM(s)", "SUM(a+b-s/2)", "AVG(s*2+e)", "SUM(a*q)", "SUM(a+q)", "AVG(q*2)", "AVG(q)",
    "SUM(a*b*q)", "SUM(s*2+e)", "SUM(s)/4", "AVG(a*b)/AVG(c)",
    "s/2", "s/7", "a/3", "a/-3", "a/(1+1)", "a/FRAC(2,3)", "r/FRAC(1,5)", "(a+b)/4-c/8", "a/q", "a/b",
    "a/c/d", "d/e", "r/r", "a*b/c", "(a*b)/(c*d)", "100/c", "a/(b+c*d)", "(a+1)/(a+1)", "a/b*b", "a/b+c/d",
    "-a/b", "r/b", "(-a)/(-b)", "e/e",
    "a/0", "a/(2-2)", "a/(3*FRAC(0,4))", "1/0+a", "s*a*b", "(s+a)*b", "a/s", "s/s", "id*2", "q/id", "a+SUM(a)",
    "SUM(id*2)", "SUM(2)", "1+2", "a*name", f"a/{2 ** 127}", f"a*{2 ** 127}", f"a+{2 ** 126}",
    "1/(a-a)", "a/(a-a)", "a/(b-b)", "SUM(a)/(SUM(a)-SUM(a))", "SUM(a/(b-b))", "SUM(a)/COUNT(*)+COUNT(*)",
    "a*b*c*a*b*c*d*a*b", "a*a*a*a*a*a*a*a*a", "a*a*a*a*a*a*a*a*a*a",
]
RANDOM_N = 250


def gen_tree(rng, depth, leaves):
    if depth == 0 or rng.random() < 0.25:
        if rng.random() < 0.7:
            return ("col", rng.choice(leaves))
        return ("lit", rng.choice([F(2), F(3), F(-4), F(7), F(1), F(1, 3), F(-5, 2)]))
    if rng.random() < 0.1:
        return ("neg", gen_tree(rng, depth - 1, leaves))
    return (rng.choice("+-*/"), gen_tree(rng, depth - 1, leaves), gen_tree(rng, depth - 1, leaves))


def tree_sql(t):
    if t[0] == "col":
        return t[1]
    if t[0] == "lit":
        v = t[1]
        if v.denominator != 1:
            return f"FRAC({v.numerator},{v.denominator})"
        return f"({v.numerator})" if v < 0 else str(v.numerator)
    if t[0] == "neg":
        return f"(-{tree_sql(t[1])})"
    return f"({tree_sql(t[1])}{t[0]}{tree_sql(t[2])})"


def main():
    out = {"comment": "generated by drivers/gen_expr_vectors.py from the Python reference (dialect v0.6); do not edit",
           "scopes": SCOPES, "static": [], "exec": {"tables": [], "cases": []}}
    for x in STATIC_T:
        out["static"].append(static_case("t", x))
    for x in STATIC_J:
        out["static"].append(static_case("j", x))
    rng = random.Random(20260626)
    for _ in range(300):
        tr = gen_tree(rng, rng.randint(1, 5), ["p", "q", "e", "id", "w", "p", "q"])
        if tr[0] in ("col", "lit"):
            continue
        out["static"].append(static_case("t", tree_sql(tr)))

    for name, schema, rows in TABLES:
        out["exec"]["tables"].append({
            "name": name, "columns": schema,
            "rows": [[sval(v) for v in row] for row in rows]})

    cases = []
    for x in T_EXPRS:
        cases.append({"table": "t", "expr": x})
    for x in ["a*b", "SUM(a*b)", "a/b", "SUM(a*b)/COUNT(*)", "SUM(a)/COUNT(*)", "a*b*c", "SUM(a+b)", "AVG(a*b)",
              "SUM(a)/SUM(c)", "1/(a*b-c*d)"]:
        for where in ({"col": "dept", "op": "=", "val": 9}, {"col": "id", "op": "<>", "val": 2},
                      {"col": "id", "op": ">", "val": 100}, {"col": "id", "op": "IN", "val": [1, 2, 4]}):
            cases.append({"table": "t", "expr": x, "where": where})
    for x in ["a*b*c", "a*b*c*d", "a*b+0", "s/2+a*3", "a*a*a*a", "a*b+c*d"]:
        for md in (0, 1, 2, 3):
            cases.append({"table": "t", "expr": x, "max_depth": md})
    for x in ["a*b*w", "SUM(a*b*w)", "AVG(a*b*w)", "a*b", "SUM(a+b)", "w*a", "SUM(a*w)", "a/w", "SUM(a/w)"]:
        cases.append({"table": "n", "expr": x})
    for x in ["a*b", "a*b*c", "a*b*a/b", "a*b/(a*b)", "a*b-a*b+c", "a/b", "b/b", "a*b+0", "SUM(a*b*c*a)",
              "a*b*c", "a*b*a*b", "a*b*a/(a*b)"]:
        cases.append({"table": "big", "expr": x})
    for x in ["a*b", "SUM(a*b)", "SUM(a)", "AVG(a)", "SUM(a)/COUNT(*)", "COUNT(*)", "a/b", "SUM(a/b)", "AVG(a*b)+1",
              "SUM(a+b)", "AVG(a+b)"]:
        cases.append({"table": "em", "expr": x})
    inner = {"left": ["emp", "e"], "steps": [{"table": "dept", "alias": "d", "left_alias": "e", "left_col": "did",
                                              "right_col": "did", "kind": "inner"}]}
    left = {"left": ["emp", "e"], "steps": [{"table": "dept", "alias": "d", "left_alias": "e", "left_col": "did",
                                             "right_col": "did", "kind": "left"}]}
    for jn in (inner, left):
        for x in ["SUM(e.sal*d.bonus*d.fx)", "SUM(e.sal*d.bonus)/COUNT(*)", "e.sal*d.bonus*d.fx", "SUM(e.sal*d.bonus), COUNT(*)",
                  "SUM(e.sal+d.bonus)", "e.sal*d.bonus", "AVG(e.sal*d.bonus)", "SUM(sal*bonus)", "e.sal/d.bonus",
                  "SUM(e.sal)", "e.sal+d.bonus", "did*sal", "e.did*sal", "d.fx/e.sal", "SUM(e.sal/d.bonus)"]:
            if "," in x:
                continue                                        # one expression per call
            cases.append({"join": jn, "expr": x})
    # random differential cases
    rng = random.Random(20260627)
    leaves = ["a", "b", "c", "d", "r", "q"]
    n0 = len(cases)
    while len(cases) - n0 < RANDOM_N:
        tr = gen_tree(rng, rng.randint(1, 4), leaves)
        if tr[0] in ("col", "lit"):
            continue
        cases.append({"table": "t", "expr": tree_sql(tr)})

    plain, auth = make_client(False), make_client(True)
    for c in cases:
        r = run_query(plain, c)
        ra = run_query(auth, c)
        if r.get("error") == "IntegrityError" or ra.get("error") == "IntegrityError":
            raise SystemExit(f"unexpected IntegrityError for {c}")
        # authenticated mode must agree with plain mode (values and errors; the cost may differ)
        assert {k: v for k, v in r.items() if k != "message"} == {k: v for k, v in ra.items() if k != "message"}, (c, r, ra)
        c = dict(c)
        c.update(r)
        out["exec"]["cases"].append(c)
    json.dump(out, sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
