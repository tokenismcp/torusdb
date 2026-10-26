# SPDX-License-Identifier: Apache-2.0
"""TorusSQL v0.6 — arithmetic expressions: arbitrary-depth products (Π_C),
division (public and owner-assisted), mixed + - * /.

Engine-level tests (in-process server). The wire / real-server variants are in
``tests/test_expr_e2e.py``; the server-view audit is in ``test_crypto_audit.py``.
"""
from __future__ import annotations

import random
from fractions import Fraction

import pytest

from torusdb_core.errors import (DepthLimitExceeded, DivisionByZero, ExecError, IntegrityError,
                                 PlanError)
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torusdb_core.protocol import N, OutOfBudget

F = Fraction

SCHEMA = ("CREATE TABLE t (id INT PLAIN, dept INT PLAIN, q INT PLAIN, a INT PAIRED, "
          "b INT PAIRED, c INT PAIRED, d INT PAIRED, r RATIONAL PAIRED, s RATIONAL ENC, "
          "e INT PAIRED)")
# id, dept, q, a, b, c, d, r, s, e     (b, d, q, r never 0 here: zero cases have their own tests)
ROWS = [
    (1, 5, 5, 2, 3, 4, 5, F(1, 2), 10, 7),
    (2, 5, 2, -5, 7, 2, -1, F(-3, 4), -3, -2),
    (3, 9, 1, 6, -4, 3, 8, F(2, 3), F(7, 3), 9),
    (4, 9, -3, 0, 11, -6, 2, F(5), 0, 1),
    (5, 9, 4, 13, -2, 5, -7, F(-1, 7), F(1, 2), -8),
]
COLS = ["id", "dept", "q", "a", "b", "c", "d", "r", "s", "e"]


def _lit(v):
    return f"FRAC({v.numerator},{v.denominator})" if isinstance(v, Fraction) and v.denominator != 1 \
        else str(int(v))


def make(auth=False, rows=ROWS, server=None):
    srv = server or NoKeyServer()
    cli = NoKeyClient(srv, authenticated=auth)
    cli.execute(SCHEMA)
    for row in rows:
        cli.execute(f"INSERT INTO t ({', '.join(COLS)}) VALUES ({', '.join(_lit(v) for v in row)})")
    return srv, cli


@pytest.fixture(params=[False, True], ids=["plain", "authenticated"])
def cli(request):
    return make(request.param)[1]


def R(i):
    return dict(zip(COLS, ROWS[i]))


def one(cli, sql):
    rows = cli.execute(sql).rows
    assert len(rows) == 1
    return rows[0]


def per_row(cli, expr, where=""):
    return one(cli, f"SELECT {expr} FROM t {where}")[0]


# ── products of arbitrary depth ──────────────────────────────────────────────
@pytest.mark.parametrize("expr,fn,depth", [
    ("a*b+0", lambda x: x["a"] * x["b"], 1),
    ("a*b*c", lambda x: x["a"] * x["b"] * x["c"], 2),
    ("a*b*c*d", lambda x: x["a"] * x["b"] * x["c"] * x["d"], 3),
    ("a*b*c*d*a", lambda x: x["a"] ** 2 * x["b"] * x["c"] * x["d"], 4),
    ("(a*b)*(c*d)", lambda x: x["a"] * x["b"] * x["c"] * x["d"], 2),   # balanced: depth 2, not 3
    ("r*r*r", lambda x: x["r"] ** 3, 2),
    ("a*b+c", lambda x: x["a"] * x["b"] + x["c"], 1),
    ("c+a*b", lambda x: x["a"] * x["b"] + x["c"], 1),
    ("a*b-c*d", lambda x: x["a"] * x["b"] - x["c"] * x["d"], 1),
    ("(a+b)*(c-d)", lambda x: (x["a"] + x["b"]) * (x["c"] - x["d"]), 1),
    ("(a+b)*(c-d)*a", lambda x: (x["a"] + x["b"]) * (x["c"] - x["d"]) * x["a"], 2),
    ("-(a*b)*c+7", lambda x: -(x["a"] * x["b"]) * x["c"] + 7, 2),
    ("2*a*b*3", lambda x: 6 * x["a"] * x["b"], 1),             # public scalars cost no level
    ("a*q", lambda x: x["a"] * x["q"], 0),                      # PLAIN operand: scalar product
    ("a*b*q", lambda x: x["a"] * x["b"] * x["q"], 1),
    ("s+s*2", lambda x: x["s"] * 3, 0),
    ("a*b+s", lambda x: x["a"] * x["b"] + x["s"], 1),          # ENC column in a linear position
    ("(a*b+c)*(c-d)*r", lambda x: (x["a"] * x["b"] + x["c"]) * (x["c"] - x["d"]) * x["r"], 3),
])
def test_per_row_expressions_match_python(cli, expr, fn, depth):
    got = per_row(cli, expr)
    assert got == [fn(R(i)) for i in range(len(ROWS))]
    assert cli.last_expr_cost["depth"] == depth


@pytest.mark.parametrize("n_levels,expr", [(1, "a*b+0"), (2, "a*b*c"), (3, "a*b*c*d")])
def test_one_owner_round_per_multiplicative_level(n_levels, expr):
    srv, cli = make()
    per_row(cli, expr)
    cost = cli.last_expr_cost
    assert cost["depth"] == n_levels and cost["mult_rounds"] == n_levels
    assert cost["products"] == n_levels * len(ROWS)            # one Beaver triple per product


def test_products_of_one_level_share_a_round():
    _, cli = make()
    got = per_row(cli, "a*b + c*d + a*d")                      # three products, all level 1
    assert got == [R(i)["a"] * R(i)["b"] + R(i)["c"] * R(i)["d"] + R(i)["a"] * R(i)["d"]
                   for i in range(len(ROWS))]
    assert cli.last_expr_cost["mult_rounds"] == 1
    assert cli.last_expr_cost["products"] == 3 * len(ROWS)


def test_rounds_follow_depth_not_node_count():
    _, cli = make()
    per_row(cli, "(a*b)*(c*d)")                                # 3 products, 2 levels
    assert cli.last_expr_cost["mult_rounds"] == 2
    assert cli.last_expr_cost["products"] == 3 * len(ROWS)


class CallSpy(NoKeyServer):
    """Records the name of every public (RPC-level) method called on the server."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if callable(attr) and not name.startswith("_") and name != "calls":
            calls = super().__getattribute__("calls")

            def spy(*a, **k):
                calls.append(name)
                return attr(*a, **k)
            return spy
        return attr


def test_every_server_call_is_a_pre_existing_rpc():
    """Expressions add no RPC: only blinded reads, Π_lin sums and Π_mult combines."""
    srv = CallSpy()
    _, cli = make(server=srv)
    srv.calls.clear()
    for sql in ["SELECT a*b*c + s/2 FROM t", "SELECT SUM(a*b*c)/COUNT(*) FROM t",
                "SELECT a/b FROM t", "SELECT SUM(a+2*b-s/4) FROM t"]:
        cli.execute(sql)
    # (`limits` is the cached hello reply, not a request)
    assert set(srv.calls) <= {"blinded_cells", "blinded_sum", "mult_combine_batch",
                              "matching_rowids", "plain_cells", "limits"}, set(srv.calls)
    assert "mult_combine_batch" in srv.calls and "blinded_sum" in srv.calls


# ── SUM / AVG over expressions ───────────────────────────────────────────────
@pytest.mark.parametrize("agg,fn", [
    ("SUM(a*b)", lambda rs: sum(x["a"] * x["b"] for x in rs)),
    ("SUM(a*b*c)", lambda rs: sum(x["a"] * x["b"] * x["c"] for x in rs)),
    ("SUM(a*b*c*d)", lambda rs: sum(x["a"] * x["b"] * x["c"] * x["d"] for x in rs)),
    ("SUM(a*b-c)", lambda rs: sum(x["a"] * x["b"] - x["c"] for x in rs)),
    ("SUM(r*r)", lambda rs: sum(x["r"] ** 2 for x in rs)),
    ("SUM(a+b)", lambda rs: sum(x["a"] + x["b"] for x in rs)),             # linear: Π_lin
    ("SUM(2*a-b+3)", lambda rs: sum(2 * x["a"] - x["b"] + 3 for x in rs)),
    ("SUM(s/4)", lambda rs: sum(F(x["s"]) / 4 for x in rs)),
    ("SUM(a)/COUNT(*)", lambda rs: F(sum(x["a"] for x in rs), len(rs))),
    ("SUM(a*b)/COUNT(*)", lambda rs: F(sum(x["a"] * x["b"] for x in rs), len(rs))),
    ("AVG(a*b)", lambda rs: F(sum(x["a"] * x["b"] for x in rs), len(rs))),
    ("AVG(a+b)", lambda rs: F(sum(x["a"] + x["b"] for x in rs), len(rs))),
    ("SUM(a)*SUM(b)", lambda rs: sum(x["a"] for x in rs) * sum(x["b"] for x in rs)),
    ("SUM(a*b)/SUM(c)", lambda rs: F(sum(x["a"] * x["b"] for x in rs), sum(x["c"] for x in rs))),
    ("SUM(a*b)*2+COUNT(*)", lambda rs: 2 * sum(x["a"] * x["b"] for x in rs) + len(rs)),
    ("SUM(e)/SUM(a*b)", lambda rs: F(sum(x["e"] for x in rs), sum(x["a"] * x["b"] for x in rs))),
])
@pytest.mark.parametrize("where,subset", [("", range(5)), ("WHERE dept = 9", [2, 3, 4])])
def test_aggregate_expressions(cli, agg, fn, where, subset):
    got = one(cli, f"SELECT {agg} FROM t {where}")[0]
    assert got == fn([R(i) for i in subset])


def test_linear_sum_is_a_pi_lin_aggregate_not_a_row_download():
    srv = CallSpy()
    _, cli = make(server=srv)
    srv.calls.clear()
    assert one(cli, "SELECT SUM(a+2*b) FROM t")[0] == sum(R(i)["a"] + 2 * R(i)["b"] for i in range(5))
    assert "blinded_cells" not in srv.calls, "a linear SUM must use server-side sums, not per-row cells"
    assert srv.calls.count("blinded_sum") == 2
    assert cli.last_expr_cost["linear_sums"] == 2 and cli.last_expr_cost["mult_rounds"] == 0


def test_several_expression_projections_and_aliases(cli):
    rs = cli.execute("SELECT SUM(a*b) AS dotp, SUM(a*b)/COUNT(*) AS mean, COUNT(*) AS n, "
                     "SUM(a*b*c) FROM t")
    assert rs.columns == ["dotp", "mean", "n", "sum(a*b*c)"]
    tot = sum(R(i)["a"] * R(i)["b"] for i in range(5))
    assert rs.rows == [[tot, F(tot, 5), 5, sum(R(i)["a"] * R(i)["b"] * R(i)["c"] for i in range(5))]]


def test_group_by_with_expressions(cli):
    rs = cli.execute("SELECT dept, SUM(a*b), SUM(a*b)/COUNT(*), SUM(a*b*c) FROM t "
                     "GROUP BY dept ORDER BY dept")
    exp = []
    for dp in (5, 9):
        rs_ = [R(i) for i in range(5) if R(i)["dept"] == dp]
        tot = sum(x["a"] * x["b"] for x in rs_)
        exp.append([dp, tot, F(tot, len(rs_)), sum(x["a"] * x["b"] * x["c"] for x in rs_)])
    assert rs.rows == exp
    rs = cli.execute("SELECT dept, a*b*c FROM t GROUP BY dept ORDER BY dept")
    assert rs.rows == [[5, [24, -70]], [9, [-72, 0, 13 * -2 * 5]]]


# ── division ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("expr,fn", [
    ("s/2", lambda x: F(x["s"]) / 2),
    ("s/7", lambda x: F(x["s"]) / 7),
    ("a/3", lambda x: F(x["a"], 3)),
    ("a/-3", lambda x: F(x["a"], -3)),
    ("a/(1+1)", lambda x: F(x["a"], 2)),
    ("a/FRAC(2,3)", lambda x: F(x["a"]) * F(3, 2)),
    ("r/FRAC(1,5)", lambda x: x["r"] * 5),
    ("(a+b)/4-c/8", lambda x: F(x["a"] + x["b"], 4) - F(x["c"], 8)),
    ("a/q", lambda x: F(x["a"], x["q"])),                        # PLAIN denominator
    ("a/b", lambda x: F(x["a"], x["b"])),
    ("a/c/d", lambda x: F(x["a"], x["c"]) / x["d"]),
    ("d/e", lambda x: F(x["d"], x["e"])),
    ("r/r", lambda x: F(1)),
    ("a*b/c", lambda x: F(x["a"] * x["b"], x["c"])),
    ("(a*b)/(c*d)", lambda x: F(x["a"] * x["b"], x["c"] * x["d"])),
    ("100/c", lambda x: F(100, x["c"])),                         # public numerator, encrypted denominator
    ("a/(b+c*d)", lambda x: F(x["a"], x["b"] + x["c"] * x["d"])),
    ("(a+1)/(a+1)", lambda x: F(1)),
    ("a/b*b", lambda x: F(x["a"])),                              # x/y*y == x exactly
    ("a/b+c/d", lambda x: F(x["a"], x["b"]) + F(x["c"], x["d"])),
    ("-a/b", lambda x: F(-x["a"], x["b"])),
])
def test_division(cli, expr, fn):
    rows = [R(i) for i in range(5)]
    got = per_row(cli, expr)
    assert got == [fn(x) for x in rows]
    assert all(isinstance(g, (int, Fraction)) for g in got)


def test_division_results_are_exact_rationals_not_floats(cli):
    got = per_row(cli, "a/b")
    assert got[0] == F(2, 3) and isinstance(got[0], Fraction)
    assert got[4] == F(13, -2) and got[4] == F(-13, 2)
    assert per_row(cli, "e/e") == [1] * 5


def test_negative_and_fractional_division(cli):
    got = per_row(cli, "r/b")
    assert got == [R(i)["r"] / R(i)["b"] for i in range(5)]
    got = per_row(cli, "(-a)/(-b)")
    assert got == [F(R(i)["a"], R(i)["b"]) for i in range(5)]


# ── zero denominators ────────────────────────────────────────────────────────
def test_division_by_encrypted_zero_is_a_loud_error(cli):
    cli.execute("UPDATE t SET b = 0 WHERE id = 2")
    with pytest.raises(DivisionByZero) as ei:
        cli.execute("SELECT a/b FROM t")
    assert isinstance(ei.value, ZeroDivisionError) and isinstance(ei.value, ExecError)
    assert "division by zero" in str(ei.value)
    # rows excluded by WHERE do not matter
    assert per_row(cli, "a/b", "WHERE id <> 2") == [F(2, 3), F(6, -4), F(0, 11), F(13, -2)]
    # in an aggregate too
    with pytest.raises(DivisionByZero):
        cli.execute("SELECT SUM(a/b) FROM t")


def test_division_by_zero_intermediate(cli):
    # a*b - c*d is 0 in some row: 2*3 - 4*5 != 0 ... build one: set c,d so that a*b == c*d
    cli.execute("UPDATE t SET c = 6, d = 1 WHERE id = 1")          # a*b = 6 = c*d
    with pytest.raises(DivisionByZero):
        cli.execute("SELECT 1/(a*b-c*d) FROM t")
    with pytest.raises(DivisionByZero):
        cli.execute("SELECT a/(a*b-c*d) FROM t")


def test_division_by_zero_plain_column_and_aggregate(cli):
    cli.execute("UPDATE t SET q = 0 WHERE id = 3")
    with pytest.raises(DivisionByZero):
        cli.execute("SELECT a/q FROM t")
    with pytest.raises(DivisionByZero):                       # COUNT(*) = 0
        cli.execute("SELECT SUM(a)/COUNT(*) FROM t WHERE id > 100")
    assert sum(R(i)["c"] for i in (0, 1, 3)) == 0              # rows 1, 2, 4: 4 + 2 - 6
    with pytest.raises(DivisionByZero):                       # SUM(c) = 0
        cli.execute("SELECT SUM(a)/SUM(c) FROM t WHERE id IN (1, 2, 4)")


@pytest.mark.parametrize("sql", ["SELECT a/0 FROM t", "SELECT a/(2-2) FROM t",
                                 "SELECT a/(3*FRAC(0,4)) FROM t", "SELECT 1/0+a FROM t"])
def test_constant_zero_denominator_is_rejected_at_plan_time(cli, sql):
    with pytest.raises(PlanError, match="division by zero"):
        cli.execute(sql)


# ── exactness budget ─────────────────────────────────────────────────────────
def test_product_beyond_the_budget_raises_never_wraps():
    _, cli = make(rows=[(1, 1, 1, 2 ** 60, 2 ** 60, 2 ** 60, 2 ** 60, F(1), 1, 1)])
    assert per_row(cli, "a*b") == [2 ** 120]
    with pytest.raises(OutOfBudget):
        cli.execute("SELECT a*b*c FROM t")                    # 2^180 > 2^126·… budget
    with pytest.raises(OutOfBudget):
        cli.execute("SELECT SUM(a*b*c*d) FROM t")


def test_intermediate_overflow_that_cancels_is_exact():
    """Ring arithmetic is exact: a transient value outside the budget is harmless."""
    big = 2 ** 100
    _, cli = make(rows=[(1, 1, 1, big + 3, big + 7, 5, 1, F(1), 1, 1)])
    assert per_row(cli, "a*b/b") == [big + 3]                 # a*b ~ 2^200, result back in range
    assert per_row(cli, "(a*b)/(a*b)") == [1]
    assert per_row(cli, "a*b-a*b+c") == [5]


def test_quotient_beyond_the_budget_raises():
    p, q = 2 ** 100 + 3, 2 ** 100 + 7                         # coprime: |num|·den ~ 2^200
    _, cli = make(rows=[(1, 1, 1, p, q, 1, 1, F(1), 1, 1)])
    with pytest.raises(OutOfBudget):
        cli.execute("SELECT a/b FROM t")
    assert per_row(cli, "b/b") == [1]


def test_division_by_huge_public_constant_is_checked():
    _, cli = make()
    with pytest.raises(PlanError):
        cli.execute(f"SELECT a/{2 ** 127} FROM t")
    with pytest.raises(PlanError):
        cli.execute(f"SELECT a*{2 ** 127} FROM t")


# ── depth limit ──────────────────────────────────────────────────────────────
def test_depth_limit_is_explicit_and_checked_before_any_request():
    srv = CallSpy()
    _, cli = make(server=srv)
    cli.max_mult_depth = 2
    assert per_row(cli, "a*b*c")                             # depth 2: allowed
    srv.calls.clear()
    with pytest.raises(DepthLimitExceeded, match="max_mult_depth"):
        cli.execute("SELECT a*b*c*d FROM t")
    assert srv.calls == [], "the depth limit must be enforced before any request is sent"
    assert issubclass(DepthLimitExceeded, PlanError)
    cli.max_mult_depth = 3
    assert per_row(cli, "a*b*c*d")
    cli.max_mult_depth = 0
    with pytest.raises(DepthLimitExceeded):
        cli.execute("SELECT a*b+0 FROM t")                    # an expression of depth 1
    assert per_row(cli, "s/2+a*3")                            # depth 0 is fine
    assert one(cli, "SELECT a * b FROM t")                    # LEGACY a*b path: unchanged by the limit


def test_default_max_depth_is_eight():
    _, cli = make()
    assert cli.max_mult_depth == 8
    chain8 = "*".join(["a"] * 9)                             # 8 products = depth 8
    chain9 = "*".join(["a"] * 10)
    per_row(cli, chain8)
    with pytest.raises(DepthLimitExceeded):
        cli.execute(f"SELECT {chain9} FROM t")


# ── NULLs (PLAIN operands, LEFT JOIN null side) ──────────────────────────────
def test_null_plain_operand_gives_null_and_aggregates_skip_it():
    cli = NoKeyClient(NoKeyServer())
    cli.execute("CREATE TABLE n (id INT PLAIN, w INT PLAIN, a INT PAIRED, b INT PAIRED)")
    for i, (w, a, b) in enumerate([(2, 3, 4), (None, 5, 6), (3, 7, 8)], 1):
        cli.execute(f"INSERT INTO n (id, w, a, b) VALUES ({i}, {'NULL' if w is None else w}, {a}, {b})")
    assert one(cli, "SELECT a*b*w FROM n")[0] == [24, None, 168]
    assert one(cli, "SELECT SUM(a*b*w) FROM n")[0] == 24 + 168
    assert one(cli, "SELECT AVG(a*b*w) FROM n")[0] == F(24 + 168, 2)


def test_join_operands_from_two_tables_and_left_join_nulls():
    cli = NoKeyClient(NoKeyServer())
    cli.execute("CREATE TABLE emp (eid INT PLAIN, did INT PLAIN, sal INT PAIRED)")
    cli.execute("CREATE TABLE dept (did INT PLAIN, bonus INT PAIRED, fx RATIONAL PAIRED)")
    for e, d, s in [(1, 10, 100), (2, 10, 200), (3, 20, 300), (4, 30, 400)]:
        cli.execute(f"INSERT INTO emp (eid, did, sal) VALUES ({e}, {d}, {s})")
    cli.execute("INSERT INTO dept (did, bonus, fx) VALUES (10, 3, FRAC(1,2))")
    cli.execute("INSERT INTO dept (did, bonus, fx) VALUES (20, 5, FRAC(2,3))")
    sql = "FROM emp e JOIN dept d ON e.did = d.did"
    assert one(cli, f"SELECT SUM(e.sal*d.bonus*d.fx) {sql}")[0] == F(100 * 3, 2) + F(200 * 3, 2) + F(300 * 5 * 2, 3)
    assert one(cli, f"SELECT SUM(e.sal*d.bonus)/COUNT(*) {sql}")[0] == F(300 + 600 + 1500, 3)
    left = "FROM emp e LEFT JOIN dept d ON e.did = d.did"
    assert one(cli, f"SELECT e.sal*d.bonus*d.fx {left}")[0] == [F(150), F(300), F(1000), None]
    assert one(cli, f"SELECT SUM(e.sal*d.bonus), COUNT(*) {left}") == [300 + 600 + 1500, 4]
    assert one(cli, f"SELECT SUM(e.sal+d.bonus) {left}")[0] == (100 + 3) + (200 + 3) + (300 + 5)
    rs = cli.execute(f"SELECT e.did, SUM(e.sal*d.bonus)/COUNT(*) {left} GROUP BY e.did ORDER BY e.did")
    assert rs.rows == [[10, 450], [20, 1500], [30, 0]]      # did 30: no match -> SUM over zero rows = 0


# ── integrity (authenticated mode) ───────────────────────────────────────────
def test_tampered_operand_is_detected_through_a_deep_product():
    srv, cli = make(True)
    srv._rows["t"][1]["b"] = (srv._rows["t"][1]["b"] + 5) % N
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a*b*c*d FROM t")
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a/b FROM t")


def test_tampered_cell_is_detected_in_a_linear_aggregate_expression():
    srv, cli = make(True)
    srv._rows["t"][3]["a"] = (srv._rows["t"][3]["a"] + 1) % N
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(a+b) FROM t")


@pytest.mark.parametrize("level", [1, 2, 3])
def test_forged_product_term_at_any_level_is_detected(level):
    calls = {"n": 0}

    class Forger(NoKeyServer):
        @staticmethod
        def mult_combine_batch(openings):
            calls["n"] += 1
            if calls["n"] == level:
                return [(e * g + 1) % N for e, g in openings]
            return [e * g % N for e, g in openings]
    _, cli = make(True, server=Forger())
    calls["n"] = 0
    with pytest.raises(IntegrityError, match="forged product"):
        cli.execute("SELECT a*b*c*d FROM t")


def test_unauthenticated_mode_does_not_detect_a_forged_product_term():
    """Documented limitation, same as for DOT: integrity needs authenticated=True."""
    class Forger(NoKeyServer):
        @staticmethod
        def mult_combine_batch(openings):
            return [(e * g + 1) % N for e, g in openings]
    _, cli = make(False, server=Forger())
    got = per_row(cli, "a*b*c")                                 # wrong, and silently so
    assert got != [R(i)["a"] * R(i)["b"] * R(i)["c"] for i in range(5)]


# ── legacy regression: pre-v0.6 queries are unchanged ────────────────────────
def test_legacy_projection_shapes_still_parse_to_their_own_nodes():
    from torussql_parser import (AvgExpr, ColRef, CountStar, CtMulExpr, DotExpr, MaxExpr, MinExpr,
                                 ScalarMulExpr, ScaledSumExpr, SumExpr, parse)
    q = parse("SELECT id, SUM(a), AVG(a), COUNT(*), 3*a, -3*a, 3*SUM(a), a*b, t.a*t.b, "
              "DOT(a,b), MIN(id), MAX(id) FROM t")
    assert [type(p) for p in q.projections] == [ColRef, SumExpr, AvgExpr, CountStar, ScalarMulExpr,
                                                ScalarMulExpr, ScaledSumExpr, CtMulExpr, CtMulExpr,
                                                DotExpr, MinExpr, MaxExpr]
    assert q.projections[5].scalar == -3


def test_legacy_queries_give_the_same_results_and_use_no_expression_machinery(cli):
    assert cli.execute("SELECT a * b FROM t").rows == [[[R(i)["a"] * R(i)["b"] for i in range(5)]]]
    assert cli.last_expr_cost is None
    assert cli.execute("SELECT DOT(a, b) FROM t").rows == [[sum(R(i)["a"] * R(i)["b"] for i in range(5))]]
    assert cli.execute("SELECT 12 * s FROM t").rows == [[[12 * F(R(i)["s"]) for i in range(5)]]]
    assert cli.execute("SELECT 12 * SUM(s) FROM t").rows[0][0] == 12 * sum(F(R(i)["s"]) for i in range(5))
    assert cli.execute("SELECT SUM(e), AVG(e), COUNT(*) FROM t").rows == \
        [[sum(R(i)["e"] for i in range(5)), F(sum(R(i)["e"] for i in range(5)), 5), 5]]
    assert cli.last_expr_cost is None
    # the legacy a*b still requires PAIRED on both sides; ENC*ENC is still rejected
    with pytest.raises(PlanError):
        cli.execute("SELECT s * e FROM t")
    with pytest.raises(PlanError, match="DOT requires INT"):
        cli.execute("SELECT DOT(r, r) FROM t")


def test_new_style_equals_legacy_for_the_shapes_they_share(cli):
    assert per_row(cli, "a*b+0") == cli.execute("SELECT a * b FROM t").rows[0][0]
    assert one(cli, "SELECT SUM(a*b) FROM t")[0] == one(cli, "SELECT DOT(a, b) FROM t")[0]
    assert per_row(cli, "a*2") == cli.execute("SELECT 2 * a FROM t").rows[0][0]


# ── policy rules shared with the open validator ──────────────────────────────
@pytest.mark.parametrize("sql,msg", [
    ("SELECT s*e FROM t", "(?i)paired"),                          # legacy shape, ENC
    ("SELECT s*a*b FROM t", "PAIRED"),                        # ENC inside a ct x ct product
    ("SELECT (s+a)*b FROM t", "PAIRED"),
    ("SELECT a/s FROM t", "PAIRED"),                          # ENC denominator
    ("SELECT s/s FROM t", "PAIRED"),
    ("SELECT id*2 FROM t", "ENC/PAIRED"),                     # PLAIN-only per-row expression
    ("SELECT q/id FROM t", "ENC/PAIRED"),
    ("SELECT a+SUM(a) FROM t", "mix"),
    ("SELECT SUM(id*2) FROM t", "encrypted"),
    ("SELECT SUM(2) FROM t", "column"),
    ("SELECT 1+2 FROM t", "no column"),
    ("SELECT a*name FROM t", "no such column"),
])
def test_policy_rejections(cli, sql, msg):
    with pytest.raises(PlanError, match=msg):
        cli.execute(sql)


def test_enc_columns_are_fine_in_linear_positions(cli):
    assert per_row(cli, "s+s/2-e*3") == [F(R(i)["s"]) * F(3, 2) - 3 * R(i)["e"] for i in range(5)]
    assert one(cli, "SELECT SUM(s*2+e), SUM(s)/4 FROM t") == [
        sum(2 * F(R(i)["s"]) + R(i)["e"] for i in range(5)),
        sum(F(R(i)["s"]) for i in range(5)) / 4]


def test_fhe_columns_give_a_clear_error_not_a_wrong_answer():
    from torusdb_core.planner import plan_query
    from torusdb_core.nokey_engine import _CatalogView
    from torusdb_core.parser import parse
    schema = {"f": [("id", "int", "plain"), ("x", "int", "fhe"), ("y", "int", "fhe"),
                    ("p", "int", "paired")]}
    cat = _CatalogView(schema)
    for sql in ["SELECT x*y*x FROM f", "SELECT x/2 FROM f", "SELECT x+1 FROM f", "SELECT SUM(x)/COUNT(*) FROM f",
                "SELECT SUM(x*y) FROM f", "SELECT p*x*p FROM f"]:
        with pytest.raises(PlanError, match="FHE"):
            plan_query(parse(sql), cat)
    for sql in ["SELECT SUM(x) FROM f", "SELECT AVG(x) FROM f", "SELECT 3 * SUM(x) FROM f",
                "SELECT DOT(x, y) FROM f"]:
        plan_query(parse(sql), cat)                           # the depth-1 FHE forms still plan
    with pytest.raises(PlanError):                            # legacy FHE a*b rejection unchanged
        plan_query(parse("SELECT x * y FROM f"), cat)


# ── randomized differential test against exact Fraction arithmetic ───────────
def _gen(rng, depth, leaves):
    """A random expression tree: ("col", n) | ("lit", v) | ("neg", x) | (op, l, r)."""
    if depth == 0 or rng.random() < 0.25:
        if rng.random() < 0.7:
            return ("col", rng.choice(leaves))
        return ("lit", rng.choice([F(2), F(3), F(-4), F(7), F(1), F(1, 3), F(-5, 2)]))
    if rng.random() < 0.1:
        return ("neg", _gen(rng, depth - 1, leaves))
    return (rng.choice("+-*/"), _gen(rng, depth - 1, leaves), _gen(rng, depth - 1, leaves))


def _sql(t):
    if t[0] == "col":
        return t[1]
    if t[0] == "lit":
        v = t[1]
        if v.denominator != 1:
            return f"FRAC({v.numerator},{v.denominator})"
        return f"({v.numerator})" if v < 0 else str(v.numerator)
    if t[0] == "neg":
        return f"(-{_sql(t[1])})"
    return f"({_sql(t[1])}{t[0]}{_sql(t[2])})"


def _py(t, row):
    if t[0] == "col":
        return F(row[t[1]])
    if t[0] == "lit":
        return t[1]
    if t[0] == "neg":
        return -_py(t[1], row)
    a, b = _py(t[1], row), _py(t[2], row)
    return a + b if t[0] == "+" else a - b if t[0] == "-" else a * b if t[0] == "*" else a / b


@pytest.mark.parametrize("auth", [False, True])
def test_random_expressions_match_fraction_arithmetic_or_fail_loudly(auth):
    from torusdb_core.protocol import _BOUND, _RANGE
    _, cli = make(auth)
    rng = random.Random(20260622 + auth)
    leaves = ["a", "b", "c", "d", "r", "q"]
    ran = zero = budget = rejected = 0
    for _ in range(250):
        tree = _gen(rng, rng.randint(1, 4), leaves)
        if tree[0] in ("col", "lit"):
            continue
        sql = f"SELECT {_sql(tree)} FROM t"
        exp, zerodiv = [], False
        for i in range(len(ROWS)):
            try:
                exp.append(_py(tree, R(i)))
            except ZeroDivisionError:
                zerodiv = True
        try:
            got = cli.execute(sql).rows[0][0]
        except PlanError as exc:
            assert any(m in str(exc) for m in ("division by zero", "no column", "ENC/PAIRED",
                                               "requires encrypted", "out of range")), (sql, exc)
            if "division by zero" in str(exc):
                assert zerodiv and not exp, sql         # a constant zero denominator: every row fails
            rejected += 1
            continue
        except DivisionByZero:
            assert zerodiv, f"spurious division by zero for {sql}"
            zero += 1
            continue
        except OutOfBudget:
            assert any(abs(v.numerator) > _BOUND or v.denominator > _BOUND
                       or abs(v.numerator) * v.denominator >= _RANGE for v in exp), sql
            budget += 1
            continue
        assert not zerodiv, f"missing division-by-zero error for {sql}"
        assert got == exp, sql
        ran += 1
    assert ran > 100, (ran, zero, budget, rejected)


def test_maximum_height_expression_runs_without_recursion_errors():
    """Height 98 (the parser allows 100): 98 owner rounds, exact result, no RecursionError."""
    rows = [(1, 1, 1, 1, 1, 1, 1, F(1), 1, 1), (2, 1, 1, -1, 1, 1, 1, F(1), 1, 1)]
    _, cli = make(rows=rows)
    cli.max_mult_depth = 120
    got = per_row(cli, "a" + "*a" * 98)                      # a^99 with a = 1, -1
    assert got == [1, -1] and cli.last_expr_cost["mult_rounds"] == 98
    got = per_row(cli, "a" + "+a" * 98)                      # a long additive chain: depth 0
    assert got == [99, -99] and cli.last_expr_cost["mult_rounds"] == 0


def test_a_zero_denominator_does_not_change_what_the_server_sees():
    """Aborting at the first zero would show the server, as a missing request, that some
    encrypted denominator was 0 (a data-dependent bit). The protocol therefore runs to its
    last round with a dummy value and only then raises."""
    srv = CallSpy()
    _, cli = make(server=srv)

    def trace(sql, expect_error):
        srv.calls.clear()
        if expect_error:
            with pytest.raises(DivisionByZero):
                cli.execute(sql)
        else:
            cli.execute(sql)
        return list(srv.calls)

    for sql in ["SELECT a/b FROM t", "SELECT c*d/(a-a+b)*a FROM t", "SELECT SUM(a/b*c) FROM t"]:
        clean = trace(sql, False)
        cli.execute("UPDATE t SET b = 0 WHERE id IN (2, 4)")
        srv.calls.clear()
        zero = trace(sql, True)
        cli.execute("UPDATE t SET b = 7 WHERE id IN (2, 4)")
        assert zero == clean, f"the request sequence depends on a zero denominator for {sql}"
        assert "mult_combine_batch" in zero


def test_linear_sum_with_unrepresentable_intermediate_coefficients_is_exact():
    """(a * 2^100) * 2^100 has a coefficient 2^200 that encode() would refuse, but the term is
    multiplied by 0 here, so the true result (0) is representable and must be returned."""
    _, cli = make(rows=[(1, 1, 1, 0, 1, 1, 1, F(1), 1, 1), (2, 1, 1, 0, 1, 1, 1, F(1), 1, 1)])
    big = 2 ** 100
    assert one(cli, f"SELECT SUM(a*{big}*{big}) FROM t")[0] == 0
    assert per_row(cli, f"a*{big}*{big}") == [0, 0]            # the per-row path agrees
