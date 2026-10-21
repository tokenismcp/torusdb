# SPDX-License-Identifier: Apache-2.0
"""v0.5 join suite: aliases, self-joins, multi-joins, LEFT JOIN, GROUP BY over
joins, WHERE on any joined table, cross-table DOT, NULL semantics, and
open-validator / closed-planner agreement for every query shape."""
from __future__ import annotations

import sys
from fractions import Fraction
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
for _p in [_REPO / "ec_fhe_query", _REPO / "ec_fhe_engine",
           _REPO / "torussql/parser"]:
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest
from torussql_parser.errors import ParseError, ValidationError
from torussql_parser.parser import parse
from torussql_parser.validate import Schema
from ecfhe_query.nokey_engine import NoKeyClient, NoKeyServer


def mk(*ddl_and_rows, authenticated=False):
    cli = NoKeyClient(NoKeyServer(), authenticated=authenticated)
    for sql in ddl_and_rows:
        cli.execute(sql)
    return cli


@pytest.fixture(params=[False, True], ids=["plain-mode", "authenticated"])
def org(request):
    """emp(eid, did, mgr, name, salary ENC) / dept(did, dname) / proj(did, pname, budget ENC)"""
    c = mk(
        "CREATE TABLE emp (eid INT PLAIN, did INT PLAIN, mgr INT PLAIN, "
        "name STR PLAIN, salary INT ENC)",
        "CREATE TABLE dept (did INT PLAIN, dname STR PLAIN)",
        "CREATE TABLE proj (did INT PLAIN, pname STR PLAIN, budget INT ENC)",
        authenticated=request.param,
    )
    for sql in [
        "INSERT INTO dept (did, dname) VALUES (10, 'Eng')",
        "INSERT INTO dept (did, dname) VALUES (20, 'Sales')",
        "INSERT INTO dept (did, dname) VALUES (30, 'Empty')",
        # eid, did, mgr, name, salary ; Dave has no department match (99)
        "INSERT INTO emp (eid, did, mgr, name, salary) VALUES (1, 10, NULL, 'Alice', 100)",
        "INSERT INTO emp (eid, did, mgr, name, salary) VALUES (2, 10, 1, 'Bob', 80)",
        "INSERT INTO emp (eid, did, mgr, name, salary) VALUES (3, 20, 1, 'Carol', 70)",
        "INSERT INTO emp (eid, did, mgr, name, salary) VALUES (4, 99, 3, 'Dave', 60)",
        "INSERT INTO proj (did, pname, budget) VALUES (10, 'Apollo', 1000)",
        "INSERT INTO proj (did, pname, budget) VALUES (10, 'Gemini', 500)",
        "INSERT INTO proj (did, pname, budget) VALUES (20, 'Mercury', 300)",
    ]:
        c.execute(sql)
    return c


def rows(c, sql):
    return c.execute(sql).rows


# ── aliases ──────────────────────────────────────────────────────────────────
def test_alias_with_and_without_as(org):
    a = rows(org, "SELECT e.name, d.dname FROM emp e JOIN dept d ON e.did = d.did ORDER BY e.name")
    b = rows(org, "SELECT e.name, d.dname FROM emp AS e JOIN dept AS d ON e.did = d.did ORDER BY e.name")
    assert a == b == [["Alice", "Eng"], ["Bob", "Eng"], ["Carol", "Sales"]]


def test_alias_hides_original_table_name(org):
    with pytest.raises(Exception, match="unknown table"):
        org.execute("SELECT emp.name FROM emp e JOIN dept d ON e.did = d.did")


def test_alias_on_single_table_query(org):
    assert rows(org, "SELECT e.name FROM emp e WHERE e.eid = 2") == [["Bob"]]


def test_qualified_names_on_single_table(org):
    r = rows(org, "SELECT emp.did, COUNT(*) FROM emp GROUP BY emp.did ORDER BY emp.did")
    assert r == [[10, 2], [20, 1], [99, 1]]


def test_reserved_word_cannot_be_alias():
    with pytest.raises(ParseError):
        parse("SELECT * FROM emp AS where")


# ── self-join ────────────────────────────────────────────────────────────────
def test_self_join_manager(org):
    r = rows(org, "SELECT e.name, m.name FROM emp e JOIN emp m ON e.mgr = m.eid ORDER BY e.name")
    assert r == [["Bob", "Alice"], ["Carol", "Alice"], ["Dave", "Carol"]]


def test_self_join_encrypted_aggregate_uses_correct_side(org):
    # SUM of the *managers'* salaries across the 3 reporting edges
    assert rows(org, "SELECT SUM(m.salary) FROM emp e JOIN emp m ON e.mgr = m.eid") == [[100 + 100 + 70]]
    # ... and of the employees' own salaries
    assert rows(org, "SELECT SUM(e.salary) FROM emp e JOIN emp m ON e.mgr = m.eid") == [[80 + 70 + 60]]


def test_self_join_bare_column_is_ambiguous(org):
    with pytest.raises(Exception, match="ambiguous"):
        org.execute("SELECT name FROM emp e JOIN emp m ON e.mgr = m.eid")


# ── multi-join ───────────────────────────────────────────────────────────────
def test_three_table_join(org):
    r = rows(org, "SELECT e.name, d.dname, p.pname FROM emp e "
                  "JOIN dept d ON e.did = d.did JOIN proj p ON p.did = d.did "
                  "ORDER BY p.pname")
    assert sorted(map(tuple, r)) == sorted([
        ("Alice", "Eng", "Apollo"), ("Bob", "Eng", "Apollo"),
        ("Alice", "Eng", "Gemini"), ("Bob", "Eng", "Gemini"),
        ("Carol", "Sales", "Mercury")])


def test_three_table_join_sums_across_tables(org):
    # emp(Alice,Bob)x proj(Apollo,Gemini) + Carol x Mercury
    r = rows(org, "SELECT COUNT(*), SUM(e.salary), SUM(p.budget) FROM emp e "
                  "JOIN dept d ON e.did = d.did JOIN proj p ON p.did = d.did")
    assert r == [[5, 100 * 2 + 80 * 2 + 70, 1000 + 500 + 1000 + 500 + 300]]


def test_join_on_references_any_earlier_table(org):
    # second ON references emp (not the immediately preceding dept)
    r = rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did "
                  "JOIN proj p ON e.did = p.did")
    assert r == [[5]]


# ── LEFT JOIN ────────────────────────────────────────────────────────────────
def test_left_join_keeps_unmatched_left_rows(org):
    r = rows(org, "SELECT e.name, d.dname FROM emp e LEFT JOIN dept d ON e.did = d.did ORDER BY e.eid")
    assert r == [["Alice", "Eng"], ["Bob", "Eng"], ["Carol", "Sales"], ["Dave", None]]


def test_left_outer_keyword(org):
    assert rows(org, "SELECT COUNT(*) FROM emp e LEFT OUTER JOIN dept d ON e.did = d.did") == [[4]]


def test_left_join_inner_vs_left_counts(org):
    assert rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did") == [[3]]
    assert rows(org, "SELECT COUNT(*) FROM emp e LEFT JOIN dept d ON e.did = d.did") == [[4]]


def test_left_join_aggregates_skip_null_side(org):
    # budget is NULL-extended for depts without projects; SUM must skip them
    r = rows(org, "SELECT SUM(p.budget) FROM dept d LEFT JOIN proj p ON d.did = p.did")
    assert r == [[1000 + 500 + 300]]
    assert rows(org, "SELECT COUNT(*) FROM dept d LEFT JOIN proj p ON d.did = p.did") == [[4]]


def test_left_join_avg_ignores_null_side(org):
    r = rows(org, "SELECT AVG(p.budget) FROM dept d LEFT JOIN proj p ON d.did = p.did")
    assert r == [[Fraction(1800, 3)]]


def test_left_join_where_on_right_column_filters_nulls(org):
    r = rows(org, "SELECT e.name FROM emp e LEFT JOIN dept d ON e.did = d.did WHERE d.dname = 'Eng' ORDER BY e.name")
    assert r == [["Alice"], ["Bob"]]


def test_left_join_order_by_nulls_last_asc_first_desc(org):
    asc = rows(org, "SELECT e.name, d.dname FROM emp e LEFT JOIN dept d ON e.did = d.did ORDER BY d.dname")
    assert asc[-1] == ["Dave", None]
    desc = rows(org, "SELECT e.name, d.dname FROM emp e LEFT JOIN dept d ON e.did = d.did ORDER BY d.dname DESC")
    assert desc[0] == ["Dave", None]


def test_left_join_null_key_never_matches():
    c = mk("CREATE TABLE a (k INT PLAIN)", "CREATE TABLE b (k INT PLAIN)",
           "INSERT INTO a (k) VALUES (NULL)", "INSERT INTO b (k) VALUES (NULL)",
           "INSERT INTO a (k) VALUES (1)", "INSERT INTO b (k) VALUES (1)")
    assert rows(c, "SELECT COUNT(*) FROM a JOIN b ON a.k = b.k") == [[1]]
    assert rows(c, "SELECT COUNT(*) FROM a LEFT JOIN b ON a.k = b.k") == [[2]]


def test_left_join_empty_right_table():
    c = mk("CREATE TABLE a (k INT PLAIN)", "CREATE TABLE b (k INT PLAIN, v INT ENC)",
           "INSERT INTO a (k) VALUES (1)", "INSERT INTO a (k) VALUES (2)")
    assert rows(c, "SELECT a.k, b.k FROM a LEFT JOIN b ON a.k = b.k ORDER BY a.k") == [[1, None], [2, None]]
    assert rows(c, "SELECT SUM(b.v) FROM a LEFT JOIN b ON a.k = b.k") == [[0]]


def test_inner_join_empty_tables():
    c = mk("CREATE TABLE a (k INT PLAIN)", "CREATE TABLE b (k INT PLAIN)")
    assert rows(c, "SELECT a.k FROM a JOIN b ON a.k = b.k") == []
    assert rows(c, "SELECT COUNT(*) FROM a JOIN b ON a.k = b.k") == [[0]]


# ── GROUP BY over joins ──────────────────────────────────────────────────────
def test_group_by_over_join_with_encrypted_sum(org):
    r = rows(org, "SELECT d.dname, COUNT(*), SUM(e.salary) FROM emp e "
                  "JOIN dept d ON e.did = d.did GROUP BY d.dname ORDER BY d.dname")
    assert r == [["Eng", 2, 180], ["Sales", 1, 70]]


def test_group_by_join_having(org):
    r = rows(org, "SELECT d.dname, COUNT(*) FROM emp e JOIN dept d ON e.did = d.did "
                  "GROUP BY d.dname HAVING COUNT(*) > 1")
    assert r == [["Eng", 2]]


def test_group_by_over_left_join_counts_null_group(org):
    r = rows(org, "SELECT d.dname, COUNT(*) FROM emp e LEFT JOIN dept d ON e.did = d.did "
                  "GROUP BY d.dname ORDER BY d.dname")
    assert r[-1] == [None, 1] and len(r) == 3


def test_group_by_multi_column(org):
    r = rows(org, "SELECT e.did, e.mgr, COUNT(*) FROM emp e GROUP BY e.did, e.mgr")
    assert sorted(r, key=repr) == sorted([[10, None, 1], [10, 1, 1], [20, 1, 1], [99, 3, 1]], key=repr)


def test_group_by_ungrouped_column_rejected_by_planner_and_validator(org):
    sql = "SELECT e.name, COUNT(*) FROM emp e GROUP BY e.did"
    with pytest.raises(Exception, match="GROUP BY"):
        org.execute(sql)


def test_group_by_star_rejected(org):
    with pytest.raises(Exception, match="GROUP BY"):
        org.execute("SELECT * FROM emp GROUP BY did")


def test_group_by_encrypted_key_rejected(org):
    with pytest.raises(Exception, match="plain"):
        org.execute("SELECT salary, COUNT(*) FROM emp GROUP BY salary")


def test_group_by_min_max_avg_scaled(org):
    r = rows(org, "SELECT d.dname, MIN(e.eid), MAX(e.eid), AVG(e.salary), 2 * SUM(e.salary) "
                  "FROM emp e JOIN dept d ON e.did = d.did GROUP BY d.dname ORDER BY d.dname")
    assert r == [["Eng", 1, 2, Fraction(90), 360], ["Sales", 3, 3, Fraction(70), 140]]


# ── WHERE across joined tables ───────────────────────────────────────────────
def test_where_on_right_table_column(org):
    r = rows(org, "SELECT e.name FROM emp e JOIN dept d ON e.did = d.did WHERE d.dname = 'Sales'")
    assert r == [["Carol"]]


def test_where_or_across_tables(org):
    r = rows(org, "SELECT e.name FROM emp e JOIN dept d ON e.did = d.did "
                  "WHERE d.dname = 'Sales' OR e.eid = 1 ORDER BY e.name")
    assert r == [["Alice"], ["Carol"]]


def test_where_in_on_right_table(org):
    r = rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did WHERE d.did IN (10, 20)")
    assert r == [[3]]


def test_where_pushdown_and_post_filter_agree(org):
    pushed = rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did WHERE e.did = 10")
    mixed = rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did WHERE e.did = 10 OR d.did = 10")
    assert pushed == mixed == [[2]]


def test_where_encrypted_column_rejected_in_join(org):
    with pytest.raises(Exception, match="encrypted"):
        org.execute("SELECT e.name FROM emp e JOIN dept d ON e.did = d.did WHERE e.salary = 100")


# ── DOT / products across tables ─────────────────────────────────────────────
def test_cross_table_dot_product():
    c = mk("CREATE TABLE a (k INT PLAIN, x INT PAIRED)",
           "CREATE TABLE b (k INT PLAIN, y INT PAIRED)",
           "INSERT INTO a (k, x) VALUES (1, 3)", "INSERT INTO a (k, x) VALUES (2, 4)",
           "INSERT INTO b (k, y) VALUES (1, 10)", "INSERT INTO b (k, y) VALUES (2, 100)")
    assert rows(c, "SELECT DOT(a.x, b.y) FROM a JOIN b ON a.k = b.k") == [[3 * 10 + 4 * 100]]
    assert rows(c, "SELECT a.x * b.y FROM a JOIN b ON a.k = b.k") == [[[30, 400]]]


def test_cross_table_dot_authenticated():
    c = mk("CREATE TABLE a (k INT PLAIN, x INT PAIRED)",
           "CREATE TABLE b (k INT PLAIN, y INT PAIRED)",
           "INSERT INTO a (k, x) VALUES (1, 7)", "INSERT INTO b (k, y) VALUES (1, 6)",
           authenticated=True)
    assert rows(c, "SELECT DOT(a.x, b.y) FROM a JOIN b ON a.k = b.k") == [[42]]


def test_left_join_dot_skips_null_side():
    c = mk("CREATE TABLE a (k INT PLAIN, x INT PAIRED)",
           "CREATE TABLE b (k INT PLAIN, y INT PAIRED)",
           "INSERT INTO a (k, x) VALUES (1, 3)", "INSERT INTO a (k, x) VALUES (2, 4)",
           "INSERT INTO b (k, y) VALUES (1, 10)")
    assert rows(c, "SELECT DOT(a.x, b.y) FROM a LEFT JOIN b ON a.k = b.k") == [[30]]
    assert rows(c, "SELECT a.x * b.y FROM a LEFT JOIN b ON a.k = b.k") == [[[30, None]]]


# ── projection shapes in joins ───────────────────────────────────────────────
def test_scalar_mul_per_row_in_join(org):
    r = rows(org, "SELECT 2 * e.salary FROM emp e JOIN dept d ON e.did = d.did WHERE d.dname = 'Eng'")
    assert r == [[[200, 160]]]


def test_distinct_over_join(org):
    r = rows(org, "SELECT DISTINCT d.dname FROM emp e JOIN dept d ON e.did = d.did ORDER BY d.dname")
    assert r == [["Eng"], ["Sales"]]


def test_limit_over_ordered_join(org):
    r = rows(org, "SELECT e.name FROM emp e JOIN dept d ON e.did = d.did ORDER BY e.name DESC LIMIT 2")
    assert r == [["Carol"], ["Bob"]]


def test_output_alias_in_join(org):
    rs = org.execute("SELECT e.name AS who, d.dname AS dept FROM emp e JOIN dept d ON e.did = d.did LIMIT 1")
    assert rs.columns == ["who", "dept"]


def test_star_expands_every_instance(org):
    rs = org.execute("SELECT * FROM emp e JOIN dept d ON e.did = d.did WHERE e.eid = 1")
    assert rs.columns == ["e.eid", "e.did", "e.mgr", "e.name", "e.salary", "d.did", "d.dname"]
    assert rs.rows == [[1, 10, None, "Alice", 100, 10, "Eng"]]


def test_join_with_deleted_rows_is_tombstone_safe(org):
    org.execute("DELETE FROM emp WHERE eid = 2")
    org.execute("DELETE FROM dept WHERE did = 20")
    assert rows(org, "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did") == [[1]]
    assert rows(org, "SELECT SUM(e.salary) FROM emp e LEFT JOIN dept d ON e.did = d.did") == [[100 + 70 + 60]]


def test_join_reflects_updates(org):
    org.execute("UPDATE emp SET salary = 500 WHERE eid = 1")
    assert rows(org, "SELECT SUM(e.salary) FROM emp e JOIN dept d ON e.did = d.did") == [[500 + 80 + 70]]


# ── ON-clause validation ─────────────────────────────────────────────────────
@pytest.mark.parametrize("sql,match", [
    ("SELECT e.name FROM emp e JOIN dept d ON e.salary = d.did", "PLAIN"),
    ("SELECT e.name FROM emp e JOIN dept d ON e.name = d.did", "incompatible"),
    ("SELECT e.name FROM emp e JOIN dept d ON e.did = e.eid", "joined table"),
    ("SELECT e.name FROM emp e JOIN dept d ON d.did = d.did", "joined table|different tables"),
    ("SELECT e.name FROM emp e JOIN dept d ON e.did = x.did", "unknown table"),
    ("SELECT e.name FROM emp e JOIN dept d ON e.nope = d.did", "no such column"),
    ("SELECT e.name FROM emp e JOIN nosuch n ON e.did = n.did", "no such table"),
    ("SELECT e.name FROM emp e JOIN dept e ON e.did = e.did", "alias|duplicate"),
])
def test_bad_join_rejected_by_engine_and_validator(org, sql, match):
    with pytest.raises(Exception, match=match):
        org.execute(sql)
    sch = Schema()
    for ddl in ["CREATE TABLE emp (eid INT PLAIN, did INT PLAIN, mgr INT PLAIN, name STR PLAIN, salary INT ENC)",
                "CREATE TABLE dept (did INT PLAIN, dname STR PLAIN)"]:
        sch.apply(parse(ddl))
    with pytest.raises(ValidationError):
        sch.validate(parse(sql))


# ── open validator and closed planner agree on every accepted shape ──────────
_GOOD = [
    "SELECT e.name, d.dname FROM emp e JOIN dept d ON e.did = d.did",
    "SELECT e.name, m.name FROM emp e JOIN emp m ON e.mgr = m.eid",
    "SELECT e.name, d.dname FROM emp e LEFT JOIN dept d ON e.did = d.did",
    "SELECT d.dname, COUNT(*), SUM(e.salary) FROM emp e JOIN dept d ON e.did = d.did GROUP BY d.dname",
    "SELECT d.dname, COUNT(*) FROM emp e JOIN dept d ON e.did = d.did GROUP BY d.dname HAVING COUNT(*) > 1",
    "SELECT COUNT(*) FROM emp e JOIN dept d ON e.did = d.did JOIN proj p ON p.did = d.did WHERE d.dname = 'Eng'",
    "SELECT e.name FROM emp e JOIN dept d ON e.did = d.did ORDER BY e.name DESC LIMIT 1",
    "SELECT * FROM emp e JOIN dept d ON e.did = d.did",
    "SELECT DISTINCT d.dname FROM emp e JOIN dept d ON e.did = d.did",
    "SELECT e.name FROM emp e JOIN dept d ON e.did = d.did ORDER BY d.dname",
]
_BAD = [
    "SELECT e.name, COUNT(*) FROM emp e GROUP BY e.did",
    "SELECT * FROM emp GROUP BY did",
    "SELECT DISTINCT e.name FROM emp e JOIN dept d ON e.did = d.did ORDER BY d.dname",
    "SELECT name FROM emp e JOIN emp m ON e.mgr = m.eid",
    "SELECT SUM(e.eid) FROM emp e",
    "SELECT e.name FROM emp e WHERE e.salary = 1",
]


def _schema():
    sch = Schema()
    for ddl in ["CREATE TABLE emp (eid INT PLAIN, did INT PLAIN, mgr INT PLAIN, name STR PLAIN, salary INT ENC)",
                "CREATE TABLE dept (did INT PLAIN, dname STR PLAIN)",
                "CREATE TABLE proj (did INT PLAIN, pname STR PLAIN, budget INT ENC)"]:
        sch.apply(parse(ddl))
    return sch


@pytest.mark.parametrize("sql", _GOOD)
def test_open_and_closed_both_accept(org, sql):
    _schema().validate(parse(sql))
    org.execute(sql)


@pytest.mark.parametrize("sql", _BAD)
def test_open_and_closed_both_reject(org, sql):
    with pytest.raises(ValidationError):
        _schema().validate(parse(sql))
    with pytest.raises(Exception):
        org.execute(sql)
