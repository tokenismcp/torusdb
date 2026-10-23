# SPDX-License-Identifier: Apache-2.0
"""Tests for INNER JOIN support (v0.4).

Covers: parser, planner, and engine-level hash join execution.
Join constraints:
  - Both ON columns must be PLAIN
  - WHERE applies only to the left (primary) table
  - Encrypted aggregates (SUM) work on joined rows from either table
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for _p in [_REPO / "core", _REPO / "parser"]:
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest
from torussql_parser.ast import Join, Select
from torussql_parser.parser import parse
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def two_table_db():
    """emp(id PLAIN, dept_id PLAIN, name STR PLAIN, salary INT ENC)
    dept(id PLAIN, name STR PLAIN)"""
    srv = NoKeyServer()
    cli = NoKeyClient(srv)

    cli.execute("CREATE TABLE emp (id INT PLAIN, dept_id INT PLAIN, name STR PLAIN, salary INT ENC)")
    cli.execute("CREATE TABLE dept (id INT PLAIN, name STR PLAIN)")

    cli.execute("INSERT INTO dept (id, name) VALUES (10, 'Engineering')")
    cli.execute("INSERT INTO dept (id, name) VALUES (20, 'Sales')")

    cli.execute("INSERT INTO emp (id, dept_id, name, salary) VALUES (1, 10, 'Alice', 90000)")
    cli.execute("INSERT INTO emp (id, dept_id, name, salary) VALUES (2, 10, 'Bob', 80000)")
    cli.execute("INSERT INTO emp (id, dept_id, name, salary) VALUES (3, 20, 'Carol', 70000)")

    return cli


# ── parser tests ─────────────────────────────────────────────────────────────

def test_parse_inner_join():
    q = parse("SELECT emp.name FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert isinstance(q, Select)
    assert len(q.joins) == 1
    j = q.joins[0]
    assert isinstance(j, Join)
    assert j.table == "dept"
    assert j.on_left == "emp.dept_id"
    assert j.on_right == "dept.id"


def test_parse_inner_join_explicit_keyword():
    q = parse("SELECT emp.id FROM emp INNER JOIN dept ON emp.dept_id = dept.id")
    assert len(q.joins) == 1
    assert q.joins[0].table == "dept"


def test_parse_bare_col_in_on():
    q = parse("SELECT name FROM emp JOIN dept ON dept_id = dept.id")
    assert q.joins[0].on_left == "dept_id"
    assert q.joins[0].on_right == "dept.id"


def test_parse_qualified_projection():
    q = parse("SELECT emp.name, dept.name FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert len(q.projections) == 2


def test_parse_join_with_where():
    q = parse("SELECT emp.name FROM emp JOIN dept ON emp.dept_id = dept.id WHERE dept_id = 10")
    assert len(q.joins) == 1
    assert q.where is not None


def test_parse_join_with_count_star():
    q = parse("SELECT COUNT(*) FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert len(q.joins) == 1


# ── engine tests ─────────────────────────────────────────────────────────────

def test_basic_join_row_projection(two_table_db):
    rs = two_table_db.execute(
        "SELECT emp.name, dept.name FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert rs.columns == ["emp.name", "dept.name"]
    assert len(rs.rows) == 3
    names = sorted(r[0] for r in rs.rows)
    assert names == ["Alice", "Bob", "Carol"]


def test_join_left_table_column_only(two_table_db):
    rs = two_table_db.execute(
        "SELECT emp.id FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert len(rs.rows) == 3
    ids = sorted(r[0] for r in rs.rows)
    assert ids == [1, 2, 3]


def test_join_right_table_column_only(two_table_db):
    rs = two_table_db.execute(
        "SELECT dept.name FROM emp JOIN dept ON emp.dept_id = dept.id")
    dept_names = sorted(r[0] for r in rs.rows)
    assert dept_names == ["Engineering", "Engineering", "Sales"]


def test_join_where_on_primary_table(two_table_db):
    rs = two_table_db.execute(
        "SELECT emp.name, dept.name FROM emp JOIN dept ON emp.dept_id = dept.id "
        "WHERE dept_id = 10")
    assert len(rs.rows) == 2
    emp_names = sorted(r[0] for r in rs.rows)
    assert emp_names == ["Alice", "Bob"]
    assert all(r[1] == "Engineering" for r in rs.rows)


def test_join_where_qualified_primary_col(two_table_db):
    rs = two_table_db.execute(
        "SELECT emp.name FROM emp JOIN dept ON emp.dept_id = dept.id "
        "WHERE emp.dept_id = 20")
    assert len(rs.rows) == 1
    assert rs.rows[0][0] == "Carol"


def test_join_no_match(two_table_db):
    rs = two_table_db.execute(
        "SELECT emp.name FROM emp JOIN dept ON emp.dept_id = dept.id "
        "WHERE dept_id = 999")
    assert rs.rows == []


def test_join_count_star(two_table_db):
    rs = two_table_db.execute(
        "SELECT COUNT(*) FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert rs.rows[0][0] == 3


def test_join_count_star_with_where(two_table_db):
    rs = two_table_db.execute(
        "SELECT COUNT(*) FROM emp JOIN dept ON emp.dept_id = dept.id WHERE dept_id = 10")
    assert rs.rows[0][0] == 2


def test_join_sum_encrypted_left(two_table_db):
    rs = two_table_db.execute(
        "SELECT SUM(emp.salary) FROM emp JOIN dept ON emp.dept_id = dept.id")
    assert rs.rows[0][0] == 240000


def test_join_sum_with_where(two_table_db):
    rs = two_table_db.execute(
        "SELECT SUM(emp.salary) FROM emp JOIN dept ON emp.dept_id = dept.id "
        "WHERE dept_id = 10")
    assert rs.rows[0][0] == 170000


def test_join_one_to_many():
    """One right row matched by multiple left rows."""
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE a (k INT PLAIN, v STR PLAIN)")
    cli.execute("CREATE TABLE b (k INT PLAIN, label STR PLAIN)")
    cli.execute("INSERT INTO a (k, v) VALUES (1, 'x')")
    cli.execute("INSERT INTO a (k, v) VALUES (1, 'y')")
    cli.execute("INSERT INTO b (k, label) VALUES (1, 'one')")
    rs = cli.execute("SELECT a.v, b.label FROM a JOIN b ON a.k = b.k")
    assert len(rs.rows) == 2
    assert all(r[1] == "one" for r in rs.rows)


def test_join_many_to_many():
    """Multiple left AND right rows with same key → Cartesian product of matches."""
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE p (k INT PLAIN)")
    cli.execute("CREATE TABLE q (k INT PLAIN)")
    cli.execute("INSERT INTO p (k) VALUES (5)")
    cli.execute("INSERT INTO p (k) VALUES (5)")
    cli.execute("INSERT INTO q (k) VALUES (5)")
    cli.execute("INSERT INTO q (k) VALUES (5)")
    rs = cli.execute("SELECT COUNT(*) FROM p JOIN q ON p.k = q.k")
    assert rs.rows[0][0] == 4   # 2 × 2


def test_join_star_select(two_table_db):
    rs = two_table_db.execute(
        "SELECT * FROM emp JOIN dept ON emp.dept_id = dept.id WHERE dept_id = 20")
    assert len(rs.rows) == 1
    # Columns should be qualified: emp.id, emp.dept_id, emp.name, emp.salary, dept.id, dept.name
    assert len(rs.columns) == 6
    assert all("." in c for c in rs.columns)


def test_join_inner_auto_bare_col(two_table_db):
    """Bare column name resolves unambiguously across joined tables."""
    # 'name' exists in both emp and dept — should raise ambiguity error
    with pytest.raises(Exception, match="ambiguous"):
        two_table_db.execute(
            "SELECT name FROM emp JOIN dept ON emp.dept_id = dept.id")


def test_join_unambiguous_bare_col():
    """Bare column name resolves when it exists in only one table."""
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE left_t (id INT PLAIN, x INT PLAIN)")
    cli.execute("CREATE TABLE right_t (id INT PLAIN, y INT PLAIN)")
    cli.execute("INSERT INTO left_t (id, x) VALUES (1, 10)")
    cli.execute("INSERT INTO right_t (id, y) VALUES (1, 20)")
    rs = cli.execute("SELECT x, y FROM left_t JOIN right_t ON left_t.id = right_t.id")
    assert rs.rows == [[10, 20]]


def test_join_error_on_limit(two_table_db):
    """LIMIT is accepted in the parser even in a join query."""
    rs = two_table_db.execute(
        "SELECT emp.name FROM emp JOIN dept ON emp.dept_id = dept.id LIMIT 1")
    assert len(rs.rows) == 1


# ── new edge-case tests (added post-review) ───────────────────────────────────

def test_join_order_by(two_table_db):
    """ORDER BY a left-table PLAIN column that is also in the SELECT list."""
    rs = two_table_db.execute(
        "SELECT emp.id, emp.name, dept.name FROM emp "
        "JOIN dept ON emp.dept_id = dept.id ORDER BY emp.id")
    assert [r[1] for r in rs.rows] == ["Alice", "Bob", "Carol"]


def test_join_order_by_desc(two_table_db):
    """ORDER BY DESC on a right-table PLAIN column that is in the SELECT list."""
    rs = two_table_db.execute(
        "SELECT emp.id, emp.name FROM emp "
        "JOIN dept ON emp.dept_id = dept.id ORDER BY emp.id DESC")
    assert [r[1] for r in rs.rows] == ["Carol", "Bob", "Alice"]


def test_join_same_table_twice_needs_alias(two_table_db):
    """Joining one table twice without aliases is ambiguous -> clear error."""
    with pytest.raises(Exception, match="alias"):
        two_table_db.execute(
            "SELECT emp.name FROM emp "
            "JOIN dept ON emp.dept_id = dept.id "
            "JOIN dept ON emp.dept_id = dept.id")


def test_join_self_join_without_alias_raises():
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE t (id INT PLAIN, parent_id INT PLAIN)")
    with pytest.raises(Exception, match="alias"):
        cli.execute("SELECT t.id FROM t JOIN t ON t.parent_id = t.id")


def test_join_reversed_on_clause():
    """ON clause written with right-table ref first still joins correctly."""
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE a (aid INT PLAIN, val STR PLAIN)")
    cli.execute("CREATE TABLE b (bid INT PLAIN, aid_fk INT PLAIN)")
    cli.execute("INSERT INTO a (aid, val) VALUES (1, 'hello')")
    cli.execute("INSERT INTO b (bid, aid_fk) VALUES (10, 1)")
    # Note: ON clause written right-table.col = left-table.col (reversed)
    rs = cli.execute("SELECT a.val, b.bid FROM a JOIN b ON b.aid_fk = a.aid")
    assert rs.rows == [["hello", 10]]
