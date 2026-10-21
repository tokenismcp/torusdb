# SPDX-License-Identifier: Apache-2.0
"""TorusSQL v0.1 conformance suite.

Executable form of TorusSQL-Spec-v0.1.md. A TorusDB engine is conformant if
this suite passes against it. Each test cites the spec section it pins.

Two kinds of checks:
  • Engine semantics — the exact result / typed error the spec requires.
  • Open/closed agreement — the open `torussql_parser` validator and the
    closed engine accept and reject exactly the same statements.
"""
from fractions import Fraction

import pytest

from torussql_parser import Schema, ValidationError, parse


# ─────────────────────────────────────────────────────────────────────────────
# §4.2  Encrypted addition / aggregation — SUM is exact, unbounded count
# ─────────────────────────────────────────────────────────────────────────────
def test_sum_is_exact(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    engine.run("INSERT INTO t (id, v) VALUES (1, FRAC(8000, 1))")
    engine.run("INSERT INTO t (id, v) VALUES (2, FRAC(9000, 1))")
    engine.run("INSERT INTO t (id, v) VALUES (3, FRAC(7000, 1))")
    assert engine.rows("SELECT SUM(v) FROM t") == [[Fraction(24000, 1)]]


# ─────────────────────────────────────────────────────────────────────────────
# §4.3  Scalar multiply: `k * col` is PER-ROW; `k * SUM(col)` scales aggregate
# ─────────────────────────────────────────────────────────────────────────────
def test_scalar_mul_per_row(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    engine.run("INSERT INTO t (id, v) VALUES (1, FRAC(100, 1))")
    engine.run("INSERT INTO t (id, v) VALUES (2, FRAC(200, 1))")
    # per-row: each value scaled by 12
    assert engine.rows("SELECT 12 * v FROM t") \
        == [[[Fraction(1200, 1), Fraction(2400, 1)]]]


def test_scaled_sum_is_aggregate(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    engine.run("INSERT INTO t (id, v) VALUES (1, FRAC(100, 1))")
    engine.run("INSERT INTO t (id, v) VALUES (2, FRAC(200, 1))")
    # 12 * (100 + 200) = 3600
    assert engine.rows("SELECT 12 * SUM(v) FROM t") == [[Fraction(3600, 1)]]


# ─────────────────────────────────────────────────────────────────────────────
# §4.4  Formal multiplication — per-row ct×ct, exact for INT and RATIONAL
# ─────────────────────────────────────────────────────────────────────────────
def test_ctmul_per_row_int_exact(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, a INT PAIRED, b INT PAIRED)")
    engine.run("INSERT INTO t (id, a, b) VALUES (1, 50, 40)")
    engine.run("INSERT INTO t (id, a, b) VALUES (2, 60, 35)")
    # per-row products, decoded independently
    assert engine.rows("SELECT a * b FROM t") == [[[2000, 2100]]]


def test_ctmul_per_row_rational_exact(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, a RATIONAL PAIRED, b RATIONAL PAIRED)")
    engine.run("INSERT INTO t (id, a, b) VALUES (1, FRAC(1, 2), FRAC(3, 4))")
    engine.run("INSERT INTO t (id, a, b) VALUES (2, FRAC(2, 3), FRAC(1, 5))")
    # 1/2·3/4 = 3/8 ; 2/3·1/5 = 2/15
    assert engine.rows("SELECT a * b FROM t") == [[[Fraction(3, 8), Fraction(2, 15)]]]


# ─────────────────────────────────────────────────────────────────────────────
# §4.5  Encrypted inner product — DOT exact for INT, rejected for RATIONAL
# ─────────────────────────────────────────────────────────────────────────────
def test_dot_int_is_exact(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, a INT PAIRED, b INT PAIRED)")
    engine.run("INSERT INTO t (id, a, b) VALUES (1, 50, 40)")
    engine.run("INSERT INTO t (id, a, b) VALUES (2, 60, 35)")
    engine.run("INSERT INTO t (id, a, b) VALUES (3, 45, 40)")
    # 50·40 + 60·35 + 45·40 = 2000 + 2100 + 1800 = 5900
    assert engine.rows("SELECT DOT(a, b) FROM t") == [[5900]]


def test_dot_rational_is_rejected(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, a RATIONAL PAIRED, b RATIONAL PAIRED)")
    engine.run("INSERT INTO t (id, a, b) VALUES (1, FRAC(1, 2), FRAC(3, 4))")
    with pytest.raises(engine.POLICY, match="DOT requires INT"):
        engine.run("SELECT DOT(a, b) FROM t")


# ─────────────────────────────────────────────────────────────────────────────
# §2.2 / §3  Policy and predicate rules — typed POLICY errors
# ─────────────────────────────────────────────────────────────────────────────
def test_sum_on_plain_rejected(engine):
    engine.run("CREATE TABLE t (id INT PLAIN)")
    with pytest.raises(engine.POLICY):
        engine.run("SELECT SUM(id) FROM t")


def test_ctmul_requires_paired(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    with pytest.raises(engine.POLICY):
        engine.run("SELECT v * v FROM t")


def test_where_on_encrypted_rejected(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    with pytest.raises(engine.POLICY):
        engine.run("SELECT id FROM t WHERE v = 5")


def test_where_on_plain_ok(engine):
    engine.run("CREATE TABLE t (id INT PLAIN, dept INT PLAIN, v RATIONAL ENC)")
    engine.run("INSERT INTO t (id, dept, v) VALUES (1, 5, FRAC(10, 1))")
    engine.run("INSERT INTO t (id, dept, v) VALUES (2, 9, FRAC(20, 1))")
    assert engine.rows("SELECT SUM(v) FROM t WHERE dept = 5") == [[Fraction(10, 1)]]


# ─────────────────────────────────────────────────────────────────────────────
# §4.6 / §3.4  v0.2 — COUNT(*), compound WHERE, ORDER BY, LIMIT
# ─────────────────────────────────────────────────────────────────────────────
def _seed_emp(engine):
    engine.run("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, "
               "name STR PLAIN, salary RATIONAL ENC)")
    for i, (d, n, s) in enumerate([(5, "alice", 8000), (5, "bob", 9000),
                                   (9, "carol", 7000)], start=1):
        engine.run(f"INSERT INTO emp (id, dept, name, salary) "
                   f"VALUES ({i}, {d}, '{n}', FRAC({s}, 1))")


def test_count_star(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT COUNT(*) FROM emp") == [[3]]


def test_compound_where_filters_count_and_sum(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT COUNT(*) FROM emp WHERE dept = 5") == [[2]]
    assert engine.rows("SELECT SUM(salary) FROM emp WHERE dept = 5 AND id > 1") \
        == [[Fraction(9000, 1)]]       # only bob


def test_order_by_and_limit(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT id, name FROM emp ORDER BY id DESC") \
        == [[3, "carol"], [2, "bob"], [1, "alice"]]
    assert engine.rows("SELECT id, name FROM emp ORDER BY id LIMIT 2") \
        == [[1, "alice"], [2, "bob"]]


def test_where_or_and_in(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT id FROM emp WHERE dept = 5 OR dept = 9 "
                       "ORDER BY id") == [[1], [2], [3]]
    assert engine.rows("SELECT id FROM emp WHERE dept IN (5, 9) "
                       "ORDER BY id") == [[1], [2], [3]]
    # DNF precedence: (dept=5 AND id>1) OR (dept=9)  → bob(2), carol(3)
    assert engine.rows("SELECT COUNT(*) FROM emp "
                       "WHERE dept = 5 AND id > 1 OR dept = 9") == [[2]]


def test_avg_encrypted_is_exact_mean(engine):
    _seed_emp(engine)
    # (8000+9000+7000)/3 = 8000
    assert engine.rows("SELECT AVG(salary) FROM emp") == [[Fraction(8000, 1)]]
    # (8000+9000)/2 = 8500  — stays encrypted, decrypts exact
    assert engine.rows("SELECT AVG(salary) FROM emp WHERE dept = 5") \
        == [[Fraction(8500, 1)]]


def test_min_max_on_plaintext(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT MIN(id), MAX(dept) FROM emp") == [[1, 9]]


def test_column_aliases(engine):
    _seed_emp(engine)
    rs = engine.run("SELECT SUM(salary) AS total, COUNT(*) AS n FROM emp")
    assert rs.columns == ["total", "n"]
    rs2 = engine.run("SELECT id AS emp_id FROM emp ORDER BY id LIMIT 1")
    assert rs2.columns == ["emp_id"] and rs2.rows == [[1]]


def test_min_max_on_encrypted_rejected(engine):
    _seed_emp(engine)
    with pytest.raises(engine.POLICY):
        engine.run("SELECT MIN(salary) FROM emp")


def test_where_comparison_on_encrypted_rejected(engine):
    _seed_emp(engine)
    with pytest.raises(engine.POLICY):
        engine.run("SELECT id FROM emp WHERE salary > 5")


def test_order_by_on_encrypted_rejected(engine):
    _seed_emp(engine)
    with pytest.raises(engine.POLICY):
        engine.run("SELECT id, salary FROM emp ORDER BY salary")


# ─────────────────────────────────────────────────────────────────────────────
# GROUP BY / HAVING / DISTINCT / UPDATE / DELETE  (v0.3 dialect completeness)
# ─────────────────────────────────────────────────────────────────────────────
def test_group_by_aggregates_per_group(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT dept, SUM(salary), COUNT(*) FROM emp "
                       "GROUP BY dept ORDER BY dept") == [[5, 17000, 2],
                                                          [9, 7000, 1]]


def test_group_by_having(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT dept, AVG(salary) FROM emp GROUP BY dept "
                       "HAVING COUNT(*) > 1 ORDER BY dept") == [[5, 8500]]


def test_distinct(engine):
    _seed_emp(engine)
    assert engine.rows("SELECT DISTINCT dept FROM emp ORDER BY dept") \
        == [[5], [9]]


def test_update_reblinds_encrypted_cell(engine):
    _seed_emp(engine)
    engine.run("UPDATE emp SET salary = FRAC(1000,1) WHERE id = 1")
    assert engine.rows("SELECT SUM(salary) FROM emp WHERE dept = 5") == [[10000]]


def test_delete_tombstones_rows(engine):
    _seed_emp(engine)
    assert engine.run("DELETE FROM emp WHERE dept = 5") == 2
    assert engine.rows("SELECT COUNT(*) FROM emp") == [[1]]
    assert engine.rows("SELECT SUM(salary) FROM emp") == [[7000]]   # only dept 9


def test_group_by_on_encrypted_rejected(engine):
    _seed_emp(engine)
    with pytest.raises(engine.POLICY):
        engine.run("SELECT salary, COUNT(*) FROM emp GROUP BY salary")


# ─────────────────────────────────────────────────────────────────────────────
# §5  Exactness — large values reconstruct exactly (no silent wrap)
# ─────────────────────────────────────────────────────────────────────────────
def test_large_values_are_exact(engine):
    """The no-key engine decodes via rational reconstruction over Z/nZ with an
    enormous budget (~2^126); realistic magnitudes are always exact, never
    silently wrapped."""
    engine.run("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    big = 10 ** 30
    engine.run(f"INSERT INTO t (id, v) VALUES (1, FRAC({big}, 1))")
    engine.run(f"INSERT INTO t (id, v) VALUES (2, FRAC({big}, 1))")
    assert engine.rows("SELECT SUM(v) FROM t") == [[2 * big]]


# ─────────────────────────────────────────────────────────────────────────────
# §7  Open/closed agreement — the open validator and the engine agree
# ─────────────────────────────────────────────────────────────────────────────
_SCHEMA_SQL = (
    "CREATE TABLE payroll ("
    "id INT PLAIN, dept INT PLAIN, salary RATIONAL ENC, "
    "rate INT PAIRED, hours INT PAIRED, "
    "frate RATIONAL PAIRED, fhours RATIONAL PAIRED)"
)

_LEGAL = [
    "SELECT SUM(salary) FROM payroll",
    "SELECT 12 * salary FROM payroll",
    "SELECT rate * hours FROM payroll",
    "SELECT frate * fhours FROM payroll",
    "SELECT DOT(rate, hours) FROM payroll",
    "SELECT SUM(salary) FROM payroll WHERE dept = 5",
    "SELECT COUNT(*) FROM payroll",
    "SELECT COUNT(*) FROM payroll WHERE dept = 5 AND id > 1",
    "SELECT id, dept FROM payroll ORDER BY id DESC LIMIT 2",
    "SELECT AVG(salary) FROM payroll",
    "SELECT MIN(id), MAX(dept) FROM payroll",
    "SELECT id FROM payroll WHERE dept IN (5, 7) OR id > 2",
    "SELECT 12 * salary FROM payroll",
    "SELECT 12 * SUM(salary) FROM payroll",
    "SELECT SUM(salary) AS total, COUNT(*) AS n FROM payroll",
    # v0.3: GROUP BY / DISTINCT / UPDATE / DELETE
    "SELECT DISTINCT dept FROM payroll",
    "SELECT dept, SUM(salary), COUNT(*) FROM payroll GROUP BY dept",
    "SELECT dept, AVG(salary) FROM payroll GROUP BY dept HAVING COUNT(*) > 1",
    "UPDATE payroll SET id = 99 WHERE dept = 5",
    "DELETE FROM payroll WHERE dept = 9",
]

_ILLEGAL = [
    "SELECT SUM(id) FROM payroll",            # SUM on plain
    "SELECT salary * salary FROM payroll",    # ctmul needs paired
    "SELECT DOT(salary, salary) FROM payroll",# dot needs paired
    "SELECT DOT(frate, fhours) FROM payroll", # dot needs INT
    "SELECT id FROM payroll WHERE salary = 5",# where on encrypted
    "SELECT id FROM payroll WHERE salary > 5",# comparison on encrypted
    "SELECT id, salary FROM payroll ORDER BY salary",  # order by encrypted
    "SELECT id FROM payroll WHERE salary IN (1, 2)",    # IN on encrypted
    "SELECT MIN(salary) FROM payroll",        # MIN on encrypted
    "SELECT MAX(rate) FROM payroll",          # MAX on paired
    # v0.3 illegal
    "SELECT salary, COUNT(*) FROM payroll GROUP BY salary",  # GROUP BY encrypted
    "DELETE FROM payroll WHERE salary = 1",                  # WHERE on encrypted
]


def _open_schema():
    s = Schema()
    s.apply(parse(_SCHEMA_SQL))
    return s


@pytest.mark.parametrize("sql", _LEGAL)
def test_open_validator_accepts_what_engine_accepts(engine, sql):
    engine.run(_SCHEMA_SQL)
    _open_schema().validate(parse(sql))      # open: no raise
    engine.run(sql)                          # closed: no raise


@pytest.mark.parametrize("sql", _ILLEGAL)
def test_open_validator_rejects_what_engine_rejects(engine, sql):
    engine.run(_SCHEMA_SQL)
    with pytest.raises(ValidationError):     # open rejects
        _open_schema().validate(parse(sql))
    with pytest.raises(engine.POLICY):       # closed rejects
        engine.run(sql)


# ─────────────────────────────────────────────────────────────────────────────
# §4.6  INNER JOIN — plaintext equality join on PLAIN columns (v0.4)
# ─────────────────────────────────────────────────────────────────────────────
_JOIN_SCHEMAS = [
    "CREATE TABLE emp (eid INT PLAIN, did INT PLAIN, salary RATIONAL ENC)",
    "CREATE TABLE dept (did INT PLAIN, dname STR PLAIN)",
]

_JOIN_LEGAL = [
    "SELECT emp.eid, dept.dname FROM emp JOIN dept ON emp.did = dept.did",
    "SELECT COUNT(*) FROM emp JOIN dept ON emp.did = dept.did",
    "SELECT SUM(emp.salary) FROM emp JOIN dept ON emp.did = dept.did",
    "SELECT emp.eid FROM emp JOIN dept ON emp.did = dept.did WHERE emp.did = 10",
    "SELECT emp.eid FROM emp INNER JOIN dept ON emp.did = dept.did",
]

_JOIN_ILLEGAL = [
    "SELECT emp.eid FROM emp JOIN dept ON emp.salary = dept.did",  # ENC ON col
]


@pytest.mark.parametrize("sql", _JOIN_LEGAL)
def test_join_open_validator_accepts(sql):
    s = Schema()
    for stmt in _JOIN_SCHEMAS:
        s.apply(parse(stmt))
    s.validate(parse(sql))   # should not raise


@pytest.mark.parametrize("sql", _JOIN_LEGAL)
def test_join_engine_accepts(engine, sql):
    for stmt in _JOIN_SCHEMAS:
        engine.run(stmt)
    engine.run(sql)   # should not raise (empty result ok)


@pytest.mark.parametrize("sql", _JOIN_ILLEGAL)
def test_join_open_validator_rejects(sql):
    s = Schema()
    for stmt in _JOIN_SCHEMAS:
        s.apply(parse(stmt))
    with pytest.raises(ValidationError):
        s.validate(parse(sql))


@pytest.mark.parametrize("sql", _JOIN_ILLEGAL)
def test_join_engine_rejects(engine, sql):
    for stmt in _JOIN_SCHEMAS:
        engine.run(stmt)
    with pytest.raises(engine.POLICY):
        engine.run(sql)
