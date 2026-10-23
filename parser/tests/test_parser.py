# SPDX-License-Identifier: Apache-2.0
"""torussql-parser tests — parsing + static validation, no engine."""
import pytest

from torussql_parser import (
    ColRef, CreateTable, CtMulExpr, DotExpr, Insert, ParseError, Schema,
    ScalarMulExpr, Select, SumExpr, ValidationError, parse,
)


# ── parsing ──────────────────────────────────────────────────────────────────
def test_create_table_normalizes_type_and_policy():
    q = parse("CREATE TABLE t (id INT PLAIN, x RATIONAL PAIRED, n STR ENC)")
    assert isinstance(q, CreateTable)
    assert q.columns == [("id", "int", "plain"),
                         ("x", "rational", "paired"),
                         ("n", "str", "encrypted")]


def test_insert_with_frac_and_null():
    q = parse("INSERT INTO t (a, b, c) VALUES (1, FRAC(2, 3), NULL)")
    assert isinstance(q, Insert)
    assert q.values == [1, ("frac", 2, 3), None]


def test_select_star():
    q = parse("SELECT * FROM t")
    assert isinstance(q, Select) and q.star


def test_select_projections():
    q = parse("SELECT id, SUM(s), 12 * s, a * b, DOT(a, b) FROM t")
    kinds = [type(p) for p in q.projections]
    assert kinds == [ColRef, SumExpr, ScalarMulExpr, CtMulExpr, DotExpr]


def test_scalar_vs_ctmul_disambiguation():
    assert isinstance(parse("SELECT 3 * x FROM t").projections[0], ScalarMulExpr)
    assert isinstance(parse("SELECT x * y FROM t").projections[0], CtMulExpr)


def test_scalar_per_row_vs_scaled_sum():
    from torussql_parser import ScaledSumExpr
    assert isinstance(parse("SELECT 3 * x FROM t").projections[0], ScalarMulExpr)
    p = parse("SELECT 3 * SUM(x) FROM t").projections[0]
    assert isinstance(p, ScaledSumExpr) and p.scalar == 3 and p.column == "x"


def test_column_aliases_parse():
    q = parse("SELECT id AS a, SUM(v) AS total, COUNT(*) AS n FROM t")
    assert q.aliases == ["a", "total", "n"]
    q2 = parse("SELECT id, dept AS d FROM t")
    assert q2.aliases == [None, "d"]


def test_where_comparison_ops_and_conjunction():
    q = parse("SELECT * FROM t WHERE dept = 5 AND age >= 18 AND name <> 'x'")
    assert len(q.where.or_terms) == 1          # single AND-group
    ops = [c.op for c in q.where.or_terms[0]]
    assert ops == ["=", ">=", "<>"]
    assert q.where.or_terms[0][0].column == "dept"


def test_where_dnf_or_of_ands():
    # AND binds tighter than OR: (a AND b) OR (c)
    q = parse("SELECT * FROM t WHERE a = 1 AND b = 2 OR c = 3")
    assert len(q.where.or_terms) == 2
    assert [a.column for a in q.where.or_terms[0]] == ["a", "b"]
    assert [a.column for a in q.where.or_terms[1]] == ["c"]


def test_where_in_list():
    from torussql_parser import InList
    q = parse("SELECT * FROM t WHERE dept IN (5, 7, 9)")
    atom = q.where.or_terms[0][0]
    assert isinstance(atom, InList)
    assert atom.column == "dept" and atom.values == [5, 7, 9]


def test_avg_min_max_parse():
    from torussql_parser import AvgExpr, MaxExpr, MinExpr
    q = parse("SELECT AVG(salary), MIN(id), MAX(dept) FROM t")
    assert [type(p) for p in q.projections] == [AvgExpr, MinExpr, MaxExpr]


def test_where_rejects_non_literal_and_bad_op():
    with pytest.raises(ParseError):
        parse("SELECT * FROM t WHERE dept = other")      # not a literal
    # a bare identifier where an operator is expected fails to tokenize as sym
    with pytest.raises(ParseError):
        parse("SELECT * FROM t WHERE dept REGEXP 5")


def test_count_star():
    from torussql_parser import CountStar
    q = parse("SELECT COUNT(*) FROM t")
    assert isinstance(q.projections[0], CountStar)


def test_order_by_and_limit():
    q = parse("SELECT id FROM t ORDER BY id DESC LIMIT 10")
    assert q.order_by.column == "id" and q.order_by.descending is True
    assert q.limit == 10
    q2 = parse("SELECT id FROM t ORDER BY id")
    assert q2.order_by.descending is False and q2.limit is None


def test_negative_limit_rejected():
    with pytest.raises(ParseError):
        parse("SELECT id FROM t LIMIT -1")


def test_group_by_having_distinct_parse():
    q = parse("SELECT DISTINCT dept, SUM(v) FROM t WHERE x = 1 "
              "GROUP BY dept HAVING COUNT(*) >= 2 ORDER BY dept LIMIT 5")
    assert q.distinct is True
    assert q.group_by == ["dept"]
    assert q.having.op == ">=" and q.having.value == 2
    assert q.order_by.column == "dept" and q.limit == 5


def test_update_parse():
    from torussql_parser import Update
    q = parse("UPDATE t SET v = FRAC(5,1), name = 'x' WHERE id = 3")
    assert isinstance(q, Update)
    assert q.assignments == [("v", ("frac", 5, 1)), ("name", "x")]
    assert q.where.or_terms[0][0].column == "id"


def test_delete_parse():
    from torussql_parser import Delete
    q = parse("DELETE FROM t WHERE dept = 9")
    assert isinstance(q, Delete) and q.table == "t"
    assert q.where.or_terms[0][0].value == 9
    assert parse("DELETE FROM t").where is None      # delete-all


def test_bad_type_and_policy_rejected():
    with pytest.raises(ParseError):
        parse("CREATE TABLE t (x FLOAT PLAIN)")
    with pytest.raises(ParseError):
        parse("CREATE TABLE t (x INT SECRET)")


def test_frac_zero_denominator_rejected():
    with pytest.raises(ParseError):
        parse("INSERT INTO t (a) VALUES (FRAC(1, 0))")


# ── validation ───────────────────────────────────────────────────────────────
@pytest.fixture
def schema():
    s = Schema()
    s.apply(parse("CREATE TABLE payroll ("
                  "id INT PLAIN, dept INT PLAIN, "
                  "salary RATIONAL ENC, "
                  "rate INT PAIRED, hours INT PAIRED, "
                  "frate RATIONAL PAIRED, fhours RATIONAL PAIRED)"))
    return s


def test_valid_queries_pass(schema):
    schema.validate(parse("SELECT SUM(salary) FROM payroll"))
    schema.validate(parse("SELECT 12 * salary FROM payroll"))
    schema.validate(parse("SELECT rate * hours FROM payroll"))
    schema.validate(parse("SELECT frate * fhours FROM payroll"))   # rational ctmul ok
    schema.validate(parse("SELECT DOT(rate, hours) FROM payroll")) # int dot ok
    schema.validate(parse("SELECT SUM(salary) FROM payroll WHERE dept = 5"))


def test_sum_on_plain_rejected(schema):
    with pytest.raises(ValidationError, match="SUM requires"):
        schema.validate(parse("SELECT SUM(id) FROM payroll"))


def test_ctmul_requires_paired(schema):
    with pytest.raises(ValidationError, match="PAIRED"):
        schema.validate(parse("SELECT salary * salary FROM payroll"))


def test_dot_requires_paired(schema):
    with pytest.raises(ValidationError, match="PAIRED"):
        schema.validate(parse("SELECT DOT(salary, salary) FROM payroll"))


def test_dot_rejects_rational(schema):
    with pytest.raises(ValidationError, match="DOT requires INT"):
        schema.validate(parse("SELECT DOT(frate, fhours) FROM payroll"))


def test_where_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="WHERE on encrypted"):
        schema.validate(parse("SELECT id FROM payroll WHERE salary = 5"))


def test_unknown_table_and_column(schema):
    with pytest.raises(ValidationError, match="no such table"):
        schema.validate(parse("SELECT * FROM ghosts"))
    with pytest.raises(ValidationError, match="no such column"):
        schema.validate(parse("SELECT nope FROM payroll"))


def test_insert_must_list_every_column(schema):
    with pytest.raises(ValidationError, match="every column"):
        schema.validate(parse("INSERT INTO payroll (id) VALUES (1)"))


def test_str_must_be_plain():
    s = Schema()
    with pytest.raises(ValidationError, match="STR columns must be PLAIN"):
        s.apply(parse("CREATE TABLE t (n STR ENC)"))


# ── Phase 2 validation ───────────────────────────────────────────────────────
def test_count_and_compound_where_validate(schema):
    schema.validate(parse("SELECT COUNT(*) FROM payroll"))
    schema.validate(parse("SELECT COUNT(*) FROM payroll WHERE dept = 5 AND id > 1"))


def test_where_comparison_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="WHERE on encrypted"):
        schema.validate(parse("SELECT id FROM payroll WHERE salary > 5"))


def test_order_by_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="ORDER BY requires a PLAIN"):
        schema.validate(parse("SELECT id, salary FROM payroll ORDER BY salary"))


def test_avg_min_max_validate(schema):
    schema.validate(parse("SELECT AVG(salary) FROM payroll"))     # avg on enc ok
    schema.validate(parse("SELECT MIN(id), MAX(dept) FROM payroll"))  # plain ok


def test_min_max_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="MIN requires a PLAIN"):
        schema.validate(parse("SELECT MIN(salary) FROM payroll"))
    with pytest.raises(ValidationError, match="MAX requires a PLAIN"):
        schema.validate(parse("SELECT MAX(rate) FROM payroll"))      # paired


def test_in_list_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="WHERE on encrypted"):
        schema.validate(parse("SELECT id FROM payroll WHERE salary IN (1, 2)"))


def test_or_of_plain_conditions_ok(schema):
    schema.validate(parse("SELECT id FROM payroll WHERE dept = 5 OR id > 2"))


def test_group_by_on_encrypted_rejected(schema):
    with pytest.raises(ValidationError, match="GROUP BY requires a PLAIN"):
        schema.validate(parse("SELECT salary, COUNT(*) FROM payroll "
                              "GROUP BY salary"))


def test_group_by_bare_col_must_be_grouped(schema):
    with pytest.raises(ValidationError, match="must appear in GROUP BY"):
        schema.validate(parse("SELECT id, SUM(salary) FROM payroll "
                              "GROUP BY dept"))
    schema.validate(parse("SELECT dept, SUM(salary) FROM payroll GROUP BY dept"))


def test_having_requires_group_by(schema):
    with pytest.raises(ValidationError, match="HAVING requires GROUP BY"):
        schema.validate(parse("SELECT COUNT(*) FROM payroll HAVING COUNT(*) > 1"))


def test_update_delete_validate(schema):
    schema.validate(parse("UPDATE payroll SET salary = FRAC(1,1) WHERE dept = 5"))
    schema.validate(parse("DELETE FROM payroll WHERE dept = 5"))
    with pytest.raises(ValidationError, match="no such column"):
        schema.validate(parse("UPDATE payroll SET ghost = 1"))
    with pytest.raises(ValidationError, match="WHERE on encrypted"):
        schema.validate(parse("DELETE FROM payroll WHERE salary = 1"))


def test_order_by_unselected_column_allowed_except_distinct_and_group(schema):
    # SQL permits ordering by a column that is not selected (v0.5)
    schema.validate(parse("SELECT dept FROM payroll ORDER BY id"))
    schema.validate(parse("SELECT id, dept FROM payroll ORDER BY id"))
    schema.validate(parse("SELECT * FROM payroll ORDER BY id"))
    with pytest.raises(ValidationError, match="DISTINCT"):
        schema.validate(parse("SELECT DISTINCT dept FROM payroll ORDER BY id"))
    with pytest.raises(ValidationError, match="GROUP BY"):
        schema.validate(parse(
            "SELECT dept, COUNT(*) FROM payroll GROUP BY dept ORDER BY id"))
