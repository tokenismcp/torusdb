# SPDX-License-Identifier: Apache-2.0
"""v0.6 arithmetic expressions — parsing and static validation, no engine."""
import random
from fractions import Fraction

import pytest

from torussql_parser import (AggCall, BinOp, ColRef, CountStar, ExprProj, Lit, Neg, ParseError,
                             Schema, ScalarMulExpr, ValidationError, parse, render_expr)

F = Fraction


def expr(sql_expr):
    p = parse(f"SELECT {sql_expr} FROM t").projections[0]
    assert isinstance(p, ExprProj), type(p)
    return p.expr


def test_precedence_and_left_associativity():
    assert expr("a+b*c") == BinOp("+", ColRef("a"), BinOp("*", ColRef("b"), ColRef("c")))
    assert expr("a-b-c") == BinOp("-", BinOp("-", ColRef("a"), ColRef("b")), ColRef("c"))
    assert expr("a/b/c") == BinOp("/", BinOp("/", ColRef("a"), ColRef("b")), ColRef("c"))
    assert expr("a*b/c") == BinOp("/", BinOp("*", ColRef("a"), ColRef("b")), ColRef("c"))
    assert expr("(a+b)*c") == BinOp("*", BinOp("+", ColRef("a"), ColRef("b")), ColRef("c"))
    assert expr("a*b*c") == BinOp("*", BinOp("*", ColRef("a"), ColRef("b")), ColRef("c"))


def test_unary_minus_and_signed_literals():
    assert expr("-a") == Neg(ColRef("a"))
    assert expr("-(a+b)") == Neg(BinOp("+", ColRef("a"), ColRef("b")))
    assert expr("a * -b") == BinOp("*", ColRef("a"), Neg(ColRef("b")))
    assert expr("a - -1") == BinOp("-", ColRef("a"), Lit(-1))
    assert expr("a*-2") == BinOp("*", ColRef("a"), Lit(-2))
    assert expr("-(-a)") == Neg(Neg(ColRef("a")))
    assert expr("- 3 * a + b") == BinOp("+", BinOp("*", Lit(-3), ColRef("a")), ColRef("b"))


@pytest.mark.parametrize("text", ["a-1", "a -1", "a - 1", "a-1*b", "x*y-2", "(a)-1"])
def test_a_negative_literal_token_in_operator_position_is_a_subtraction(text):
    e = expr(text)
    assert isinstance(e, BinOp) and e.op == "-"


def test_minus_one_times_binds_like_subtraction_of_a_product():
    assert expr("a-2*b") == BinOp("-", ColRef("a"), BinOp("*", Lit(2), ColRef("b")))


def test_fraction_and_integer_literals():
    assert expr("a / FRAC(2, 3)") == BinOp("/", ColRef("a"), Lit(F(2, 3)))
    assert expr("a + FRAC(4, 2)") == BinOp("+", ColRef("a"), Lit(2))
    with pytest.raises(ParseError):
        parse("SELECT a + FRAC(1, 0) FROM t")


def test_aggregates_in_expressions():
    e = expr("SUM(a*b)/COUNT(*)")
    assert e == BinOp("/", AggCall("SUM", BinOp("*", ColRef("a"), ColRef("b"))), AggCall("COUNT"))
    assert expr("AVG(a+1)*2") == BinOp("*", AggCall("AVG", BinOp("+", ColRef("a"), Lit(1))), Lit(2))


def test_legacy_shapes_keep_their_node_types():
    from torussql_parser import (AvgExpr, CtMulExpr, DotExpr, MaxExpr, MinExpr, ScaledSumExpr,
                                 SumExpr)
    q = parse("SELECT id, SUM(a), AVG(a), COUNT(*), 3*a, -3*a, 3*SUM(a), a*b, t.a*t.b, "
              "DOT(a,b), MIN(id), MAX(id), (a), SUM(t.a) FROM t")
    assert [type(p).__name__ for p in q.projections] == [
        "ColRef", "SumExpr", "AvgExpr", "CountStar", "ScalarMulExpr", "ScalarMulExpr",
        "ScaledSumExpr", "CtMulExpr", "CtMulExpr", "DotExpr", "MinExpr", "MaxExpr", "ColRef", "SumExpr"]
    assert q.projections[5] == ScalarMulExpr(scalar=-3, column="a")


def test_shapes_just_outside_the_legacy_forms_are_expressions():
    for text in ["a*3", "a*b*c", "3*a+1", "3*SUM(a)+1", "SUM(a)*3", "2*3*a", "SUM(a)/COUNT(*)",
                 "a*FRAC(1,2)", "(a+b)"]:
        assert isinstance(parse(f"SELECT {text} FROM t").projections[0], ExprProj), text


@pytest.mark.parametrize("sql", [
    "SELECT a+ FROM t", "SELECT (a FROM t", "SELECT a b FROM t", "SELECT a+*b FROM t",
    "SELECT sqrt(a) FROM t", "SELECT MIN(a)+1 FROM t", "SELECT 1+DOT(a,b) FROM t",
    "SELECT SUM(SUM(a)) FROM t", "SELECT SUM(a+COUNT(*)) FROM t", "SELECT COUNT(a) FROM t",
    "SELECT a, FROM t", "SELECT FROM t", "SELECT a/ FROM t", "SELECT SUM() FROM t",
])
def test_malformed_expressions_are_parse_errors(sql):
    with pytest.raises(ParseError):
        parse(sql)


def test_expression_height_is_bounded():
    flat = "a" + "+a" * 98                                    # height 98: fine
    parse(f"SELECT {flat} FROM t")
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "a+" * 200 + "a FROM t")
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "(" * 150 + "a" + ")" * 150 + " + a" * 150 + " FROM t")
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "- " * 300 + "a FROM t")
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "(" * 100000 + "a FROM t")                 # no RecursionError
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "- " * 100000 + "a FROM t")
    with pytest.raises(ParseError, match="nested too deeply"):
        parse("SELECT " + "SUM(" * 1000 + "a FROM t")


def test_render_round_trips_through_the_parser():
    rng = random.Random(5)

    def gen(d):
        if d == 0 or rng.random() < 0.2:
            return rng.choice([ColRef("a"), ColRef("b"), ColRef("t.c"), Lit(rng.choice([2, 7, -3, F(1, 3)]))])
        if rng.random() < 0.15:
            x = gen(d - 1)
            return Lit(-x.value) if isinstance(x, Lit) else Neg(x)
        return BinOp(rng.choice("+-*/"), gen(d - 1), gen(d - 1))
    for _ in range(300):
        e = gen(4)
        if isinstance(e, (ColRef, Lit)):
            continue
        text = render_expr(e)
        back = parse(f"SELECT {text} FROM t").projections[0]
        assert render_expr(back.expr if isinstance(back, ExprProj) else ColRef("?")) == text, text


# ── static validation ────────────────────────────────────────────────────────
@pytest.fixture
def schema():
    s = Schema()
    s.apply(parse("CREATE TABLE t (id INT PLAIN, name STR PLAIN, e RATIONAL ENC, "
                  "p INT PAIRED, q INT PAIRED, f INT FHE)"))
    return s


@pytest.mark.parametrize("sql", [
    "SELECT p*q*p FROM t", "SELECT p*q+e FROM t", "SELECT e/2+e FROM t", "SELECT p/q FROM t",
    "SELECT p*id FROM t", "SELECT e*id*id FROM t", "SELECT 100/p FROM t", "SELECT -p*q FROM t",
    "SELECT SUM(p*q*p) FROM t", "SELECT SUM(e+p*2)/COUNT(*) FROM t", "SELECT AVG(p/q) FROM t",
    "SELECT SUM(p)*SUM(q) FROM t", "SELECT SUM(p)/SUM(q)+1 FROM t", "SELECT COUNT(*)*2 FROM t",
    "SELECT id, SUM(p*q) FROM t GROUP BY id", "SELECT SUM(p*q) AS x FROM t WHERE id > 1",
    "SELECT AVG(id*2) FROM t",
])
def test_valid(schema, sql):
    schema.validate(parse(sql))


@pytest.mark.parametrize("sql,msg", [
    ("SELECT e*p FROM t", "PAIRED"),
    ("SELECT e*p*q FROM t", "PAIRED"),
    ("SELECT (e+p)*q FROM t", "PAIRED"),
    ("SELECT p/e FROM t", "PAIRED"),
    ("SELECT e/e FROM t", "PAIRED"),
    ("SELECT 5/e FROM t", "PAIRED"),
    ("SELECT p/0 FROM t", "division by zero"),
    ("SELECT p/(3-3) FROM t", "division by zero"),
    ("SELECT p/(FRAC(1,2)-FRAC(1,2)) FROM t", "division by zero"),
    ("SELECT id*2+id FROM t", "ENC/PAIRED"),
    ("SELECT id/id FROM t", "ENC/PAIRED"),
    ("SELECT SUM(id*2) FROM t", "SUM requires"),
    ("SELECT SUM(5) FROM t", "contains a column"),
    ("SELECT 1+2 FROM t", "no column"),
    ("SELECT p+SUM(q) FROM t", "mix"),
    ("SELECT name*2+p FROM t", "STR"),
    ("SELECT f*2+p FROM t", "FHE"),
    ("SELECT SUM(f)/COUNT(*) FROM t", "FHE"),
    (f"SELECT p/{2**127} FROM t", "out of range"),
    (f"SELECT p*{2**127}+p FROM t", "out of range"),
    ("SELECT SUM(p*q) FROM t ORDER BY id", "ORDER BY"),
    ("SELECT p*q*p FROM t LIMIT 3", "LIMIT"),
    ("SELECT nope*p*q FROM t", "no such column"),
])
def test_invalid(schema, sql, msg):
    with pytest.raises(ValidationError, match=msg):
        schema.validate(parse(sql))


def test_analysis_reports_depth_and_costs(schema):
    from torussql_parser import analyze_expr
    t = schema.tables["t"]

    def info(sql_expr):
        e = parse(f"SELECT {sql_expr} FROM t").projections[0].expr
        return analyze_expr(e, lambda ref: ("t", t.column(ref)))[1]
    assert info("p*q+e").depth == 1 and info("p*q+e").kind == "row"
    assert info("p*q*p*q").depth == 3 and info("p*q*p*q").ct_muls == 3
    assert info("(p*q)*(p*q)").depth == 2 and info("(p*q)*(p*q)").ct_muls == 3
    assert info("p/q").depth == 1 and info("p/q").inversions == 1
    assert info("100/p").depth == 0 and info("100/p").inversions == 1
    assert info("p/id").depth == 0
    assert info("p/4").inversions == 0 and info("p/4").depth == 0
    assert info("SUM(p*q*p)/COUNT(*)").kind == "agg"
    assert info("SUM(p*q)/SUM(p)").depth == 2


def test_constants_are_folded_exactly(schema):
    from torussql_parser import analyze_expr
    t = schema.tables["t"]
    e = parse("SELECT p / (1/3 + FRAC(1,6)) FROM t").projections[0].expr
    folded, _ = analyze_expr(e, lambda ref: ("t", t.column(ref)))
    assert folded == BinOp("/", ColRef("p"), Lit(F(1, 2)))
