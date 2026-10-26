# SPDX-License-Identifier: Apache-2.0
"""v0.6.1 expressions over FHE columns — static analysis, no engine.

The accepted set is exactly: public affine combinations of depth-1 products of integer-LINEAR
operands, aggregated (SUM(L*R), SUM(..)*SUM(..)) or plain linear sums next to such a product.
Everything else is rejected with a message that says why, never evaluated."""
import re
from fractions import Fraction

import pytest

from torussql_parser import Schema, ValidationError, analyze_expr, parse
from torussql_parser import fhe_expr as fx
from torussql_parser.expr import _fold

F = Fraction


@pytest.fixture(autouse=True)
def _clean_grammar(monkeypatch):
    """The tests below exercise the grammar itself; the one spelling that stays rejected for v0.5
    conformance (`SUM(x*y)` of two bare FHE columns, see test_the_one_spelling_kept_rejected) is switched
    off here."""
    monkeypatch.setattr(fx, "REJECT_BARE_COLUMN_PRODUCT", False)


@pytest.fixture
def schema():
    s = Schema()
    s.apply(parse("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE, c INT FHE, d INT FHE, "
                  "p INT PAIRED, e RATIONAL ENC, w INT PLAIN, name STR PLAIN)"))
    s.apply(parse("CREATE TABLE u (id INT PLAIN, a INT FHE)"))
    return s


def info(schema, text, table="t"):
    t = schema.tables[table]
    e = parse(f"SELECT {text} FROM {table}").projections[0].expr
    return analyze_expr(e, lambda ref: (table, t.column(ref)))


@pytest.mark.parametrize("text,products", [
    ("SUM(a*b)", 1),
    ("SUM(a*a)", 1),
    ("SUM((a+2*b)*(c-d))", 1),
    ("SUM((a+1)*(b-3))", 1),
    ("SUM(-a*b)", 1),
    ("SUM(2*a*3*b)", 1),                                  # constants fold into the operands
    ("SUM(a)*SUM(b)", 1),
    ("(SUM(a)+2*SUM(b))*(SUM(c)-1)", 1),
    ("SUM(a+1)*SUM(b-3)", 1),                             # the constant is multiplied by the row count
    ("3*SUM(a)*SUM(b)", 1),
    ("2*SUM(a*b)-SUM(c*d)/4+7", 2),
    ("SUM(a*b)*2", 1),
    ("SUM(a*b*1099511627777)", 1),                         # a public scalar of the RESULT may be large
    ("SUM(a*b)/3", 1),
    ("SUM(a*b)+SUM(c)", 1),                               # a plain linear sum next to a product
    ("SUM(a*b+c)", 1),
    ("SUM(a*b-5)", 1),
    ("AVG(a*b)", 1),
    ("AVG(a*b)/2+1", 1),
    ("AVG(a*b+c*d)", 2),
    ("-SUM(a*b)", 1),
    ("SUM(a)*SUM(b)+SUM(c*d)", 2),
])
def test_accepted_shapes(schema, text, products):
    folded, i = info(schema, text)
    assert i.fhe and i.kind == "agg" and i.enc and i.depth == 0 and i.ct_muls == products
    assert i.inversions == 0


def test_constants_are_folded_and_the_structure_is_exposed(schema):
    t = schema.tables["t"]
    e = parse("SELECT SUM((a+2*b)*(c-d)) + 2*3 FROM t").projections[0].expr
    res, folded = fx.analyze(e, lambda r: ("t", t.column(r)), _fold)
    assert res.products == 1
    (coef, term), = [x for x in res.terms if x[1][0] == "sumprod"]
    _k, L, R = term
    assert L.coefs == {"a": 1, "b": 2} and R.coefs == {"c": 1, "d": -1}
    assert res.const == {0: 6}


@pytest.mark.parametrize("text,frag", [
    # depth: a product of products, or of a product and anything
    ("SUM(a*b)*SUM(c*d)", "product of products"),
    ("SUM(a*b*c)", "product of products"),
    ("SUM(a*b)*SUM(c)", "product of products"),
    ("SUM(a)*SUM(b)*SUM(c)", "product of products"),
    ("SUM((a*b)*(c*d))", "product of products"),
    ("SUM(a*b)*SUM(a*b)", "product of products"),
    # AVG / sums are not linear operands
    ("AVG(a)*AVG(b)", "factor of a product"),
    ("(SUM(a)+SUM(b))*AVG(c)", "factor of a product"),
    # bare, per-row, no product
    ("a+1", "FHE column"),
    ("SUM(a)+SUM(b)", "FHE column"),
    ("SUM(a)*2", "FHE column"),
    ("SUM(a)+3", "FHE column"),
    # division
    ("SUM(a*b)/SUM(c)", "FHE column"),
    ("SUM(a)/COUNT(*)", "FHE column"),
    ("SUM(a*b)/0", "division by zero"),
    ("SUM(a/2*b)", "not an integer"),
    ("SUM((a+b)/2*c)", "not an integer"),
    # other policies in the same expression
    ("SUM(a*p)", "FHE column"),
    ("SUM(a)*p", "FHE column"),
    ("SUM(a*b)+SUM(p)", "FHE column"),
    ("SUM(a*b)+SUM(e)", "FHE column"),
    ("SUM(a*b)*w", "FHE column"),
    ("SUM(a*b)+id", "FHE column"),
    ("p*SUM(a*b)", "FHE column"),
    ("SUM(a*name)", "FHE column"),
    # bounds
    ("SUM(1099511627777*a*b)", "2^40"),
    ("SUM((a+1099511627777)*b)", "2^40"),
    ("SUM(a)*(SUM(b)+1099511627777)", "2^40"),
    ("SUM((a-a)*b)", "no FHE column"),
    # a constant product / aggregate of constants
    ("SUM(5)*SUM(a)", "column"),
])
def test_rejection_matrix(schema, text, frag):
    with pytest.raises(ValidationError, match=re.escape(frag)):
        info(schema, text)


def test_operand_width_is_bounded(schema):
    s = Schema()
    cols = ", ".join(f"c{i} INT FHE" for i in range(18))
    s.apply(parse(f"CREATE TABLE w (id INT PLAIN, {cols})"))
    t = s.tables["w"]
    lin = "+".join(f"c{i}" for i in range(17))
    e = parse(f"SELECT SUM(({lin})*c17) FROM w").projections[0].expr
    with pytest.raises(ValidationError, match="at most 16"):
        analyze_expr(e, lambda r: ("w", t.column(r)))
    lin = "+".join(f"c{i}" for i in range(16))
    e = parse(f"SELECT SUM(({lin})*c17) FROM w").projections[0].expr
    assert analyze_expr(e, lambda r: ("w", t.column(r)))[1].fhe


def test_per_row_products_stay_unavailable(schema):
    # the projection `a * b` of two FHE columns is rejected by the validator (unchanged since v0.5)
    with pytest.raises(ValidationError):
        schema.validate(parse("SELECT a * b FROM t"))
    # ... and an aggregate-free product written as an expression names the way out
    with pytest.raises(ValidationError, match="aggregate it"):
        info(schema, "(a+1)*(b+1)")
    with pytest.raises(ValidationError, match="aggregate it"):
        info(schema, "(a+1)*b+2")


def test_pre_v061_rejections_keep_their_text(schema):
    old = ("FHE column 'a' cannot be used inside an arithmetic expression "
           "(FHE columns support SUM, AVG, k*SUM and DOT only)")
    for text in ("a+1", "SUM(a)/COUNT(*)", "a*2+p"):
        with pytest.raises(ValidationError) as ei:
            info(schema, text)
        assert str(ei.value) == old, text


def test_validator_accepts_and_rejects_through_schema_validate(schema):
    schema.validate(parse("SELECT SUM((a+2*b)*(c-d)) FROM t WHERE id > 3"))
    schema.validate(parse("SELECT w, SUM(a*b) FROM t GROUP BY w"))
    schema.validate(parse("SELECT SUM(a)*SUM(b), COUNT(*) FROM t"))
    with pytest.raises(ValidationError):
        schema.validate(parse("SELECT SUM(a*b)*SUM(c*d) FROM t"))
    with pytest.raises(ValidationError, match="FHE"):
        schema.validate(parse("SELECT SUM(a*p) FROM t"))


def test_fhe_columns_cannot_be_joined(schema):
    with pytest.raises(ValidationError, match="FHE column"):
        schema.validate(parse("SELECT SUM(x.a*y.a) FROM t x JOIN u y ON x.id = y.id"))


def test_non_fhe_expressions_are_unchanged(schema):
    folded, i = info(schema, "p*p+e")
    assert not i.fhe and i.depth == 1
    with pytest.raises(ValidationError, match="PAIRED"):
        info(schema, "e*e+p")


def test_unknown_columns_still_report_themselves(schema):
    with pytest.raises(ValidationError, match="no such column"):
        info(schema, "SUM(a*nope)")


def test_the_one_spelling_kept_rejected(schema, monkeypatch):
    """`SUM(x*y)` / `SUM(x*x)` over two bare FHE columns is `DOT(x, y)`. The pre-v0.6.1 conformance suite and the
    cross-language vectors pin it as rejected with the old text, so it stays rejected by default; every neighbouring
    shape is accepted. Flip fx.REJECT_BARE_COLUMN_PRODUCT to lift it."""
    monkeypatch.setattr(fx, "REJECT_BARE_COLUMN_PRODUCT", True)
    old = ("FHE column 'a' cannot be used inside an arithmetic expression "
           "(FHE columns support SUM, AVG, k*SUM and DOT only)")
    for text in ("SUM(a*b)", "SUM(a*a)"):
        with pytest.raises(ValidationError) as ei:
            info(schema, text)
        assert str(ei.value) == old
    schema.validate(parse("SELECT DOT(a, b) FROM t"))
    for text in ("SUM((a+0)*b)", "SUM(a*b)*1", "SUM(a*b+0)", "SUM(2*a*b)", "SUM(a*b)/1"):
        assert info(schema, text)[1].fhe, text
