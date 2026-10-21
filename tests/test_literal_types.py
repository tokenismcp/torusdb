# SPDX-License-Identifier: Apache-2.0
"""Literal type rules: the open validator and the closed planner reject the
same statements, and nothing ill-typed is ever stored."""
import pytest

from torussql_parser.errors import ValidationError
from torussql_parser.parser import parse
from torussql_parser.validate import Schema
from ecfhe_query.nokey_engine import NoKeyClient, NoKeyServer

DDL = "CREATE TABLE t (i INT PLAIN, s STR PLAIN, e INT ENC, r RATIONAL ENC, q RATIONAL PLAIN)"

BAD = [
    "INSERT INTO t (i,s,e,r,q) VALUES ('abc', 'x', 1, 1, 1)",      # string -> INT
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 5, 1, 1, 1)",            # number -> STR
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', NULL, 1, 1)",       # NULL -> ENC
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', 1, NULL, 1)",
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', 'q', 1, 1)",        # string -> ENC
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', FRAC(1,2), 1, 1)",  # fraction -> INT
    "INSERT INTO t (i,s,e,r,q) VALUES (FRAC(3,2), 'x', 1, 1, 1)",
    "UPDATE t SET e = 'z'", "UPDATE t SET s = 3", "UPDATE t SET e = NULL",
    "SELECT i FROM t WHERE i = 'abc'", "SELECT i FROM t WHERE s < 5",
    "SELECT i FROM t WHERE s IN (1, 2)", "DELETE FROM t WHERE i = 'x'",
]
GOOD = [
    "INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', 1, 1, 1)",
    "INSERT INTO t (i,s,e,r,q) VALUES (NULL, NULL, 2, FRAC(1,3), FRAC(1,3))",
    "INSERT INTO t (i,s,e,r,q) VALUES (FRAC(4,2), 'x', 1, 1, 1)",   # integral FRAC -> INT
    "UPDATE t SET i = NULL", "UPDATE t SET r = 5",
    "SELECT i FROM t WHERE i = 1", "SELECT i FROM t WHERE s = 'x'",
    "SELECT i FROM t WHERE q > 0",
]


@pytest.fixture
def pair():
    sch = Schema(); sch.apply(parse(DDL))
    cli = NoKeyClient(NoKeyServer()); cli.execute(DDL)
    return sch, cli


@pytest.mark.parametrize("sql", BAD)
def test_both_layers_reject(pair, sql):
    sch, cli = pair
    with pytest.raises(ValidationError):
        sch.validate(parse(sql))
    with pytest.raises(Exception) as ei:
        cli.execute(sql)
    assert type(ei.value).__name__ in ("PlanError",), ei.value
    assert cli.execute("SELECT COUNT(*) FROM t").rows == [[0]]      # nothing stored


@pytest.mark.parametrize("sql", GOOD)
def test_both_layers_accept(pair, sql):
    sch, cli = pair
    sch.validate(parse(sql))
    cli.execute("INSERT INTO t (i,s,e,r,q) VALUES (1, 'x', 1, 1, 1)")
    cli.execute(sql)


def test_integral_frac_is_stored_as_int(pair):
    _, cli = pair
    cli.execute("INSERT INTO t (i,s,e,r,q) VALUES (FRAC(4,2), 'x', 1, 1, 1)")
    row = cli.execute("SELECT i FROM t").rows[0][0]
    assert row == 2 and type(row) is int
