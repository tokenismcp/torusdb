# SPDX-License-Identifier: Apache-2.0
"""SQL conveniences desugared/evaluated identically by validator, engine and wire:
BETWEEN, NOT IN, IS [NOT] NULL, [NOT] LIKE, OFFSET, IF [NOT] EXISTS."""
from __future__ import annotations

import pytest

import torussql
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torussql_parser import ParseError, Schema, ValidationError, parse
from test_ops import Running

ROWS = [(1, "alice", 10), (2, "bob", 20), (3, "carol", None), (4, "alicia", 40),
        (5, None, 50), (6, "a_b%c", 60)]


def seeded(c):
    c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN, age INT PLAIN, v INT ENC)")
    for i, n, a in ROWS:
        nm = "NULL" if n is None else "'" + n + "'"
        ag = "NULL" if a is None else a
        c.execute(f"INSERT INTO t (id, name, age, v) VALUES ({i}, {nm}, {ag}, {i * 100})")


def ids(c, where):
    return [r[0] for r in c.execute(f"SELECT id FROM t WHERE {where} ORDER BY id").rows]


CASES = [
    ("age BETWEEN 20 AND 50", [2, 4, 5]),
    ("age BETWEEN 10 AND 10", [1]),
    ("id NOT IN (1, 2, 3)", [4, 5, 6]),
    ("age NOT IN (10, 20)", [4, 5, 6]),                  # NULL age is never "not in"
    ("age IS NULL", [3]),
    ("age IS NOT NULL", [1, 2, 4, 5, 6]),
    ("name IS NULL", [5]),
    ("name LIKE 'ali%'", [1, 4]),
    ("name LIKE '_ob'", [2]),
    ("name LIKE '%c%'", [1, 3, 4, 6]),
    ("name NOT LIKE 'ali%'", [2, 3, 6]),                 # NULL name matches neither
    ("name LIKE 'a\\_b%'", []),                          # no ESCAPE: backslash is literal
    ("name LIKE 'a_b%c'", [6]),
    ("age IS NULL OR name LIKE 'bob'", [2, 3]),
    ("age BETWEEN 10 AND 40 AND name NOT LIKE '%a%'", [2]),
]


@pytest.mark.parametrize("where,expected", CASES)
def test_predicates_in_process(where, expected):
    c = NoKeyClient(NoKeyServer())
    seeded(c)
    assert [r[0] for r in c.execute(f"SELECT id FROM t WHERE {where} ORDER BY id").rows] == expected


@pytest.mark.parametrize("storage", ["memory", "disk"])
def test_predicates_over_the_wire_with_and_without_indexes(tmp_path, storage):
    s = Running(db=str(tmp_path / "db"), storage=storage)
    try:
        with s.connect() as c:
            seeded(c)
            for _ in range(2):                           # second round: with indexes
                for where, expected in CASES:
                    assert ids(c, where) == expected, where
                c.execute("CREATE INDEX ON t (age)")
                c.execute("CREATE INDEX ON t (name)")
                c.execute("CREATE INDEX ON t (id)")
            assert c.execute("DELETE FROM t WHERE age BETWEEN 40 AND 60") == 3
            assert ids(c, "age IS NOT NULL") == [1, 2]
            c.execute("UPDATE t SET age = 99 WHERE name LIKE 'bob'")
            assert ids(c, "age BETWEEN 90 AND 100") == [2]
    finally:
        s.stop()


def test_offset_and_limit():
    c = NoKeyClient(NoKeyServer())
    seeded(c)
    q = "SELECT id FROM t ORDER BY id"
    assert [r[0] for r in c.execute(q + " LIMIT 2 OFFSET 1").rows] == [2, 3]
    assert [r[0] for r in c.execute(q + " OFFSET 4").rows] == [5, 6]
    assert c.execute(q + " LIMIT 5 OFFSET 99").rows == []
    with pytest.raises(Exception):
        c.execute("SELECT 2 * v FROM t OFFSET 1")        # per-row encrypted expression


def test_if_exists_and_if_not_exists():
    c = NoKeyClient(NoKeyServer())
    c.execute("CREATE TABLE IF NOT EXISTS t (id INT PLAIN)")
    c.execute("INSERT INTO t (id) VALUES (1)")
    c.execute("CREATE TABLE IF NOT EXISTS t (id INT PLAIN)")      # no-op, data kept
    assert c.execute("SELECT COUNT(*) FROM t").rows == [[1]]
    with pytest.raises(Exception, match="already exists"):
        c.execute("CREATE TABLE t (id INT PLAIN)")
    c.execute("DROP TABLE IF EXISTS nope")
    c.execute("DROP TABLE IF EXISTS t")
    with pytest.raises(Exception, match="no such table"):
        c.execute("DROP TABLE t")


def test_left_join_is_null_finds_unmatched_rows():
    c = NoKeyClient(NoKeyServer())
    c.execute("CREATE TABLE a (k INT PLAIN)")
    c.execute("CREATE TABLE b (k INT PLAIN, w INT PLAIN)")
    for k in (1, 2, 3):
        c.execute(f"INSERT INTO a (k) VALUES ({k})")
    c.execute("INSERT INTO b (k, w) VALUES (2, 7)")
    rows = c.execute("SELECT a.k FROM a LEFT JOIN b ON a.k = b.k WHERE b.w IS NULL ORDER BY a.k").rows
    assert [r[0] for r in rows] == [1, 3]


def test_validator_parity():
    sch = Schema()
    sch.apply(parse("CREATE TABLE t (id INT PLAIN, name STR PLAIN, v INT ENC)"))
    for ok in ("SELECT id FROM t WHERE name LIKE 'a%'", "SELECT id FROM t WHERE id BETWEEN 1 AND 2",
               "SELECT id FROM t WHERE name IS NULL", "SELECT id FROM t WHERE id NOT IN (1, 2)",
               "SELECT id FROM t LIMIT 1 OFFSET 2", "CREATE TABLE IF NOT EXISTS t (x INT PLAIN)",
               "DROP TABLE IF EXISTS zzz"):
        sch.validate(parse(ok))
    for bad in ("SELECT id FROM t WHERE id LIKE '1%'", "SELECT id FROM t WHERE name LIKE 5",
                "SELECT id FROM t WHERE v IS NULL", "SELECT id FROM t WHERE v BETWEEN 1 AND 2",
                "DROP TABLE zzz", "SELECT 2 * v FROM t OFFSET 1"):
        with pytest.raises(ValidationError):
            sch.validate(parse(bad))
    for bad in ("SELECT id FROM t WHERE id BETWEEN 1", "SELECT id FROM t WHERE id IS 5",
                "SELECT id FROM t OFFSET -1", "SELECT id FROM t WHERE id NOT 5"):
        with pytest.raises(ParseError):
            parse(bad)


def test_if_not_exists_is_atomic_on_the_server_and_adopts_unknown_tables(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        with s.connect() as a, s.connect() as b:
            a.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
            call = a._wire.call
            cols = [["id", "int", "plain"], ["v", "int", "encrypted"]]
            assert call("create", ["t", cols, True]) is False          # exists: no error, no change
            assert call("create", ["u", cols, True]) is None          # created
            with pytest.raises(Exception, match="already exists"):
                call("create", ["u", cols])
            assert call("drop", ["nope", True]) is False
            with pytest.raises(Exception, match="no such table"):
                call("drop", ["nope"])
            # a client that never heard of `t` adopts the server's schema (read-only)
            b.execute("CREATE TABLE IF NOT EXISTS t (id INT PLAIN, v INT ENC)")
            assert b.client._schema["t"] == [("id", "int", "plain"), ("v", "int", "encrypted")]
            with pytest.raises(Exception, match="learned from the server"):
                b.execute("INSERT INTO t (id, v) VALUES (1, 2)")
            b.execute("DROP TABLE IF EXISTS u")
            assert "u" not in call("tables", [])
    finally:
        s.stop()
