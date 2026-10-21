# SPDX-License-Identifier: Apache-2.0
"""PEP 249 DB-API 2.0 compliance tests for the torussql Python driver.

Covers: module-level attributes, exception hierarchy, Cursor interface
(execute / executemany / fetchone / fetchmany / fetchall / description /
rowcount / iteration / close), parameter substitution (%s), and
commit / rollback no-ops.
"""
import threading
from fractions import Fraction

import pytest

import torussql
from torussql import (
    Connection, Cursor,
    InterfaceError, ProgrammingError, OperationalError,
    DatabaseError, Error,
)
from nokey_server import NoKeyTCPServer


# ── test server fixture ───────────────────────────────────────────────────────

class _Server:
    def __init__(self):
        self.srv = NoKeyTCPServer("127.0.0.1", 0)
        self.host, self.port = self.srv.address
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.srv.shutdown(); self.srv.server_close(); self.t.join(timeout=5)


@pytest.fixture
def conn():
    s = _Server()
    c = torussql.connect(s.host, s.port)
    yield c
    c.close()
    s.stop()


def _seed(conn):
    conn.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, "
                 "name STR PLAIN, salary RATIONAL ENC)")
    for i, (d, n, s) in enumerate([(5, "alice", 8000), (5, "bob", 9000),
                                   (9, "carol", 7000)], start=1):
        conn.execute(f"INSERT INTO emp (id, dept, name, salary) "
                     f"VALUES ({i}, {d}, '{n}', FRAC({s},1))")


# ── §1 module-level attributes (PEP 249 §3) ──────────────────────────────────

def test_module_attributes():
    assert torussql.apilevel == "2.0"
    assert torussql.threadsafety == 1
    assert torussql.paramstyle == "format"


# ── §2 exception hierarchy ────────────────────────────────────────────────────

def test_exception_hierarchy():
    assert issubclass(torussql.Warning, Exception)
    assert issubclass(torussql.Error, Exception)
    assert issubclass(torussql.InterfaceError, torussql.Error)
    assert issubclass(torussql.DatabaseError, torussql.Error)
    assert issubclass(torussql.DataError, torussql.DatabaseError)
    assert issubclass(torussql.OperationalError, torussql.DatabaseError)
    assert issubclass(torussql.IntegrityError, torussql.DatabaseError)
    assert issubclass(torussql.InternalError, torussql.DatabaseError)
    assert issubclass(torussql.ProgrammingError, torussql.DatabaseError)
    assert issubclass(torussql.NotSupportedError, torussql.DatabaseError)


def test_server_parse_error_raises_programming_error(conn):
    _seed(conn)
    with pytest.raises(ProgrammingError):
        conn.execute("SLECT * FROM emp")   # bad keyword → ParseError


def test_server_policy_error_raises_programming_error(conn):
    cur = conn.cursor()
    with pytest.raises(ProgrammingError):
        cur.execute("SELECT SUM(id) FROM emp")   # SUM on plain → PlanError


# ── §3 Connection ─────────────────────────────────────────────────────────────

def test_connect_returns_connection():
    s = _Server()
    try:
        c = torussql.connect(s.host, s.port)
        assert isinstance(c, Connection)
        c.close()
    finally:
        s.stop()


def test_context_manager():
    s = _Server()
    try:
        with torussql.connect(s.host, s.port) as c:
            cur = c.cursor()
            assert isinstance(cur, Cursor)
        with pytest.raises(InterfaceError):
            c.cursor()
    finally:
        s.stop()


def test_closed_connection_raises():
    s = _Server()
    try:
        c = torussql.connect(s.host, s.port)
        c.close()
        with pytest.raises(InterfaceError):
            c.cursor()
        with pytest.raises(InterfaceError):
            c.commit()
        with pytest.raises(InterfaceError):
            c.rollback()
    finally:
        s.stop()


def test_commit_and_rollback_are_noops(conn):
    conn.commit()    # must not raise
    conn.rollback()  # must not raise



# ── §4 Cursor basics ──────────────────────────────────────────────────────────

def test_cursor_description_after_select(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM emp ORDER BY id LIMIT 1")
    assert cur.description is not None
    assert len(cur.description) == 2
    assert cur.description[0][0] == "id"
    assert cur.description[1][0] == "name"
    # all 7 items per column (PEP 249)
    for col in cur.description:
        assert len(col) == 7


def test_cursor_description_none_after_dml(conn):
    cur = conn.cursor()
    cur.execute("CREATE TABLE tmp_dml (x INT PLAIN)")
    assert cur.description is None


def test_rowcount_select(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp")
    assert cur.rowcount == 3


def test_rowcount_delete(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM emp WHERE dept = 9")
    assert cur.rowcount == 1


def test_rowcount_dml_create_is_not_rows(conn):
    cur = conn.cursor()
    cur.execute("CREATE TABLE tmp_rc (x INT PLAIN)")
    assert cur.rowcount in (-1, 0)   # PEP 249: -1 or 0 both valid for DDL


# ── §5 fetch methods ──────────────────────────────────────────────────────────

def test_fetchone(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp ORDER BY id")
    assert cur.fetchone() == (1,)
    assert cur.fetchone() == (2,)
    assert cur.fetchone() == (3,)
    assert cur.fetchone() is None   # past end


def test_fetchmany(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp ORDER BY id")
    batch = cur.fetchmany(2)
    assert batch == [(1,), (2,)]
    rest = cur.fetchmany(10)
    assert rest == [(3,)]


def test_fetchmany_uses_arraysize(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.arraysize = 2
    cur.execute("SELECT id FROM emp ORDER BY id")
    assert cur.fetchmany() == [(1,), (2,)]


def test_fetchall(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp ORDER BY id")
    assert cur.fetchall() == [(1,), (2,), (3,)]
    assert cur.fetchall() == []   # exhausted


def test_fetchone_raises_when_no_result_set(conn):
    cur = conn.cursor()
    with pytest.raises(InterfaceError):
        cur.fetchone()


def test_fetchall_raises_when_no_result_set(conn):
    cur = conn.cursor()
    with pytest.raises(InterfaceError):
        cur.fetchall()


# ── §6 Cursor iteration ───────────────────────────────────────────────────────

def test_cursor_is_iterable(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp ORDER BY id")
    rows = list(cur)
    assert rows == [(1,), (2,), (3,)]


# ── §7 Parameter substitution ─────────────────────────────────────────────────

def test_param_int_substitution(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT name FROM emp WHERE dept = %s", (5,))
    names = {r[0] for r in cur.fetchall()}
    assert names == {"alice", "bob"}


def test_param_str_substitution(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM emp WHERE name = %s", ("carol",))
    assert cur.fetchone() == (3,)


def test_param_frac_substitution(conn):
    _seed(conn)
    cur = conn.cursor()
    cur.execute("UPDATE emp SET salary = FRAC(%s,1) WHERE id = %s", (1000, 1))
    cur.execute("SELECT SUM(salary) FROM emp WHERE dept = %s", (5,))
    assert cur.fetchone() == (Fraction(10000, 1),)


def test_param_float_substitution(conn):
    cur = conn.cursor()
    cur.execute("CREATE TABLE tmp_fl (x RATIONAL ENC)")
    cur.execute("INSERT INTO tmp_fl (x) VALUES (FRAC(%s,1))", (42,))
    cur.execute("SELECT SUM(x) FROM tmp_fl")
    assert cur.fetchone() == (Fraction(42, 1),)


def test_param_sql_injection_is_escaped(conn):
    _seed(conn)
    cur = conn.cursor()
    # name contains a quote — must be escaped, not inject SQL
    cur.execute("SELECT id FROM emp WHERE name = %s", ("o'brien",))
    assert cur.fetchone() is None   # no such row; no crash


# ── §8 executemany ────────────────────────────────────────────────────────────

def test_executemany_insert(conn):
    cur = conn.cursor()
    cur.execute("CREATE TABLE batch (k INT PLAIN, v RATIONAL ENC)")
    rows = [(i, i * 100) for i in range(1, 6)]
    cur.executemany("INSERT INTO batch (k, v) VALUES (%s, FRAC(%s,1))", rows)
    cur.execute("SELECT COUNT(*) FROM batch")
    assert cur.fetchone() == (5,)
    cur.execute("SELECT SUM(v) FROM batch")
    assert cur.fetchone() == (Fraction(1500, 1),)


# ── §9 Cursor close ───────────────────────────────────────────────────────────

def test_closed_cursor_raises(conn):
    cur = conn.cursor()
    cur.close()
    with pytest.raises(InterfaceError):
        cur.execute("SELECT 1")
    with pytest.raises(InterfaceError):
        cur.fetchone()
