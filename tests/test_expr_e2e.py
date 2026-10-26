# SPDX-License-Identifier: Apache-2.0
"""TorusSQL v0.6 expressions over the wire: a real keyless TCP server and the owner driver.

Arbitrary-depth products (Π_C: one batched owner round per ciphertext x ciphertext level),
division (public and owner-assisted), mixed + - * /, transactions, errors through the DB-API
layer, and an audit of everything the server process receives."""
import threading
from fractions import Fraction

import pytest

import torussql
from nokey_server import NoKeyTCPServer
from torusdb_core.protocol import N, encode, Owner

F = Fraction

ROWS = [(1, 5, 2, 3, 4, 5, F(1, 2), 10), (2, 5, -5, 7, 2, -1, F(-3, 4), -3),
        (3, 9, 6, -4, 3, 8, F(2, 3), 7), (4, 9, 0, 11, -6, 2, F(5), 0),
        (5, 9, 13, -2, 5, -7, F(-1, 7), 4)]


class Running:
    def __init__(self, db=None):
        self.srv = NoKeyTCPServer("127.0.0.1", 0, db)
        self.host, self.port = self.srv.address
        self.log = []                                    # (method, args) as the server receives them
        real = self.srv.engine.dispatch

        def spy(method, args, session=None):
            self.log.append((method, args))
            return real(method, args, session)
        self.srv.engine.dispatch = spy
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.srv.shutdown(); self.srv.server_close(); self.t.join(timeout=5)


@pytest.fixture
def server():
    s = Running()
    yield s
    s.stop()


def _lit(v):
    return f"FRAC({v.numerator},{v.denominator})" if isinstance(v, F) and v.denominator != 1 else str(int(v))


def seed(conn):
    conn.execute("CREATE TABLE t (id INT PLAIN, dept INT PLAIN, a INT PAIRED, b INT PAIRED, "
                 "c INT PAIRED, d INT PAIRED, r RATIONAL PAIRED, s RATIONAL ENC)")
    for row in ROWS:
        conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES (" +
                     ", ".join(_lit(v) for v in row) + ")")


def col(name):
    k = ["id", "dept", "a", "b", "c", "d", "r", "s"].index(name)
    return [row[k] for row in ROWS]


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_depth_two_and_three_products_over_the_wire(server, auth):
    with torussql.connect(server.host, server.port, authenticated=auth) as conn:
        seed(conn)
        a, b, c, d = col("a"), col("b"), col("c"), col("d")
        assert conn.execute("SELECT a*b*c FROM t").rows == [[[x * y * z for x, y, z in zip(a, b, c)]]]
        assert conn.client.last_expr_cost["mult_rounds"] == 2
        assert conn.execute("SELECT a*b*c*d FROM t").rows == \
            [[[w * x * y * z for w, x, y, z in zip(a, b, c, d)]]]
        assert conn.client.last_expr_cost["mult_rounds"] == 3
        assert conn.execute("SELECT SUM(a*b*c*d) FROM t").rows == \
            [[sum(w * x * y * z for w, x, y, z in zip(a, b, c, d))]]
        assert conn.execute("SELECT (a+b)*(c-d)*a + s/2 FROM t").rows == \
            [[[(x + y) * (z - w) * x + F(s, 2) for x, y, z, w, s in zip(a, b, c, d, col("s"))]]]


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_division_over_the_wire(server, auth):
    with torussql.connect(server.host, server.port, authenticated=auth) as conn:
        seed(conn)
        a, b, c, r, s = col("a"), col("b"), col("c"), col("r"), col("s")
        assert conn.execute("SELECT s/4 FROM t").rows == [[[F(x, 4) for x in s]]]
        assert conn.execute("SELECT a/b FROM t").rows == [[[F(x, y) for x, y in zip(a, b)]]]
        assert conn.execute("SELECT r/c, 12/c FROM t").rows == \
            [[[x / y for x, y in zip(r, c)], [F(12, y) for y in c]]]
        assert conn.execute("SELECT SUM(a*b)/COUNT(*) FROM t").rows == \
            [[F(sum(x * y for x, y in zip(a, b)), 5)]]
        assert conn.execute("SELECT SUM(a)/SUM(c), AVG(a*b) FROM t").rows == \
            [[F(sum(a), sum(c)), F(sum(x * y for x, y in zip(a, b)), 5)]]
        assert conn.execute("SELECT dept, SUM(a*b)/COUNT(*) FROM t GROUP BY dept ORDER BY dept").rows == \
            [[5, F(6 - 35, 2)], [9, F(-24 + 0 - 26, 3)]]


def test_errors_surface_through_the_dbapi_layer(server):
    conn = torussql.connect(server.host, server.port, max_mult_depth=2)
    seed(conn)
    cur = conn.cursor()
    cur.execute("UPDATE t SET b = 0 WHERE id = 3")
    with pytest.raises(torussql.DataError, match="division by zero"):
        cur.execute("SELECT a/b FROM t")
    cur.execute("SELECT a/b FROM t WHERE id <> 3")
    assert cur.fetchall() == [([F(2, 3), F(-5, 7), 0, F(13, -2)],)]
    with pytest.raises(torussql.ProgrammingError, match="division by zero"):
        cur.execute("SELECT a/0 FROM t")
    with pytest.raises(torussql.ProgrammingError, match="max_mult_depth"):
        cur.execute("SELECT a*b*c*d FROM t")
    with pytest.raises(torussql.ProgrammingError, match="PAIRED"):
        cur.execute("SELECT s*a*b FROM t")
    conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES "
                 f"(9, 9, {2 ** 70}, {2 ** 70}, 1, 1, 1, 1)")
    with pytest.raises(torussql.DataError):                          # OutOfBudget, never a wrong number
        cur.execute("SELECT a*b*c FROM t WHERE id = 9")
    conn.close()


def test_expressions_see_uncommitted_changes_and_rollback_restores(server):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        before = conn.execute("SELECT SUM(a*b*c) FROM t").rows
        conn.begin()
        conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES (6, 5, 10, 10, 10, 1, 1, 1)")
        conn.execute("UPDATE t SET b = 0 WHERE id = 1")
        assert conn.execute("SELECT SUM(a*b*c) FROM t").rows[0][0] == \
            before[0][0] + 1000 - 2 * 3 * 4
        with pytest.raises(torussql.DataError):                       # the open transaction sees b = 0 ...
            conn.execute("SELECT a/b FROM t")
        conn.rollback()
        assert conn.execute("SELECT SUM(a*b*c) FROM t").rows == before     # ... and rollback undoes it
        assert conn.execute("SELECT a/b FROM t").rows[0][0][0] == F(2, 3)
        with conn.transaction():
            conn.execute("UPDATE t SET a = 100 WHERE id = 1")
            assert conn.execute("SELECT a*b*c FROM t WHERE id = 1").rows == [[[100 * 3 * 4]]]
        assert conn.execute("SELECT a*b*c FROM t WHERE id = 1").rows == [[[1200]]]


def test_expressions_after_reconnect_with_the_same_vault(server, tmp_path):
    v = str(tmp_path / "x.vault")
    with torussql.connect(server.host, server.port, vault_path=v) as conn:
        seed(conn)
    with torussql.connect(server.host, server.port, vault_path=v) as conn:
        assert conn.execute("SELECT SUM(a*b*c)/COUNT(*) FROM t").rows == \
            [[F(sum(x * y * z for x, y, z in zip(col("a"), col("b"), col("c"))), 5)]]


def test_server_process_receives_only_blinded_data_for_expressions(server):
    """Everything the server process is sent while the owner runs multi-level products and
    divisions: no mask, no encoded plaintext, no intermediate, no inverse, no quotient, and only
    pre-existing RPC names."""
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        queries = ["SELECT a*b*c*d FROM t", "SELECT SUM(a*b*c*a) FROM t", "SELECT a/b FROM t",
                   "SELECT r/c * a FROM t", "SELECT SUM(a*b)/COUNT(*) FROM t",
                   "SELECT s/4 + a*b*c FROM t", "SELECT SUM(a+b-s/2) FROM t"]
        n0 = len(server.log)
        for q in queries:
            conn.execute(q)
        sent = server.log[n0:]
        masks = set(conn.client._masks.values())
        alpha = conn.client._alpha

    methods = {m for m, _ in sent}
    # (blinded_scaled_sum is the pre-existing authenticated-mode MAC check of a Π_lin sum)
    assert methods <= {"blinded_cells", "blinded_sum", "blinded_scaled_sum", "mult_combine_batch",
                       "matching_rowids", "plain_cells", "schema", "tables"}, methods
    assert "mult_combine_batch" in methods

    def ints(x, out):
        if isinstance(x, bool):
            return
        if isinstance(x, int):
            out.add(x)
        elif isinstance(x, str):
            try:
                out.add(int(x))
            except ValueError:
                pass
        elif isinstance(x, dict):
            for v in x.values():
                ints(v, out)
        elif isinstance(x, (list, tuple)):
            for v in x:
                ints(v, out)
    seen = set()
    for _m, args in sent:
        ints(args, seen)
    assert not (masks & seen) and alpha not in seen
    a, b, c, d, r, s = (col(k) for k in "abcdrs")
    secrets_ = set()
    for i in range(5):
        for v in (a[i], b[i], c[i], d[i], r[i], s[i], a[i] * b[i], a[i] * b[i] * c[i],
                  a[i] * b[i] * c[i] * d[i], a[i] * b[i] * c[i] * a[i], F(a[i], b[i]), F(1, b[i]),
                  r[i] / c[i], r[i] / c[i] * a[i], F(1, c[i]) if c[i] else 0, F(s[i], 4)):
            e = encode(v)
            if not 0 <= e < 1000:                          # tiny values would collide with row ids
                secrets_.add(e)
    assert not (secrets_ & seen), "an encoded plaintext/intermediate reached the server process"
    # the openings that did reach it are huge uniform-looking residues, not small numbers
    opened = []
    for m, args in sent:
        if m == "mult_combine_batch":
            opened += [int(x) for pair in args[0] for x in pair]
    assert opened
    assert sum(1 for x in opened if x > N // 100) > 0.95 * len(opened)


def test_fhe_columns_report_a_clear_error_over_the_wire(server):
    with torussql.connect(server.host, server.port) as conn:
        conn.execute("CREATE TABLE f (id INT PLAIN, x INT FHE, y INT FHE)")
        for sql in ["SELECT x*y*x FROM f", "SELECT x/2 FROM f", "SELECT SUM(x)/COUNT(*) FROM f"]:
            with pytest.raises(torussql.ProgrammingError, match="FHE"):
                conn.cursor().execute(sql)
