# SPDX-License-Identifier: Apache-2.0
"""End-to-end no-key delegation over TCP: keyless server ↔ owner driver.

Proves the deployed architecture — the server process holds no keys and only
blinded scalars; the driver holds the mask vault; encrypted SUM/AVG/DOT are
computed on blinded data and unblinded at the owner. Includes server-restart
persistence (blinded snapshot) and client mask-vault persistence.
"""
import threading
from fractions import Fraction

import pytest

from torussql.nokey import connect
from nokey_server import NoKeyTCPServer


class RunningServer:
    def __init__(self, db_path=None):
        self.srv = NoKeyTCPServer("127.0.0.1", 0, db_path)
        self.host, self.port = self.srv.address
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.srv.shutdown(); self.srv.server_close(); self.t.join(timeout=5)


@pytest.fixture
def server():
    s = RunningServer()
    yield s
    s.stop()


def _seed(conn):
    conn.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, "
                 "salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)")
    for (i, d, s, r, h) in [(1, 5, 8000, 50, 40), (2, 5, 9000, 60, 35),
                            (3, 9, 7000, 45, 40)]:
        conn.execute(f"INSERT INTO emp (id, dept, salary, rate, hours) "
                     f"VALUES ({i}, {d}, FRAC({s},1), {r}, {h})")


def test_encrypted_sum_avg_over_the_wire(server):
    with connect(server.host, server.port) as conn:
        _seed(conn)
        assert conn.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
        assert conn.execute("SELECT AVG(salary) FROM emp WHERE dept = 5").rows \
            == [[8500]]


def test_encrypted_dot_over_the_wire(server):
    with connect(server.host, server.port) as conn:
        _seed(conn)
        assert conn.execute("SELECT DOT(rate, hours) FROM emp").rows == [[5900]]


def test_plain_and_count_and_order(server):
    with connect(server.host, server.port) as conn:
        _seed(conn)
        assert conn.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
        assert conn.execute("SELECT id, dept FROM emp ORDER BY id DESC").rows \
            == [[3, 9], [2, 5], [1, 5]]


def test_authenticated_mode_over_the_wire(server):
    """The integrity MAC (no-key §IX) works end-to-end: the owner enables it,
    the keyless server stores/aggregates the parallel MAC column, results
    verify."""
    with connect(server.host, server.port, authenticated=True) as conn:
        _seed(conn)
        assert conn.client.authenticated
        assert conn.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
        assert conn.execute("SELECT 12 * SUM(salary) FROM emp").rows == [[288000]]


def test_group_by_update_delete_over_the_wire(server):
    with connect(server.host, server.port) as conn:
        _seed(conn)
        assert conn.execute("SELECT dept, SUM(salary), COUNT(*) FROM emp "
                            "GROUP BY dept ORDER BY dept").rows \
            == [[5, 17000, 2], [9, 7000, 1]]
        conn.execute("UPDATE emp SET salary = FRAC(1000,1) WHERE id = 1")
        assert conn.execute("SELECT SUM(salary) FROM emp WHERE dept = 5").rows \
            == [[10000]]
        assert conn.execute("DELETE FROM emp WHERE dept = 9") == 1
        assert conn.execute("SELECT COUNT(*) FROM emp").rows == [[2]]


def test_server_holds_no_keys(server):
    """The live server's engine state contains no key/secret/mask."""
    blob = repr(vars(server.srv.engine.srv))
    for forbidden in ("secret", "keypair", "mask", "sk", "pk"):
        assert forbidden not in blob


def test_server_stores_only_blinded_scalars(server):
    with connect(server.host, server.port) as conn:
        _seed(conn)
    # reach into the live server's storage: the salary cells are full-width
    # one-time-padded scalars, never the small plaintext encodings.
    from ecfhe.nokey import encode
    srv = server.srv.engine.srv
    plain = {encode(8000), encode(9000), encode(7000)}
    stored = {srv.blinded_cell("emp", "salary", i) for i in range(3)}
    assert stored.isdisjoint(plain)
    assert all(x > 2 ** 200 for x in stored)


def test_persistence_server_restart_and_client_masks(tmp_path):
    dbp = str(tmp_path / "nokey.db")
    maskp = str(tmp_path / "masks.json")

    s1 = RunningServer(db_path=dbp)
    try:
        with connect(s1.host, s1.port) as conn:
            _seed(conn)
            assert conn.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
            conn.save_masks(maskp)               # owner persists its mask vault
    finally:
        s1.stop()

    # New server process from the blinded snapshot; new client loads its masks.
    s2 = RunningServer(db_path=dbp)
    try:
        with connect(s2.host, s2.port) as conn:
            conn.load_masks(maskp)
            assert conn.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
            assert conn.execute("SELECT DOT(rate, hours) FROM emp").rows == [[5900]]
    finally:
        s2.stop()
