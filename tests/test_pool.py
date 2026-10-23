# SPDX-License-Identifier: Apache-2.0
"""Thread-safe connections and the connection pool."""
from __future__ import annotations

import threading

import pytest

import torussql
from torussql.pool import ConnectionPool, PoolTimeout
from test_ops import Running


@pytest.fixture
def srv():
    s = Running()
    yield s
    s.stop()


def test_one_connection_can_be_shared_between_threads(srv):
    c = srv.connect()
    c.execute("CREATE TABLE t (w INT PLAIN, n INT PLAIN)")
    errs = []

    def work(w):
        try:
            for n in range(40):
                c.execute(f"INSERT INTO t (w, n) VALUES ({w}, {n})")
            with c.transaction():                       # holds the connection for the whole tx
                c.execute(f"INSERT INTO t (w, n) VALUES ({w}, 1000)")
                c.execute(f"INSERT INTO t (w, n) VALUES ({w}, 1001)")
        except Exception as exc:                        # noqa: BLE001
            errs.append(exc)
    ths = [threading.Thread(target=work, args=(w,)) for w in range(6)]
    [t.start() for t in ths]; [t.join(60) for t in ths]
    assert not errs, errs
    assert c.execute("SELECT COUNT(*) FROM t").rows == [[6 * 42]]
    assert torussql.threadsafety == 2
    c.close()


def test_pool_reuses_limits_and_cleans_up(srv):
    pool = ConnectionPool(3, acquire_timeout=0.5, host=srv.host, port=srv.port,
                          trust_server_schema=True)
    with pool.connection() as c:
        c.execute("CREATE TABLE t (id INT PLAIN)")
    seen = set()

    def work(i):
        with pool.connection() as c:
            seen.add(id(c))
            c.execute(f"INSERT INTO t (id) VALUES ({i})")
    ths = [threading.Thread(target=work, args=(i,)) for i in range(30)]
    [t.start() for t in ths]; [t.join(30) for t in ths]
    assert len(seen) <= 3
    with pool.connection() as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[30]]
        # a connection returned mid-transaction is rolled back, not leaked
        c.begin(); c.execute("INSERT INTO t (id) VALUES (999)")
    with pool.connection() as c:
        assert c.execute("SELECT COUNT(*) FROM t WHERE id = 999").rows == [[0]]
    held = [pool._acquire() for _ in range(3)]
    with pytest.raises(PoolTimeout):
        with pool.connection():
            pass
    for conn, born in held:
        pool._idle.put((conn, born))
    pool.close()
    with pytest.raises(torussql.InterfaceError):
        with pool.connection():
            pass


def test_pool_replaces_dead_connections(srv):
    pool = ConnectionPool(2, host=srv.host, port=srv.port, trust_server_schema=True)
    with pool.connection() as c:
        c.execute("CREATE TABLE t (id INT PLAIN)")
        c._wire.close()                                  # kill the socket under the pool
    with pool.connection() as c:                         # the dead one is discarded
        c.execute("INSERT INTO t (id) VALUES (1)")
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[1]]
    pool.close()


def test_vault_pool_larger_than_one_is_refused(srv, tmp_path):
    with pytest.raises(torussql.InterfaceError, match="single owner"):
        ConnectionPool(2, host=srv.host, port=srv.port, vault_path=str(tmp_path / "v"))
    ConnectionPool(1, host=srv.host, port=srv.port, vault_path=str(tmp_path / "v")).close()
