# SPDX-License-Identifier: Apache-2.0
"""WAL-shipping replication: bootstrap, streaming, read-only, restart, promotion."""
from __future__ import annotations

import time

import pytest

import torussql
from test_ops import ADMIN, TOKENS, Running

REPL = {"token": ADMIN}


def wait_for(cond, timeout=15.0, what="condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if cond():
                return
        except Exception:                                # noqa: BLE001
            pass
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def count(srv, table="t"):
    with srv.connect(token=ADMIN) as c:
        return c.execute(f"SELECT COUNT(*) FROM {table}").rows[0][0]


def replica(primary, db, **cfg):
    return Running(db=db, tokens=dict(TOKENS), replica_of=(primary.host, primary.port),
                   repl_conn=dict(REPL), repl_poll=0.3, **cfg)


@pytest.fixture
def pair(tmp_path):
    p = Running(db=str(tmp_path / "p"), tokens=dict(TOKENS))
    with p.connect(token=ADMIN) as c:
        c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN)")
        for i in range(20):
            c.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'a')")
    r = replica(p, str(tmp_path / "r"))
    yield p, r, tmp_path
    for x in (r, p):
        try:
            x.stop()
        except Exception:                                # noqa: BLE001
            pass


def test_replica_bootstraps_streams_and_is_read_only(pair):
    p, r, _ = pair
    wait_for(lambda: count(r) == 20, what="bootstrap")
    with p.connect(token=ADMIN) as c:
        for i in range(20, 50):
            c.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'b')")
        c.execute("UPDATE t SET name = 'upd' WHERE id = 3")
        c.execute("DELETE FROM t WHERE id = 4")
        c.begin()
        c.execute("INSERT INTO t (id, name) VALUES (500, 'tx')")
        c.execute("UPDATE t SET name = 'zz' WHERE id = 5")
        c.commit()
        c.begin()
        c.execute("INSERT INTO t (id, name) VALUES (501, 'gone')")
        c.rollback()
        c.execute("CREATE TABLE u (x INT PLAIN)")
        c.execute("INSERT INTO u (x) VALUES (9)")
        c.execute("CREATE INDEX ON t (id)")
    wait_for(lambda: count(r) == 50 and count(r, "u") == 1, what="streaming")
    with r.connect(token=ADMIN) as c:
        assert c.execute("SELECT name FROM t WHERE id = 3").rows == [["upd"]]
        assert c.execute("SELECT name FROM t WHERE id = 5").rows == [["zz"]]
        assert c.execute("SELECT COUNT(*) FROM t WHERE id = 4").rows == [[0]]
        assert c.execute("SELECT COUNT(*) FROM t WHERE id = 501").rows == [[0]]
        wait_for(lambda: c._wire.call("table_info", ["t"])["indexes"] == ["id"], what="index")
        with pytest.raises(Exception, match="read-only replica"):
            c.execute("INSERT INTO t (id, name) VALUES (1000, 'x')")
        st = c._wire.call("repl_status", [])
        assert st["role"] == "replica" and st["cluster_id"] == p.srv.engine.cluster_id
    assert r.srv.engine.repl_pos == tuple(p.srv.engine._ring.end)


def test_replica_survives_restart_and_resumes_without_rebootstrap(pair):
    p, r, tmp = pair
    wait_for(lambda: count(r) == 20)
    r.stop()                                             # clean stop -> checkpoint with position
    with p.connect(token=ADMIN) as c:
        for i in range(30):
            c.execute(f"INSERT INTO t (id, name) VALUES ({100 + i}, 'while down')")
    r2 = replica(p, str(tmp / "r"))
    try:
        wait_for(lambda: count(r2) == 50, what="catch-up after restart")
        assert r2.srv.engine._follower.fatal is None
    finally:
        r2.stop()


def test_replica_crash_recovery_keeps_position_via_journal(pair):
    p, r, tmp = pair
    wait_for(lambda: count(r) == 20)
    with p.connect(token=ADMIN) as c:
        for i in range(10):
            c.execute(f"INSERT INTO t (id, name) VALUES ({200 + i}, 'x')")
    wait_for(lambda: count(r) == 30)
    pos = r.srv.engine.repl_pos
    eng = r.srv.engine
    eng._follower.stop(); eng._follower.join(5)
    r.srv.shutdown(); r.srv.socket.close()
    eng._journal.close(); eng.srv.close(); eng._dblock.release()      # crash: no checkpoint
    r2 = replica(p, str(tmp / "r"))
    try:
        assert r2.srv.engine.repl_pos == pos and count(r2) == 30
        with p.connect(token=ADMIN) as c:
            c.execute("INSERT INTO t (id, name) VALUES (999, 'after')")
        wait_for(lambda: count(r2) == 31)
    finally:
        r2.stop()


def test_follows_across_primary_checkpoints_and_restart(pair):
    p, r, tmp = pair
    wait_for(lambda: count(r) == 20)
    with p.connect(token=ADMIN) as c:
        c.execute("INSERT INTO t (id, name) VALUES (300, 'g0')")
    p.srv.engine.checkpoint()
    with p.connect(token=ADMIN) as c:
        c.execute("INSERT INTO t (id, name) VALUES (301, 'g1')")
    wait_for(lambda: count(r) == 22, what="across a checkpoint")
    r.stop()
    p.stop()                                             # primary restart = checkpoint + new gen
    p2 = Running(db=str(tmp / "p"), tokens=dict(TOKENS))
    r2 = replica(p2, str(tmp / "r"))
    try:
        with p2.connect(token=ADMIN) as c:
            c.execute("INSERT INTO t (id, name) VALUES (302, 'g2')")
        wait_for(lambda: count(r2) == 23, what="after primary restart")
        assert r2.srv.engine._follower.fatal is None
    finally:
        r2.stop(); p2.stop()
    p.srv = p2.srv


def test_promotion_makes_the_replica_writable_with_a_new_timeline(pair):
    p, r, tmp = pair
    wait_for(lambda: count(r) == 20)
    with r.connect(token=ADMIN) as c:
        out = c._wire.call("promote", [])
        assert out == {"role": "primary", "timeline": 2}
        c.execute("INSERT INTO t (id, name) VALUES (777, 'new primary')")
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[21]]
        with pytest.raises(Exception, match="already a primary"):
            c._wire.call("promote", [])
    p.stop()
    # a restarted old-timeline replica of the promoted node must not silently follow it
    r3 = Running(db=str(tmp / "r3"), tokens=dict(TOKENS), replica_of=(r.host, r.port),
                 repl_conn=dict(REPL), repl_poll=0.3)
    try:
        wait_for(lambda: count(r3) == 21, what="fresh replica of the new primary")
        assert r3.srv.engine.timeline == 2
    finally:
        r3.stop()


def test_replication_is_admin_only_and_refuses_foreign_clusters(pair):
    p, r, _ = pair
    wait_for(lambda: count(r) == 20)
    from test_ops import RO, RW
    for tok in (RO, RW):
        with p.connect(token=tok) as c:
            with pytest.raises(torussql.Error, match="may not call"):
                c._wire.call("repl_fetch", ["", 1, [0, 0], 10, 0])
    with p.connect(token=ADMIN) as c:
        call = c._wire.call
        with pytest.raises(torussql.Error, match="different cluster_id"):
            call("repl_fetch", ["deadbeef", 1, [0, 0], 10, 0])
        with pytest.raises(torussql.Error, match="timeline mismatch"):
            call("repl_fetch", [p.srv.engine.cluster_id, 9, [0, 0], 10, 0])
        with pytest.raises(torussql.Error, match="too far behind"):
            call("repl_fetch", [p.srv.engine.cluster_id, 1, [0, 3], 10, 0])
