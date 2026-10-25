# SPDX-License-Identifier: Apache-2.0
"""Anchored table-state integrity with a THRESHOLD FHE key (the MAC secret is opened lazily from the
custodians; the anchor leaves are keyed by it)."""
from __future__ import annotations

import pytest

import torussql
from test_fhe_threshold import (DOT_ALL, ROWS, SCHEMA, keyset, keyset2, tkey)      # noqa: F401  (fixtures)
from test_fhe_table_integrity import lie_scan
from test_ops import Running
from torusdb_core.fhe_anchor import MemoryAnchor

IE = torussql.IntegrityError


def seed(c):
    c.execute(SCHEMA)
    for i, d, r, h in ROWS:
        c.execute(f"INSERT INTO emp (id, dept, rate, hours) VALUES ({i}, {d}, {r}, {h})")


def test_full_sql_with_a_threshold_key_and_an_anchor(tkey, tmp_path):
    ap = str(tmp_path / "anchor.json")
    s = Running()
    try:
        with s.connect(fhe_key=tkey, authenticated=True, integrity_anchor=ap) as c:
            seed(c)
            assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
            assert c.execute("SELECT AVG(rate), COUNT(*) FROM emp WHERE dept = 5").rows[0][1] == 3
            assert c.execute("SELECT 3 * SUM(hours) FROM emp WHERE dept = 5").rows == [[3 * 410]]
            assert c.execute("SELECT id, rate FROM emp WHERE id = 3").rows == [[3, 30]]
            assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[DOT_ALL]]       # local mode, anchored
            c.execute("UPDATE emp SET rate = 45, dept = 7 WHERE id = 1")
            c.execute("DELETE FROM emp WHERE id = 4")
            assert c.execute("SELECT id, dept, rate FROM emp").rows == [[1, 7, 45], [2, 5, 55], [3, 7, 30]]
            assert c.execute("SELECT SUM(rate) FROM emp WHERE dept = 7").rows == [[75]]
            c.verify_table("emp")
        with s.connect(fhe_key=tkey, authenticated=True, integrity_anchor=ap) as c2:       # fresh owner: full scan
            assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
            assert c2.execute("SELECT SUM(hours) FROM emp").rows == [[160 + 150 + 120]]
            # a server that forgets a matching row (the F3 lie) is caught at the next scan
            liar = s.connect(fhe_key=tkey, authenticated=True, integrity_anchor=ap)
            lie_scan(liar, lambda n, rows: (n, [tuple(r) for r in rows][:-1]))
            with pytest.raises(IE):
                liar.execute("SELECT COUNT(*) FROM emp WHERE dept = 5")
            liar.close()
            # the cached owner is not misled by a lying matching_rowids either
            srv = c2.client.server
            real = srv.matching_rowids
            srv.matching_rowids = lambda t, w: real(t, w)[:-1]
            assert c2.execute("SELECT COUNT(*) FROM emp WHERE dept = 7").rows == [[2]]
            srv.matching_rowids = real
    finally:
        s.stop()


def test_threshold_key_in_process_engine_with_a_memory_anchor(tkey):
    from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
    srv = NoKeyServer()
    cl = NoKeyClient(srv, fhe=tkey, authenticated=True, integrity_anchor=MemoryAnchor())
    seed(cl)
    assert cl.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    srv._rows["emp"].kill([0])                                      # the server drops a row behind our back
    cl._amgr.snaps.clear()
    from torusdb_core.errors import IntegrityError
    with pytest.raises(IntegrityError):
        cl.execute("SELECT COUNT(*) FROM emp")
