# SPDX-License-Identifier: Apache-2.0
"""Transaction scheduling: idle-in-transaction timeout and first-come-first-served BEGIN."""
from __future__ import annotations

import threading
import time

import pytest

from torussql import ServerBusyError
from test_ops import Running


def test_idle_transaction_is_aborted_but_an_active_one_is_not():
    s = Running(tx_idle_timeout=0.4, tx_timeout=60, tx_wait=3.0)
    try:
        a, b = s.connect(), s.connect()
        a.execute("CREATE TABLE t (x INT PLAIN)")
        b.sync_schema()
        a.begin()
        for i in range(5):                                   # busy: total 1 s > idle limit
            time.sleep(0.2)
            a.execute(f"INSERT INTO t (x) VALUES ({i})")
        a.commit()
        a.begin()
        a.execute("INSERT INTO t (x) VALUES (99)")
        time.sleep(0.6)                                      # goes idle
        b.execute("INSERT INTO t (x) VALUES (100)")          # the idle writer is evicted
        with pytest.raises(ServerBusyError, match="timed out"):
            a.commit()
        assert b.execute("SELECT COUNT(*) FROM t").rows == [[6]]
        a.close(); b.close()
    finally:
        s.stop()


def test_waiting_begins_are_served_in_arrival_order():
    s = Running(tx_wait=10.0, tx_idle_timeout=0)
    try:
        holder = s.connect()
        holder.execute("CREATE TABLE t (x INT PLAIN)")
        holder.begin()
        order, conns = [], []

        def waiter(name):
            c = s.connect()
            c.sync_schema()
            conns.append(c)
            with c.transaction():
                order.append(name)
                c.execute(f"INSERT INTO t (x) VALUES ({len(order)})")
        ths = []
        for name in "abcd":
            t = threading.Thread(target=waiter, args=(name,))
            t.start(); ths.append(t)
            time.sleep(0.25)                                 # make arrival order deterministic
        assert s.srv.engine.stats_snapshot()["tx_waiters"] == 4
        holder.commit()
        for t in ths:
            t.join(20)
        assert order == list("abcd")
        holder.close()
        for c in conns:
            c.close()
    finally:
        s.stop()
