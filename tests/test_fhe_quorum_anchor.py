# SPDX-License-Identifier: Apache-2.0
"""QuorumAnchor: the integrity anchor replicated over k-of-n custodians (custody/anchor.py), the
custodian-side AnchorStore, and the time-based re-verification option."""
from __future__ import annotations

import copy
import threading

import pytest

import torussql
from torusdb_core.fhe_anchor import (AnchorConflict, AnchorQuorumError, Change, StaleServerError)
from torussql.custody.anchor import QuorumAnchor
from torussql.custody.anchorstore import AnchorStore
from torussql.custody.group import CustodyError
from torussql.custody.net import Custodian, CustodianServer, LocalNode, RemoteCustodian
from torussql.custody.quorum import QuorumError

import test_fhe_table_integrity as base
from test_fhe_table_integrity import (KEY, Q, HONEST, ROWS, IE, Crash, die, eng, image, lie_scan,
                                      same, store, swap_db)

TOKEN = "anchor-token-0123456789abcd"


def custodian(path=None, perms=None, **kw):
    return Custodian(None, {"owner": TOKEN, "reader": TOKEN + "r", "keyonly": TOKEN + "k"},
                     permissions={"owner": perms or {"anchor"}, "reader": {"anchor_read"},
                                  "keyonly": {"key"}},
                     anchors=AnchorStore(path), **kw)


class Node(LocalNode):
    """In-process custodian that can be switched off or made to lie."""
    down = False
    liar = None                                  # callable(method, args, real_result) -> result

    def call(self, method, args):
        if self.down:
            raise QuorumError(f"{self.label}: down")
        out = super().call(method, args)
        return self.liar(method, args, out) if self.liar else out


def nodes(tmp_path, n=5, persist=True, caller="owner"):
    return [Node(custodian(str(tmp_path / f"a{i}.log") if persist else None), caller=caller,
                 label=f"c{i}") for i in range(n)]


def qa(ns, k=3, **kw):
    return QuorumAnchor(ns, threshold=k, **kw)


# ═══ the custodian-side register ═════════════════════════════════════════════
def test_register_cas_repair_and_durability(tmp_path):
    p = str(tmp_path / "s.log")
    st = AnchorStore(p)
    assert st.get("a") == (0, None)
    assert st.cas("a", 0, "v1") == (True, 1, "v1")
    assert st.cas("a", 0, "v1") == (True, 1, "v1")               # a re-sent write that already landed
    assert st.cas("a", 0, "other") == (False, 1, "v1")           # CAS on the version
    assert st.cas("a", 1, "v2")[0]
    assert not st.repair("a", 1, "v1")                           # never backwards
    assert st.repair("a", 5, "v5") and st.get("a") == (5, "v5")
    assert st.repair("a", 5, "v5b") and st.get("a") == (5, "v5b")    # same version, divergent content: replaced
    st.close()
    again = AnchorStore(p)                                        # fsync'd record log: survives a restart
    assert again.get("a") == (5, "v5b")
    again.close()
    sealed = AnchorStore(str(tmp_path / "sealed.log"), "pw-1234567890")
    sealed.cas("a", 0, "x")
    sealed.close()
    assert AnchorStore(str(tmp_path / "sealed.log"), "pw-1234567890").get("a") == (1, "x")
    with pytest.raises(CustodyError):
        AnchorStore(str(tmp_path / "sealed.log"), "wrong-pass-1234")
    with pytest.raises(CustodyError):
        again.cas("", 0, "x")
    with pytest.raises(CustodyError):
        again.cas("a", 0, 5)


def test_register_log_compacts(tmp_path):
    st = AnchorStore(str(tmp_path / "s.log"))
    for i in range(1100):
        assert st.cas("a", i, f"v{i}")[0]
    assert st.stats()["log_records"] < 1100
    st.close()
    assert AnchorStore(str(tmp_path / "s.log")).get("a") == (1100, "v1099")


def test_permissions_are_separate_from_key_and_mask_permissions(tmp_path):
    c = custodian()
    key_only = LocalNode(c, caller="keyonly")
    reader = LocalNode(c, caller="reader")
    owner = LocalNode(c, caller="owner")
    with pytest.raises(QuorumError, match="lacks permission"):
        key_only.call("anchor_get", ["a"])
    assert reader.call("anchor_get", ["a"]) == {"s": 0, "v": None}
    with pytest.raises(QuorumError, match="lacks permission"):
        reader.call("anchor_cas", ["a", 0, "x"])                 # a reader cannot write
    with pytest.raises(QuorumError, match="lacks permission"):
        reader.call("anchor_repair", ["a", 1, "x"])
    assert owner.call("anchor_cas", ["a", 0, "x"])["ok"]
    with pytest.raises(QuorumError):                             # an anchor token is no key / mask token
        owner.call("partial", ["00"])
    with pytest.raises(QuorumError):
        owner.call("mask_get", [0, "t", "c", []])
    with pytest.raises(CustodyError):                            # a custodian without an anchor store
        Custodian(None, {"o": TOKEN}, permissions={"o": {"anchor"}})


# ═══ QuorumAnchor as an Anchor ═══════════════════════════════════════════════
def test_quorum_anchor_passes_the_anchor_contract(tmp_path):
    base.test_anchor_cas_pending_finish_abort_and_history(tmp_path, lambda p: qa(nodes(tmp_path)))


def test_parameter_validation(tmp_path):
    ns = nodes(tmp_path)
    for kw in (dict(k=0), dict(k=6), dict(k=3, write_quorum=2), dict(k=2, write_quorum=3),   # n - W >= k
               dict(k=3, write_quorum=6)):
        with pytest.raises(Exception):
            qa(ns, kw.pop("k"), **kw)
    assert qa(ns, 3).w == 3 and qa(ns, 2).w == 4 and qa(ns, 4).w == 4


def test_two_custodians_down_still_works_and_three_fail_closed(tmp_path):
    ns = nodes(tmp_path)
    a = qa(ns)
    a.begin_commit({"t": Change(None, 7, 1)}, "x")
    a.finish_commit(["t"], "x")
    ns[0].down = ns[1].down = True
    assert a.get("t").root == 7                                   # read with 3 of 5
    a.begin_commit({"t": Change(1, 8, 2)}, "y")                   # write with W = 3
    a.finish_commit(["t"], "y")
    ns[2].down = True                                             # below the read threshold
    with pytest.raises(AnchorQuorumError, match="only 2 of 5"):
        a.get("t")
    with pytest.raises(AnchorQuorumError):
        a.begin_commit({"t": Change(2, 9, 3)}, "z")
    for n in ns:
        n.down = False
    assert a.get("t").root == 8 and a.get("t").epoch == 2         # nothing was lost or half-applied


def test_write_below_quorum_fails_safe_and_heals(tmp_path):
    ns = nodes(tmp_path)
    a = qa(ns)
    a.begin_commit({"t": Change(None, 1, 1)}, "x")
    a.finish_commit(["t"], "x")
    for n in ns[:3]:
        n.down = True
    with pytest.raises(AnchorQuorumError):                        # only 2 of the needed 3 accept: reads fail first
        a.begin_commit({"t": Change(1, 2, 2)}, "y")
    # reads work (2 of 5 is below k), so craft the partial write at the register level instead:
    for n in ns:
        n.down = False
    for n in ns[2:]:
        n.down = True                                             # now only c0, c1 are up
    with pytest.raises(AnchorQuorumError):
        a.get("t")
    for n in ns:
        n.down = False
    e = a.get("t")
    assert (e.epoch, e.root, e.pending) == (1, 1, None)           # the failed attempts changed nothing visible
    a.begin_commit({"t": Change(1, 2, 2)}, "y")                   # and the next write simply works
    a.finish_commit(["t"], "y")
    assert a.get("t").root == 2


def test_a_partial_write_is_not_believed_and_is_overwritten(tmp_path):
    ns = nodes(tmp_path)
    a = qa(ns)
    a.begin_commit({"t": Change(None, 1, 1)}, "x")
    a.finish_commit(["t"], "x")
    # a crashed writer left a new version on only two custodians
    s0 = ns[0].custodian.anchors
    seq, raw = s0.get(a.aid)
    other = QuorumAnchor(ns[:2], threshold=2, write_quorum=2)      # same registers, writes via 2 nodes only
    other.begin_commit({"t": Change(1, 99, 5)}, "ghost")
    assert a.get("t").root == 1 and a.get("t").pending is None    # 2 copies < k: ignored
    a.begin_commit({"t": Change(1, 2, 2)}, "y")                   # a real write wins and repairs the two
    a.finish_commit(["t"], "y")
    assert a.get("t").root == 2
    assert not a.problems or all("differs" in p or "version" in p for p in a.problems)
    vals = {n.custodian.anchors.get(a.aid) for n in ns}
    assert len(vals) <= 2


def test_a_lying_custodian_is_outvoted(tmp_path):
    ns = nodes(tmp_path)
    a = qa(ns)
    a.begin_commit({"t": Change(None, 5, 3)}, "x")
    a.finish_commit(["t"], "x")
    lies = {
        "older version": lambda m, args, out: {"s": 1, "v": out["v"]} if m == "anchor_get" else out,
        "empty": lambda m, args, out: {"s": 0, "v": None} if m == "anchor_get" else out,
        "other root, higher version": lambda m, args, out:
            ({"s": out["s"] + 5, "v": out["v"].replace('"root":"5"', '"root":"6"')} if m == "anchor_get" else out),
        "garbage": lambda m, args, out: {"nonsense": True} if m == "anchor_get" else out,
        "unreachable": None,
    }
    for name, lie in lies.items():
        ns[4].liar, ns[4].down = lie, lie is None
        e = a.get("t")
        assert (e.root, e.count, e.epoch) == (5, 3, 1), name
        assert a.problems, name                                    # and the deviation is reported
    # a custodian that claims to have stored a write it dropped cannot make an unsafe commit pass
    ns[4].down, ns[4].liar = False, lambda m, args, out: {"ok": True, "s": 99, "v": "x"} if m == "anchor_cas" else out
    a.begin_commit({"t": Change(1, 6, 4)}, "y")
    a.finish_commit(["t"], "y")
    assert a.get("t").root == 6
    # two liars (< k) agreeing on a forged higher version are still outvoted
    forged = lambda m, args, out: {"s": 50, "v": out["v"].replace('"root":"6"', '"root":"1"')} if m == "anchor_get" else out
    ns[3].liar = ns[4].liar = forged
    assert a.get("t").root == 6
    # ... but k = 3 colluding custodians are the stated limit of the design
    ns[2].liar = forged
    assert a.get("t").root == 1


def test_rolled_back_custodians_are_outvoted_and_repaired(tmp_path):
    ns = nodes(tmp_path)
    a = qa(ns)
    a.begin_commit({"t": Change(None, 1, 1)}, "x")
    a.finish_commit(["t"], "x")
    old = [copy.deepcopy(n.custodian.anchors._reg) for n in ns]
    for i, (r, c) in enumerate([(2, 2), (3, 3)]):
        a.begin_commit({"t": Change(i + 1, r, c)}, f"t{i}")
        a.finish_commit(["t"], f"t{i}")
    cur = a.get("t")
    assert cur.epoch == 3
    for n in ns[:2]:                                               # two custodians restore an old register file
        n.custodian.anchors._reg = copy.deepcopy(old[ns.index(n)])
    e = a.get("t")
    assert (e.epoch, e.root) == (3, 3)                              # the majority blocks the rollback
    assert any("c0" in p or "c1" in p for p in a.problems)
    seqs = {n.custodian.anchors.get(a.aid)[0] for n in ns}
    assert len(seqs) == 1                                            # read-repair brought them forward again
    for n in ns[:3]:                                               # k = 3 rolled back: the stated limit
        n.custodian.anchors._reg = copy.deepcopy(old[ns.index(n)])
    assert a.get("t").epoch == 1


def test_two_owners_race_on_the_compare_and_swap(tmp_path):
    ns = nodes(tmp_path)
    anchors = [qa(ns), qa(ns)]
    anchors[0].begin_commit({"t": Change(None, 0, 0)}, "c")
    anchors[0].finish_commit(["t"], "c")
    for rnd in range(12):
        e = anchors[0].get("t").epoch
        results, barrier = [], threading.Barrier(2)

        def go(i):
            barrier.wait()
            try:
                anchors[i].begin_commit({"t": Change(e, 100 + i, 1)}, f"tx{rnd}-{i}")
                results.append(("won", i))
            except AnchorConflict:
                results.append(("lost", i))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert sorted(r[0] for r in results) == ["lost", "won"], results
        winner = next(i for r, i in results if r == "won")
        got = anchors[1 - winner].get("t")
        assert got.pending.root == 100 + winner and got.pending.txid == f"tx{rnd}-{winner}"
        anchors[winner].finish_commit(["t"], f"tx{rnd}-{winner}")
    assert anchors[0].get("t").epoch == 13


# ═══ the full SQL path with a QuorumAnchor ═══════════════════════════════════
class QEnv(base.Env):
    def __init__(self, tmp_path, ns, **qkw):
        super().__init__(tmp_path)
        self.ns, self.qkw = ns, qkw

    def quorum(self):
        return qa(self.ns, **self.qkw)

    def conn(self, s, anchored=True, **kw):
        if anchored:
            kw.setdefault("integrity_anchor", self.quorum())
        return super().conn(s, anchored, **kw)


@pytest.fixture
def qenv(tmp_path):
    e = QEnv(tmp_path, nodes(tmp_path))
    yield e
    e.close()


def test_sql_honest_flow_and_attacks_with_a_quorum_anchor(qenv):
    s, c = qenv.seeded()
    assert same(c.execute(Q).rows, HONEST)
    c.execute("UPDATE emp SET rate = 41 WHERE id = 1")
    c.execute("DELETE FROM emp WHERE id = 4")
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 1)")
    c.rollback()
    assert c.execute("SELECT id, rate FROM emp").rows == [[1, 41], [2, 55], [3, 30]]
    other = qenv.conn(s)                                          # a second owner, its own QuorumAnchor object
    assert other.execute("SELECT SUM(rate) FROM emp").rows == [[41 + 55 + 30]]
    # server lies about the row set / rolls the table back: caught through the replicated anchor
    liar = qenv.conn(s)
    lie_scan(liar, lambda n, rows: (n, [tuple(r) for r in rows][:-1]))
    with pytest.raises(IE):
        liar.execute("SELECT COUNT(*) FROM emp")
    old = image(s)
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (7, 5, 7)")
    swap_db(s, old)
    with pytest.raises(IE, match="behind the anchor"):
        qenv.conn(s).execute("SELECT COUNT(*) FROM emp")
    # even two rolled-back custodians cannot hide the newer anchor state
    swap_db(s, old)
    for nd in qenv.ns[:2]:
        nd.custodian.anchors._reg = {}
    with pytest.raises(IE, match="behind the anchor"):
        qenv.conn(s).execute("SELECT COUNT(*) FROM emp")


def test_commit_with_too_few_custodians_fails_safely(qenv):
    s, c = qenv.seeded()
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    for nd in qenv.ns[:3]:
        nd.down = True                                              # the anchor can no longer be updated
    with pytest.raises(torussql.OperationalError, match="anchor"):
        c.commit()
    assert not c.in_transaction
    for nd in qenv.ns:
        nd.down = False
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[4]]      # the server rolled the insert back
    assert qenv.conn(s).execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    with c.transaction():                                            # and the system carries on
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    assert qenv.conn(s).execute("SELECT SUM(rate) FROM emp").rows == [[154]]


def test_reads_survive_two_custodians_down_and_fail_closed_with_three(qenv):
    s, c = qenv.seeded()
    qenv.ns[0].down = qenv.ns[1].down = True
    other = qenv.conn(s)
    assert other.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    other.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")        # W = 3 of the 3 left
    qenv.ns[2].down = True
    with pytest.raises(torussql.OperationalError, match="anchor"):
        qenv.conn(s).execute("SELECT SUM(rate) FROM emp")


def test_pending_settlement_matches_the_file_anchor_behaviour(qenv):
    s, c = qenv.seeded()
    before = qenv.quorum().get("emp")
    real_call = c._wire.call

    def call(method, args):
        if method == "tx_commit":
            raise Crash()
        return real_call(method, args)
    c._wire.call = call
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(Crash):
        c.commit()
    assert qenv.quorum().get("emp").pending is not None
    die(c)
    c2 = qenv.conn(s)                                               # scan == old root -> abort
    e = qenv.quorum().get("emp")
    assert e.pending is None and (e.epoch, e.root) == (before.epoch, before.root)
    assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    # crash after the server committed -> finish
    c2.client._amgr.finish = lambda: (_ for _ in ()).throw(Crash())
    c2.begin()
    c2.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(Crash):
        c2.commit()
    die(c2)
    c3 = qenv.conn(s)
    e = qenv.quorum().get("emp")
    assert e.pending is None and e.epoch == before.epoch + 1 and e.count == 5
    assert c3.execute("SELECT SUM(rate) FROM emp").rows == [[154]]
    # neither state -> integrity error
    c3.client._amgr.finish = lambda: (_ for _ in ()).throw(Crash())
    c3.begin()
    c3.execute("INSERT INTO emp (id, dept, rate) VALUES (10, 5, 1)")
    with pytest.raises(Crash):
        c3.commit()
    die(c3)
    with eng(s)._lock:
        store(s).kill([0])
    with pytest.raises(IE, match="does not match the anchor"):
        qenv.conn(s)


def test_two_owners_write_concurrently_through_one_quorum(qenv):
    s, c1 = qenv.seeded()
    c2 = qenv.conn(s)
    errs = []

    def work(c, base):
        try:
            for i in range(4):
                c.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({base + i}, 5, 1)")
        except Exception as exc:                                    # noqa: BLE001
            errs.append(exc)
    ts = [threading.Thread(target=work, args=(c, b)) for c, b in ((c1, 100), (c2, 200))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs, errs
    final = qenv.conn(s)
    assert final.execute("SELECT COUNT(*) FROM emp").rows == [[12]]
    assert final.verify_table("emp")["rows"] == 12


def test_anchor_survives_custodian_restarts(tmp_path):
    ns = nodes(tmp_path)
    s = Running_()
    try:
        c = base.Env(tmp_path).conn(s, integrity_anchor=qa(ns))
        c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (1, 1, 5)")
        c.close()
        ns2 = [Node(custodian(str(tmp_path / f"a{i}.log")), label=f"r{i}", caller="owner") for i in range(5)]
        c = base.Env(tmp_path).conn(s, integrity_anchor=qa(ns2))   # fresh custodian processes, same files
        assert c.execute("SELECT SUM(rate) FROM emp").rows == [[5]]
        c.close()
    finally:
        s.stop()


def Running_():
    from test_ops import Running
    return Running()


# ═══ real network custodians ═════════════════════════════════════════════════
class NetNodes:
    def __init__(self, tmp_path, n=5):
        self.servers, self.ports, self.paths = [], [], []
        for i in range(n):
            self.paths.append(str(tmp_path / f"net{i}.log"))
            self.start(i)

    def start(self, i):
        srv = CustodianServer("127.0.0.1", 0 if i >= len(self.ports) else self.ports[i], custodian(self.paths[i]))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        if i >= len(self.ports):
            self.ports.append(srv.address[1])
            self.servers.append(srv)
        else:
            self.servers[i] = srv

    def stop(self, i):
        self.servers[i].shutdown()
        self.servers[i].server_close()
        self.servers[i].custodian.anchors.close()

    def remotes(self):
        return [RemoteCustodian("127.0.0.1", p, TOKEN, timeout=5) for p in self.ports]


def test_network_custodians_end_to_end_with_failures_and_restart(tmp_path):
    net = NetNodes(tmp_path)
    from test_ops import Running
    s = Running()
    env = base.Env(tmp_path)
    try:
        mk = lambda: QuorumAnchor(net.remotes(), threshold=3)                    # noqa: E731
        c = env.conn(s, integrity_anchor=mk())
        c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
        for i, d, r in ROWS:
            c.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({i}, {d}, {r})")
        net.stop(0)
        net.stop(1)                                                              # two custodians die
        c.execute("UPDATE emp SET rate = 41 WHERE id = 1")
        other = env.conn(s, integrity_anchor=mk())
        assert other.execute("SELECT SUM(rate) FROM emp").rows == [[41 + 55 + 30 + 20]]
        net.start(0)                                                             # one restarts (stale register)
        c.execute("DELETE FROM emp WHERE id = 4")
        assert env.conn(s, integrity_anchor=mk()).execute("SELECT COUNT(*) FROM emp").rows == [[3]]
        net.stop(2)
        net.stop(3)
        net.stop(4)
        with pytest.raises(torussql.OperationalError, match="anchor"):
            env.conn(s, integrity_anchor=mk())                                   # connect settles: no quorum
    finally:
        env.close()
        s.stop()
        for i in range(5):
            try:
                net.stop(i)
            except Exception:                                                    # noqa: BLE001
                pass


# ═══ time-based re-verification ══════════════════════════════════════════════
def test_recheck_seconds_catches_a_silent_rollback_within_the_period(tmp_path):
    env = base.Env(tmp_path)
    try:
        s, c = env.seeded()
        now = [1000.0]
        c2 = env.conn(s, integrity_recheck_seconds=60)
        c2.client._amgr.clock = lambda: now[0]
        c2.execute("SELECT COUNT(*) FROM emp")                        # scan 1, cached
        scans = c2.client._amgr.stats["scans"]
        old = image(s)
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")     # another owner advances the epoch
        assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[5]]       # epoch change -> rescan (scan 2)
        swap_db(s, old)                                                    # SILENT rollback, epoch unchanged
        now[0] += 30
        assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[5]]       # still inside the period: cache
        assert c2.client._amgr.stats["scans"] == scans + 1
        now[0] += 31
        with pytest.raises(IE, match="behind the anchor"):
            c2.execute("SELECT COUNT(*) FROM emp")                         # the period elapsed: verified again
    finally:
        env.close()


def test_recheck_catches_silent_tampering_and_default_is_off(tmp_path):
    env = base.Env(tmp_path)
    try:
        s, c = env.seeded()
        now = [0.0]
        watch = env.conn(s, integrity_recheck_seconds=10)
        plain = env.conn(s)                                            # default: no periodic recheck
        for x in (watch, plain):
            x.client._amgr.clock = lambda: now[0]
            x.execute("SELECT COUNT(*) FROM emp")
        with eng(s)._lock:
            store(s).kill([0])                                         # data the owners are not reading
        now[0] += 5
        assert watch.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
        now[0] += 10_000
        assert plain.execute("SELECT COUNT(*) FROM emp").rows == [[4]]  # None = off
        with pytest.raises(IE, match="does not match the anchor"):
            watch.execute("SELECT COUNT(*) FROM emp")
        with pytest.raises(Exception, match="positive"):
            env.conn(s, integrity_recheck_seconds=0)
    finally:
        env.close()


# ═══ CLI: `custody serve --anchor-store` and `torussql --anchor-custodian` ════
def test_cli_anchor_daemons_and_client_flags(tmp_path, monkeypatch, capsys):
    import os
    import re
    import subprocess
    import sys
    from pathlib import Path
    from torusdb_core import fhe
    from torussql import cli
    from test_ops import Running
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root / "drivers" / "python"), str(root / "core"),
                                         str(root / "parser"), env.get("PYTHONPATH", "")])
    tok = tmp_path / "tokens"
    tok.write_text(f"owner:{TOKEN}:anchor\n")
    os.chmod(tok, 0o600)
    procs, specs = [], []
    s = Running()
    try:
        for i in range(3):
            p = subprocess.Popen([sys.executable, "-m", "torussql.custody", "serve", "--no-passphrase",
                                  "--anchor-store", str(tmp_path / f"cli{i}.log"), "--listen", "127.0.0.1:0",
                                  "--token-file", str(tok)],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(p)
            line = p.stdout.readline()
            assert "anchor store" in line
            specs.append("127.0.0.1:" + re.search(r"on 127\.0\.0\.1:(\d+)", line).group(1))
        keyfile = str(tmp_path / "fhe.key")
        fhe.save_key(KEY, keyfile, None)
        monkeypatch.setenv("AT", TOKEN)
        common = ["-h", "127.0.0.1", "-p", str(s.port), "--authenticated", "--fhe-key", keyfile,
                  "--trust-server-schema", "--anchor-token-env", "AT", "--anchor-threshold", "2",
                  "--integrity-recheck-seconds", "30"]
        for sp in specs:
            common += ["--anchor-custodian", sp]
        assert cli.main(common + ["-c", "CREATE TABLE t (id INT PLAIN, v INT FHE)",
                                  "-c", "INSERT INTO t (id, v) VALUES (1, 7)",
                                  "-c", "INSERT INTO t (id, v) VALUES (2, 8)"]) == 0
        capsys.readouterr()
        assert cli.main(common + ["-c", "SELECT SUM(v), COUNT(*) FROM t"]) == 0
        assert "15" in capsys.readouterr().out
        # the anchor lives on the custodians, not in a file; a wrong flag combination is refused
        assert cli.main(["-p", str(s.port), "--anchor-custodian", specs[0]]) == 2
    finally:
        for p in procs:
            p.terminate()
        s.stop()
