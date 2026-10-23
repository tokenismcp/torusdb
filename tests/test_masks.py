# SPDX-License-Identifier: Apache-2.0
"""Threshold mask cluster: the owner's masks secret-shared among custodians."""
from __future__ import annotations

import json
import os
import random
import threading
import time
from fractions import Fraction

import pytest

import torussql
from torusdb_core.errors import ExecError, IntegrityError
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torussql.custody import laurent, run_local_ceremony
from torussql.custody.masks import (MaskClusterError, MaskUnavailable, MaskWriteError,
                                    ThresholdMaskStore, reshare_masks)
from torussql.custody.net import Custodian, CustodianServer, Limits, LocalNode, RemoteCustodian
from torussql.custody.quorum import QuorumError
from torussql.custody.recordlog import LogCorrupt, LogLocked, RecordLog
from torussql.custody.shares import Frozen, MaskShareStore, Q, ShareConflict
from nokey_server import NoKeyTCPServer

TOKEN = "owner-token-0123456789abc"
ADMIN = {"key", "mask_write", "mask_read", "mask_admin"}


class Node(LocalNode):
    """LocalNode with fault injection and a call log."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.mode = "ok"
        self.log: list[tuple[str, list]] = []

    def call(self, method, args):
        self.log.append((method, args))
        if self.mode == "down":
            raise QuorumError(f"{self.label}: ConnectionError: host unreachable")
        out = super().call(method, args)
        if self.mode == "lie":
            if method == "mask_sum":
                out["s"] = format((int(out["s"], 16) + 12345) % Q, "x")
            elif method == "mask_get":
                out["s"] = [None if s is None else format((int(s, 16) + 777) % Q, "x")
                            for s in out["s"]]
        return out


def make_cluster(tmp_path=None, k=3, n=5, perms=None, persist=False, limits=None,
                 passphrase="store-pass", **store_kw):
    shares, pub, _ = run_local_ceremony(k, n)
    nodes, customs = [], []
    for s in shares:
        path = str(tmp_path / f"masks_{s.index}.log") if persist else None
        store = MaskShareStore(path, passphrase if persist else None)
        c = Custodian(s, {"owner": TOKEN}, permissions={"owner": perms or ADMIN},
                      masks=store, limits=limits)
        customs.append(c)
        nodes.append(Node(c, caller="owner", label=f"n{s.index}"))
    return nodes, customs, ThresholdMaskStore(nodes, k, **store_kw), shares, pub


def init(store, auth=False):
    store.initialize(authenticated=auth)
    return store


def workload(c):
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary INT ENC, "
              "rate INT PAIRED, hrs INT PAIRED, bonus RATIONAL ENC)")
    c.execute("CREATE TABLE dept (dept INT PLAIN, name STR PLAIN)")
    c.execute("INSERT INTO dept (dept, name) VALUES (5, 'eng')")
    c.execute("INSERT INTO dept (dept, name) VALUES (9, 'ops')")
    for i in range(1, 9):
        c.execute(f"INSERT INTO emp (id, dept, salary, rate, hrs, bonus) VALUES "
                  f"({i}, {5 if i % 2 else 9}, {100 * i}, {i}, {i + 2}, FRAC({i}, 3))")
    c.execute("UPDATE emp SET salary = 777 WHERE id = 3")
    c.execute("DELETE FROM emp WHERE id = 8")
    out = []
    for q in ["SELECT SUM(salary), AVG(salary), COUNT(*) FROM emp",
              "SELECT DOT(rate, hrs) FROM emp",
              "SELECT rate * hrs FROM emp WHERE dept = 5",
              "SELECT id, salary, bonus FROM emp WHERE id < 5 ORDER BY id",
              "SELECT d.name, COUNT(*), SUM(e.salary), 2 * SUM(e.bonus) FROM emp e "
              "JOIN dept d ON e.dept = d.dept GROUP BY d.name ORDER BY d.name",
              "SELECT SUM(bonus) FROM emp WHERE dept = 9"]:
        out.append(c.execute(q).rows)
    return out


@pytest.fixture(scope="module")
def reference():
    return {auth: workload(NoKeyClient(NoKeyServer(), authenticated=auth))
            for auth in (False, True)}


# ── functional parity with the local vault ───────────────────────────────────
@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_same_answers_as_a_local_vault(auth, reference):
    nodes, _c, store, *_ = make_cluster()
    init(store, auth)
    c = NoKeyClient(NoKeyServer(), maskstore=store)
    assert c.authenticated == auth
    assert workload(c) == reference[auth]
    assert len(c._masks) == 0                      # the owner process holds NO masks


def test_masks_are_recoverable_only_from_a_quorum(tmp_path):
    nodes, customs, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    c.execute("INSERT INTO t (a, v) VALUES (1, 4242)")
    cid, ver = srv._rows["t"][0]["__cid__"], srv._rows["t"][0]["__mv__v"]
    shares = [(cu.masks._gens[0].x, cu.masks._gens[0].tables["t"][(cid, "v", ver)][0])
              for cu in customs]
    from torusdb_core.protocol import encode
    blinded = srv._rows["t"][0]["v"]
    r = (blinded - encode(4242)) % Q
    assert laurent.reconstruct(shares[:3], Q) == r          # any quorum → the mask
    assert laurent.reconstruct(shares[2:5], Q) == r
    assert all(y != r for _x, y in shares)                  # no single custodian holds it
    assert len({y for _x, y in shares}) == 5


def test_custodians_never_receive_plaintext_or_blinded_cells():
    nodes, _c, store, *_ = make_cluster()
    init(store, True)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC, w INT PAIRED)")
    for i in range(1, 6):
        c.execute(f"INSERT INTO t (a, v, w) VALUES ({i}, {10 ** 9 + i}, {3 * 10 ** 9 + 7 * i})")
    c.execute("SELECT SUM(v), DOT(w, w) FROM t")
    c.execute("SELECT v FROM t")
    from torusdb_core.protocol import encode
    seen = set()

    def walk(x):
        if isinstance(x, (list, tuple)):
            for y in x: walk(y)
        elif isinstance(x, dict):
            for y in x.values(): walk(y)
        elif isinstance(x, int):
            seen.add(x)
        elif isinstance(x, str):
            try: seen.add(int(x, 16))
            except ValueError: pass
    for nd in nodes:
        for _m, args in nd.log:
            walk(args)
    blinded = {int(srv._rows["t"][i][col]) for i in range(5) for col in ("v", "w", "__mac__v", "__mac__w")}
    plains = ({encode(10 ** 9 + i) for i in range(1, 6)}
              | {encode(3 * 10 ** 9 + 7 * i) for i in range(1, 6)})
    seen = {v for v in seen if v > 2 ** 32}          # ignore versions, counts, points
    assert not (blinded & seen), "a blinded server cell reached a custodian"
    assert not (plains & seen), "a plaintext reached a custodian"
    assert c._alpha not in seen                       # α is shared, never sent whole


def test_aggregate_queries_reveal_no_individual_mask():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    c = NoKeyClient(NoKeyServer(), maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in range(20):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i})")
    for nd in nodes:
        nd.log.clear()
    assert c.execute("SELECT SUM(v) FROM t").rows == [[190]]
    assert c.execute("SELECT AVG(v) FROM t").rows == [[Fraction(19, 2)]]
    methods = {m for nd in nodes for m, _ in nd.log}
    assert "mask_sum" in methods and "mask_get" not in methods
    for nd in nodes:
        nd.log.clear()
    c.execute("SELECT v FROM t WHERE a < 3")          # reading cells necessarily reveals them
    assert "mask_get" in {m for nd in nodes for m, _ in nd.log}


# ── availability and write safety ────────────────────────────────────────────
def test_reads_survive_two_custodians_down_writes_need_all_by_default():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in range(1, 5):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i * 10})")
    nodes[0].mode = nodes[3].mode = "down"
    assert c.execute("SELECT SUM(v) FROM t").rows == [[100]]
    assert c.execute("SELECT v FROM t WHERE a = 2").rows == [[20]]
    with pytest.raises(MaskWriteError, match="NOT written"):
        c.execute("INSERT INTO t (a, v) VALUES (9, 90)")
    assert len(srv._rows["t"]) == 4                    # nothing reached the server
    nodes[1].mode = "down"                             # 3 of 5 down → below quorum
    with pytest.raises(MaskUnavailable):
        c.execute("SELECT SUM(v) FROM t")


def test_relaxed_write_quorum_then_repair_restores_full_redundancy():
    nodes, customs, store, *_ = make_cluster(write_quorum=3)
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    nodes[4].mode = nodes[3].mode = "down"
    for i in range(1, 6):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i})")
    assert c.execute("SELECT SUM(v) FROM t").rows == [[15]]
    assert sum(len(cu.masks._gens[0].tables.get("t", {})) for cu in customs[3:]) == 0
    nodes[4].mode = nodes[3].mode = "ok"
    assert store.repair()["restored_shares"] == 10     # 5 cells × 2 custodians
    assert all(len(cu.masks._gens[0].tables["t"]) == 5 for cu in customs)
    nodes[0].mode = nodes[1].mode = "down"             # now the repaired ones carry the read
    assert c.execute("SELECT SUM(v) FROM t").rows == [[15]]


def test_a_lying_custodian_is_outvoted_and_reported():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    c = NoKeyClient(NoKeyServer(), maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in range(1, 6):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i * 7})")
    nodes[2].mode = "lie"
    assert c.execute("SELECT SUM(v) FROM t").rows == [[105]]
    assert c.execute("SELECT v FROM t ORDER BY a").rows == [[7], [14], [21], [28], [35]]
    assert "n3" in store.faulty


def test_with_only_k_answers_a_lie_is_caught_by_the_mac_but_not_without_it():
    for auth, expect in ((True, IntegrityError), (False, None)):
        nodes, _c, store, *_ = make_cluster(read_grace=0.0)
        init(store, auth)
        c = NoKeyClient(NoKeyServer(), maskstore=store)
        c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
        c.execute("INSERT INTO t (a, v) VALUES (1, 50)")
        nodes[0].mode = nodes[1].mode = "down"           # exactly k=3 left
        nodes[2].mode = "lie"
        if expect:
            with pytest.raises(expect):
                c.execute("SELECT SUM(v) FROM t")
        else:
            assert c.execute("SELECT SUM(v) FROM t").rows != [[50]]   # documented: no integrity


def test_a_majority_of_liars_is_refused_not_guessed():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    c = NoKeyClient(NoKeyServer(), maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    c.execute("INSERT INTO t (a, v) VALUES (1, 5)")
    for nd, delta in zip(nodes[:3], (1, 2, 3)):
        nd.mode = "lie"
    with pytest.raises(MaskClusterError, match="inconsistent|disagree"):
        c.execute("SELECT SUM(v) FROM t")


# ── crash safety ─────────────────────────────────────────────────────────────
def test_a_failed_server_write_leaves_only_harmless_orphan_masks_that_gc_collects():
    nodes, customs, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    c.execute("INSERT INTO t (a, v) VALUES (1, 11)")
    real = srv.insert
    srv.insert = lambda *a, **k: (_ for _ in ()).throw(OSError("server down"))
    with pytest.raises(OSError):
        c.execute("INSERT INTO t (a, v) VALUES (2, 22)")
    srv.insert = real
    n_masks = lambda: len(customs[0].masks._gens[0].tables["t"])
    assert n_masks() == 2                              # the orphan exists …
    assert c.execute("SELECT SUM(v) FROM t").rows == [[11]]   # … and harms nothing
    assert store.gc(min_age=3600)["deleted"] == 0      # too young to touch (could be in flight)
    assert store.gc(min_age=0)["deleted"] == 5         # 1 orphan × 5 custodians
    assert n_masks() == 1 and c.execute("SELECT SUM(v) FROM t").rows == [[11]]


def test_update_keeps_the_old_version_until_gc_so_a_rollback_is_safe():
    nodes, customs, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    c.execute("INSERT INTO t (a, v) VALUES (1, 10)")
    snapshot = json.dumps(srv.to_body(), default=str)
    c.execute("UPDATE t SET v = 99 WHERE a = 1")
    assert c.execute("SELECT SUM(v) FROM t").rows == [[99]]
    versions = sorted(k[2] for k in customs[0].masks._gens[0].tables["t"])
    assert len(versions) == 2 and versions[0] != versions[1]
    srv.__dict__.update(NoKeyServer.from_body(json.loads(snapshot)).__dict__)   # server rolls back
    assert c.execute("SELECT SUM(v) FROM t").rows == [[10]]                     # old mask still there
    srv2 = srv
    c.execute("UPDATE t SET v = 55 WHERE a = 1")
    # superseded v1 + the orphan left by the rolled-back update = 2 versions × 5 custodians
    assert store.gc(min_age=0)["deleted"] == 10
    assert len(customs[0].masks._gens[0].tables["t"]) == 1
    assert c.execute("SELECT SUM(v) FROM t").rows == [[55]]


def test_a_malicious_server_swapping_cell_references_is_caught_in_authenticated_mode():
    nodes, _c, store, *_ = make_cluster()
    init(store, True)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in (1, 2, 3):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i * 100})")
    r0, r1 = srv._rows["t"][0], srv._rows["t"][1]
    # swapping only the cell-group id points at a (cid, version) that does not exist …
    r0["__cid__"], r1["__cid__"] = r1["__cid__"], r0["__cid__"]
    with pytest.raises((MaskUnavailable, IntegrityError)):
        c.execute("SELECT v FROM t WHERE a = 1")
    r0["__cid__"], r1["__cid__"] = r1["__cid__"], r0["__cid__"]          # restore
    # … swapping id AND version makes a valid-looking but WRONG mask: the MAC catches it
    for k in ("__cid__", "__mv__v", "__mv____mac__v"):
        r0[k], r1[k] = r1[k], r0[k]
    with pytest.raises(IntegrityError):
        c.execute("SELECT v FROM t WHERE a = 1")


def test_rows_without_a_cluster_reference_are_refused():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    c.execute("INSERT INTO t (a, v) VALUES (1, 1)")
    del srv._rows["t"][0]["__cid__"]
    with pytest.raises(ExecError, match="no mask-cluster reference"):
        c.execute("SELECT SUM(v) FROM t")


# ── permissions and limits ───────────────────────────────────────────────────
def test_permissions_are_least_privilege(tmp_path):
    shares, pub, _ = run_local_ceremony(2, 3)
    toks = {"ingest": "ingest-token-0123456789a", "reader": "reader-token-0123456789a",
            "admin": "admin--token-0123456789a", "keyonly": "keyonly-token-0123456789"}
    customs = [Custodian(s, toks, masks=MaskShareStore(), permissions={
        "ingest": {"mask_write"}, "reader": {"mask_read"}, "admin": ADMIN}) for s in shares]
    mk = lambda who: [Node(c, caller=who, label=f"n{i}") for i, c in enumerate(customs)]
    admin = ThresholdMaskStore(mk("admin"), 2)
    admin.initialize()
    # an ingest-only token can store masks but can never read or sum them back
    w = ThresholdMaskStore(mk("ingest"), 2, gen=0)
    w._put("t", [("c" * 32, "v", 1, 12345)])
    with pytest.raises(QuorumError, match="lacks permission"):
        w.nodes[0].call("mask_sum", [0, "t", "v", [["c" * 32, 1, 1]]])
    with pytest.raises(QuorumError, match="lacks permission"):
        w.nodes[0].call("mask_get", [0, "t", "v", [["c" * 32, 1]]])
    rd = mk("reader")[0]
    assert rd.call("mask_sum", [0, "t", "v", [["c" * 32, 1, 1]]])["x"] == 1
    for bad in (("mask_put", [0, 1, []]), ("mask_delete", [0, []]), ("mask_drop_table", [0, "t"]),
                ("mask_list", [0, "t", None, 10]), ("mask_freeze", [0, True]), ("mask_stats", [])):
        with pytest.raises(QuorumError, match="lacks permission"):
            rd.call(*bad)
    ko = Node(customs[0], caller="keyonly")
    with pytest.raises(QuorumError, match="lacks permission"):
        ko.call("mask_sum", [0, "t", "v", []])
    assert ko.call("partial", [shares[0].public.g.hex(shares[0].public.g.G), ""])


def test_limits_min_aggregate_reveal_quota_and_item_cap():
    nodes, customs, store, *_ = make_cluster(limits=Limits(
        max_items_per_request=50, reveal_rows_per_minute=10, min_aggregate_rows=3))
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in range(12):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i})")
    assert c.execute("SELECT SUM(v) FROM t").rows == [[66]]
    with pytest.raises(QuorumError, match="fewer than 3"):
        nodes[0].call("mask_sum", [0, "t", "v", [["x" * 32, 1, 2]]])      # 2 cells < 3
    with pytest.raises(MaskClusterError):
        c.execute("SELECT SUM(v) FROM t WHERE a < 2")                      # policy: too few rows
    assert c.execute("SELECT v FROM t WHERE a < 6 ORDER BY a").rows == [[i] for i in range(6)]
    with pytest.raises(MaskUnavailable, match="quota"):
        c.execute("SELECT v FROM t")                                       # 6 + 12 > 10/min
    with pytest.raises(QuorumError, match="too many items"):
        nodes[0].call("mask_put", [0, 1, [["t", "c", "v", 1, "1"]] * 51])


def test_uninitialised_and_misconfigured_clusters_are_refused():
    nodes, _c, store, *_ = make_cluster()
    with pytest.raises(MaskClusterError, match="not initialised"):
        NoKeyClient(NoKeyServer(), maskstore=store)
    init(store)
    with pytest.raises(MaskClusterError, match="already initialised"):
        store.initialize()
    wrong = ThresholdMaskStore(nodes, 2)
    with pytest.raises(MaskClusterError, match="configured k=3"):
        wrong.config()
    wrong_xs = ThresholdMaskStore(nodes, 3, xs=[1, 2, 3, 4, 6])
    with pytest.raises(MaskClusterError, match="xs"):
        wrong_xs.config()
    with pytest.raises(MaskClusterError, match="distinct"):
        ThresholdMaskStore(nodes, 3, xs=[1, 1, 2, 3, 4])
    auto = ThresholdMaskStore(make_cluster()[0], 3, auto_init=True)
    assert auto.config() == {"authenticated": False, "alpha": 0}


def test_find_orphans_never_deletes_when_the_cluster_is_merely_unreachable():
    nodes, _c, store, *_ = make_cluster()
    init(store)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=store)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
    for i in range(4):
        c.execute(f"INSERT INTO t (a, v) VALUES ({i}, {i})")
    for nd in nodes[:3]:
        nd.mode = "down"
    with pytest.raises(MaskUnavailable):
        store.available("t", "v", [0, 1, 2, 3])
    for nd in nodes:
        nd.mode = "ok"
    assert store.available("t", "v", [0, 1, 2, 3]) == [True] * 4
    del srv._rows["t"][1]["__cid__"]
    assert store.available("t", "v", [0, 1, 2, 3]) == [True, False, True, True]


# ── full stack over TCP: stateless owner, second client, transactions ────────
@pytest.fixture
def stack(tmp_path):
    shares, pub, _ = run_local_ceremony(3, 5)
    servers, ports, customs = [], [], []
    for s in shares:
        cu = Custodian(s, {"owner": TOKEN}, permissions={"owner": ADMIN},
                       masks=MaskShareStore(str(tmp_path / f"m{s.index}.log"), "pw"))
        srv = CustodianServer("127.0.0.1", 0, cu)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv); ports.append(srv.address[1]); customs.append(cu)
    db = NoKeyTCPServer("127.0.0.1", 0)
    threading.Thread(target=db.serve_forever, daemon=True).start()

    def cluster(**kw):
        return ThresholdMaskStore([RemoteCustodian("127.0.0.1", p, TOKEN, group=pub.g)
                                   for p in ports], 3, **kw)
    first = cluster()
    first.initialize(authenticated=True)
    yield db.address, cluster, servers, customs, tmp_path
    for srv in servers:
        try: srv.shutdown(); srv.server_close()
        except Exception: pass
    db.shutdown(); db.server_close()


def test_stateless_owner_second_client_and_transactions(stack):
    addr, cluster, servers, customs, tmp = stack
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c:
        assert c.client.authenticated and len(c.client._masks) == 0
        c.execute("CREATE TABLE emp (id INT PLAIN, salary INT ENC)")
        c.cursor().executemany("INSERT INTO emp (id, salary) VALUES (%s, %s)",
                               [(i, i * 100) for i in range(1, 11)])
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[5500]]
        with c.transaction():
            c.execute("UPDATE emp SET salary = 1 WHERE id = 1")
            c.execute("INSERT INTO emp (id, salary) VALUES (99, 99)")
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[5500 - 100 + 1 + 99]]
        c.begin()
        c.execute("UPDATE emp SET salary = 123456 WHERE id = 2")
        c.execute("DELETE FROM emp WHERE id = 3")
        c.rollback()
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[5500]]    # == 5500-100+1+99
    # a brand-new process: no vault file, no local state — only the cluster
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c2:
        assert c2.execute("SELECT COUNT(*), SUM(salary) FROM emp").rows == [[11, 5500]]
        c2.execute("UPDATE emp SET salary = 5 WHERE id = 4")
        assert c2.find_orphans() == {}
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c3:
        assert c3.execute("SELECT SUM(salary) FROM emp").rows == [[5500 - 400 + 5]]


def test_custodian_restart_keeps_every_mask(stack):
    addr, cluster, servers, customs, tmp = stack
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c:
        c.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
        c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(i, i) for i in range(50)])
    for cu in customs:                                 # "restart": reopen each store from disk
        cu.masks.close()
    for cu, idx in zip(customs, range(1, 6)):
        cu.masks = MaskShareStore(str(tmp / f"m{idx}.log"), "pw")
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c:
        assert c.execute("SELECT SUM(v) FROM t").rows == [[1225]]


def test_wrong_vault_style_misuse_is_rejected(stack):
    addr, cluster, *_ = stack
    with pytest.raises(torussql.ProgrammingError, match="replaces the local vault"):
        torussql.connect(*addr, mask_cluster=cluster(), vault_path="/tmp/x")


def test_repair_orphans_refuses_to_delete_most_of_a_table(stack):
    addr, cluster, *_ = stack
    with torussql.connect(*addr, mask_cluster=cluster(), trust_server_schema=True) as c:
        c.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
        c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(i, i) for i in range(10)])
        c._wire.call("insert", ["t", {"id": {"t": "i", "v": "99"}, "v": {"t": "i", "v": "5"},
                                      "__mac__v": {"t": "i", "v": "5"}}])        # row with no refs
        assert c.find_orphans() == {"t": [10]}
        assert c.repair_orphans() == 1
        assert c.find_orphans() == {}
        # a wrong cluster would make EVERYTHING look orphaned → refuse
        c.client.maskstore.available = lambda t, col, ids: [False] * len(ids)
        with pytest.raises(torussql.ProgrammingError, match="wrong vault or mask cluster"):
            c.repair_orphans()


# ── re-sharing to a new committee ────────────────────────────────────────────
def test_reshare_moves_every_mask_to_a_new_committee(tmp_path):
    old_nodes, old_customs, old, *_ = make_cluster()
    init(old, True)
    srv = NoKeyServer()
    c = NoKeyClient(srv, maskstore=old)
    c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC, w INT PAIRED)")
    for i in range(1, 31):
        c.execute(f"INSERT INTO t (a, v, w) VALUES ({i}, {i * 3}, {i})")
    c.execute("UPDATE t SET v = 1000 WHERE a = 7")
    want = c.execute("SELECT SUM(v), DOT(w, w) FROM t").rows
    new_nodes, _cu, _s, *_ = make_cluster(k=4, n=7)            # a different committee shape
    new = reshare_masks(old, new_nodes, 4)
    assert (new.k, new.n, new.gen) == (4, 7, 1)
    with pytest.raises(Frozen):                                # the old generation is closed to writes
        old_customs[0].masks.put(0, 1, [("t", "zz", "v", 9, 5)])
    c2 = NoKeyClient(srv, maskstore=ThresholdMaskStore(new_nodes, 4, gen=1))
    c2._coltype, c2._colpolicy, c2._schema = c._coltype, c._colpolicy, c._schema
    assert c2.authenticated and c2._alpha == c._alpha          # integrity key survived
    assert c2.execute("SELECT SUM(v), DOT(w, w) FROM t").rows == want
    c2.execute("INSERT INTO t (a, v, w) VALUES (99, 1, 1)")    # new generation accepts writes
    assert c2.execute("SELECT SUM(v) FROM t").rows == [[want[0][0] + 1]]
    # the new committee tolerates 3 failures of 7; the old one is not needed any more
    for nd in new_nodes[:3]:
        nd.mode = "down"
    assert c2.execute("SELECT SUM(v) FROM t").rows == [[want[0][0] + 1]]


# ── the building blocks ──────────────────────────────────────────────────────
def test_share_store_semantics(tmp_path):
    p = str(tmp_path / "s.log")
    st = MaskShareStore(p, "pw")
    assert st.put(0, 3, [("t", "c1", "v", 1, 11), ("t", "c2", "v", 1, 22)]) == 2
    assert st.put(0, 3, [("t", "c1", "v", 1, 11)]) == 0                  # idempotent
    with pytest.raises(ShareConflict, match="never reused"):
        st.put(0, 3, [("t", "c1", "v", 1, 12)])
    with pytest.raises(ShareConflict, match="point"):
        st.put(0, 4, [("t", "c9", "v", 1, 1)])                           # one point per generation
    with pytest.raises(Exception, match="out of range"):
        st.put(0, 3, [("t", "c3", "v", 1, Q)])
    assert st.sum(0, "t", "v", [("c1", 1, 2), ("c2", 1, 1)]) == (44, 3)
    from torussql.custody.shares import MissingShare
    with pytest.raises(MissingShare):
        st.sum(0, "t", "v", [("c1", 1, 1), ("nope", 1, 1)])
    assert st.get(0, "t", "v", [("c1", 1), ("nope", 1)]) == ([11, None], 3)
    assert st.meta_put(0, "k", {"a": 1}, if_absent=True) and not st.meta_put(0, "k", 2, if_absent=True)
    st.set_frozen(0, True)
    with pytest.raises(Frozen):
        st.put(0, 3, [("t", "c4", "v", 1, 1)])
    st.set_frozen(0, False)
    st.put(0, 3, [("t", "c%03d" % i, "v", 1, i) for i in range(10)])
    page, nxt = st.list_page(0, "t", None, 4)
    page2, _ = st.list_page(0, "t", nxt, 100)
    assert len(page) == 4 and len(page2) == len(st._gens[0].tables["t"]) - 4
    st.delete(0, [("t", "c1", "v", 1)])
    st.drop_table(0, "other")
    st.compact()
    st.close()
    st2 = MaskShareStore(p, "pw")
    assert st2.get(0, "t", "v", [("c1", 1), ("c2", 1)]) == ([None, 22], 3)
    assert st2.meta_get(0, "k") == {"a": 1}
    st2.drop_table(0, "t")
    st2.close()
    assert MaskShareStore(p, "pw").tables(0) == []


def test_record_log_torn_tail_corruption_wrong_passphrase_and_failed_append(tmp_path, monkeypatch):
    p = str(tmp_path / "l.log")
    log = RecordLog(p, b"TESTLOG1", "pw")
    list(log.open())
    for i in range(5):
        log.append({"i": i})
    log.close()
    good = open(p, "rb").read()
    # torn final record → dropped; the 5 good ones survive and appends continue cleanly
    open(p, "wb").write(good + b'S 00ab')
    log = RecordLog(p, b"TESTLOG1", "pw")
    assert [r["i"] for r in log.open()] == [0, 1, 2, 3, 4]
    log.append({"i": 5}); log.close()
    assert [r["i"] for r in RecordLog(p, b"TESTLOG1", "pw").open()] == [0, 1, 2, 3, 4, 5]
    # corruption in the MIDDLE → refuse, never truncate the later valid records
    lines = open(p, "rb").read().split(b"\n")
    lines[3] = lines[3][:-4] + b"beef"
    open(p, "wb").write(b"\n".join(lines))
    before = open(p, "rb").read()
    with pytest.raises(LogCorrupt, match="refusing"):
        list(RecordLog(p, b"TESTLOG1", "pw").open())
    assert open(p, "rb").read() == before
    # wrong / missing passphrase never modifies the file
    open(p, "wb").write(good)
    for pw in ("nope", None):
        with pytest.raises(LogLocked):
            list(RecordLog(p, b"TESTLOG1", pw).open())
    assert open(p, "rb").read() == good
    # a deleted record is detected through the sequence numbers
    lines = good.split(b"\n")
    open(p, "wb").write(b"\n".join(lines[:2] + lines[3:]))
    with pytest.raises(LogCorrupt, match="corrupt|out of sequence"):   # position is in the AAD
        list(RecordLog(p, b"TESTLOG1", "pw").open())
    # a failed append (disk full part-way) leaves no trace, even after later successes
    open(p, "wb").write(good)
    log = RecordLog(p, b"TESTLOG1", "pw")
    list(log.open())
    real = os.write
    calls = {"n": 0}

    def flaky(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real(fd, bytes(data)[: len(data) // 2])
            raise OSError(28, "No space left on device")
        return real(fd, data)
    monkeypatch.setattr("torussql.recordlog.os.write", flaky)
    with pytest.raises(OSError):
        log.append({"i": "GHOST"})
    log.append({"i": 6})
    log.close()
    monkeypatch.undo()
    recs = [r["i"] for r in RecordLog(p, b"TESTLOG1", "pw").open()]
    assert recs == [0, 1, 2, 3, 4, 6] and "GHOST" not in recs


def test_robust_reconstruct_majority_rules():
    k, n = 3, 7
    s = random.Random(1).randrange(Q)
    sh = laurent.split(s, laurent.Params(k, n, Q))
    assert laurent.robust_reconstruct(sh, k, Q) == (s, [])
    for bad_count in (1, 2, 3):                         # up to n−k−1... majority still wins
        bad = [(x, (y + 5) % Q) if i < bad_count else (x, y) for i, (x, y) in enumerate(sh)]
        sec, faulty = laurent.robust_reconstruct(bad, k, Q)
        assert sec == s and len(faulty) == bad_count
    bad = [(x, (y + i + 1) % Q) if i < 4 else (x, y) for i, (x, y) in enumerate(sh)]
    with pytest.raises(laurent.InconsistentShares):
        laurent.robust_reconstruct(bad, k, Q)
    with pytest.raises(laurent.InconsistentShares):
        laurent.robust_reconstruct(sh + [(sh[0][0], (sh[0][1] + 1) % Q)], k, Q)   # same holder twice


def test_bn254_order_matches_the_engine_field():
    from torusdb_core.protocol import N
    assert Q == N
