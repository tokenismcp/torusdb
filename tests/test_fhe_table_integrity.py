# SPDX-License-Identifier: Apache-2.0
"""Anchored table-state integrity for FHE tables (core/torusdb_core/fhe_anchor.py).

Every attack is run twice: against an owner WITH an integrity anchor (must raise IntegrityError)
and against one without (the negative control: the same attack succeeds, so the anchor — not the
tags alone — is what blocks it)."""
from __future__ import annotations

import copy
import glob
import json
import os
import shutil
import stat

import pytest

import torussql
from torusdb_core import fhe
from torusdb_core.fhe_anchor import (
    AnchorConflict, AnchorFileError, AnchorMissingError, Change, FileAnchor, MemoryAnchor,
    StaleServerError, canon_value)
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from test_ops import ADMIN, RW, RO, TOKENS, Running

KEY = fhe.FheKey(value_range=10_000)
ROWS = [(1, 5, 40), (2, 5, 55), (3, 7, 30), (4, 5, 20)]
Q = "SELECT SUM(rate), AVG(rate), COUNT(*) FROM emp WHERE dept = 5"
HONEST = [[115, 115 / 3, 3]]
IE = torussql.IntegrityError


def same(rows, want):
    return [[float(x) if hasattr(x, "denominator") else x for x in r] for r in rows] == \
           [[float(x) for x in r] for r in want]


class Env:
    def __init__(self, tmp_path):
        self.tmp, self._servers, self._conns = tmp_path, [], []
        self.anchor_path = str(tmp_path / "anchor.json")

    def server(self, **cfg):
        s = Running(**cfg)
        self._servers.append(s)
        return s

    def conn(self, s, anchored=True, **kw):
        if anchored:
            kw.setdefault("integrity_anchor", self.anchor_path)
        kw.setdefault("fhe_key", KEY)
        kw.setdefault("authenticated", True)
        c = s.connect(**kw)
        self._conns.append(c)
        return c

    def seeded(self, anchored=True, rows=ROWS, **cfg):
        s = self.server(**cfg)
        c = self.conn(s, anchored)
        c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
        for i, d, r in rows:
            c.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({i}, {d}, {r})")
        return s, c

    def close(self):
        for c in self._conns:
            try:
                c.close()
            except Exception:                                    # noqa: BLE001
                pass
        for s in self._servers:
            try:
                s.stop()
            except Exception:                                    # noqa: BLE001
                pass


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def eng(s):
    return s.srv.engine


def store(s, table="emp"):
    return eng(s).srv._rows[table]


def swap_db(s, body):
    """The server 'restores a backup': replaces its whole database by an older image."""
    with eng(s)._lock:
        eng(s).srv = NoKeyServer.from_body(body)


def image(s):
    with eng(s)._lock:
        return copy.deepcopy(eng(s).srv.to_body())


def lie_scan(c, edit):
    """Interpose on the scan answer of this connection (a lying server)."""
    srv = c.client.server
    real = srv.fhe_rows

    def lying(table, start, count):
        n, rows = real(table, start, count)
        return edit(n, [list(r) for r in rows])
    srv.fhe_rows = lying
    return real


# ═══ the anchor store ════════════════════════════════════════════════════════
@pytest.mark.parametrize("make", [lambda p: MemoryAnchor(), lambda p: FileAnchor(str(p / "a.json"))])
def test_anchor_cas_pending_finish_abort_and_history(tmp_path, make):
    a = make(tmp_path)
    assert a.get("t") is None
    a.begin_commit({"t": Change(None, 0, 0)}, "tx0")           # CREATE
    assert a.get("t").pending.epoch == 1 and a.get("t").epoch == 0
    with pytest.raises(AnchorConflict, match="pending"):
        a.begin_commit({"t": Change(0, 5, 1)}, "tx1")           # a commit is already pending
    a.finish_commit(["t"], "tx0")
    e = a.get("t")
    assert (e.epoch, e.root, e.count, e.pending) == (1, 0, 0, None)
    a.begin_commit({"t": Change(1, 99, 2)}, "tx2")
    a.abort(["t"], "tx2")
    assert (a.get("t").epoch, a.get("t").root, a.get("t").pending) == (1, 0, None)
    with pytest.raises(AnchorConflict, match="epoch"):          # compare-and-swap on the epoch
        a.begin_commit({"t": Change(0, 7, 1)}, "tx3")
    a.begin_commit({"t": Change(1, 99, 2)}, "tx4")
    with pytest.raises(AnchorConflict):
        a.finish_commit(["t"], "someone-else")                  # not our pending commit
    a.finish_commit(["t"], "tx4")
    a.finish_commit(["t"], "tx4")                               # idempotent: already settled
    assert (a.get("t").epoch, a.get("t").root, a.get("t").count) == (2, 99, 2)
    assert (1, 0, 0) in a.get("t").history
    # all-or-nothing across tables
    with pytest.raises(AnchorConflict):
        a.begin_commit({"t": Change(2, 1, 1), "u": Change(5, 1, 1)}, "tx5")
    assert a.get("t").pending is None and a.get("u") is None
    # a table that is dropped
    a.begin_commit({"t": Change(2, None)}, "tx6")
    a.finish_commit(["t"], "tx6")
    assert a.get("t") is None


def test_file_anchor_is_0600_crash_safe_and_refuses_unsafe_files(tmp_path):
    p = tmp_path / "a.json"
    a = FileAnchor(str(p))
    a.set("t", 123, 4, None)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert json.loads(p.read_text())["v"] == 1
    assert not glob.glob(str(p) + ".tmp.*")                     # temporary files are gone
    assert FileAnchor(str(p)).get("t").root == 123              # survives a new instance (new process)
    os.chmod(p, 0o644)
    with pytest.raises(AnchorFileError, match="permissions"):
        a.get("t")
    os.chmod(p, 0o600)
    p.write_text("not json")
    with pytest.raises(AnchorFileError, match="corrupt"):        # never silently start from empty
        a.get("t")
    p.write_text(json.dumps({"format": "torussql-fhe-anchor", "v": 99, "tables": {}}))
    with pytest.raises(AnchorFileError, match="version"):
        a.get("t")
    p.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    os.symlink(target, p)
    with pytest.raises(AnchorFileError):
        a.get("t")
    with pytest.raises(AnchorFileError):
        a.set("t", 1, 1, None)
    with pytest.raises(AnchorFileError, match="directory"):
        FileAnchor(str(tmp_path / "nodir" / "a.json"))


def test_two_file_anchor_objects_are_serialised(tmp_path):
    p = str(tmp_path / "a.json")
    a, b = FileAnchor(p), FileAnchor(p)
    a.begin_commit({"t": Change(None, 5, 1)}, "x")
    with pytest.raises(AnchorConflict):                         # b sees a's pending commit
        b.begin_commit({"t": Change(0, 6, 2)}, "y")
    a.finish_commit(["t"], "x")
    b.begin_commit({"t": Change(1, 6, 2)}, "y")
    b.finish_commit(["t"], "y")
    assert a.get("t").epoch == 2


def test_canonical_values_are_unambiguous():
    from fractions import Fraction
    assert canon_value(5) == canon_value(True * 5) == canon_value(Fraction(5, 1))
    assert len({canon_value(v) for v in (None, 0, "0", "", b"", Fraction(1, 2), 1, "1")}) == 8


# ═══ honest flows ════════════════════════════════════════════════════════════
def test_honest_flows_over_tcp(env):
    s, c = env.seeded()
    assert same(c.execute(Q).rows, HONEST)
    assert c.execute("SELECT id, rate FROM emp WHERE dept = 5").rows == [[1, 40], [2, 55], [4, 20]]
    assert c.execute("SELECT id FROM emp WHERE dept = 7 OR id = 1").rows == [[1], [3]]
    assert c.execute("SELECT 3 * SUM(rate) FROM emp").rows == [[3 * 145]]
    assert c.execute("SELECT DOT(rate, rate) FROM emp").rows == [[40 * 40 + 55 * 55 + 30 * 30 + 20 * 20]]
    c.execute("UPDATE emp SET rate = 45, dept = 7 WHERE id = 1")
    c.execute("DELETE FROM emp WHERE id = 4")
    assert c.execute("SELECT id, dept, rate FROM emp").rows == [[1, 7, 45], [2, 5, 55], [3, 7, 30]]
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
    # explicit transactions: rollback discards the delta (and the anchor), commit keeps it
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 1)")
    c.execute("DELETE FROM emp WHERE id = 2")
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]   # sees its own changes: 3 - 1 + 1
    c.rollback()
    assert c.execute("SELECT id FROM emp").rows == [[1], [2], [3]]
    with c.transaction():
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 1)")
        c.execute("UPDATE emp SET rate = 2 WHERE id = 9")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[45 + 55 + 30 + 2]]
    cur = c.cursor()
    cur.executemany("INSERT INTO emp (id, dept, rate) VALUES (%s, %s, %s)", [(20, 1, 3), (21, 1, 4)])
    assert c.execute("SELECT SUM(rate) FROM emp WHERE dept = 1").rows == [[7]]
    info = c.verify_table("emp")
    assert info["rows"] == 6
    # a second client with the same key and anchor sees it all (it must scan: another epoch)
    c2 = env.conn(s)
    assert c2.execute("SELECT SUM(rate) FROM emp").rows == [[45 + 55 + 30 + 2 + 7]]
    assert c2.client._amgr.stats["scans"] == 1
    # the anchor survives: a new owner process with the same files verifies the same state
    c3 = env.conn(s)
    assert c3.execute("SELECT COUNT(*) FROM emp").rows == [[6]]


def test_anchor_state_is_cached_per_epoch_and_not_rescanned(env):
    s, c = env.seeded()
    m = c.client._amgr
    n0 = m.stats["scans"]
    for _ in range(3):
        c.execute(Q)
    c.execute("UPDATE emp SET rate = 41 WHERE id = 1")
    c.execute(Q)
    assert m.stats["scans"] == n0                                # own writes update the snapshot in place
    other = env.conn(s)
    other.execute("INSERT INTO emp (id, dept, rate) VALUES (8, 5, 8)")
    c.execute(Q)
    assert m.stats["scans"] == n0 + 1                            # another owner advanced the epoch


def test_scan_is_chunked(env):
    s, c = env.seeded(rows=[(i, i % 3, i) for i in range(1, 8)], fhe_max_scan_rows=3)
    assert c.client._fhe_limits()["max_scan_rows"] == 3
    c2 = env.conn(s)
    assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[7]]
    assert c2.client._amgr.stats["scan_rows"] == 7
    with pytest.raises(Exception, match="at most 3"):
        c2._wire.call("fhe_rows", ["emp", 0, 4])


def test_mixed_table_with_enc_column_and_plain_only_tables(env):
    s = env.server()
    c = env.conn(s)
    c.execute("CREATE TABLE mix (id INT PLAIN, sal INT ENC, rate INT FHE)")
    c.execute("CREATE TABLE plainonly (id INT PLAIN, v INT PLAIN)")
    c.execute("INSERT INTO mix (id, sal, rate) VALUES (1, 100, 7)")
    c.execute("INSERT INTO plainonly (id, v) VALUES (1, 2)")
    c.execute("UPDATE mix SET sal = 150, rate = 8 WHERE id = 1")
    assert c.execute("SELECT id, sal, rate FROM mix").rows == [[1, 150, 8]]
    assert c.client._amgr.anchor.tables() == ["mix"]              # tables without FHE columns are not anchored
    assert c.execute("SELECT v FROM plainonly").rows == [[2]]


def test_drop_and_recreate_resets_the_anchor_and_a_rolled_back_create_leaves_nothing(env):
    s, c = env.seeded()
    c.execute("DROP TABLE emp")
    assert c.client._amgr.anchor.get("emp") is None
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (1, 1, 1)")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[1]]
    c.begin()
    c.execute("CREATE TABLE tmp (a INT PLAIN, b INT FHE)")
    c.rollback()
    assert c.client._amgr.anchor.get("tmp") is None
    # a rolled-back DROP leaves the anchor untouched
    c.begin()
    c.execute("DROP TABLE emp")
    c.rollback()
    assert c.client._amgr.anchor.get("emp") is not None
    assert env.conn(s).execute("SELECT COUNT(*) FROM emp").rows == [[1]]
    # the server drops and re-creates the table behind the owner's back
    c.client.server.drop("emp")
    c.client.server.create("emp", [("id", "int", "plain"), ("dept", "int", "plain"), ("rate", "int", "fhe")])
    with pytest.raises(IE, match="anchor"):
        env.conn(s).execute("SELECT COUNT(*) FROM emp")


def test_size_guard(env):
    s, c = env.seeded(rows=ROWS)
    small = env.conn(s, integrity_anchor_max_rows=2)
    with pytest.raises(Exception, match="limit"):
        small.execute("SELECT COUNT(*) FROM emp")


def test_anchor_needs_authentication_and_a_key(env):
    s = env.server()
    with pytest.raises(torussql.ProgrammingError):
        s.connect(fhe_key=KEY, integrity_anchor=env.anchor_path)
    with pytest.raises(torussql.ProgrammingError):
        s.connect(authenticated=True, integrity_anchor=env.anchor_path)


# ═══ adopt_table (trust on first use) ════════════════════════════════════════
def test_adopt_table(env):
    s, plain = env.seeded(anchored=False)                         # data written before any anchor existed
    c = env.conn(s)
    with pytest.raises(torussql.ProgrammingError, match="adopt_table"):
        c.execute(Q)
    with pytest.raises(torussql.ProgrammingError, match="adopt_table"):
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (5, 1, 1)")
    info = c.adopt_table("emp")
    assert info["rows"] == 4
    assert same(c.execute(Q).rows, HONEST)
    with pytest.raises(torussql.DataError, match="already has an anchor"):
        c.adopt_table("emp")
    # from now on the row set is protected
    store(s).kill([0])
    with pytest.raises(IE):
        env.conn(s).execute(Q)
    c.adopt_table("emp", replace=True)                            # the owner decides to re-adopt (TOFU again)
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]


def test_adopt_is_only_as_honest_as_the_server_at_that_moment(env):
    s, plain = env.seeded(anchored=False)
    store(s).set_cell(2, "dept", 5)                               # tampered BEFORE adoption
    c = env.conn(s)
    c.adopt_table("emp")
    assert c.execute("SELECT COUNT(*) FROM emp WHERE dept = 5").rows == [[4]]   # the lie became the anchor


# ═══ attacks: row sets (F3) — each against anchor and control ════════════════
@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_poc5_selection_lie_drop_and_add(env, anchored):
    s, c = env.seeded(anchored)
    srv = c.client.server
    real, calls = srv.matching_rowids, []
    srv.matching_rowids = lambda t, w: calls.append(1) or real(t, w)[:-1]       # 'forgets' the last match
    dropped = c.execute(Q).rows
    srv.matching_rowids = lambda t, w: calls.append(1) or real(t, w) + [2]      # adds a non-matching row
    added = c.execute(Q).rows
    srv.matching_rowids = real
    if anchored:
        assert not calls                                          # the owner never asks the server who matches
        assert same(dropped, HONEST) and same(added, HONEST)
    else:
        assert not same(dropped, HONEST) and not same(added, HONEST)   # accepted, wrong: the F3 bug
        assert dropped[0][2] == 2 and added[0][2] == 4


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_count_and_avg_denominators_cannot_be_lied_about(env, anchored):
    s, c = env.seeded(anchored)
    srv = c.client.server
    real = srv.matching_rowids
    srv.matching_rowids = lambda t, w: real(t, w)[:1]
    got = c.execute("SELECT COUNT(*), AVG(rate) FROM emp").rows
    srv.matching_rowids = real
    if anchored:
        assert got[0][0] == 4
    else:
        assert got[0][0] == 1


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_poc5_plain_column_tamper_in_storage(env, anchored):
    s, c = env.seeded(anchored)
    c._wire.call("update_cell", ["emp", 2, "dept", {"t": "i", "v": "5"}])             # dept of id 3: 7 -> 5
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE, match="does not match the anchor"):
            fresh.execute(Q)
        with pytest.raises(IE):
            c.verify_table("emp")
        assert same(c.execute(Q).rows, HONEST)                    # the cached, anchored state still answers truthfully
    else:
        assert fresh.execute(Q).rows[0][2] == 4                   # accepted: wrong COUNT


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_server_adds_a_row(env, anchored):
    s, c = env.seeded(anchored)
    with eng(s)._lock:
        st = store(s)
        st.append(dict(st.row(0)))                                # a copy of a valid row, new slot
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE, match="does not match the anchor"):
            fresh.execute("SELECT COUNT(*) FROM emp")
    else:
        assert fresh.execute("SELECT COUNT(*) FROM emp").rows == [[5]]


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_server_drops_or_resurrects_rows(env, anchored):
    s, c = env.seeded(anchored)
    c.execute("DELETE FROM emp WHERE id = 4")
    with eng(s)._lock:
        store(s).revive([3])                                      # resurrect the deleted row
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE):
            fresh.execute("SELECT COUNT(*) FROM emp")
    else:
        assert fresh.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    with eng(s)._lock:
        store(s).kill([3, 0])                                     # now drop a live row as well
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE):
            fresh.execute("SELECT COUNT(*) FROM emp")
    else:
        assert fresh.execute("SELECT COUNT(*) FROM emp").rows == [[2]]


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_server_hides_a_delete(env, anchored):
    s, c = env.seeded(anchored)
    c.client.server.delete_rows = lambda t, ids: len(ids)         # claims it deleted, did nothing
    c.execute("DELETE FROM emp WHERE id = 2")
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE):
            fresh.execute("SELECT COUNT(*) FROM emp")
        with pytest.raises(IE):
            c.verify_table("emp")
    else:
        assert fresh.execute("SELECT COUNT(*) FROM emp").rows == [[4]]     # the 'deleted' row is still there


def test_lying_scan_dead_flags_extra_rows_and_shape(env):
    s, c = env.seeded()
    c.execute("DELETE FROM emp WHERE id = 3")                     # slot 2 is dead
    cases = {
        "live row reported dead": lambda n, rows: (n, [(r[0], True, None, None) if r[0] == 1 else tuple(r)
                                                       for r in rows]),
        "dead row reported live": lambda n, rows: (n, [(r[0], False, list(rows[0][2]), list(rows[0][3]))
                                                       if r[0] == 2 else tuple(r) for r in rows]),
        "a row hidden by a short answer": lambda n, rows: (n, [tuple(r) for r in rows][:-1]),
        "slot count understated": lambda n, rows: (n - 1, [tuple(r) for r in rows][:-1]),
        "a plain value changed": lambda n, rows: (n, [(r[0], r[1], [r[2][0], 6], r[3]) if r[0] == 0 else tuple(r)
                                                      for r in rows]),
        "a write nonce changed": lambda n, rows: (n, [(r[0], r[1], r[2], [(r[3][0][0] + 2, r[3][0][1], r[3][0][2])])
                                                      if r[0] == 0 else tuple(r) for r in rows]),
        "a cell hash changed": lambda n, rows: (n, [(r[0], r[1], r[2], [(r[3][0][0], b"\0" * 32, r[3][0][2])])
                                                    if r[0] == 0 else tuple(r) for r in rows]),
        "a row duplicated": lambda n, rows: (n, [tuple(r) for r in rows] + [tuple(rows[0])]),
        "wrong shape": lambda n, rows: (n, [(r[0], r[1], r[2][:1], r[3]) if r[0] == 0 else tuple(r) for r in rows]),
        "slots swapped": lambda n, rows: (n, [tuple(rows[1]), tuple(rows[0])] + [tuple(r) for r in rows[2:]]),
    }
    for name, edit in cases.items():
        liar = env.conn(s)
        lie_scan(liar, edit)
        with pytest.raises(IE):
            liar.execute("SELECT COUNT(*) FROM emp")
        assert name
    honest = env.conn(s)
    assert honest.execute("SELECT COUNT(*) FROM emp").rows == [[3]]


def test_malformed_scan_replies_are_integrity_failures(env):
    s, c = env.seeded()
    liar = env.conn(s)
    real = liar.client.server._c.call

    def broken(method, args):
        r = real(method, args)
        if method == "fhe_rows":
            r["rows"][0] = [0, 0, "garbage"]
        return r
    liar.client.server._c.call = broken
    with pytest.raises(IE, match="malformed"):
        liar.execute("SELECT COUNT(*) FROM emp")


# ═══ attacks: freshness / replay ═════════════════════════════════════════════
@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_whole_table_rolled_back_to_an_older_complete_state(env, anchored):
    s, c = env.seeded(anchored)
    old = image(s)
    c.execute("UPDATE emp SET rate = 99 WHERE id = 2")
    c.execute("DELETE FROM emp WHERE id = 1")
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (7, 5, 7)")
    swap_db(s, old)                                               # value + tag + nonce + row set, all consistent
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE) as ei:
            fresh.execute(Q)
        assert "behind the anchor" in str(ei.value)
        with pytest.raises(IE):
            c.execute("SELECT SUM(rate) FROM emp")                # even the cached owner notices at the first fetch
        with pytest.raises(IE):
            c.execute("SELECT id, rate FROM emp")
    else:
        assert same(fresh.execute(Q).rows, HONEST)                # the old table is accepted as current
        assert fresh.execute("SELECT rate FROM emp WHERE id = 2").rows == [[55]]


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_replay_of_one_old_row_version(env, anchored):
    s, c = env.seeded(anchored)
    st = store(s)
    old = {col: st.row(1)[col] for col in ("rate", "__fmac__rate", "__fnonce__rate")}
    c.execute("UPDATE emp SET rate = 99 WHERE id = 2")
    with eng(s)._lock:
        for col, v in old.items():
            st.set_cell(1, col, v)
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE):
            fresh.execute("SELECT SUM(rate) FROM emp")
        with pytest.raises(IE):
            c.execute("SELECT rate FROM emp WHERE id = 2")        # cached owner: hash of the fetched cell
        with pytest.raises(IE):
            c.execute("SELECT SUM(rate) FROM emp")                # cached owner: the anchored nonce is not the old one
    else:
        assert fresh.execute("SELECT rate FROM emp WHERE id = 2").rows == [[55]]   # stale value accepted
        assert fresh.execute("SELECT SUM(rate) FROM emp").rows == [[145]]


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "control"])
def test_swapped_rows(env, anchored):
    s, c = env.seeded(anchored)
    st = store(s)
    with eng(s)._lock:
        a, b = dict(st.row(0)), dict(st.row(1))
        for col in ("rate", "__fmac__rate", "__fnonce__rate"):
            st.set_cell(0, col, b[col])
            st.set_cell(1, col, a[col])
    with pytest.raises(IE):                                       # the row-bound tags already catch a swap of FHE data
        env.conn(s, anchored).execute("SELECT id, rate FROM emp")
    with eng(s)._lock:                                            # swap back, then swap a PLAIN column instead
        for col in ("rate", "__fmac__rate", "__fnonce__rate"):
            st.set_cell(0, col, a[col])
            st.set_cell(1, col, b[col])
        st.set_cell(0, "dept", 7)
        st.set_cell(2, "dept", 5)
    fresh = env.conn(s, anchored)
    if anchored:
        with pytest.raises(IE):
            fresh.execute(Q)
    else:
        assert fresh.execute(Q).rows[0][0] != 115                 # undetected without an anchor


def test_poc4_affine_mixing_under_an_anchor(env):
    s, c = env.seeded()
    srv = c.client.server
    old_v = srv.plain_cells("emp", "rate", [1])[0]
    old_t = srv.plain_cells("emp", "__fmac__rate", [1])[0]
    c.execute("UPDATE emp SET rate = 56 WHERE id = 2")
    new_v = srv.plain_cells("emp", "rate", [1])[0]
    new_t = srv.plain_cells("emp", "__fmac__rate", [1])[0]
    honest = c.execute("SELECT SUM(rate) FROM emp").rows
    assert honest == [[40 + 56 + 30 + 20]]
    cell = lambda col, i: srv.plain_cells("emp", col, [i])[0]     # noqa: E731
    real = srv.fhe_sum

    def liar(lam):
        def fake(table, col, ids, k=1):
            if table != "emp" or ids != [0, 1, 2, 3]:
                return real(table, col, ids, k)
            o, n = (old_v, new_v) if col == "rate" else (old_t, new_t)
            rest = fhe.sum_cells([cell(col, 0), cell(col, 2), cell(col, 3)], None, k)
            mixed = fhe.add_sums(fhe.sum_cells([o], None, lam * k), fhe.sum_cells([n], None, (1 - lam) * k))
            return fhe.add_sums(rest, mixed)
        return fake
    for lam in (1, -500, 7):
        srv.fhe_sum = liar(lam)
        with pytest.raises(IE):
            c.execute("SELECT SUM(rate) FROM emp")
    srv.fhe_sum = liar(0)                                         # lam = 0 is the honest answer
    assert c.execute("SELECT SUM(rate) FROM emp").rows == honest


def test_colluding_server_honest_scan_but_other_cells_later(env):
    s, c = env.seeded()
    srv = c.client.server
    real = srv.plain_cells
    # (a) cell reads: the scan was honest, but the cell bytes served later are another row's / an older version
    other = real("emp", "rate", [0, 1, 2, 3])
    srv.plain_cells = lambda t, col, ids: ([other[(i + 1) % 4] for i in ids] if (t, col) == ("emp", "rate")
                                           else real(t, col, ids))
    with pytest.raises(IE, match="anchored"):
        c.execute("SELECT id, rate FROM emp")
    # (b) the same cell bytes but a lying tag
    tags = real("emp", "__fmac__rate", [0, 1, 2, 3])
    srv.plain_cells = lambda t, col, ids: ([tags[(i + 1) % 4] for i in ids] if col == "__fmac__rate"
                                           else real(t, col, ids))
    with pytest.raises(IE, match="anchored"):
        c.execute("SELECT id, rate FROM emp")
    srv.plain_cells = real
    # (c) the nonces the server reports are never used: lying about them changes nothing
    srv.plain_cells = lambda t, col, ids: ([12345] * len(ids) if col == "__fnonce__rate" else real(t, col, ids))
    assert c.execute("SELECT id, rate FROM emp").rows == [[r[0], r[2]] for r in ROWS]
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    srv.plain_cells = real
    # (d) sums over cells other than the anchored ones
    st = store(s)
    with eng(s)._lock:
        saved = st.row(0)["rate"]
        st.set_cell(0, "rate", st.row(1)["rate"])                 # storage now holds another row's cell
    with pytest.raises(IE):
        c.execute("SELECT SUM(rate) FROM emp")
    with eng(s)._lock:
        st.set_cell(0, "rate", saved)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]


def test_dot_local_mode_still_works_and_catches_a_tampered_operand(env):
    s, c = env.seeded()
    assert c.execute("SELECT DOT(rate, rate) FROM emp").rows == [[1600 + 3025 + 900 + 400]]
    srv = c.client.server
    real = srv.plain_cells
    other = real("emp", "rate", [0, 1, 2, 3])
    srv.plain_cells = lambda t, col, ids: ([other[0]] * len(ids) if col == "rate" else real(t, col, ids))
    with pytest.raises(IE):
        c.execute("SELECT DOT(rate, rate) FROM emp")


# ═══ replicas ════════════════════════════════════════════════════════════════
def test_replica_lagging_behind_the_anchor_is_refused_explicitly(env, tmp_path):
    from test_replication import wait_for
    p = env.server(db=str(tmp_path / "p"), tokens=dict(TOKENS))
    owner = env.conn(p, token=RW)
    owner.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
    for i, d, r in ROWS[:3]:
        owner.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({i}, {d}, {r})")
    r = env.server(db=str(tmp_path / "r"), tokens=dict(TOKENS), replica_of=(p.host, p.port),
                   repl_conn={"token": ADMIN}, repl_poll=0.3)
    reader = env.conn(r, token=RO)
    wait_for(lambda: reader.execute("SELECT COUNT(*) FROM emp").rows == [[3]], what="replica bootstrap")
    fol = r.srv.engine._follower
    fol.stop()                                                    # the replica stops following
    fol.join(timeout=40)
    owner.execute("INSERT INTO emp (id, dept, rate) VALUES (4, 5, 20)")
    lagging = env.conn(r, token=RO)
    with pytest.raises(IE, match="behind the anchor"):
        lagging.execute("SELECT SUM(rate) FROM emp")
    # the primary itself is fine, and a replica that has caught up is accepted
    assert env.conn(p, token=RO).execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    r2 = env.server(db=str(tmp_path / "r2"), tokens=dict(TOKENS), replica_of=(p.host, p.port),
                    repl_conn={"token": ADMIN}, repl_poll=0.3)
    wait_for(lambda: env.conn(r2, token=RO).execute("SELECT SUM(rate) FROM emp").rows == [[145]],
             what="caught-up replica")


# ═══ crash recovery of the pending commit ════════════════════════════════════
class Crash(BaseException):
    """Simulated process death."""


def die(c):
    """The process dies: its sockets are closed (the server rolls back an open transaction)."""
    try:
        c._wire.close()
    except Exception:                                             # noqa: BLE001
        pass


def test_crash_between_pending_and_commit_aborts_on_next_connect(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    before = anchor.get("emp")
    real_call = c._wire.call

    def call(method, args):
        if method == "tx_commit":
            raise Crash()                                         # pending is written, the commit never sent
        return real_call(method, args)
    c._wire.call = call
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    c.execute("UPDATE emp SET rate = 41 WHERE id = 1")
    with pytest.raises(Crash):
        c.commit()
    assert anchor.get("emp").pending is not None                  # recorded BEFORE tx_commit
    die(c)
    c2 = env.conn(s)                                              # settles by scanning: server state = old root
    e = anchor.get("emp")
    assert e.pending is None and (e.epoch, e.root, e.count) == (before.epoch, before.root, before.count)
    assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    assert c2.execute("SELECT SUM(rate) FROM emp").rows == [[145]]


def test_crash_after_the_server_committed_finishes_on_next_connect(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    before = anchor.get("emp")
    c.client._amgr.finish = lambda: (_ for _ in ()).throw(Crash())    # dies right after the server's "ok"
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(Crash):
        c.commit()
    assert anchor.get("emp").pending is not None
    die(c)
    c2 = env.conn(s)
    e = anchor.get("emp")
    assert e.pending is None and e.epoch == before.epoch + 1 and e.count == 5
    assert c2.execute("SELECT SUM(rate) FROM emp").rows == [[154]]


def test_pending_that_matches_neither_state_is_an_integrity_error(env):
    s, c = env.seeded()
    c.client._amgr.finish = lambda: (_ for _ in ()).throw(Crash())
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(Crash):
        c.commit()
    die(c)
    with eng(s)._lock:
        store(s).kill([0])                                        # the server then tampers
    with pytest.raises(IE, match="does not match the anchor"):
        env.conn(s)


def test_lost_commit_reply_committed_is_finished_via_tx_status(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    e0 = anchor.get("emp").epoch
    real_call = c._wire.call

    def call(method, args):
        r = real_call(method, args)
        if method == "tx_commit":
            c._wire.close()
            raise torussql.nokey.ConnectionLost("reply lost")
        return r
    c._wire.call = call
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    c.commit()                                                    # resolves through tx_status: committed
    e = anchor.get("emp")
    assert e.pending is None and e.epoch == e0 + 1
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[154]]
    assert env.conn(s).execute("SELECT COUNT(*) FROM emp").rows == [[5]]


def test_lost_commit_reply_not_processed_is_aborted(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    before = anchor.get("emp")
    real_call = c._wire.call

    def call(method, args):
        if method == "tx_commit":
            c._wire.close()                                       # never reaches the server: it rolls back
            raise torussql.nokey.ConnectionLost("request lost")
        return real_call(method, args)
    c._wire.call = call
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(torussql.OperationalError, match="did not take effect"):
        c.commit()
    e = anchor.get("emp")
    assert e.pending is None and e.epoch == before.epoch and e.root == before.root
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]


def test_in_doubt_commit_leaves_pending_and_next_connect_settles(env, monkeypatch):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    real_call = c._wire.call

    def call(method, args):
        r = real_call(method, args)
        if method == "tx_commit":
            c._wire.close()
            raise torussql.nokey.ConnectionLost("reply lost")
        return r
    c._wire.call = call
    monkeypatch.setattr(torussql.nokey, "_Conn", lambda *a, **k: (_ for _ in ()).throw(
        torussql.OperationalError("server unreachable")))
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    with pytest.raises(torussql.nokey.TransactionInDoubt):
        c.commit()
    assert anchor.get("emp").pending is not None
    monkeypatch.undo()
    c2 = env.conn(s)
    assert anchor.get("emp").pending is None
    assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[5]]


def test_a_failed_statement_rolls_back_the_delta(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    e0 = anchor.get("emp")
    with pytest.raises(Exception):
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 999999)")      # out of range: refused
    assert anchor.get("emp").epoch == e0.epoch
    with pytest.raises(Exception):
        with c.transaction():
            c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
            raise RuntimeError("boom")
    assert anchor.get("emp").epoch == e0.epoch
    assert c.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    assert env.conn(s).execute("SELECT COUNT(*) FROM emp").rows == [[4]]


# ═══ several owners sharing one anchor ═══════════════════════════════════════
def test_two_owners_share_one_anchor(env):
    s, c1 = env.seeded()
    c2 = env.conn(s)
    assert c2.execute("SELECT COUNT(*) FROM emp").rows == [[4]]
    c2.execute("INSERT INTO emp (id, dept, rate) VALUES (5, 5, 5)")
    assert c1.execute("SELECT COUNT(*) FROM emp").rows == [[5]]           # c1 sees the new epoch, rescans, passes
    c1.execute("UPDATE emp SET rate = 1 WHERE id = 5")
    assert c2.execute("SELECT SUM(rate) FROM emp").rows == [[40 + 55 + 30 + 20 + 1]]
    # a lying server cannot hide c2's commit from c1 by serving the state c1 last saw
    old = image(s)
    c2.execute("INSERT INTO emp (id, dept, rate) VALUES (6, 5, 6)")
    swap_db(s, old)
    with pytest.raises(IE, match="behind the anchor"):
        c1.execute("SELECT COUNT(*) FROM emp")


def test_a_foreign_epoch_advance_during_a_transaction_aborts_the_commit(env):
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    e = anchor.get("emp")
    anchor.set("emp", e.root, e.count, e.epoch)                   # someone else moved the anchor
    with pytest.raises(torussql.OperationalError, match="epoch"):
        c.commit()
    assert not c.in_transaction
    assert FileAnchor(env.anchor_path).get("emp").pending is None
    assert env.conn(s).execute("SELECT COUNT(*) FROM emp").rows == [[4]]


# ═══ disk-backed server: restoring an older store ════════════════════════════
def test_restored_old_database_files_are_detected(env, tmp_path):
    db = str(tmp_path / "db")
    s = env.server(db=db)
    c = env.conn(s)
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
    for i, d, r in ROWS[:3]:
        c.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({i}, {d}, {r})")
    c.close()
    s.stop()
    backup = tmp_path / "backup"
    backup.mkdir()
    for f in glob.glob(db + "*"):
        shutil.copy(f, backup)
    s = env.server(db=db)
    c = env.conn(s)
    c.execute("UPDATE emp SET rate = 99 WHERE id = 1")
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (4, 5, 20)")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[99 + 55 + 30 + 20]]
    c.close()
    s.stop()
    for f in glob.glob(db + "*"):
        os.unlink(f)
    for f in backup.iterdir():
        shutil.copy(f, tmp_path / f.name)
    s = env.server(db=db)
    c = env.conn(s)
    with pytest.raises(IE, match="behind the anchor"):
        c.execute("SELECT SUM(rate) FROM emp")


# ═══ in-process engine (no wire) ═════════════════════════════════════════════
def test_in_process_engine_with_a_memory_anchor():
    srv = NoKeyServer()
    anchor = MemoryAnchor()
    cl = NoKeyClient(srv, authenticated=True, fhe=KEY, integrity_anchor=anchor)
    cl.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")
    for i, d, r in ROWS:
        cl.execute(f"INSERT INTO emp (id, dept, rate) VALUES ({i}, {d}, {r})")
    assert same(cl.execute(Q).rows, HONEST)
    cl.execute("UPDATE emp SET rate = 41 WHERE id = 1")
    cl.execute("DELETE FROM emp WHERE id = 4")
    assert cl.execute("SELECT id, rate FROM emp").rows == [[1, 41], [2, 55], [3, 30]]
    assert anchor.get("emp").count == 3 and anchor.get("emp").pending is None
    cl.verify_table("emp")
    # a lying subclass of the server
    class Liar(NoKeyServer):
        def matching_rowids(self, table, where):
            return super().matching_rowids(table, where)[:-1]
    srv.__class__ = Liar
    assert cl.execute("SELECT COUNT(*) FROM emp").rows == [[3]]       # never consulted
    srv.__class__ = NoKeyServer
    # a second client of the same anchor over a rolled-back server image
    body = copy.deepcopy(srv.to_body())
    cl.execute("INSERT INTO emp (id, dept, rate) VALUES (8, 5, 8)")
    stale = NoKeyClient(NoKeyServer.from_body(body), authenticated=True, fhe=KEY, integrity_anchor=anchor)
    stale._schema.update(cl._schema)
    stale._coltype.update(cl._coltype)
    stale._colpolicy.update(cl._colpolicy)
    with pytest.raises(StaleServerError):
        stale.execute("SELECT COUNT(*) FROM emp")


def test_engine_without_authentication_refuses_an_anchor():
    with pytest.raises(Exception, match="authenticated"):
        NoKeyClient(NoKeyServer(), fhe=KEY, integrity_anchor=MemoryAnchor())


# ═══ another owner scanning while a commit is in flight ═══════════════════════
def test_a_reader_never_aborts_a_commit_that_is_on_its_way(env):
    s, c = env.seeded()
    reader = env.conn(s)
    anchor = FileAnchor(env.anchor_path)
    e0 = anchor.get("emp")
    real_call = c._wire.call
    seen = {}

    def call(method, args):
        if method == "tx_commit":
            seen["pending"] = anchor.get("emp").pending is not None
            seen["read"] = reader.execute("SELECT COUNT(*) FROM emp").rows       # old state, pending in the anchor
            seen["still_pending"] = anchor.get("emp").pending is not None
        return real_call(method, args)
    c._wire.call = call
    c.begin()
    c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    c.commit()
    assert seen == {"pending": True, "read": [[4]], "still_pending": True}
    e = anchor.get("emp")
    assert e.pending is None and e.epoch == e0.epoch + 1
    assert reader.execute("SELECT COUNT(*) FROM emp").rows == [[5]]


def test_a_reader_that_sees_the_new_state_first_finishes_the_commit_for_the_committer(env):
    s, c = env.seeded()
    reader = env.conn(s)
    anchor = FileAnchor(env.anchor_path)
    real_finish = c.client._amgr.finish

    def finish():
        assert anchor.get("emp").pending is not None
        assert reader.execute("SELECT COUNT(*) FROM emp").rows == [[5]]          # settles it
        assert anchor.get("emp").pending is None
        real_finish()                                                             # must accept that
    c.client._amgr.finish = finish
    with c.transaction():
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[154]]


def test_a_pending_commit_aborted_by_a_lying_reader_is_recorded_again(env):
    """A server that tells readers 'unknown' for a commit that is really on its way makes a reader abort the
    pending record; the committer, told 'committed', re-records it instead of leaving the anchor behind."""
    s, c = env.seeded()
    anchor = FileAnchor(env.anchor_path)
    e0 = anchor.get("emp")
    real_finish = c.client._amgr.finish

    def finish():
        anchor.abort(["emp"])                                     # the reader's (wrong) abort
        assert anchor.get("emp").epoch == e0.epoch and anchor.get("emp").pending is None
        real_finish()
    c.client._amgr.finish = finish
    with c.transaction():
        c.execute("INSERT INTO emp (id, dept, rate) VALUES (9, 5, 9)")
    e = anchor.get("emp")
    assert e.epoch == e0.epoch + 1 and e.count == 5 and e.pending is None
    assert env.conn(s).execute("SELECT SUM(rate) FROM emp").rows == [[154]]
