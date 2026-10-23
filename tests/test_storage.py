# SPDX-License-Identifier: Apache-2.0
"""Disk storage engine: stores, indexes, checkpoint/recovery, compaction, server."""
from __future__ import annotations

import os
import random
import time
from fractions import Fraction
from pathlib import Path

import pytest

import durability as dur
from test_ops import Running
from torusdb_core.store import (DiskStorage, MemoryTable, PagedTable, StoreCorrupt,
                                decode_row, encode_row)

BIG = (1 << 253) + 12345


# ── codec ────────────────────────────────────────────────────────────────────
def test_row_codec_is_exact_for_big_ints_fractions_and_none():
    row = {"a": BIG, "b": -BIG, "c": Fraction(-7, 3), "d": None, "e": "x'y", "f": True, "g": 5}
    back = decode_row(encode_row(row))
    assert back == row and type(back["f"]) is bool and back["a"] == BIG


# ── store contract (both back ends) ──────────────────────────────────────────
@pytest.fixture(params=["memory", "paged"])
def table(request, tmp_path):
    t = MemoryTable() if request.param == "memory" else PagedTable(str(tmp_path / "h.heap"), 16)
    yield t
    t.close()


def test_append_read_and_cell(table):
    ids = [table.append({"a": i, "b": str(i)}) for i in range(100)]
    assert ids == list(range(100)) and len(table) == 100
    assert table.row(57) == {"a": 57, "b": "57"} and table.cell(57, "a") == 57
    assert table.cell(57, "zz", None) is None
    with pytest.raises(KeyError):
        table.cell(57, "zz")


def test_undo_closures_restore_exactly_in_reverse_order(table):
    for i in range(5):
        table.append({"a": i})
    table.create_index("a")
    n0, mark = table.mark()
    table.append({"a": 50})
    u1 = table.set_cell(1, "a", 111)
    u2 = table.set_cell(1, "a", 222)
    u3 = table.set_cell(0, "a", 333)
    table.kill([2])
    assert table.candidates([[("a", "=", 222)]]) == [1]
    table.revive([2])
    u3(); u2(); u1()
    table.rewind(n0, mark)
    assert [table.row(i)["a"] for i in range(len(table))] == [0, 1, 2, 3, 4]
    assert table.candidates([[("a", "=", 1)]]) == [1]
    assert table.candidates([[("a", "=", 222)]]) == [] and len(table) == 5
    assert table.dead_count() == 0


def test_kill_revive_and_live_ids(table):
    for i in range(6):
        table.append({"a": i})
    assert table.kill([1, 3, 3]) == [1, 3]
    assert list(table.live_ids()) == [0, 2, 4, 5] and table.live_count() == 4
    assert table.dead_ids() == [1, 3]
    table.revive([3])
    assert table.dead_ids() == [1]


def test_index_candidates_are_a_superset_and_track_every_mutation(table):
    rng = random.Random(7)
    vals = [rng.randrange(20) for _ in range(300)]
    for v in vals:
        table.append({"a": v, "s": str(v % 5)})
    table.create_index("a")
    table.create_index("s")
    cur = list(vals)
    for _ in range(200):
        op = rng.randrange(3)
        i = rng.randrange(len(cur))
        if op == 0:
            cur[i] = rng.randrange(20); table.set_cell(i, "a", cur[i])
        elif op == 1:
            table.kill([i])
        else:
            table.revive([i])
    live = set(table.live_ids())
    for op, ref in (("=", lambda x: x == 7), ("<", lambda x: x < 5), (">=", lambda x: x >= 15),
                    ("<=", lambda x: x <= 3), (">", lambda x: x > 18)):
        want = {i for i in live if ref(cur[i])}
        got = set(table.candidates([[("a", op, 7 if op == "=" else
                                      {"<": 5, ">=": 15, "<=": 3, ">": 18}[op])]]))
        assert want <= got and got <= live
    assert set(table.candidates([[("a", "in", [1, 2, 3])]])) >= {i for i in live if cur[i] in (1, 2, 3)}
    # an OR with an unindexed branch cannot use the indexes
    assert table.candidates([[("a", "=", 1)], [("nope", "=", 1)]]) is None
    assert table.candidates([[("a", "!=", 1)]]) is None


# ── paged heap: persistence, crash safety, corruption, compaction ────────────
def test_paged_slot_table_roundtrip_and_post_checkpoint_bytes_are_discarded(tmp_path):
    t = PagedTable(str(tmp_path / "h.heap"))
    for i in range(50):
        t.append({"a": i, "big": BIG + i})
    t.kill([4])
    t.flush(); t.write_index_file(str(tmp_path / "s"))
    slots, end = len(t), t.heap_len
    t.append({"a": 999, "big": 1})                       # written after the checkpoint
    t.set_cell(3, "a", -1)
    t.close()
    r = PagedTable(str(tmp_path / "h.heap"))
    r.load_index_file(str(tmp_path / "s"), slots, end)
    assert len(r) == 50 and r.heap_len == end and os.path.getsize(tmp_path / "h.heap") == end
    assert r.row(3) == {"a": 3, "big": BIG + 3} and r.dead_ids() == [4]
    r.close()


def test_paged_detects_corrupt_record_and_bad_slot_table(tmp_path):
    t = PagedTable(str(tmp_path / "h.heap"))
    for i in range(10):
        t.append({"a": i})
    t.flush(); t.write_index_file(str(tmp_path / "s"))
    slots, end = len(t), t.heap_len
    t.close()
    raw = bytearray((tmp_path / "h.heap").read_bytes())
    raw[20] ^= 0xFF
    (tmp_path / "h.heap").write_bytes(bytes(raw))
    r = PagedTable(str(tmp_path / "h.heap"))
    r.load_index_file(str(tmp_path / "s"), slots, end)
    with pytest.raises(StoreCorrupt):
        for i in range(10):
            r.row(i)
    r.close()
    sraw = bytearray((tmp_path / "s").read_bytes())
    sraw[-1] ^= 1
    (tmp_path / "s").write_bytes(bytes(sraw))
    with pytest.raises(StoreCorrupt):
        PagedTable(str(tmp_path / "h.heap")).load_index_file(str(tmp_path / "s"), slots, end)
    with pytest.raises(StoreCorrupt):                    # manifest disagrees with the file
        PagedTable(str(tmp_path / "h.heap")).load_index_file(str(tmp_path / "s"), slots + 1, end)


def test_heap_shorter_than_checkpoint_is_refused(tmp_path):
    t = PagedTable(str(tmp_path / "h.heap"))
    for i in range(10):
        t.append({"a": i})
    t.flush(); t.write_index_file(str(tmp_path / "s"))
    slots, end = len(t), t.heap_len
    t.close()
    os.truncate(tmp_path / "h.heap", end - 5)
    with pytest.raises(StoreCorrupt, match="shorter"):
        PagedTable(str(tmp_path / "h.heap")).load_index_file(str(tmp_path / "s"), slots, end)


def test_compaction_drops_old_versions_and_keeps_ids_and_dead_flags(tmp_path):
    t = PagedTable(str(tmp_path / "a.heap"))
    for i in range(20):
        t.append({"a": i})
    for _ in range(10):
        for i in range(20):
            t.set_cell(i, "a", i + 1000)
    t.kill([5])
    before = t.heap_len
    c = t.compact(str(tmp_path / "b.heap"))
    assert c.heap_len < before / 5 and len(c) == 20
    assert c.row(7) == {"a": 1007} and c.dead_ids() == [5]
    t.close(); c.close()


# ── server integration ───────────────────────────────────────────────────────
def _crash(s):
    """Stop without the clean-shutdown checkpoint (simulates a power loss)."""
    s.srv.shutdown(); s.srv.socket.close()
    eng = s.srv.engine
    eng._journal.close(); eng.srv.close(); eng._dblock.release()


@pytest.fixture
def dbpath(tmp_path):
    return str(tmp_path / "db")


def test_disk_server_survives_crash_via_journal_and_clean_restart_via_checkpoint(dbpath):
    s = Running(db=dbpath, storage="disk", cache_rows=16, checkpoint_every=10_000)
    with s.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN, v INT ENC)")
        for i in range(120):
            c.execute(f"INSERT INTO t (id, name, v) VALUES ({i}, 'n{i % 7}', {i})")
        c.execute("UPDATE t SET name = 'zzz' WHERE id = 5")
        c.execute("DELETE FROM t WHERE id = 6")
    _crash(s)
    assert Path(dbpath + ".data").is_dir()
    s2 = Running(db=dbpath, storage="disk", cache_rows=16)
    with s2.connect(vault_path=None) as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[119]]
        assert c.execute("SELECT name FROM t WHERE id = 5").rows == [["zzz"]]
        assert c.execute("SELECT COUNT(*) FROM t WHERE id = 6").rows == [[0]]
    s2.stop()                                            # clean stop -> checkpoint + manifest
    body, gen, _ = dur.read_snapshot(dbpath)
    assert body["paged"] == 1 and gen >= 1 and "rows" not in body
    s3 = Running(db=dbpath, storage="disk", cache_rows=16)
    with s3.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[119]]
    s3.stop()


def test_disk_server_rolls_back_transactions_including_updates_and_drops(dbpath):
    s = Running(db=dbpath, storage="disk")
    with s.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN)")
        c.execute("CREATE TABLE keep (x INT PLAIN)")
        for i in range(5):
            c.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'a')")
        c.execute("INSERT INTO keep (x) VALUES (1)")
        c.begin()
        c.execute("INSERT INTO t (id, name) VALUES (50, 'new')")
        c.execute("UPDATE t SET name = 'changed' WHERE id = 1")
        c.execute("UPDATE t SET name = 'again' WHERE id = 1")
        c.execute("INSERT INTO t (id, name) VALUES (51, 'new2')")
        c.execute("DELETE FROM t WHERE id = 2")
        c.execute("DROP TABLE keep")
        c.rollback()
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[5]]
        assert c.execute("SELECT name FROM t WHERE id = 1").rows == [["a"]]
        assert c.execute("SELECT COUNT(*) FROM t WHERE id = 2").rows == [[1]]
        assert c.execute("SELECT x FROM keep").rows == [[1]]
        c.execute("INSERT INTO t (id, name) VALUES (60, 'after')")
    s.stop()
    s2 = Running(db=dbpath, storage="disk")
    with s2.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[6]]
        assert c.execute("SELECT x FROM keep").rows == [[1]]
    s2.stop()


def test_disk_server_compacts_and_collects_old_files(dbpath):
    s = Running(db=dbpath, storage="disk", checkpoint_every=10_000)
    s.srv.engine._storage.compact_min_bytes = 0
    with s.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN)")
        for i in range(30):
            c.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'x')")
        for r in range(8):
            c.execute(f"UPDATE t SET name = 'v{r}'")
        gen = s.srv.engine.checkpoint()
    files = sorted(os.listdir(dbpath + ".data"))
    assert len(files) == 2, files                       # one heap + one slot table
    with s.connect() as c:
        assert c.execute("SELECT name FROM t WHERE id = 3").rows == [["v7"]]
    s.stop()
    assert gen >= 1


def test_secondary_index_changes_plans_not_answers_and_survives_restart(dbpath):
    s = Running(db=dbpath, storage="disk")
    with s.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, grp INT PLAIN, name STR PLAIN)")
        for i in range(200):
            c.execute(f"INSERT INTO t (id, grp, name) VALUES ({i}, {i % 10}, 'n{i % 4}')")
        want = c.execute("SELECT COUNT(*) FROM t WHERE grp = 3 AND id > 100").rows
        c._wire.call("create_index", ["t", "grp"])
        c._wire.call("create_index", ["t", "name"])
        assert c.execute("SELECT COUNT(*) FROM t WHERE grp = 3 AND id > 100").rows == want
        assert c.execute("SELECT COUNT(*) FROM t WHERE grp IN (1, 2) OR name = 'n3'").rows == \
            [[sum(1 for i in range(200) if i % 10 in (1, 2) or i % 4 == 3)]]
        c.execute("UPDATE t SET grp = 99 WHERE id = 3")
        assert c.execute("SELECT COUNT(*) FROM t WHERE grp = 99").rows == [[1]]
        assert c.execute("SELECT COUNT(*) FROM t WHERE grp = 3").rows == [[19]]
        info = c._wire.call("table_info", ["t"])
        assert info["indexes"] == ["grp", "name"]
        with pytest.raises(Exception, match="only PLAIN"):
            c.execute("CREATE TABLE e (k INT PLAIN, v INT ENC)")
            c._wire.call("create_index", ["e", "v"])
    _crash(s)
    s2 = Running(db=dbpath, storage="disk")
    with s2.connect() as c:
        assert c._wire.call("table_info", ["t"])["indexes"] == ["grp", "name"]
        assert c.execute("SELECT COUNT(*) FROM t WHERE grp = 99").rows == [[1]]
    s2.stop()


def test_memory_snapshot_migrates_to_disk_and_backup_restores_into_disk(dbpath, tmp_path):
    m = Running(db=dbpath)                               # memory mode (logical snapshot)
    with m.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN)")
        for i in range(10):
            c.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'r{i}')")
        c.execute("DELETE FROM t WHERE id = 0")
    m.stop()
    d = Running(db=dbpath, storage="disk", backup_dir=str(tmp_path / "bk"))
    with d.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[9]]
        c.execute("INSERT INTO t (id, name) VALUES (100, 'disk')")
        bak = c._wire.call("backup", [])
    d.stop()
    assert dur.read_snapshot(bak)[0].get("rows")         # backups are logical
    dur.restore_backup(dbpath, bak)
    import shutil; shutil.rmtree(dbpath + ".data")       # restoring onto a fresh data dir
    d2 = Running(db=dbpath, storage="disk")
    with d2.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM t").rows == [[10]]
    d2.stop()
    with pytest.raises(dur.CorruptDatabase):             # manifest opened in memory mode
        Running(db=dbpath)


def test_create_index_sql_end_to_end_and_validator_parity(dbpath):
    from torussql_parser import Schema, parse
    from torussql_parser.errors import ValidationError
    sch = Schema()
    sch.apply(parse("CREATE TABLE t (id INT PLAIN, v INT ENC)"))
    sch.validate(parse("CREATE INDEX ON t (id)"))
    for bad in ("CREATE INDEX ON t (v)", "CREATE INDEX ON t (nope)", "CREATE INDEX ON nope (id)"):
        with pytest.raises(ValidationError):
            sch.validate(parse(bad))
    s = Running(db=dbpath, storage="disk")
    with s.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
        c.execute("CREATE INDEX ON t (id)")
        assert c._wire.call("table_info", ["t"])["indexes"] == ["id"]
        c.execute("DROP INDEX ON t (id)")
        assert c._wire.call("table_info", ["t"])["indexes"] == []
        for bad in ("CREATE INDEX ON t (v)", "CREATE INDEX ON t (zz)"):
            with pytest.raises(Exception):
                c.execute(bad)
        c.begin()
        c.execute("CREATE INDEX ON t (id)")
        c.rollback()
        assert c._wire.call("table_info", ["t"])["indexes"] == []
    s.stop()


# ── snapshot reads: readers never wait for (or see) a writer's open transaction ─
@pytest.mark.parametrize("storage", ["memory", "disk"])
def test_readers_see_last_committed_state_while_a_write_tx_is_open(dbpath, storage):
    s = Running(db=dbpath, storage=storage, tx_wait=0.5)
    with s.connect() as w, s.connect() as r:
        w.execute("CREATE TABLE t (id INT PLAIN, name STR PLAIN)")
        w.execute("CREATE TABLE gone (x INT PLAIN)")
        for i in range(6):
            w.execute(f"INSERT INTO t (id, name) VALUES ({i}, 'old')")
        w.execute("INSERT INTO gone (x) VALUES (1)")
        r.sync_schema()
        w.begin()
        w.execute("INSERT INTO t (id, name) VALUES (100, 'new')")
        w.execute("UPDATE t SET name = 'edited' WHERE id = 1")
        w.execute("DELETE FROM t WHERE id = 2")
        w.execute("DROP TABLE gone")
        w.execute("CREATE TABLE fresh (y INT PLAIN)")
        t0 = time.monotonic()
        assert r.execute("SELECT COUNT(*) FROM t").rows == [[6]]            # no 10 s wait
        assert r.execute("SELECT name FROM t WHERE id = 1").rows == [["old"]]
        assert r.execute("SELECT COUNT(*) FROM t WHERE id = 2").rows == [[1]]
        assert r.execute("SELECT COUNT(*) FROM t WHERE id = 100").rows == [[0]]
        assert r.execute("SELECT x FROM gone").rows == [[1]]
        assert "fresh" not in r._wire.call("tables", [])
        assert time.monotonic() - t0 < 2
        # the writer sees its own changes
        assert w.execute("SELECT COUNT(*) FROM t").rows == [[6]]            # +1 insert, -1 delete
        assert w.execute("SELECT name FROM t WHERE id = 1").rows == [["edited"]]
        w.commit()
        assert r.execute("SELECT name FROM t WHERE id = 1").rows == [["edited"]]
        assert r.execute("SELECT COUNT(*) FROM t WHERE id = 100").rows == [[1]]
        assert "fresh" in r._wire.call("tables", []) and "gone" not in r._wire.call("tables", [])
        # rolled-back changes never become visible, and writers still serialize
        w.begin()
        w.execute("UPDATE t SET name = 'nope'")
        assert r.execute("SELECT COUNT(*) FROM t WHERE name = 'nope'").rows == [[0]]
        with pytest.raises(Exception, match="locked by another transaction"):
            r.execute("INSERT INTO t (id, name) VALUES (7, 'x')")
        w.rollback()
        assert r.execute("SELECT COUNT(*) FROM t WHERE name = 'nope'").rows == [[0]]
    s.stop()
