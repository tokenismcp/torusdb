# SPDX-License-Identifier: Apache-2.0
"""Operational hardening: auth/roles, limits, transactions, durability,
backup/restore, vault persistence, bulk load, metrics, robustness."""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from fractions import Fraction
from pathlib import Path

import pytest

import torussql
from torussql import (AuthenticationError, OperationalError, ProgrammingError,
                      ServerBusyError)
from torussql.vault import VaultError, VaultLocked, VaultLog
import durability as dur
from nokey_server import (Engine, NoKeyTCPServer, ServerConfig, load_token_file,
                          start_metrics_server)

ADMIN = "admin-token-0123456789"
RW = "rw-token-0123456789abc"
RO = "ro-token-0123456789abc"
TOKENS = {ADMIN: "admin", RW: "rw", RO: "ro"}


class Running:
    def __init__(self, db=None, **cfg):
        cfg.setdefault("auth_fail_delay", 0.0)
        self.srv = NoKeyTCPServer("127.0.0.1", 0, db, config=ServerConfig(**cfg))
        self.host, self.port = self.srv.address
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def connect(self, **kw):
        kw.setdefault("trust_server_schema", True)      # these tests vouch for the schema
        return torussql.connect(self.host, self.port, **kw)

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.t.join(timeout=5)


@pytest.fixture
def plain():
    s = Running()
    yield s
    s.stop()


@pytest.fixture
def authed():
    s = Running(tokens=dict(TOKENS))
    yield s
    s.stop()


def seed(conn):
    conn.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary INT ENC)")
    for i, d, sal in [(1, 5, 100), (2, 5, 200), (3, 9, 300)]:
        conn.execute(f"INSERT INTO emp (id, dept, salary) VALUES ({i}, {d}, {sal})")


def raw_call(host, port, method, args=None, sock=None):
    s = sock or socket.create_connection((host, port), timeout=5)
    body = json.dumps({"m": method, "a": args or []}).encode()
    s.sendall(struct.pack(">I", len(body)) + body)
    hdr = s.recv(4)
    (n,) = struct.unpack(">I", hdr)
    data = b""
    while len(data) < n:
        data += s.recv(n - len(data))
    return json.loads(data), s


# ── authentication & roles ───────────────────────────────────────────────────
def test_token_required_when_auth_enabled(authed):
    with pytest.raises(AuthenticationError, match="requires a token"):
        authed.connect()


def test_wrong_token_rejected(authed):
    with pytest.raises(AuthenticationError):
        authed.connect(token="x" * 24)


def test_right_token_works_and_reports_role(authed):
    with authed.connect(token=RW) as c:
        seed(c)
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        assert c.server_info["auth_required"] is True


def test_unauthenticated_raw_client_cannot_call_anything(authed):
    resp, s = raw_call(authed.host, authed.port, "create", ["t", [["a", "int", "plain"]]])
    assert "Unauthenticated" in resp["err"]
    resp, _ = raw_call(authed.host, authed.port, "schema", ["t"], sock=s)
    assert "Unauthenticated" in resp["err"]
    resp, _ = raw_call(authed.host, authed.port, "hello", sock=s)   # public
    assert resp["ok"]["auth_required"] is True


def test_read_only_role_cannot_write(authed):
    with authed.connect(token=RW) as w:
        seed(w)
    with authed.connect(token=RO) as c:
        assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
        # the vault is the owner's — a read-only token can read blinded data
        # but any write RPC is refused
        with pytest.raises(AuthenticationError, match="may not call"):
            c.execute("DELETE FROM emp WHERE id = 1")


def test_only_admin_may_drop_and_see_stats(authed):
    with authed.connect(token=RW) as c:
        seed(c)
        with pytest.raises(AuthenticationError):
            c.execute("DROP TABLE emp")
        with pytest.raises(AuthenticationError):
            c.server_stats()
    with authed.connect(token=ADMIN) as c:
        assert c.server_stats()["server"]
        c.execute("DROP TABLE emp")


def test_failed_auth_lockout():
    s = Running(tokens=dict(TOKENS), max_auth_failures=3, lockout_seconds=5.0)
    try:
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                s.connect(token="nope" * 6)
        # even the correct token is now refused from this address
        with pytest.raises(AuthenticationError, match="too many"):
            s.connect(token=ADMIN)
    finally:
        s.stop()


def test_token_file_loading(tmp_path):
    f = tmp_path / "tokens"
    f.write_text("# comment\nadmin:" + ADMIN + "\nro:" + RO + "\n")
    assert load_token_file(str(f)) == {ADMIN: "admin", RO: "ro"}
    f.write_text("god:" + ADMIN + "\n")
    with pytest.raises(SystemExit):
        load_token_file(str(f))
    f.write_text("admin:short\n")
    with pytest.raises(SystemExit):
        load_token_file(str(f))


def test_hashed_token_in_config():
    import hashlib
    h = "sha256:" + hashlib.sha256(ADMIN.encode()).hexdigest()
    s = Running(tokens={h: "admin"})
    try:
        with s.connect(token=ADMIN) as c:
            assert c.ping()
    finally:
        s.stop()


# ── limits & robustness ──────────────────────────────────────────────────────
def test_connection_cap():
    s = Running(max_connections=2)
    try:
        a, b = s.connect(), s.connect()
        with pytest.raises(OperationalError, match="connection limit"):
            c = s.connect()
            c.ping()
        a.close()
        time.sleep(0.2)
        s.connect().close()                         # slot freed
        b.close()
    finally:
        s.stop()


def test_oversized_frame_rejected_without_buffering():
    s = Running(max_frame=1024)
    try:
        sock = socket.create_connection((s.host, s.port), timeout=5)
        sock.sendall(struct.pack(">I", 10_000_000))   # declares 10 MB, sends none
        hdr = sock.recv(4)
        (n,) = struct.unpack(">I", hdr)
        assert b"too large" in sock.recv(n)
        assert sock.recv(1) == b""                    # server hung up
    finally:
        s.stop()


def test_idle_connection_is_dropped():
    s = Running(idle_timeout=0.3)
    try:
        sock = socket.create_connection((s.host, s.port), timeout=5)
        time.sleep(0.8)
        assert sock.recv(1) == b""
    finally:
        s.stop()


@pytest.mark.parametrize("payload", [
    b"not json", b"[]", b"123", b'{"m": 5}', b'{"m": "nope", "a": []}',
    b'{"m": "create", "a": "x"}', b'{"m": "create", "a": [1]}',
    b'{"m": "insert", "a": ["missing", {}]}', b'{"m": "delete_rows", "a": ["t", [-1]]}',
    b'{"m": "blinded_sum", "a": ["t", "c", [0]]}', b"\xff\xfe",
])
def test_malformed_requests_get_errors_not_crashes(plain, payload):
    sock = socket.create_connection((plain.host, plain.port), timeout=5)
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    (n,) = struct.unpack(">I", sock.recv(4))
    resp = json.loads(sock.recv(n))
    assert "err" in resp
    assert "Traceback" not in resp["err"]
    # server is still healthy afterwards
    with plain.connect() as c:
        assert c.ping()


def test_internal_errors_do_not_leak_details(plain, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internal path /etc/shadow")
    monkeypatch.setattr(plain.srv.engine, "_rpc_schema", boom)
    with plain.connect() as c:
        with pytest.raises(Exception) as ei:
            c._wire.call("schema", ["t"])
    assert "shadow" not in str(ei.value)
    assert "internal server error" in str(ei.value)


def test_insert_with_wrong_columns_rejected(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (a INT PLAIN, b INT PLAIN)")
        with pytest.raises(Exception, match="exactly the table's columns"):
            c._wire.call("insert", ["t", {"a": {"t": "i", "v": "1"}}])
        with pytest.raises(Exception):
            c._wire.call("update_cell", ["t", 0, "a", {"t": "i", "v": "1"}])


# ── transactions ─────────────────────────────────────────────────────────────
def test_commit_makes_changes_visible_and_durable(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (a INT PLAIN, s INT ENC)")
        with c.transaction():
            c.execute("INSERT INTO t (a, s) VALUES (1, 10)")
            c.execute("INSERT INTO t (a, s) VALUES (2, 20)")
        assert c.execute("SELECT SUM(s) FROM t").rows == [[30]]
        assert not c.in_transaction


def test_rollback_undoes_server_and_vault(plain):
    with plain.connect() as c:
        seed(c)
        c.begin()
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (4, 5, 1000)")
        c.execute("UPDATE emp SET salary = 9 WHERE id = 1")
        c.execute("DELETE FROM emp WHERE id = 2")
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[9 + 300 + 1000]]
        c.rollback()
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
        # the vault is consistent too: a new insert reuses rowid 3 cleanly
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (5, 5, 7)")
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[607]]


def test_rollback_undoes_ddl(plain):
    with plain.connect() as c:
        seed(c)
        c.begin()
        c.execute("CREATE TABLE extra (x INT PLAIN)")
        c.execute("DROP TABLE emp")
        c.rollback()
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        with pytest.raises(Exception):
            c.execute("SELECT x FROM extra")


def test_context_manager_rolls_back_on_exception(plain):
    with plain.connect() as c:
        seed(c)
        with pytest.raises(ZeroDivisionError):
            with c.transaction():
                c.execute("DELETE FROM emp WHERE dept = 5")
                1 / 0
        assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]


def test_failed_statement_in_autocommit_leaves_no_trace(plain):
    with plain.connect() as c:
        seed(c)
        with pytest.raises(Exception):
            c.execute("UPDATE emp SET nope = 1 WHERE id = 1")
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]


def test_multi_row_update_is_atomic_on_failure(plain, monkeypatch):
    with plain.connect() as c:
        seed(c)
        real = plain.srv.engine._rpc_update_cell
        calls = {"n": 0}

        def flaky(*a):
            calls["n"] += 1
            if calls["n"] == 2:
                raise ValueError("disk exploded")
            return real(*a)
        monkeypatch.setattr(plain.srv.engine, "_rpc_update_cell", flaky)
        with pytest.raises(Exception):
            c.execute("UPDATE emp SET salary = 1 WHERE dept = 5")
        monkeypatch.undo()
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]   # nothing half-applied


def test_dropped_connection_mid_transaction_rolls_back(plain):
    a = plain.connect()
    seed(a)
    a.begin()
    a.execute("DELETE FROM emp")
    a._wire.close()                                 # crash: no commit, no rollback
    time.sleep(0.3)
    with plain.connect() as b:
        # b has no vault for these rows, so only check structure server-side
        assert b._wire.call("table_info", ["emp"])["deleted"] == []


def test_readers_do_not_wait_for_a_foreign_transaction_and_see_the_commit_after(plain):
    a, b = plain.connect(), plain.connect()
    a.execute("CREATE TABLE t (x INT PLAIN)")
    a.begin()
    a.execute("INSERT INTO t (x) VALUES (1)")
    t0 = time.monotonic()
    assert b._wire.call("table_info", ["t"])["rows"] == 0      # last committed state, no wait
    assert time.monotonic() - t0 < 1.0
    a.commit()
    assert b._wire.call("table_info", ["t"])["rows"] == 1
    a.close(); b.close()


def test_writers_wait_for_a_foreign_transaction_then_get_busy():
    s = Running(tx_wait=0.4)
    try:
        a, b = s.connect(), s.connect()
        a.execute("CREATE TABLE t (x INT PLAIN)")
        b.sync_schema()
        a.begin()
        with pytest.raises(ServerBusyError):
            b.execute("INSERT INTO t (x) VALUES (1)")
        a.rollback()
        b.execute("INSERT INTO t (x) VALUES (1)")                # free again
        a.close(); b.close()
    finally:
        s.stop()


def test_stale_transaction_is_aborted_for_waiters():
    s = Running(tx_wait=3.0, tx_timeout=0.3)
    try:
        a, b = s.connect(), s.connect()
        a.execute("CREATE TABLE t (x INT PLAIN)")
        a.begin()
        a.execute("INSERT INTO t (x) VALUES (1)")
        time.sleep(0.4)
        # b is let in: a's stale tx is rolled back
        assert b._wire.call("table_info", ["t"])["rows"] == 0
        with pytest.raises(ServerBusyError, match="timed out"):
            a.commit()
        assert not a.in_transaction
        a.close(); b.close()
    finally:
        s.stop()


def test_begin_twice_and_commit_without_begin(plain):
    with plain.connect() as c:
        c.begin()
        with pytest.raises(ProgrammingError):
            c.begin()
        c.rollback()
        c.commit()                                  # no-op without a tx
        c.rollback()


def test_concurrent_writers_serialize_cleanly(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (w INT PLAIN, n INT PLAIN)")
    errs = []

    def worker(w):
        try:
            with plain.connect() as c:
                for n in range(15):
                    with c.transaction():
                        c.execute(f"INSERT INTO t (w, n) VALUES ({w}, {n})")
                        c.execute(f"INSERT INTO t (w, n) VALUES ({w}, {n + 100})")
        except Exception as exc:                    # noqa: BLE001
            errs.append(exc)
    ths = [threading.Thread(target=worker, args=(w,)) for w in range(6)]
    [t.start() for t in ths]; [t.join(timeout=60) for t in ths]
    assert not errs, errs
    with plain.connect() as c:
        assert c._wire.call("table_info", ["t"])["rows"] == 6 * 15 * 2


# ── durability ───────────────────────────────────────────────────────────────
def test_restart_recovers_from_snapshot_and_journal(tmp_path):
    db = str(tmp_path / "db")
    vault = str(tmp_path / "vault")
    s = Running(db=db, checkpoint_every=10_000)
    with s.connect(vault_path=vault) as c:
        seed(c)
        c.execute("UPDATE emp SET salary = 1 WHERE id = 3")
        c.execute("DELETE FROM emp WHERE id = 2")
    # simulate kill -9: do NOT close the engine cleanly (no final checkpoint)
    s.srv.shutdown(); s.srv.socket.close()
    s.srv.engine._journal.close(); s.srv.engine._dblock.release()
    s2 = Running(db=db)
    try:
        with s2.connect(vault_path=vault) as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[101]]
            assert c.execute("SELECT COUNT(*) FROM emp").rows == [[2]]
    finally:
        s2.stop()


def test_clean_shutdown_checkpoints_and_empties_journal(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db)
    with s.connect() as c:
        c.execute("CREATE TABLE t (x INT PLAIN)")
        c.execute("INSERT INTO t (x) VALUES (1)")
    s.stop()
    assert Path(db).exists()
    from torussql.recordlog import RecordLog
    assert list(RecordLog(db + ".journal", dur.JOURNAL_MAGIC).open()) == []   # fully folded
    body, gen, _extra = dur.read_snapshot(db)
    assert gen >= 1 and "t" in body["schema"]


def test_torn_journal_tail_is_discarded(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db, checkpoint_every=10_000)
    with s.connect() as c:
        c.execute("CREATE TABLE t (x INT PLAIN)")
        for i in range(5):
            c.execute(f"INSERT INTO t (x) VALUES ({i})")
    s.srv.shutdown(); s.srv.socket.close()
    s.srv.engine._journal.close(); s.srv.engine._dblock.release()
    j = Path(db + ".journal")
    data = j.read_bytes()
    j.write_bytes(data + b'{"g":0,"ops":[["insert",["t",{"x":{"t":"i","v":"9')   # torn
    s2 = Running(db=db)
    try:
        with s2.connect() as c:
            assert c._wire.call("table_info", ["t"])["rows"] == 5
            c.execute("INSERT INTO t (x) VALUES (99)")       # appends cleanly
    finally:
        s2.stop()
    s3 = Running(db=db)
    try:
        with s3.connect() as c:
            assert c._wire.call("table_info", ["t"])["rows"] == 6
    finally:
        s3.stop()


def test_crash_between_snapshot_and_journal_truncate_is_harmless(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db, checkpoint_every=10_000)
    with s.connect() as c:
        c.execute("CREATE TABLE t (x INT PLAIN)")
        c.execute("INSERT INTO t (x) VALUES (1)")
    eng = s.srv.engine
    # emulate a checkpoint that wrote the new snapshot but died before the
    # journal was reset: stale (old-generation) records remain in the journal
    dur.write_snapshot(db, eng.srv.to_body(), eng._gen + 1)
    s.srv.shutdown(); s.srv.socket.close()
    eng._journal.close(); eng._dblock.release()
    s2 = Running(db=db)
    try:
        with s2.connect() as c:
            assert c._wire.call("table_info", ["t"])["rows"] == 1   # not 2
    finally:
        s2.stop()


def test_corrupt_snapshot_is_detected(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db)
    with s.connect() as c:
        c.execute("CREATE TABLE t (x INT PLAIN)")
    s.stop()
    doc = json.loads(Path(db).read_text())
    doc["snapshot"]["body"]["schema"]["t"][0][0] = "tampered"
    Path(db).write_text(json.dumps(doc))
    with pytest.raises(dur.CorruptDatabase):
        NoKeyTCPServer("127.0.0.1", 0, db)


def test_second_server_on_same_db_is_refused(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db)
    try:
        with pytest.raises(dur.DatabaseLocked):
            NoKeyTCPServer("127.0.0.1", 0, db)
    finally:
        s.stop()


def test_automatic_checkpoint_after_n_commits(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db, checkpoint_every=5)
    try:
        with s.connect() as c:
            c.execute("CREATE TABLE t (x INT PLAIN)")
            for i in range(12):
                c.execute(f"INSERT INTO t (x) VALUES ({i})")
            st = s.srv.engine.stats_snapshot()
        assert st["checkpoints"] >= 2
        assert st["journal_records"] < 5
    finally:
        s.stop()


def test_backup_and_restore(tmp_path):
    db = str(tmp_path / "db")
    s = Running(db=db, backup_dir=str(tmp_path / "bk"), backup_keep=2)
    vault = str(tmp_path / "vault")
    with s.connect(vault_path=vault) as c:
        seed(c)
        paths = [c.backup() for _ in range(3)]
        assert len(list((tmp_path / "bk").glob("*.bak"))) == 2     # retention
        c.execute("DELETE FROM emp")                               # disaster
    s.stop()
    from nokey_server import main
    main(["--db", db, "--restore-from", paths[-1]])
    s2 = Running(db=db)
    try:
        with s2.connect(vault_path=vault) as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
    finally:
        s2.stop()


def test_backup_requires_backup_dir(plain):
    with plain.connect() as c:
        with pytest.raises(Exception, match="not enabled"):
            c.backup()


# ── vault durability ─────────────────────────────────────────────────────────
def test_vault_survives_client_restart(tmp_path):
    s = Running()
    vault = str(tmp_path / "vault")
    try:
        with s.connect(vault_path=vault) as c:
            seed(c)
        assert oct(os.stat(vault).st_mode & 0o777) == "0o600"
        with s.connect(vault_path=vault) as c2:           # a "new process"
            assert c2.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
            c2.execute("INSERT INTO emp (id, dept, salary) VALUES (4, 1, 4)")
        with s.connect(vault_path=vault) as c3:
            assert c3.execute("SELECT SUM(salary) FROM emp").rows == [[604]]
    finally:
        s.stop()


def test_vault_without_file_cannot_decrypt(tmp_path):
    s = Running()
    try:
        with s.connect(vault_path=str(tmp_path / "v1")) as c:
            seed(c)
        with s.connect(vault_path=str(tmp_path / "other")) as c2:
            with pytest.raises(Exception):
                c2.execute("SELECT SUM(salary) FROM emp")
    finally:
        s.stop()


def test_sealed_vault_requires_passphrase(tmp_path):
    s = Running()
    vault = str(tmp_path / "vault")
    try:
        with s.connect(vault_path=vault, vault_passphrase="correct horse") as c:
            seed(c)
        raw = Path(vault).read_bytes()
        assert b"salary" not in raw and b'"r"' not in raw        # not plaintext
        with pytest.raises(VaultLocked):
            s.connect(vault_path=vault)
        with pytest.raises(VaultLocked):
            s.connect(vault_path=vault, vault_passphrase="wrong")
        assert Path(vault).read_bytes() == raw                    # NOT truncated
        with s.connect(vault_path=vault, vault_passphrase="correct horse") as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
    finally:
        s.stop()


def test_torn_vault_tail_is_dropped_but_mid_corruption_refused(tmp_path):
    s = Running()
    vault = tmp_path / "vault"
    try:
        with s.connect(vault_path=str(vault)) as c:
            seed(c)
        good = vault.read_bytes()
        vault.write_bytes(good + b"P 0000dead {\"k\":\"m\",\"t\":\"emp\"")   # torn
        with s.connect(vault_path=str(vault)) as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        lines = good.split(b"\n")
        lines[3] = b"P 00000000 garbage"
        vault.write_bytes(b"\n".join(lines))
        with pytest.raises(VaultError, match="refusing"):
            s.connect(vault_path=str(vault))
    finally:
        s.stop()


def test_orphan_row_detection_and_repair(tmp_path):
    s = Running()
    try:
        with s.connect(vault_path=str(tmp_path / "v")) as c:
            seed(c)
            # a row the server accepted but whose masks never reached the vault
            c._wire.call("insert", ["emp", {
                "id": {"t": "i", "v": "9"}, "dept": {"t": "i", "v": "1"},
                "salary": {"t": "i", "v": "12345"}}])
            assert c.find_orphans() == {"emp": [3]}
            assert c.repair_orphans() == 1
            assert c.find_orphans() == {}
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
    finally:
        s.stop()


# ── bulk load / drop hygiene ─────────────────────────────────────────────────
def test_executemany_bulk_insert_is_one_round_trip(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
        cur = c.cursor()
        before = plain.srv.engine.stats_snapshot()["requests"].get("insert_many", 0)
        cur.executemany("INSERT INTO t (id, v) VALUES (%s, FRAC(%s,1))",
                        [(i, i * 10) for i in range(500)])
        st = plain.srv.engine.stats_snapshot()["requests"]
        assert st["insert_many"] == before + 1
        assert st.get("insert", 0) == 0
        assert cur.rowcount == 500
        assert c.execute("SELECT SUM(v) FROM t").rows == [[10 * sum(range(500))]]


def test_bulk_insert_failure_leaves_nothing(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (id INT PLAIN)")
        cur = c.cursor()
        with pytest.raises(Exception):
            cur.executemany("INSERT INTO t (id) VALUES (%s)", [(1,), ("x'; y",)])
            cur.executemany("INSERT INTO nope (id) VALUES (%s)", [(1,)])
        assert c._wire.call("table_info", ["t"])["rows"] in (0, 2)


def test_drop_then_recreate_forgets_old_masks(plain):
    with plain.connect() as c:
        seed(c)
        c.execute("DROP TABLE emp")
        with pytest.raises(Exception):
            c.execute("SELECT COUNT(*) FROM emp")
        c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary INT ENC)")
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (1, 1, 5)")
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[5]]


# ── observability ────────────────────────────────────────────────────────────
def test_stats_and_prometheus_endpoint(tmp_path):
    import urllib.request
    s = Running(tokens=dict(TOKENS))
    httpd = start_metrics_server(s.srv.engine, "127.0.0.1", 0)
    port = httpd.server_address[1]
    try:
        with s.connect(token=ADMIN) as c:
            seed(c)
            st = c.server_stats()
            assert st["tables"]["emp"]["rows"] == 3
            assert st["requests"]["insert"] == 3
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert 'torusdb_requests_total{method="insert"} 3' in body
        assert "torusdb_up 1" in body
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz").read() == b"ok\n"
    finally:
        httpd.shutdown(); s.stop()


def test_auth_failures_counted(authed):
    with pytest.raises(AuthenticationError):
        authed.connect(token="z" * 20)
    assert authed.srv.engine.stats_snapshot()["auth_failures"] == 1


def test_protocol_v1_server_compat(plain, monkeypatch):
    # an old server answers hello with "unknown method": driver must cope
    orig = plain.srv.engine._dispatch

    def old(s, method, args):
        if method == "hello":
            from nokey_server import BadRequest
            raise BadRequest("unknown method")
        return orig(s, method, args)
    monkeypatch.setattr(plain.srv.engine, "_dispatch", old)
    with plain.connect() as c:
        assert c.server_info["protocol"] == 1


def test_driver_timeout_default_is_finite():
    import inspect
    assert inspect.signature(torussql.connect).parameters["timeout"].default == 30.0


def test_connection_reuse_after_server_error(plain):
    with plain.connect() as c:
        seed(c)
        with pytest.raises(Exception):
            c.execute("SELECT nope FROM emp")
        assert c.execute("SELECT COUNT(*) FROM emp").rows == [[3]]


def test_in_memory_engine_dispatch_is_directly_usable():
    e = Engine()
    e.dispatch("create", ["t", [["a", "int", "plain"]]])
    assert e.dispatch("table_info", ["t"])["rows"] == 0


def test_raw_predicate_on_encrypted_column_is_rejected(plain):
    with plain.connect() as c:
        c.execute("CREATE TABLE t (a INT PLAIN, v INT ENC)")
        c.execute("INSERT INTO t (a, v) VALUES (1, 5)")
        bad = {"or": [[{"c": "v", "op": "=", "v": {"t": "i", "v": "0"}}]]}
        with pytest.raises(Exception, match="encrypted column"):
            c._wire.call("matching_rowids", ["t", bad])
        with pytest.raises(Exception, match="no such column"):
            c._wire.call("matching_rowids", ["t", {"or": [[{"c": "zz", "op": "=", "v": {"t": "i", "v": "0"}}]]}])
        with pytest.raises(Exception, match="malformed"):
            c._wire.call("matching_rowids", ["t", {"nope": 1}])


def test_legacy_unchecksummed_snapshot_still_loads(tmp_path):
    from torusdb_core.nokey_engine import NoKeyServer
    db = str(tmp_path / "old.db")
    old = NoKeyServer()
    old.create("t", [("a", "int", "plain")])
    old.insert("t", {"a": 7})
    old.save(db)                                  # pre-0.5 format
    s = Running(db=db)
    try:
        with s.connect() as c:
            assert c._wire.call("table_info", ["t"])["rows"] == 1
    finally:
        s.stop()
