# SPDX-License-Identifier: Apache-2.0
"""FHE columns: the server sums and multiplies ciphertexts with NO key."""
from __future__ import annotations

import pytest

import torussql
from torusdb_core import fhe
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from py_ecc.optimized_bn128 import G1, add, multiply, neg, pairing
from test_ops import Running

KEY = fhe.FheKey(value_range=50_000)


def test_scheme_roundtrip_sum_and_dot_with_signs():
    xs, ys = [3, -5, 7, 100, 0], [2, 4, -6, 9, 55]
    A, B = [KEY.encrypt(x) for x in xs], [KEY.encrypt(y) for y in ys]
    assert [KEY.decrypt_cell(c) for c in A] == xs
    assert KEY.decrypt_sum(fhe.sum_cells(A)) == sum(xs)
    assert KEY.decrypt_dot(fhe.dot_cells(A, B)) == sum(a * b for a, b in zip(xs, ys))
    # partial results combine publicly (this is how large queries are chunked)
    part = fhe.add_sums(fhe.sum_cells(A[:2]), fhe.sum_cells(A[2:]))
    assert KEY.decrypt_sum(part) == sum(xs)
    d = fhe.mul_dots(fhe.dot_cells(A[:3], B[:3]), fhe.dot_cells(A[3:], B[3:]))
    assert KEY.decrypt_dot(d) == sum(a * b for a, b in zip(xs, ys))
    assert KEY.decrypt_sum(fhe.sum_cells([])) == 0


def test_out_of_range_results_raise_instead_of_returning_garbage():
    big = fhe.FheKey(value_range=100)
    cts = [big.encrypt(90), big.encrypt(90)]
    with pytest.raises(fhe.FheError):
        big.decrypt_sum(fhe.sum_cells(cts))                 # 180 > 100
    with pytest.raises(fhe.FheError, match="range"):
        big.encrypt(101)


def test_no_value_oracle_for_the_evaluator():
    """With the public key alone nobody can test 'does this cell encrypt v?'
    (the test that breaks shared-randomness paired ciphertexts)."""
    ct = KEY.encrypt(1234)
    c1, c2, d1, d2 = fhe.parse_cell(ct)
    for v in (1234, 1, 0):
        lhs = pairing(fhe.G2 if hasattr(fhe, "G2") else __import__("py_ecc.optimized_bn128", fromlist=["G2"]).G2,
                      add(c2, neg(multiply(G1, v))))
        assert lhs != pairing(d1, KEY.Q)
    # encryption is randomised: equal plaintexts give unrelated ciphertexts
    assert KEY.encrypt(5) != KEY.encrypt(5)


def test_malformed_ciphertexts_are_rejected():
    ct = KEY.encrypt(1)
    for bad in (ct[:-1], ct + b"\0", b"", bytes(384)[:383], ct[:64] + bytes([ct[64] ^ 1]) + ct[65:]):
        with pytest.raises(fhe.FheError):
            fhe.parse_cell(bad)


def test_key_file_sealed_and_secret_not_leaked(tmp_path):
    p = str(tmp_path / "k")
    fhe.save_key(KEY, p, "pw")
    assert KEY.secret_bytes.hex().encode() not in open(p, "rb").read()
    assert fhe.load_key(p, "pw").decrypt_cell(KEY.encrypt(42)) == 42
    with pytest.raises(fhe.FheError):
        fhe.load_key(p, "wrong")
    assert str(KEY.secret_bytes.hex()) not in repr(KEY)
    import pickle
    with pytest.raises(TypeError):
        pickle.dumps(KEY)


# ── SQL end to end ───────────────────────────────────────────────────────────
def seed(c):
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE, hours INT FHE)")
    rows = [(1, 5, 40, 160), (2, 5, 55, 150), (3, 7, 30, 120), (4, 5, 20, 100)]
    for i, d, r, h in rows:
        c.execute(f"INSERT INTO emp (id, dept, rate, hours) VALUES ({i}, {d}, {r}, {h})")
    return rows


def test_sql_in_process():
    srv = NoKeyServer()
    c = NoKeyClient(srv, fhe=KEY)
    rows = seed(c)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[sum(r[2] for r in rows)]]
    assert c.execute("SELECT SUM(rate), COUNT(*) FROM emp WHERE dept = 5").rows == [[115, 3]]
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[sum(r[2] * r[3] for r in rows)]]
    assert c.execute("SELECT DOT(rate, hours) FROM emp WHERE dept = 5").rows == [[40 * 160 + 55 * 150 + 20 * 100]]
    assert c.execute("SELECT AVG(rate) FROM emp WHERE dept = 5").rows[0][0] == __import__("fractions").Fraction(115, 3)
    assert c.execute("SELECT id, rate FROM emp WHERE id = 3").rows == [[3, 30]]
    c.execute("UPDATE emp SET rate = 60 WHERE id = 1")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[60 + 55 + 30 + 20]]
    c.execute("DELETE FROM emp WHERE id = 4")
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[60 * 160 + 55 * 150 + 30 * 120]]
    assert c.execute("SELECT SUM(rate) FROM emp WHERE dept = 99").rows == [[0]]
    # the server never saw a plaintext: every FHE cell it stores is an opaque 384-byte blob
    cells = [r["rate"] for r in srv._rows["emp"]]
    assert all(isinstance(x, bytes) and len(x) == 384 for x in cells)
    assert not any(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28" in x for x in cells)


def test_sql_rules_are_enforced_by_validator_and_planner():
    from torussql_parser import Schema, ValidationError, parse
    sch = Schema()
    sch.apply(parse("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE, p INT PAIRED, r RATIONAL ENC)"))
    for ok in ("SELECT SUM(a) FROM t", "SELECT DOT(a, b) FROM t", "SELECT AVG(a), COUNT(*) FROM t",
               "SELECT a FROM t WHERE id = 1"):
        sch.validate(parse(ok))
    for bad in ("SELECT DOT(a, p) FROM t", "SELECT 2 * a FROM t", "SELECT a * b FROM t",
                "SELECT SUM(a) FROM t WHERE a = 1", "SELECT id FROM t ORDER BY a",
                "SELECT MIN(a) FROM t", "SELECT SUM(a) FROM t t1 JOIN t t2 ON t1.id = t2.id"):
        with pytest.raises(ValidationError):
            sch.validate(parse(bad))
    with pytest.raises(ValidationError):
        sch.validate(parse("CREATE TABLE u (x RATIONAL FHE)"))
    c = NoKeyClient(NoKeyServer(), fhe=KEY)
    c.execute("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE, p INT PAIRED)")
    for bad in ("SELECT DOT(a, p) FROM t", "SELECT 2 * a FROM t", "SELECT MIN(a) FROM t",
                "SELECT SUM(a) FROM t WHERE a = 1", "CREATE TABLE u (x STR FHE)"):
        with pytest.raises(Exception):
            c.execute(bad)
    with pytest.raises(Exception, match="no FHE key"):
        NoKeyClient(NoKeyServer()).execute("CREATE TABLE z (a INT FHE)") or None
        c2 = NoKeyClient(NoKeyServer())
        c2.execute("CREATE TABLE z (a INT FHE)")
        c2.execute("INSERT INTO z (a) VALUES (1)")


def test_over_the_wire_disk_storage_and_a_second_client_with_the_same_key(tmp_path):
    s = Running(db=str(tmp_path / "db"), storage="disk")
    try:
        with s.connect(fhe_key=KEY) as c:
            rows = seed(c)
            assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[sum(r[2] * r[3] for r in rows)]]
            c.begin()
            c.execute("UPDATE emp SET rate = 1 WHERE id = 2")
            c.rollback()
            assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
        # a different process holding only the key (no vault, no masks) reads the same data
        with s.connect(fhe_key=KEY) as c2:
            assert c2.execute("SELECT SUM(hours) FROM emp WHERE dept = 5").rows == [[410]]
            assert c2.execute("SELECT rate FROM emp WHERE id = 2").rows == [[55]]
        # without the key the data is unreadable and writes are refused
        with s.connect() as c3:
            with pytest.raises(Exception, match="FHE key"):
                c3.execute("SELECT SUM(rate) FROM emp")
        # a hostile client cannot plant garbage or plaintext in an FHE column
        with s.connect(fhe_key=KEY) as c4:
            call = c4._wire.call
            with pytest.raises(Exception, match="FHE"):
                call("update_cell", ["emp", 0, "rate", {"t": "i", "v": "7"}])
            with pytest.raises(Exception, match="invalid FHE ciphertext"):
                call("update_cell", ["emp", 0, "rate", {"t": "x", "v": "AAAA"}])
            with pytest.raises(Exception, match="not an FHE column"):
                call("update_cell", ["emp", 0, "id", {"t": "x", "v": "AAAA"}])
            with pytest.raises(Exception, match="at most"):
                call("fhe_dot", ["emp", "rate", [0] * 301, "emp", "hours", [0] * 301])
    finally:
        s.stop()


def test_fhe_cells_survive_snapshot_restart_and_replication(tmp_path):
    from test_replication import ADMIN, TOKENS, replica, wait_for
    p = Running(db=str(tmp_path / "p"), tokens=dict(TOKENS))
    r = None
    try:
        with p.connect(token=ADMIN, fhe_key=KEY) as c:
            seed(c)
        r = replica(p, str(tmp_path / "r"))
        with r.connect(token=ADMIN, fhe_key=KEY) as c:
            wait_for(lambda: c.execute("SELECT COUNT(*) FROM emp").rows == [[4]], what="bootstrap")
            with p.connect(token=ADMIN, fhe_key=KEY) as pc:
                pc.execute("INSERT INTO emp (id, dept, rate, hours) VALUES (9, 5, 10, 10)")
            wait_for(lambda: c.execute("SELECT SUM(rate) FROM emp").rows == [[155]], what="stream")
            assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[40 * 160 + 55 * 150 + 30 * 120 + 20 * 100 + 100]]
        p.stop()                                         # checkpoint (streamed snapshot incl. bytes)
        p2 = Running(db=str(tmp_path / "p"), tokens=dict(TOKENS))
        with p2.connect(token=ADMIN, fhe_key=KEY) as c:
            assert c.execute("SELECT SUM(rate) FROM emp").rows == [[155]]
        p2.stop()
    finally:
        if r:
            r.stop()
