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
HAVE_MCL = "mcl" in fhe.available_backends()


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


def test_no_value_oracle_even_for_someone_holding_both_public_keys():
    """Try every pairing identity between the cell and the PUBLIC keys Q (G1) and Q2 (G2)."""
    from py_ecc.optimized_bn128 import G2 as PG2
    be = fhe._fb.get("pyecc")
    key = fhe.FheKey(KEY._s, 50_000, backend="pyecc")
    ct = key.encrypt(1234)
    c1, c2, d1, d2 = fhe.parse_cell(ct, "pyecc")
    Q, Q2 = key.Q, key.Q2
    assert Q2 != be.g2_mul(be.G2, key._s)                 # the G2 key is NOT s·G2

    def identities(v):
        a1 = pairing(PG2, add(c2, neg(multiply(G1, v))))              # e(G2, C2 − vP)
        a2 = pairing(add(d2, neg(multiply(PG2, v))), G1)              # e(D2 − vG2, P)
        return [a1 == pairing(Q2, c1), a1 == pairing(d1, Q),
                a2 == pairing(d1, Q), a2 == pairing(Q2, c1),
                pairing(d1, c2) == pairing(d2, c1) if v == 0 else False]
    for v in (1234, 1, 0, 7):
        assert not any(identities(v)), v
    # positive control: with the WEAK key Q2 = s·G2 the same test does confirm the true value
    weak_Q2 = multiply(PG2, key._s)
    assert pairing(PG2, add(c2, neg(multiply(G1, 1234)))) == pairing(weak_Q2, c1)
    assert key.encrypt(5) != key.encrypt(5)               # randomised


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


def test_row_level_fhe_products_sql_in_process():
    """v0.6.2: SELECT L*R FROM t on FHE columns -- one ciphertext per row, the server pairs it
    (keyless), the owner decrypts each individually. Mirrors PAIRED's row-level `a*b`."""
    srv = NoKeyServer()
    c = NoKeyClient(srv, fhe=KEY)
    rows = seed(c)
    want = [r[2] * r[3] for r in rows]
    assert c.execute("SELECT rate * hours FROM emp").rows == [[want]]
    want2 = [(r[2] + 1) * (r[3] - 5) for r in rows]
    assert c.execute("SELECT (rate+1)*(hours-5) FROM emp").rows == [[want2]]
    # WHERE narrows the rows first
    sel = [r for r in rows if r[1] == 5]
    assert c.execute("SELECT rate * hours FROM emp WHERE dept = 5").rows == [
        [[r[2] * r[3] for r in sel]]]
    # the full wire audit (what reaches the server) for this shape lives in test_fhe_expr.py


def test_sql_rules_are_enforced_by_validator_and_planner():
    from torussql_parser import Schema, ValidationError, parse
    sch = Schema()
    sch.apply(parse("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE, p INT PAIRED, r RATIONAL ENC)"))
    for ok in ("SELECT SUM(a) FROM t", "SELECT DOT(a, b) FROM t", "SELECT AVG(a), COUNT(*) FROM t",
               "SELECT a FROM t WHERE id = 1",
               # v0.6.2: a bare per-row product of two FHE columns is now a feature (one ciphertext
               # per row, the server pairs it, keyless) — mirrors PAIRED's row-level `a * b`.
               "SELECT a * b FROM t"):
        sch.validate(parse(ok))
    for bad in ("SELECT DOT(a, p) FROM t", "SELECT 2 * a FROM t", "SELECT a * p FROM t",
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
            with pytest.raises(Exception, match="FHE"):                      # binary value in a non-FHE column
                call("update_cell", ["emp", 0, "id", {"t": "x", "v": "AAAA"}])
            with pytest.raises(Exception, match="at most"):
                call("fhe_dot", ["emp", "rate", [0] * 6001, "emp", "hours", [0] * 6001])
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


# ── back ends: pure Python and native mcl must agree and interoperate ────────
needs_mcl = pytest.mark.skipif(not HAVE_MCL, reason="mclbn256 not installed")


@needs_mcl
@pytest.mark.parametrize("enc_be,eval_be,dec_be", [
    ("pyecc", "mcl", "mcl"), ("mcl", "pyecc", "pyecc"), ("mcl", "mcl", "pyecc"), ("pyecc", "pyecc", "mcl")])
def test_backends_interoperate_on_cells_sums_and_dots(enc_be, eval_be, dec_be):
    s = KEY._s
    enc = fhe.FheKey(s, 50_000, backend=enc_be)
    dec = fhe.FheKey(s, 50_000, backend=dec_be)
    xs, ys = [3, -5, 7, 100], [2, 4, -6, 9]
    A, B = [enc.encrypt(x) for x in xs], [enc.encrypt(y) for y in ys]
    assert enc.Q is not None and [dec.decrypt_cell(c) for c in A] == xs      # points are library-independent
    assert dec.decrypt_sum(fhe.sum_cells(A, eval_be)) == sum(xs)
    blob = fhe.dot_cells(A, B, eval_be)
    # a DOT blob is decoded by the back end that made it, whichever back end the key prefers
    assert dec.decrypt_dot(blob) == sum(a * b for a, b in zip(xs, ys))
    assert blob[:1] == {"pyecc": b"\x01", "mcl": b"\x02"}[eval_be]
    part = fhe.mul_dots(fhe.dot_cells(A[:2], B[:2], eval_be), fhe.dot_cells(A[2:], B[2:], eval_be))
    assert dec.decrypt_dot(part) == sum(a * b for a, b in zip(xs, ys))


@needs_mcl
def test_mcl_rejects_invalid_points_and_subgroup_cheats():
    ct = bytearray(KEY.encrypt(5))
    for off in (3, 70, 140, 270):                       # corrupt a coordinate in each point
        bad = bytearray(ct); bad[off] ^= 0x55
        with pytest.raises(fhe.FheError):
            fhe.parse_cell(bytes(bad), "mcl")


@needs_mcl
def test_native_backend_is_orders_of_magnitude_faster():
    import time
    k = fhe.FheKey(value_range=10_000, backend="mcl")
    cts = [k.encrypt(i) for i in range(40)]
    t = time.perf_counter()
    blob = fhe.dot_cells(cts[:20], cts[20:], "mcl")
    assert time.perf_counter() - t < 2.0                 # pure Python needs ~4 s for 20 rows
    assert k.decrypt_dot(blob) == sum(a * b for a, b in zip(range(20), range(20, 40)))


@needs_mcl
def test_server_uses_the_native_backend_and_a_pure_client_can_still_decrypt(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        for backend in ("mcl", "pyecc"):
            key = fhe.FheKey(KEY._s, 50_000, backend=backend)
            with s.connect(fhe_key=key) as c:
                c.execute(f"CREATE TABLE IF NOT EXISTS emp (id INT PLAIN, rate INT FHE, hours INT FHE)")
                if backend == "mcl":
                    c.execute("INSERT INTO emp (id, rate, hours) VALUES (1, 40, 160)")
                    c.execute("INSERT INTO emp (id, rate, hours) VALUES (2, 55, 150)")
                assert c.execute("SELECT SUM(rate), DOT(rate, hours) FROM emp").rows == [[95, 14650]]
        with s.connect(fhe_key=fhe.FheKey(KEY._s, 50_000, backend="mcl")) as c:
            with pytest.raises(Exception, match="backend must be"):
                c._wire.call("fhe_dot", ["emp", "rate", [0], "emp", "hours", [0], "bogus"])
            with pytest.raises(Exception, match="at most"):
                c._wire.call("fhe_dot", ["emp", "rate", [0] * 6001, "emp", "hours", [0] * 6001, "mcl"])
    finally:
        s.stop()


@needs_mcl
def test_canonical_gt_encoding_is_a_ring_isomorphism_and_the_pinned_generator_is_right():
    from py_ecc.optimized_bn128 import FQ12
    mcl = fhe._fb.get("mcl")
    g = mcl.gt_gen()
    h = mcl.gt_pow(g, 987654321)
    a, b_ = FQ12(fhe._fb._rd(mcl.gt_to(g), 12)), FQ12(fhe._fb._rd(mcl.gt_to(h), 12))
    assert FQ12(fhe._fb._rd(mcl.gt_to(mcl.gt_mul(g, h)), 12)) == a * b_       # multiplication preserved
    assert mcl.gt_to(mcl.gt_from(mcl.gt_to(h))) == mcl.gt_to(h)                # round trip
    assert mcl.gt_gen_bytes() == fhe._fb.MCL_GT_GENERATOR                       # the published constant


@needs_mcl
def test_native_dot_results_decrypt_without_the_native_library():
    """The py_ecc-only decoder reads a result made by the native back end."""
    xs, ys = [3, -5, 7], [2, 4, -6]
    nat = fhe.FheKey(KEY._s, 50_000, backend="mcl")
    blob = fhe.dot_cells([nat.encrypt(x) for x in xs], [nat.encrypt(y) for y in ys], "mcl")
    assert blob[:1] == b"\x02"
    dec = fhe._fb.McLDecodeOnly()
    pure = fhe.FheKey(KEY._s, 50_000, backend="pyecc")
    be = pure.be
    real = fhe._fb.by_tag
    fhe._fb.by_tag = lambda tag: dec if bytes(tag) == b"\x02" else real(tag)
    try:
        assert pure.decrypt_dot(blob) == sum(a * b for a, b in zip(xs, ys))
    finally:
        fhe._fb.by_tag = real


# ── integrity (authenticated=True) ───────────────────────────────────────────
from torusdb_core.errors import IntegrityError as CoreIntegrity


def auth_client():
    srv = NoKeyServer()
    c = NoKeyClient(srv, fhe=KEY, authenticated=True)
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE, hours INT FHE)")
    for i, d, r, h in [(1, 5, 40, 160), (2, 5, 55, 150), (3, 7, 30, 120), (4, 5, 20, 100)]:
        c.execute(f"INSERT INTO emp (id, dept, rate, hours) VALUES ({i}, {d}, {r}, {h})")
    return srv, c


def test_authenticated_reads_sums_scaled_sums_and_updates():
    srv, c = auth_client()
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    assert c.execute("SELECT SUM(rate) FROM emp WHERE dept = 5").rows == [[115]]
    assert c.execute("SELECT 3 * SUM(rate) FROM emp").rows == [[435]]            # scalar mult of the ciphertext
    assert c.execute("SELECT -2 * SUM(hours) FROM emp WHERE dept = 5").rows == [[-820]]
    assert c.execute("SELECT id, rate FROM emp WHERE id = 3").rows == [[3, 30]]
    c.execute("UPDATE emp SET rate = 60 WHERE id = 1")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[165]]
    c.execute("DELETE FROM emp WHERE id = 4")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    assert "__fmac__rate" in srv._rows["emp"].row(0)                              # tags are stored server-side


def test_a_lying_server_is_caught():
    srv, c = auth_client()
    store = srv._rows["emp"]
    # 1. a value replaced by another valid ciphertext (tag no longer matches)
    good = store.row(1)["rate"]
    store.set_cell(1, "rate", KEY.encrypt(999))
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT SUM(rate) FROM emp")
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT rate FROM emp WHERE id = 2")
    store.set_cell(1, "rate", good)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    # 2. a whole row swapped (value AND its tag) with another row's
    r0, r2 = store.row(0), store.row(2)
    a = (r0["rate"], r0["__fmac__rate"]); b = (r2["rate"], r2["__fmac__rate"])
    store.set_cell(0, "rate", b[0]); store.set_cell(0, "__fmac__rate", b[1])
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT rate FROM emp WHERE id = 1")
    store.set_cell(0, "rate", a[0]); store.set_cell(0, "__fmac__rate", a[1])
    # 3. an answer scaled, or computed over fewer / duplicated rows
    real = srv.fhe_sum
    for lie in (lambda t, col, ids, k=1: real(t, col, ids, k * 2),
                lambda t, col, ids, k=1: real(t, col, ids[:-1], k),
                lambda t, col, ids, k=1: real(t, col, ids + ids[:1], k)):
        srv.fhe_sum = lie
        with pytest.raises(CoreIntegrity):
            c.execute("SELECT SUM(rate) FROM emp")
        with pytest.raises(CoreIntegrity):
            c.execute("SELECT 2 * SUM(hours) FROM emp")
    srv.fhe_sum = real
    assert c.execute("SELECT SUM(hours) FROM emp").rows == [[530]]


def test_untagged_data_is_refused_by_an_authenticated_client_and_dot_needs_opt_in():
    srv = NoKeyServer()
    plain_c = NoKeyClient(srv, fhe=KEY)                      # writes without tags
    plain_c.execute("CREATE TABLE t (a INT FHE, b INT FHE)")
    plain_c.execute("INSERT INTO t (a, b) VALUES (2, 3)")
    auth = NoKeyClient(srv, fhe=KEY, authenticated=True)
    auth._schema, auth._coltype, auth._colpolicy = plain_c._schema, plain_c._coltype, plain_c._colpolicy
    with pytest.raises(CoreIntegrity):
        auth.execute("SELECT a FROM t")
    with pytest.raises(CoreIntegrity):
        auth.execute("SELECT SUM(a) FROM t")
    _, c = auth_client()
    want = 40 * 160 + 55 * 150 + 30 * 120 + 20 * 100
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[want]]       # auto -> local, verified
    assert c.execute("SELECT DOT(rate, hours) FROM emp WHERE dept = 5").rows == [[40 * 160 + 55 * 150 + 20 * 100]]
    c.fhe_dot_mode = "delegated"                                                 # explicit opt-in to the server product
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[want]]
    c.fhe_dot_mode = "bogus"
    with pytest.raises(Exception, match="fhe_dot_mode"):
        c.execute("SELECT DOT(rate, hours) FROM emp")


def test_local_dot_catches_a_tampered_operand_and_delegated_dot_does_not():
    srv, c = auth_client()
    store = srv._rows["emp"]
    store.set_cell(1, "hours", KEY.encrypt(1))                 # server swaps one operand cell for another value
    c.fhe_dot_mode = "local"
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT DOT(rate, hours) FROM emp")
    c.fhe_dot_mode = "delegated"                               # the unverified path silently returns a wrong number
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows != [[40 * 160 + 55 * 150 + 30 * 120 + 20 * 100]]
    # local mode also verifies the tags of untouched rows and works over a wire connection
    c.fhe_dot_mode = "local"
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT DOT(rate, hours) FROM emp WHERE dept = 5")


def test_authenticated_insert_is_atomic_over_the_wire(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        with s.connect(fhe_key=KEY, authenticated=True) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            c.execute("INSERT INTO t (id, v) VALUES (1, 10)")
            c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(2, 20), (3, 30)])
            assert c.execute("SELECT SUM(v) FROM t").rows == [[60]]
            assert c.execute("SELECT 2 * SUM(v) FROM t WHERE id > 1").rows == [[100]]
            # the tag write fails midway -> the row must not exist at all
            real_b, real_1 = c.client.server.update_cells, c.client.server.update_cell
            def boom(*a, **k):
                raise RuntimeError("network died")
            c.client.server.update_cells = c.client.server.update_cell = boom
            with pytest.raises(Exception):
                c.execute("INSERT INTO t (id, v) VALUES (4, 40)")
            c.client.server.update_cells, c.client.server.update_cell = real_b, real_1
            assert c._wire.call("table_info", ["t"])["rows"] == 3
            assert c.execute("SELECT SUM(v) FROM t").rows == [[60]]
        # a server that tampers on disk is caught by a fresh authenticated client
        with s.connect(fhe_key=KEY, authenticated=True) as c2:
            c2._wire.call("update_cell", ["t", 0, "v", {"t": "x", "v": __import__("base64").b64encode(KEY.encrypt(11)).decode()}])
            with pytest.raises(torussql.IntegrityError):
                c2.execute("SELECT SUM(v) FROM t")
    finally:
        s.stop()


def test_published_vectors():
    """proto/fhe-vectors.json is what other-language drivers are tested against."""
    import json
    from pathlib import Path
    v = json.loads((Path(__file__).resolve().parents[1] / "proto/fhe-vectors.json").read_text())
    key = fhe.FheKey.from_secret_bytes(bytes.fromhex(v["secret"]), v["range"], backend="pyecc")
    A = [bytes.fromhex(c) for c in v["cells_a"]]
    assert [key.decrypt_cell(c) for c in A] == v["values_a"]
    assert key.decrypt_sum(bytes.fromhex(v["sum_blob"])) == v["sum_expected"]
    assert key.decrypt_sum(bytes.fromhex(v["scaled3_sum_blob"])) == v["scaled3_expected"]
    assert key.decrypt_dot(bytes.fromhex(v["dot_blob_pyecc"])) == v["dot_expected"]
    if v["dot_blob_mcl"]:
        assert key.decrypt_dot(bytes.fromhex(v["dot_blob_mcl"])) == v["dot_expected"]   # via the decode-only path if needed
    mac = v["mac"]
    assert hex(key.alpha) == mac["alpha"]
    nonces = [int(n, 16) for n in mac["nonces"]]
    assert [hex(key.gamma(mac["table"], mac["column"], i, n)) for i, n in zip(mac["row_ids"], nonces)] == mac["gamma"]
    assert key.decrypt_sum_verified(bytes.fromhex(v["sum_blob"]), bytes.fromhex(mac["tag_sum_blob"]),
                                    mac["table"], mac["column"], mac["row_ids"], nonces=nonces) == v["sum_expected"]
    gens = v["gt_generators"]
    assert fhe._fb.get("pyecc").gt_to(fhe._fb.get("pyecc").gt_gen()).hex() == gens["pyecc_tag01"]
    assert fhe._fb.MCL_GT_GENERATOR.hex() == gens["mcl_tag02"]


@pytest.mark.parametrize("backend", ["pyecc", "mcl"])
def test_dot_decryption_refuses_components_outside_the_gt_subgroup(backend):
    """A hostile server must not be able to make the secret exponent act on a small-order element."""
    import random
    from py_ecc.optimized_bn128 import FQ12
    if backend == "mcl" and not HAVE_MCL:
        pytest.skip("mclbn256 not installed")
    key = fhe.FheKey(KEY._s, 50_000, backend=backend)
    A, B = [key.encrypt(3), key.encrypt(4)], [key.encrypt(5), key.encrypt(6)]
    blob = fhe.dot_cells(A, B, backend)
    assert key.decrypt_dot(blob) == 3 * 5 + 4 * 6
    be = fhe._fb.by_tag(blob[:1])
    junk = be.gt_from(be.gt_to(FQ12([random.randrange(2, fhe._fb.P_MOD) for _ in range(12)])) if False else
                      b"".join(random.randrange(2, fhe._fb.P_MOD).to_bytes(32, "big") for _ in range(12))) \
        if backend == "pyecc" else None
    for pos in (0, 1, 2):                                                          # c00, c01, c10
        parts = [blob[1 + i * 384:1 + (i + 1) * 384] for i in range(4)]
        if backend == "pyecc":
            parts[pos] = be.gt_to(be.gt_mul(be.gt_from(parts[pos]), junk))
        else:                                  # a random Fp12 element in the canonical encoding
            parts[pos] = b"".join(random.randrange(2, fhe._fb.P_MOD).to_bytes(32, "big") for _ in range(12))
        with pytest.raises((fhe.FheError)):
            key.decrypt_dot(blob[:1] + b"".join(parts))
    # an out-of-range answer is refused even if the BSGS grid happens to reach it
    small = fhe.FheKey(KEY._s, 10, backend="pyecc")
    with pytest.raises(fhe.FheError):
        small.decrypt_sum(fhe.sum_cells([KEY.encrypt(10), KEY.encrypt(10)], "pyecc"))


# ── batch writes and negotiated limits ───────────────────────────────────────
def test_update_cells_is_atomic_batched_and_hello_publishes_limits(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        with s.connect(fhe_key=KEY, authenticated=True) as c:
            lim = c.server_info["limits"]
            assert lim["max_items"] > 0 and lim["fhe"]["max_sum_rows"] > 0
            assert lim["fhe"]["max_dot_rows"]["pyecc"] < lim["fhe"]["max_dot_rows"]["mcl"]
            assert "pyecc" in lim["fhe"]["backends"] and lim["fhe"]["recommended_dot_rows"]["pyecc"] <= 100
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            calls = []
            real = c._wire.call
            c._wire.call = lambda m, a: (calls.append(m), real(m, a))[1]
            c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(i, i) for i in range(30)])
            assert calls.count("update_cells") == 1 and "update_cell" not in calls   # ONE tag round trip, not 30
            c._wire.call = real
            assert c.execute("SELECT SUM(v) FROM t").rows == [[sum(range(30))]]
            # atomic: a bad item rolls the whole batch back
            before = c._wire.call("plain_cells", ["t", "v", [0, 1]])
            good = {"t": "x", "v": __import__("base64").b64encode(KEY.encrypt(7)).decode()}
            with pytest.raises(Exception, match="FHE"):
                c._wire.call("update_cells", ["t", [[0, "v", good], [1, "v", {"t": "i", "v": "5"}]]])
            assert c._wire.call("plain_cells", ["t", "v", [0, 1]]) == before
            with pytest.raises(Exception, match="takes"):
                c._wire.call("update_cells", ["t", [[0, "v"]]])
    finally:
        s.stop()


def test_engine_sizes_requests_from_the_servers_limits(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        with s.connect(fhe_key=KEY) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(i, i) for i in range(12)])
            c.client.server.limits = lambda: {"fhe": {"max_sum_rows": 5, "max_dot_rows": {"pyecc": 4, "mcl": 4},
                                                       "recommended_dot_rows": {"pyecc": 3, "mcl": 3}}}
            sizes = []
            real = c._wire.call
            c._wire.call = lambda m, a: (sizes.append((m, len(a[2]))) if m.startswith("fhe_") else None, real(m, a))[1]
            assert c.execute("SELECT SUM(v) FROM t").rows == [[66]]
            assert c.execute("SELECT DOT(v, v) FROM t").rows == [[sum(i * i for i in range(12))]]
            assert max(n for m, n in sizes if m == "fhe_sum") <= 5
            assert max(n for m, n in sizes if m == "fhe_dot") <= 3
    finally:
        s.stop()
