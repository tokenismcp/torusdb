# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the independent red-team review of FHE columns (F2, F5–F9)."""
from __future__ import annotations

import base64
import threading
import time

import pytest

import torussql
from torusdb_core import fhe
from torusdb_core import fhe_backend as fb
from test_ops import Running

KEY = fhe.FheKey(value_range=10_000)
HAVE_MCL = "mcl" in fhe.available_backends()
needs_mcl = pytest.mark.skipif(not HAVE_MCL, reason="mclbn256 not installed")


# ── F2: affine mixing of two versions of one row ─────────────────────────────
@pytest.mark.parametrize("lam", [1, 0, -500, 7])
def test_old_and_new_versions_cannot_be_mixed_affinely(lam):
    s = Running()
    try:
        with s.connect(fhe_key=KEY, authenticated=True) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            for i, v in [(1, 10), (2, 20), (3, 30)]:
                c.execute(f"INSERT INTO t (id, v) VALUES ({i}, {v})")
            srv = c.client.server
            old_v = srv.plain_cells("t", "v", [1])[0]
            old_t = srv.plain_cells("t", "__fmac__v", [1])[0]
            c.execute("UPDATE t SET v = 21 WHERE id = 2")
            new_v = srv.plain_cells("t", "v", [1])[0]
            new_t = srv.plain_cells("t", "__fmac__v", [1])[0]
            assert c.execute("SELECT SUM(v) FROM t").rows == [[61]]
            cell = lambda col, i: srv.plain_cells("t", col, [i])[0]    # noqa: E731
            real = srv.fhe_sum

            def fake(table, col, ids, k=1):
                if table != "t" or ids != [0, 1, 2]:
                    return real(table, col, ids, k)
                o, n = (old_v, new_v) if col == "v" else (old_t, new_t)
                rest = fhe.sum_cells([cell(col, 0), cell(col, 2)], None, k)
                mixed = fhe.add_sums(fhe.sum_cells([o], None, lam * k),
                                     fhe.sum_cells([n], None, (1 - lam) * k))
                return fhe.add_sums(rest, mixed)
            srv.fhe_sum = fake
            if lam == 0:                       # lam = 0 is the honest answer (pure new version)
                assert c.execute("SELECT SUM(v) FROM t").rows == [[61]]
            else:                              # includes lam = 1 (replay of the old cell) and the mixtures
                with pytest.raises(torussql.IntegrityError):
                    c.execute("SELECT SUM(v) FROM t")
    finally:
        s.stop()


def test_every_write_gets_a_fresh_nonce_and_a_missing_nonce_is_refused():
    s = Running()
    try:
        with s.connect(fhe_key=KEY, authenticated=True) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            c.execute("INSERT INTO t (id, v) VALUES (1, 5)")
            srv = c.client.server
            n1 = srv.plain_cells("t", "__fnonce__v", [0])[0]
            c.execute("UPDATE t SET v = 6 WHERE id = 1")
            n2 = srv.plain_cells("t", "__fnonce__v", [0])[0]
            assert isinstance(n1, int) and isinstance(n2, int) and n1 != n2
            assert c.execute("SELECT v FROM t").rows == [[6]]
            # the server hides the nonce -> the owner refuses instead of guessing
            real = srv.plain_cells
            srv.plain_cells = lambda t, col, ids: ([None] * len(ids) if col.startswith("__fnonce__")
                                                    else real(t, col, ids))
            with pytest.raises(torussql.IntegrityError):
                c.execute("SELECT v FROM t")
            with pytest.raises(torussql.IntegrityError):
                c.execute("SELECT SUM(v) FROM t")
            srv.plain_cells = real
            # nonce columns are validated by the server
            with pytest.raises(Exception, match="nonce"):
                c._wire.call("update_cell", ["t", 0, "__fnonce__v", {"t": "i", "v": "-3"}])
            with pytest.raises(Exception):
                c._wire.call("update_cell", ["t", 0, "__fnonce__id", {"t": "i", "v": "5"}])
    finally:
        s.stop()


# ── F6: GT components are checked one by one, exactly ────────────────────────
@pytest.mark.parametrize("backend", ["pyecc", "mcl"])
def test_dot_decryption_rejects_small_order_pairs_whose_product_looks_valid(backend):
    from py_ecc.optimized_bn128 import FQ12
    if backend == "mcl" and not HAVE_MCL:
        pytest.skip("mclbn256 not installed")
    key = fhe.FheKey(KEY._s, 10_000, backend=backend)
    cells = [key.encrypt(3), key.encrypt(4)]
    blob = fhe.dot_cells(cells, cells, backend)
    assert key.decrypt_dot(blob) == 25
    py = fb.get("pyecc")
    # t of small order inside Fp12*: t = u^((p^12-1)/l) for a random u; l = 5 divides p^12-1
    import random
    l_ = 5
    while True:
        u = FQ12([random.randrange(2, fb.P_MOD) for _ in range(12)])
        t = u ** ((fb.P_MOD ** 12 - 1) // l_)
        if t != FQ12.one():
            break
    assert t ** l_ == FQ12.one()
    be = fb.by_tag(blob[:1])
    parts = [blob[1 + i * 384:1 + (i + 1) * 384] for i in range(4)]
    to = lambda x: be.gt_from(py.gt_to(x)) if backend == "mcl" else x          # noqa: E731
    back = lambda g: be.gt_to(g)                                              # noqa: E731
    c01, c10 = be.gt_from(parts[1]), be.gt_from(parts[2])
    parts[1] = back(be.gt_mul(c01, to(t)))
    parts[2] = back(be.gt_mul(c10, to(t ** (l_ - 1))))                           # t · t^(l-1) = 1: product unchanged
    with pytest.raises(fhe.FheError, match="subgroup"):
        key.decrypt_dot(blob[:1] + b"".join(parts))


@needs_mcl
def test_native_subgroup_test_is_exact():
    from py_ecc.optimized_bn128 import FQ12
    import random
    mcl, py = fb.get("mcl"), fb.get("pyecc")
    good = mcl.gt_gen()
    assert mcl.gt_in_subgroup(good)
    for _ in range(3):
        junk = FQ12([random.randrange(2, fb.P_MOD) for _ in range(12)])
        t = junk ** ((fb.P_MOD ** 12 - 1) // 5)
        if t == FQ12.one():
            continue
        g = mcl.gt_from(py.gt_to(t))
        assert not mcl.gt_in_subgroup(g) and not py.gt_in_subgroup(t)


# ── F7: the discrete-log search no longer leaks the value through its running time ──
def test_dlog_start_is_randomised_and_still_correct():
    key = fhe.FheKey(KEY._s, 5_000, backend="pyecc")
    seen = set()
    orig = fhe.secrets.randbelow
    calls = []
    fhe.secrets.randbelow = lambda n: (calls.append(n), orig(n))[1]
    try:
        for v in (-5000, -1, 0, 1, 4999, 5000, 123):
            assert key.decrypt_cell(key.encrypt(v)) == v
    finally:
        fhe.secrets.randbelow = orig
    assert len(calls) >= 7 * 3                    # 3 randomisations per encrypt+decrypt, incl. the walk start


# ── F10: range cap ───────────────────────────────────────────────────────────
def test_range_is_capped():
    for bad in (0, -5, (1 << 40) + 1, 10 ** 30, 1.5, True):
        with pytest.raises(fhe.FheError):
            fhe.FheKey(value_range=bad)
    fhe.FheKey(value_range=1 << 40)


# ── F8 / F5: write-time validation, DoS levers ───────────────────────────────
def test_g2_subgroup_is_proven_when_a_cell_is_written():
    from py_ecc.optimized_bn128 import FQ2, b2, is_on_curve, multiply, normalize, G2
    # a point on the twist but NOT in the prime-order subgroup: try x = 1, 2, … until y exists
    py = fb.get("pyecc")
    P = fb.P_MOD
    bad = None
    for x0 in range(2, 200):
        x = FQ2([x0, 1])
        rhs = x ** 3 + b2
        for _ in range(1):
            y = rhs ** ((P * P + 7) // 16) if False else None
        # square root in Fp2 via py_ecc is awkward; use the library's cofactor trick instead:
        break
    # build the point by clearing nothing: a random point on the twist = hash-to-curve by trial
    import random
    for _ in range(200):
        x = FQ2([random.randrange(P), random.randrange(P)])
        rhs = x ** 3 + b2
        # Euler criterion in Fp2 (norm is a square in Fp) then sqrt by exponentiation
        cand = rhs ** ((P ** 2 + 7) // 16)
        for root in (cand, cand * FQ2([0, 1])):
            if root * root == rhs:
                bad = (x, root, FQ2([1, 0]))
                break
        if bad:
            break
    if bad is None or not is_on_curve(bad, b2):
        pytest.skip("could not construct a twist point quickly")
    from py_ecc.optimized_bn128 import curve_order
    if multiply(bad, curve_order)[2] == FQ2.zero():
        pytest.skip("constructed point happens to be in the subgroup")
    raw = KEY.encrypt(5)
    forged = raw[:128] + py.g2_to(bad) + raw[256:]
    with pytest.raises(fhe.FheError):
        fhe.parse_cell(forged, "pyecc", strict=True)        # a write is refused ...
    fhe.parse_cell(forged, "pyecc")                         # ... while the cheap read-path parse does not pay for it


def test_server_validates_before_the_lock_and_rejects_dos_levers(tmp_path):
    s = Running(db=str(tmp_path / "db"))
    try:
        with s.connect(fhe_key=KEY) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, v INT FHE)")
            c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(i, i) for i in range(8)])
            call = c._wire.call
            # duplicate ids are refused in SUM and DOT
            with pytest.raises(Exception, match="distinct"):
                call("fhe_sum", ["t", "v", [0, 0, 1]])
            with pytest.raises(Exception, match="distinct"):
                call("fhe_dot", ["t", "v", [0, 0], "t", "v", [1, 2]])
            # a client cannot force the slow pure-Python back end (it gets the server's own)
            info = call("hello", []) if False else None
            want = fb.default().name
            blob = base64.b64decode(call("fhe_dot", ["t", "v", [0, 1], "t", "v", [2, 3],
                                                     "pyecc" if want == "mcl" else "mcl"]))
            assert blob[:1] == fb.get(want).tag
            # a huge batch of garbage cells is rejected before it can hold the global lock
            bad = {"t": "x", "v": base64.b64encode(bytes(384)).decode()}      # all-zero = identity: valid
            junk = {"t": "x", "v": base64.b64encode(b"\x01" * 384).decode()}
            t0 = time.monotonic()
            with pytest.raises(Exception, match="invalid FHE"):
                call("update_cells", ["t", [[0, "v", junk]] * 400])
            assert time.monotonic() - t0 < 5
            call("update_cell", ["t", 0, "v", bad])
    finally:
        s.stop()


# ── F9: backend initialisation is thread-safe ───────────────────────────────
@needs_mcl
def test_concurrent_first_use_of_the_native_backend(tmp_path):
    import subprocess, sys, os
    code = ("import threading, sys\n"
            "sys.path[:0] = %r\n"
            "from torusdb_core import fhe_backend as fb\n"
            "errs = []\n"
            "def go():\n"
            "    try: fb.get('mcl')\n"
            "    except Exception as e: errs.append(repr(e))\n"
            "ts = [threading.Thread(target=go) for _ in range(12)]\n"
            "[t.start() for t in ts]; [t.join() for t in ts]\n"
            "print(len(errs), errs[:1])\n") % ([p for p in sys.path if "torussql" in p or "mcl" in p],)
    for _ in range(3):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)), timeout=120)
        assert out.stdout.startswith("0 "), out.stdout + out.stderr


def test_key_file_with_an_absurd_range_is_refused(tmp_path):
    """A hostile or corrupted key file must not make the owner build a gigantic table."""
    import json
    good = str(tmp_path / "k")
    fhe.save_key(KEY, good, None)
    raw = open(good, "rb").read()
    head, _, body = raw.partition(b"\n")
    d = json.loads(body)
    d["range"] = 10 ** 30
    bad = str(tmp_path / "bad")
    open(bad, "wb").write(head + b"\n" + json.dumps(d).encode())
    with pytest.raises(fhe.FheError, match="range"):
        fhe.load_key(bad, None)
    assert fhe.load_key(good, None).range == KEY.range
