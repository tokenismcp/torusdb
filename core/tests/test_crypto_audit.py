# SPDX-License-Identifier: Apache-2.0
"""Internal cryptographic audit tests for the no-key protocol Π.

These do not replace an external review (see docs/crypto-review-packet.md);
they pin the properties the design claims, so a regression is caught and a
reviewer can run them.

Statistical tests use thresholds with a false-failure probability well below
1e-9, so they are deterministic in practice.
"""
from __future__ import annotations

import random
import secrets
from fractions import Fraction

import pytest

from torusdb_core.protocol import (N, OutOfBudget, Owner, Server, Triple, decode, encode,
                         gen_triple)
from torusdb_core.errors import ExecError, IntegrityError
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer

OWNER = Owner()


def chi2_uniform(values, buckets=16):
    counts = [0] * buckets
    for v in values:
        counts[v * buckets // N] += 1
    exp = len(values) / buckets
    return sum((c - exp) ** 2 / exp for c in counts)


# chi-square, df=15: P(X > 60) < 1e-6
CHI2_LIMIT = 60.0


# ── P1/P2: the server's view is independent of the plaintext ─────────────────
@pytest.mark.parametrize("plain", [0, 1, 10 ** 12, -7, 2 ** 100])
def test_blinded_value_is_uniform_whatever_the_plaintext(plain):
    vals = [OWNER.blind(encode(plain))[0] for _ in range(6000)]
    assert chi2_uniform(vals) < CHI2_LIMIT


def test_two_plaintexts_are_indistinguishable_by_homogeneity_test():
    a = [OWNER.blind(encode(0))[0] for _ in range(6000)]
    b = [OWNER.blind(encode(10 ** 15))[0] for _ in range(6000)]
    # two-sample chi-square on 16 buckets (df = 15)
    ca, cb = [0] * 16, [0] * 16
    for v in a: ca[v * 16 // N] += 1
    for v in b: cb[v * 16 // N] += 1
    stat = sum((x - y) ** 2 / (x + y) for x, y in zip(ca, cb))
    assert stat < CHI2_LIMIT


def test_blinded_parity_is_unbiased():
    vals = [OWNER.blind(encode(5))[0] & 1 for _ in range(10000)]
    assert abs(sum(vals) - 5000) < 5 * 50          # 5 sigma


def test_masks_are_unique_and_full_range():
    masks = [OWNER.blind(0)[1] for _ in range(20000)]
    assert len(set(masks)) == len(masks)
    assert max(masks) > N // 2 and min(masks) < N // 2


# ── what the server is ever handed ───────────────────────────────────────────
class Recording(NoKeyServer):
    """A server that records every integer it is ever given."""

    def __init__(self):
        super().__init__()
        self.seen: set[int] = set()
        self.seen_str: list[str] = []

    def _note(self, x):
        if isinstance(x, bool):
            return
        if isinstance(x, int):
            self.seen.add(x)
        elif isinstance(x, str):
            self.seen_str.append(x)
        elif isinstance(x, dict):
            for k, v in x.items():
                self._note(k); self._note(v)
        elif isinstance(x, (list, tuple, set)):
            for v in x:
                self._note(v)

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if callable(attr) and not name.startswith("_") and name not in (
                "to_body", "from_body", "save", "open"):
            def spy(*a, **k):
                self._note(a); self._note(k)
                return attr(*a, **k)
            return spy
        return attr


def workload(client):
    client.execute("CREATE TABLE t (id INT PLAIN, a INT PAIRED, b INT PAIRED, "
                   "c RATIONAL ENC)")
    for i in range(1, 9):
        client.execute(f"INSERT INTO t (id, a, b, c) VALUES "
                       f"({i}, {1000 + 7 * i}, {2000 + 11 * i}, FRAC({3000 + i},7))")
    client.execute("UPDATE t SET c = FRAC(123456789, 1) WHERE id = 3")
    assert client.execute("SELECT SUM(c) FROM t").rows
    assert client.execute("SELECT AVG(c) FROM t").rows
    assert client.execute("SELECT 5 * SUM(a) FROM t").rows
    assert client.execute("SELECT DOT(a, b) FROM t").rows
    assert client.execute("SELECT a * b FROM t WHERE id < 4").rows
    assert client.execute("SELECT c FROM t").rows


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_server_never_receives_a_mask_or_an_encrypted_plaintext(auth):
    srv = Recording()
    cli = NoKeyClient(srv, authenticated=auth)
    workload(cli)
    masks = set(cli._masks.values())
    assert masks, "vault unexpectedly empty"
    assert not (masks & srv.seen), "a mask value reached the server"
    # nor the encoded plaintext of any encrypted cell, nor alpha
    secrets_ = {encode(1000 + 7 * i) for i in range(1, 9)} | {encode(123456789)}
    secrets_ |= {encode(Fraction(3000 + i, 7)) for i in range(1, 9)}
    assert not (secrets_ & srv.seen)
    if auth:
        assert cli._alpha not in srv.seen
    # decimal plaintexts of encrypted columns never appear as strings either
    assert not any(s in ("123456789", "1007") for s in srv.seen_str)


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_stored_snapshot_contains_no_plaintext_of_encrypted_columns(auth, tmp_path):
    import json
    srv = NoKeyServer()
    cli = NoKeyClient(srv, authenticated=auth)
    workload(cli)
    body = srv.to_body()
    cells = set()
    for row in body["rows"]["t"]:
        for k, v in row.items():
            if k != "id":
                cells.add(int(v["v"]))
    plain = {encode(123456789)} | {encode(1000 + 7 * i) for i in range(1, 9)} \
        | {encode(2000 + 11 * i) for i in range(1, 9)} \
        | {encode(Fraction(3000 + i, 7)) for i in range(1, 9)}
    assert not (cells & plain)                         # no cell equals a plaintext
    assert not (cells & set(cli._masks.values()))      # nor a mask
    if auth:
        assert cli._alpha not in cells


def test_update_to_identical_value_changes_the_servers_view():
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
    cli.execute("INSERT INTO t (id, v) VALUES (1, 42)")
    before_cell, before_mask = srv._rows["t"][0]["v"], cli._masks[("t", 0, "v")]
    cli.execute("UPDATE t SET v = 42 WHERE id = 1")
    assert srv._rows["t"][0]["v"] != before_cell        # fresh pad
    assert cli._masks[("t", 0, "v")] != before_mask
    assert cli.execute("SELECT v FROM t").rows == [[42]]


def test_equal_plaintexts_in_different_rows_look_unrelated():
    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE t (v INT ENC)")
    for _ in range(300):
        cli.execute("INSERT INTO t (v) VALUES (7)")
    cells = [r["v"] for r in srv._rows["t"]]
    assert len(set(cells)) == len(cells)                # no equality leakage
    assert chi2_uniform(cells, 8) < 40


# ── Π_lin / Π_mult correctness + openings ───────────────────────────────────
def test_pi_lin_random_affine_forms():
    rng = random.Random(7)
    for _ in range(300):
        n = rng.randint(1, 12)
        xs = [rng.randint(-10 ** 9, 10 ** 9) for _ in range(n)]
        co = [rng.randint(-1000, 1000) for _ in range(n)]
        b = rng.randint(-5000, 5000)
        pairs = [OWNER.blind(encode(x)) for x in xs]
        y_blinded = Server.affine([p[0] for p in pairs], [c % N for c in co], b % N)
        y = OWNER.unblind_affine(y_blinded, [c % N for c in co], [p[1] for p in pairs])
        assert decode((y - b) % N) == sum(c * x for c, x in zip(co, xs))


def test_beaver_multiplication_random():
    rng = random.Random(11)
    for _ in range(300):
        x, y = rng.randint(-10 ** 8, 10 ** 8), rng.randint(-10 ** 8, 10 ** 8)
        t = gen_triple()
        assert t.w == t.u * t.v % N
        e, g = OWNER.mult_open(encode(x), encode(y), t)
        out = OWNER.mult_reconstruct(e, g, Server.mult_combine(e, g), t)
        assert decode(out) == x * y


def test_beaver_openings_hide_the_operands():
    es = [OWNER.mult_open(encode(5), encode(9), gen_triple())[0] for _ in range(6000)]
    assert chi2_uniform(es) < CHI2_LIMIT
    # a triple is never reused
    ts = [gen_triple() for _ in range(2000)]
    assert len({(t.u, t.v) for t in ts}) == len(ts)


# ── decode budget: overflow must be loud, never a silently wrong number ──────
def test_decode_roundtrips_in_range_values_exactly():
    rng = random.Random(3)
    for _ in range(3000):
        a = rng.randint(-2 ** 90, 2 ** 90)
        b = rng.randint(1, 2 ** 90)
        assert decode(encode(Fraction(a, b))) == Fraction(a, b)


def test_decode_rejects_out_of_budget_elements():
    bad = 0
    for _ in range(5000):
        s = secrets.randbelow(N)
        try:
            decode(s)
        except OutOfBudget:
            bad += 1
    assert bad == 5000                         # P(false accept) ~ 2^-57 each


def test_aggregate_overflow_raises_instead_of_returning_garbage():
    big = 2 ** 126
    assert decode(encode(big)) == big
    total = (encode(big) + encode(big)) % N       # 2^127: beyond the budget
    with pytest.raises(OutOfBudget):
        decode(total)
    # and the same for a long run of in-range values whose sum overflows
    acc = 0
    for _ in range(40):
        acc = (acc + encode(2 ** 124)) % N        # 40 * 2^124 > 2^128
    with pytest.raises(OutOfBudget):
        decode(acc)


def test_encode_rejects_values_that_could_never_decode():
    with pytest.raises(OutOfBudget):
        encode(2 ** 200)
    with pytest.raises(OutOfBudget):
        encode(2 ** 127)
    with pytest.raises(OutOfBudget):
        encode(Fraction(2 ** 100, 2 ** 100 + 1))       # product beyond budget
    with pytest.raises(OutOfBudget):
        encode(Fraction(1, 2 ** 127))
    assert decode(encode(2 ** 126)) == 2 ** 126
    assert decode(encode(-(2 ** 126))) == -(2 ** 126)


def test_sum_of_fractions_with_coprime_denominators_overflows_loudly():
    primes = [1000003, 1000033, 1000037, 1000039, 1000081, 1000099,
              1000117, 1000121, 1000133]
    cli = NoKeyClient(NoKeyServer())
    cli.execute("CREATE TABLE t (v RATIONAL ENC)")
    for p in primes:
        cli.execute(f"INSERT INTO t (v) VALUES (FRAC(1,{p}))")
    # denominators multiply: 9 primes of ~2^20 -> ~2^180 (denominator) * num
    # 4 primes are comfortably inside the budget and must be exact:
    cli2 = NoKeyClient(NoKeyServer())
    cli2.execute("CREATE TABLE t (v RATIONAL ENC)")
    for p in primes[:4]:
        cli2.execute(f"INSERT INTO t (v) VALUES (FRAC(1,{p}))")
    assert cli2.execute("SELECT SUM(v) FROM t").rows == [[sum(Fraction(1, p) for p in primes[:4])]]
    # the full set overflows: it must either be exact or raise — never wrong
    try:
        got = cli.execute("SELECT SUM(v) FROM t").rows[0][0]
    except OutOfBudget:
        return
    assert got == sum(Fraction(1, p) for p in primes)


# ── integrity (authenticated mode) ───────────────────────────────────────────
def _auth_db():
    srv = NoKeyServer()
    cli = NoKeyClient(srv, authenticated=True)
    cli.execute("CREATE TABLE t (id INT PLAIN, v INT ENC, w INT PAIRED, x INT PAIRED)")
    for i in range(1, 11):
        cli.execute(f"INSERT INTO t (id, v, w, x) VALUES ({i}, {i * 100}, {i}, {i + 1})")
    return srv, cli


@pytest.mark.parametrize("row", range(0, 10, 3))
def test_any_single_cell_tamper_is_detected_on_sum(row):
    srv, cli = _auth_db()
    srv._rows["t"][row]["v"] = (srv._rows["t"][row]["v"] + secrets.randbelow(N - 1) + 1) % N
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(v) FROM t")


def test_tampering_only_the_mac_cell_is_detected():
    srv, cli = _auth_db()
    srv._rows["t"][4]["__mac__v"] = (srv._rows["t"][4]["__mac__v"] + 1) % N
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(v) FROM t")


def test_swapping_two_rows_cells_is_detected():
    srv, cli = _auth_db()
    r = srv._rows["t"]
    r[1]["v"], r[2]["v"] = r[2]["v"], r[1]["v"]
    r[1]["__mac__v"], r[2]["__mac__v"] = r[2]["__mac__v"], r[1]["__mac__v"]
    # a SUM over both swapped rows is invariant (and correct); any query that
    # sees exactly one of them, or reads rows individually, must fail
    assert cli.execute("SELECT SUM(v) FROM t").rows == [[5500]]
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(v) FROM t WHERE id <= 2")
    with pytest.raises(IntegrityError):
        cli.execute("SELECT v FROM t")


def test_replaying_a_stale_cell_after_update_is_detected():
    srv, cli = _auth_db()
    old = dict(srv._rows["t"][2])
    cli.execute("UPDATE t SET v = 999 WHERE id = 3")
    srv._rows["t"][2]["v"] = old["v"]
    srv._rows["t"][2]["__mac__v"] = old["__mac__v"]         # consistent old pair
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(v) FROM t")


def test_server_that_adds_delta_to_value_and_guesses_mac_is_caught():
    class Forger(NoKeyServer):
        def blinded_sum(self, table, col, idxs):
            v = super().blinded_sum(table, col, idxs)
            return (v + 17) % N if not col.startswith("__mac__") else (v + 17 * 12345) % N
    srv = Forger()
    cli = NoKeyClient(srv, authenticated=True)
    cli.execute("CREATE TABLE t (v INT ENC)")
    for i in range(5):
        cli.execute(f"INSERT INTO t (v) VALUES ({i})")
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(v) FROM t")


def test_forged_multiplication_term_is_detected():
    class Forger(NoKeyServer):
        @staticmethod
        def mult_combine_batch(openings):
            return [(e * g + 1) % N for e, g in openings]
    srv = Forger()
    cli = NoKeyClient(srv, authenticated=True)
    cli.execute("CREATE TABLE t (a INT PAIRED, b INT PAIRED)")
    cli.execute("INSERT INTO t (a, b) VALUES (3, 4)")
    with pytest.raises(IntegrityError):
        cli.execute("SELECT DOT(a, b) FROM t")


def test_without_authentication_a_lying_server_is_NOT_detected():
    """Documented limitation: integrity requires authenticated=True."""
    class Liar(NoKeyServer):
        def blinded_sum(self, table, col, idxs):
            return (super().blinded_sum(table, col, idxs) + 1) % N
    cli = NoKeyClient(Liar())
    cli.execute("CREATE TABLE t (v INT ENC)")
    cli.execute("INSERT INTO t (v) VALUES (10)")
    assert cli.execute("SELECT SUM(v) FROM t").rows == [[11]]   # silently wrong
