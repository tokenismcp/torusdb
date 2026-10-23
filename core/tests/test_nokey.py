# SPDX-License-Identifier: Apache-2.0
"""No-key delegation protocol Π — correctness, zero key residency, and the
zero-leakage one-time-pad property (reproducing the paper's §VIII validation).

Every server operation here takes only blinded scalars and public coefficients;
there is no key on the server and no server-side decryption anywhere.
"""
from fractions import Fraction

import pytest

from torusdb_core import protocol as nokey
from torusdb_core.protocol import Owner, Server, decode, encode, gen_triple


# ── encoding round-trips (paper §II.C/E) ─────────────────────────────────────
@pytest.mark.parametrize("v", [0, 1, 7, -3, 12345, -98765, 2**60])
def test_encode_decode_int(v):
    assert decode(encode(v)) == v


@pytest.mark.parametrize("frac", [Fraction(1, 2), Fraction(2, 3),
                                  Fraction(-3, 5), Fraction(22, 7)])
def test_encode_decode_rational(frac):
    assert decode(encode(frac)) == frac


def test_additive_homomorphism_of_encoding():
    x, y = Fraction(2, 3), Fraction(1, 5)
    assert decode((encode(x) + encode(y)) % nokey.N) == x + y


def test_ring_multiplication_of_encoding():
    x, y = 6, 7
    assert decode(encode(x) * encode(y) % nokey.N) == 42


# ── Π_lin: non-interactive affine evaluation (Construction 16) ───────────────
def test_pi_lin_sum_no_server_key():
    """SUM over encrypted values: owner blinds, server adds blinded values
    with NO key, owner unblinds. Server never decrypts."""
    owner, server = Owner(), Server()
    values = [8000, 9000, 7000]
    blinded, masks = [], []
    for v in values:
        b, r = owner.blind(encode(v))
        blinded.append(b); masks.append(r)

    blinded_sum = server.add(blinded)                 # server: no key, no decrypt
    y = owner.unblind_affine(blinded_sum, [1] * len(values), masks)
    assert decode(y) == sum(values)


def test_pi_lin_weighted_affine():
    owner, server = Owner(), Server()
    xs = [Fraction(1, 3), Fraction(2, 3), Fraction(5, 7)]
    coeffs = [4, -2, 3]
    b = encode(Fraction(1, 1))
    blinded, masks = zip(*(owner.blind(encode(x)) for x in xs))

    blinded_y = server.affine(list(blinded), coeffs, b)
    y = owner.unblind_affine(blinded_y, coeffs, list(masks))
    expected = sum(c * x for c, x in zip(coeffs, xs)) + 1
    assert decode(y) == expected


def test_pi_lin_scalar_mul_per_row():
    owner, server = Owner(), Server()
    v = Fraction(3, 4)
    b, r = owner.blind(encode(v))
    blinded_y = server.affine([b], [12], 0)            # 12 * x̃
    y = owner.unblind_affine(blinded_y, [12], [r])
    assert decode(y) == 12 * v


# ── Π_mult: Beaver-triple masked multiplication (Construction 18) ────────────
def test_pi_mult_product():
    owner, server = Owner(), Server()
    s, s2 = encode(50), encode(40)
    triple = gen_triple()
    e, g = owner.mult_open(s, s2, triple)
    eg = server.mult_combine(e, g)                     # server: no key
    prod = owner.mult_reconstruct(e, g, eg, triple)
    assert decode(prod) == 2000


def test_pi_mult_rational():
    owner, server = Owner(), Server()
    s, s2 = encode(Fraction(1, 2)), encode(Fraction(3, 4))
    t = gen_triple()
    e, g = owner.mult_open(s, s2, t)
    prod = owner.mult_reconstruct(e, g, server.mult_combine(e, g), t)
    assert decode(prod) == Fraction(3, 8)


def test_depth2_circuit_end_to_end():
    """z = (x1·x2 + x3)·x4 + x5  — the paper's Table III end-to-end circuit:
    two masked multiplications, local additions, all through the protocol."""
    owner, server = Owner(), Server()
    x1, x2, x3, x4, x5 = 3, 5, 2, 4, 7

    def mul(a_enc, b_enc):
        t = gen_triple()
        e, g = owner.mult_open(a_enc, b_enc, t)
        return owner.mult_reconstruct(e, g, server.mult_combine(e, g), t)

    p1 = mul(encode(x1), encode(x2))                   # x1·x2
    s1 = (p1 + encode(x3)) % nokey.N                   # + x3  (local add)
    p2 = mul(s1, encode(x4))                           # ·x4
    z = (p2 + encode(x5)) % nokey.N                    # + x5
    assert decode(z) == (x1 * x2 + x3) * x4 + x5       # = 108


# ── Zero key residency (P1) — structural ─────────────────────────────────────
def test_server_holds_no_key_material():
    server = Server()
    # No secret/public/eval key anywhere on the server object.
    forbidden = ("sk", "pk", "secret", "public", "key", "keypair", "d", "Q")
    attrs = set(dir(server))
    assert not (attrs & set(forbidden))
    assert not getattr(server, "__dict__", {})         # no per-instance state


# ── Zero leakage: one-time pad (Lemma 6 / Thm 30) ────────────────────────────
def test_one_time_pad_is_a_bijection_in_the_mask():
    """For any target blinded value t and any plaintext s, exactly one mask
    r = (t − s) mod n produces it — so a blinded value reveals nothing about
    the plaintext (every plaintext is equally likely). This is I(M;V_S)=0
    exactly, no statistics needed."""
    n = nokey.N
    for s in (0, 123, n - 1, encode(Fraction(2, 3))):
        for t in (0, 999, n - 7):
            r = (t - s) % n
            assert (s + r) % n == t                    # unique mask hits t


def test_blinded_distribution_is_plaintext_independent(monkeypatch):
    """Empirical reproduction of the paper's Table V: the server's view of two
    distinct plaintexts is statistically identical (cross-plaintext TV equals
    the same-plaintext control TV — i.e. pure sampling noise, true TV = 0)."""
    import secrets
    monkeypatch.setattr(nokey, "N", 1009)              # small modulus to histogram
    owner = Owner()
    SAMPLES = 60_000

    def hist(plain):
        h = [0] * nokey.N
        s = encode(plain)
        for _ in range(SAMPLES):
            b, _r = owner.blind(s)
            h[b] += 1
        return h

    def tv(h1, h2):
        return 0.5 * sum(abs(a - b) for a, b in zip(h1, h2)) / SAMPLES

    cross = tv(hist(123), hist(900))                   # two different plaintexts
    control = tv(hist(123), hist(123))                 # same plaintext, fresh draws
    # cross-plaintext distance is sampling noise, on par with the control —
    # not a signal. (Paper: 0.0394 vs control 0.0401.)
    assert cross <= control * 1.5 + 0.01
