# SPDX-License-Identifier: Apache-2.0
"""FHE columns under THRESHOLD custody: the secret ``s`` exists only as k-of-n custodian shares."""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from fractions import Fraction
from pathlib import Path

import pytest

import torussql
from torusdb_core import fhe
from torusdb_core.fhe import FheError
from torusdb_core.fhe_threshold import ThresholdFheKey, bundle_fingerprint
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torusdb_core.errors import IntegrityError as CoreIntegrity
from torussql.custody import (InsufficientPartials, LocalCustodian, Quorum, QuorumError,
                              laurent, run_local_ceremony)
from torussql.custody import gt as cgt
from torussql.custody.group import InvalidPoint
from torussql.custody import get_group as get_group_
from torussql.custody.net import Custodian, CustodianServer, LocalNode, RemoteCustodian
from test_ops import Running

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "owner-token-0123456789abc"
RANGE = 50_000
HAVE_MCL = "mcl" in fhe.available_backends()
ROWS = [(1, 5, 40, 160), (2, 5, 55, 150), (3, 7, 30, 120), (4, 5, 20, 100)]
SCHEMA = "CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE, hours INT FHE)"
DOT_ALL = sum(r[2] * r[3] for r in ROWS)


# ── fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def keyset():
    return run_local_ceremony(3, 5, "bn254")


def local_nodes(shares, rate=100_000, approve=None, cls=LocalNode, **kw):
    return [cls(Custodian(s, {"local": TOKEN}, rate_per_minute=rate, approve=approve),
                label=f"c{s.index}", **kw) for s in shares]


@pytest.fixture(scope="module")
def keyset2():
    """The INDEPENDENT second secret s2: a DKG IN THE GROUP G2 (public key = Q2 in G2; no G1 image)."""
    return run_local_ceremony(3, 5, "bn254g2")


def mk(keyset, keyset2, *, Q2=None, nodes=None, nodes2=None, **kw):
    """ThresholdFheKey over in-process custodians (override either quorum for a test)."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    return ThresholdFheKey(pub, local_nodes(shares) if nodes is None else nodes, pub2,
                           local_nodes(shares2) if nodes2 is None else nodes2, Q2=Q2, **kw)


@pytest.fixture(scope="module")
def tkey(keyset, keyset2):
    """A threshold key whose two quorums are five in-process custodians each (full dispatch path)."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    return ThresholdFheKey.create(pub, local_nodes(shares), pub2, local_nodes(shares2),
                                  value_range=RANGE)


class Net:
    """n custodian daemons (threads) on loopback."""

    def __init__(self, shares, tmp_path, rate=100_000, approve=None):
        self.servers, self.custodians, self.ports = [], [], []
        for s in shares:
            c = Custodian(s, {"owner": TOKEN}, rate_per_minute=rate, approve=approve,
                          audit_path=str(tmp_path / f"audit{s.index}.log"))
            srv = CustodianServer("127.0.0.1", 0, c)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv); self.custodians.append(c); self.ports.append(srv.address[1])
        self.g = shares[0].public.g

    def remotes(self, idx=None):
        return [RemoteCustodian("127.0.0.1", self.ports[i], TOKEN, group=self.g)
                for i in (range(len(self.ports)) if idx is None else idx)]

    def kill(self, i):
        self.servers[i].shutdown(); self.servers[i].server_close()

    def stop(self):
        for s in self.servers:
            try:
                s.shutdown(); s.server_close()
            except Exception:                                            # noqa: BLE001
                pass


@pytest.fixture
def net(keyset, tmp_path):
    n = Net(keyset[0], tmp_path)
    yield n
    n.stop()


@pytest.fixture
def net2(keyset2, tmp_path):
    (tmp_path / "k2").mkdir()
    n = Net(keyset2[0], tmp_path / "k2")
    yield n
    n.stop()


def seed(c):
    c.execute(SCHEMA)
    for i, d, r, h in ROWS:
        c.execute(f"INSERT INTO emp (id, dept, rate, hours) VALUES ({i}, {d}, {r}, {h})")


def run_sql_suite(c, authenticated=False):
    """The same statements, compared against known answers."""
    seed(c)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    assert c.execute("SELECT SUM(rate), COUNT(*) FROM emp WHERE dept = 5").rows == [[115, 3]]
    assert c.execute("SELECT AVG(rate) FROM emp WHERE dept = 5").rows[0][0] == Fraction(115, 3)
    assert c.execute("SELECT 3 * SUM(rate) FROM emp").rows == [[435]]
    assert c.execute("SELECT -2 * SUM(hours) FROM emp WHERE dept = 5").rows == [[-820]]
    assert c.execute("SELECT id, rate FROM emp WHERE id = 3").rows == [[3, 30]]
    assert c.execute("SELECT id, rate, hours FROM emp").rows == [[i, r, h] for i, _d, r, h in ROWS]
    c.execute("UPDATE emp SET rate = 60 WHERE id = 1")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[60 + 55 + 30 + 20]]
    c.execute("DELETE FROM emp WHERE id = 4")
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    # authenticated: DOT is computed and verified locally (fhe_dot_mode="auto"); otherwise the
    # server's ★_ct product is decrypted through the quorum
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[60 * 160 + 55 * 150 + 30 * 120]]
    assert c.execute("SELECT DOT(rate, hours) FROM emp WHERE dept = 5").rows == [[60 * 160 + 55 * 150]]


# ── equality with the non-threshold key ──────────────────────────────────────
def test_results_equal_the_plain_key_in_memory(tkey):
    """Same statements on a plain FheKey and on the threshold key give identical results."""
    plain = fhe.FheKey(value_range=RANGE)
    out = []
    for key in (plain, tkey):
        c = NoKeyClient(NoKeyServer(), fhe=key)
        seed(c)
        out.append([c.execute(q).rows for q in (
            "SELECT SUM(rate), SUM(hours) FROM emp", "SELECT AVG(hours) FROM emp",
            "SELECT 7 * SUM(rate) FROM emp WHERE dept = 5", "SELECT id, rate FROM emp",
            "SELECT DOT(rate, hours) FROM emp", "SELECT DOT(rate, hours) FROM emp WHERE id = 2")])
    assert out[0] == out[1]
    assert out[1][4] == [[DOT_ALL]]


def test_cross_ciphertexts_between_plain_and_threshold_keys_cannot_mix(keyset, tkey):
    """Different secrets: a plain key cannot decrypt the threshold key's cells (and v.v.)."""
    plain = fhe.FheKey(value_range=RANGE)
    cell = tkey.encrypt(12)
    with pytest.raises(FheError, match="outside"):
        plain.decrypt_cell(cell)
    assert tkey.decrypt_cell(cell) == 12


def test_encrypt_decrypt_primitives(tkey):
    vals = [0, 1, -1, 49_999, -50_000, 123]
    cells = [tkey.encrypt(v) for v in vals]
    assert tkey.decrypt_cells(cells) == vals
    assert [tkey.decrypt_cell(c) for c in cells[:2]] == vals[:2]
    assert tkey.decrypt_sum(fhe.sum_cells(cells, tkey.be)) == sum(vals)
    assert tkey.decrypt_sum(fhe.sum_cells(cells, tkey.be, scale=-3)) == -3 * sum(vals)
    with pytest.raises(FheError):
        tkey.encrypt(RANGE + 1)
    with pytest.raises(FheError, match="outside"):
        tkey.decrypt_sum(fhe.sum_cells([tkey.encrypt(RANGE)] * 2, tkey.be))
    # plain-key cells made with the same PUBLIC key decrypt too (public-key encryption)
    assert tkey.decrypt_sum(fhe.sum_cells([cells[3], cells[1]], tkey.be)) == vals[3] + vals[1]   # 50000: exactly in range


def test_dot_matches_plain_and_signs(tkey):
    a, b = [3, -4, 5, 0], [10, 20, -6, 99]
    ca, cb = [tkey.encrypt(v) for v in a], [tkey.encrypt(v) for v in b]
    assert tkey.decrypt_dot(fhe.dot_cells(ca, cb, tkey.be)) == sum(x * y for x, y in zip(a, b))
    assert tkey.decrypt_dot(fhe.dot_cells([], [], tkey.be)) == 0


# ── s is never reassembled, never held ───────────────────────────────────────
def test_the_secret_is_never_reassembled_by_any_operation(keyset, keyset2, monkeypatch):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)   # for the checks below
    x2 = laurent.reconstruct([(s.index, s.y) for s in shares2[:3]], pub.g.order)
    boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("key reassembled!"))
    monkeypatch.setattr(laurent, "reconstruct", boom)
    monkeypatch.setattr(laurent, "robust_reconstruct", boom)
    key = ThresholdFheKey.create(pub, local_nodes(shares[1:4]), pub2, local_nodes(shares2[2:5]),
                                 value_range=RANGE)
    assert key.decrypt_cells([key.encrypt(5)]) == [5]
    assert key.decrypt_dot(fhe.dot_cells([key.encrypt(6)], [key.encrypt(7)], key.be)) == 42
    c = NoKeyClient(NoKeyServer(), fhe=key, authenticated=True)
    seed(c)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    # nothing the owner process holds is, or is derived from, the secret exponent
    forbidden = {x, pub.g.order - x, x2, pub.g.order - x2, x * x2 % pub.g.order}
    seen = []

    def walk(o, depth=0):
        if depth > 4 or id(o) in {id(s) for s in seen}:
            return
        seen.append(o)
        if isinstance(o, int) and o in forbidden:
            raise AssertionError("the key's secret is held in memory")
        if isinstance(o, (bytes, bytearray)) and any(int(v).to_bytes(32, "big") in o for v in (x, x2)):
            raise AssertionError("the key's secret is held in memory")
        if isinstance(o, dict):
            for v in o.values():
                walk(v, depth + 1)
        elif isinstance(o, (list, tuple, set)):
            for v in o:
                walk(v, depth + 1)
        elif hasattr(o, "__dict__") and not isinstance(o, type):
            for k, v in vars(o).items():
                if k not in ("share", "_share"):      # custodians (the shares live THERE) are other processes
                    walk(v, depth + 1)
    walk(key.__dict__)
    for attr in ("_s", "_s2", "secret_bytes"):
        assert not hasattr(key, attr)
    assert "secret" not in repr(key)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(key)
    # the public bundle holds no secret
    blob = json.dumps(key.bundle())
    assert all(format(v, "064x") not in blob for v in (x, x2))


# ── below quorum / failing and lying custodians ──────────────────────────────
def test_below_quorum_cannot_decrypt(keyset, keyset2, tkey):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    weak = mk(keyset, keyset2, Q2=tkey._q2_raw, nodes=local_nodes(shares[:2]), value_range=RANGE)
    cell = tkey.encrypt(5)
    with pytest.raises(InsufficientPartials):
        weak.decrypt_cell(cell)
    with pytest.raises(InsufficientPartials):
        weak.decrypt_dot(fhe.dot_cells([cell], [cell], weak.be))
    # a quorum on s but only 2 of the 3 needed for s2: cells work, DOT does not
    weak2 = mk(keyset, keyset2, Q2=tkey._q2_raw, nodes2=local_nodes(shares2[:2]), value_range=RANGE)
    assert weak2.decrypt_cell(cell) == 5
    with pytest.raises(InsufficientPartials):
        weak2.decrypt_dot(fhe.dot_cells([cell], [cell], weak2.be))
    # Q2 is a public key (needs no quorum); the MAC secret does need one (below)
    assert mk(keyset, keyset2, nodes2=local_nodes(shares2[:2]), value_range=RANGE)._q2_raw == tkey._q2_raw
    weak_mac = mk(keyset, keyset2, Q2=tkey._q2_raw, nodes=local_nodes(shares[:2]),
                  mac=tkey.bundle()["mac"], value_range=RANGE)
    with pytest.raises(InsufficientPartials):
        weak_mac.alpha
    # the minimum quorum works, whichever k custodians answer (independently for s and s2)
    for sel, sel2 in (([0, 1, 2], [2, 3, 4]), ([2, 3, 4], [0, 1, 2]), ([0, 2, 4], [1, 3, 4])):
        k3 = mk(keyset, keyset2, Q2=tkey._q2_raw, nodes=local_nodes([shares[i] for i in sel]),
                nodes2=local_nodes([shares2[i] for i in sel2]), value_range=RANGE)
        assert k3.decrypt_cell(cell) == 5
        assert k3.decrypt_dot(fhe.dot_cells([cell], [tkey.encrypt(9)], k3.be)) == 45


def test_dot_is_impossible_without_the_second_secret(keyset, keyset2, tkey):
    """No quorum for s2 (only the public bundle's Q2): encryption and cell/SUM reads work, DOT fails."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    key = ThresholdFheKey(pub, local_nodes(shares), pub2, None, Q2=tkey._q2_raw, value_range=RANGE)
    cell = key.encrypt(11)
    assert key.decrypt_cell(cell) == 11
    with pytest.raises(FheError, match="second secret"):
        key.decrypt_dot(fhe.dot_cells([cell], [cell], key.be))
    assert ThresholdFheKey(pub, local_nodes(shares), pub2, None).Q2 is not None     # Q2 = pub2.X
    # using the SAME key for both secrets is refused (key 2 must be a bn254g2 key)
    with pytest.raises(FheError, match="bn254g2"):
        ThresholdFheKey(pub, local_nodes(shares), pub, local_nodes(shares), Q2=tkey._q2_raw)


class Liar(LocalNode):
    """A custodian that answers with plausible-looking but wrong values."""
    mode = "d"

    def partial_batch(self, Es, context=b""):
        parts = super().partial_batch(Es, context)
        g = self.g
        if self.mode == "d":
            return [type(p)(p.index, g.add(p.D, g.G), p.proof) for p in parts]        # wrong D
        if self.mode == "z":
            return [type(p)(p.index, p.D, type(p.proof)(p.proof.R1, p.proof.R2, (p.proof.z + 1) % fhe.N))
                    for p in parts]                                                   # broken proof
        if self.mode == "index":
            return [type(p)(p.index % 5 + 1, p.D, p.proof) for p in parts]            # claims to be another
        if self.mode == "other-share":
            other = super().partial_batch([g.add(E, g.G) for E in Es], context)       # valid, wrong E
            return [type(p)(p.index, p.D, q.proof) for p, q in zip(parts, other)]
        return parts

    def gt_partial_batch(self, cs, context=b""):
        parts = super().gt_partial_batch(cs, context)
        out = []
        for p in parts:
            if self.mode == "d":                      # D multiplied by the GT generator-ish element
                bad = cgt.gt_encode(cgt.gt_decode(p.D) * cgt.gt_decode(cs[0]))
                out.append(type(p)(p.index, bad, p.proof))
            elif self.mode == "z":
                pr = p.proof
                out.append(type(p)(p.index, p.D, type(pr)(pr.R1, pr.R2, (pr.z + 1) % fhe.N)))
            else:                                     # cannot-be-forged index swap
                out.append(type(p)(p.index % 5 + 1, p.D, p.proof))
        return out


class Slow(LocalNode):
    """An honest custodian that answers a little later, so a liar is examined first."""

    def partial_batch(self, *a, **k):
        time.sleep(0.3)
        return super().partial_batch(*a, **k)

    def gt_partial_batch(self, *a, **k):
        time.sleep(0.3)
        return super().gt_partial_batch(*a, **k)


@pytest.mark.parametrize("mode", ["d", "z", "index", "other-share"])
def test_a_lying_custodian_is_detected_and_excluded(keyset, keyset2, tkey, mode):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    nodes = local_nodes(shares, cls=Slow)
    nodes[0] = Liar(nodes[0].custodian, label="liar")
    nodes[0].mode = mode
    nodes2 = local_nodes(shares2, cls=Slow)
    nodes2[0] = Liar(nodes2[0].custodian, label="liar")          # a liar in the s2 quorum too
    nodes2[0].mode = mode
    key = mk(keyset, keyset2, nodes=nodes, nodes2=nodes2, Q2=tkey._q2_raw, value_range=RANGE)
    cell = tkey.encrypt(77)
    assert key.decrypt_cell(cell) == 77                              # liar excluded, answer right
    assert "liar" in key.quorum.last_problems
    if mode != "other-share":
        a, b = tkey.encrypt(6), tkey.encrypt(7)
        assert key.decrypt_dot(fhe.dot_cells([a], [b], key.be)) == 42
        assert "liar" in key.quorum.last_problems and "liar" in key.quorum2.last_problems


def test_liars_beyond_the_threshold_fail_closed_never_wrong(keyset, keyset2, tkey):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    # 3 of 5 custodians lie: only 2 honest remain (< k=3). Must raise, not return garbage.
    nodes = local_nodes(shares)
    for i in (0, 1, 2):
        nodes[i] = Liar(nodes[i].custodian, label=f"liar{i}")
    key = mk(keyset, keyset2, nodes=nodes, Q2=tkey._q2_raw, value_range=RANGE)
    with pytest.raises(InsufficientPartials) as ei:
        key.decrypt_cell(tkey.encrypt(5))
    assert "liar0" in str(ei.value)
    with pytest.raises(InsufficientPartials):
        key.decrypt_dot(fhe.dot_cells([tkey.encrypt(2)], [tkey.encrypt(3)], key.be))
    # the same for liars in the s2 quorum: DOT fails closed, cells (s only) are fine
    nodes2 = local_nodes(shares2)
    for i in (0, 1, 2):
        nodes2[i] = Liar(nodes2[i].custodian, label=f"liar{i}")
    key2 = mk(keyset, keyset2, nodes2=nodes2, Q2=tkey._q2_raw, value_range=RANGE)
    assert key2.decrypt_cell(tkey.encrypt(5)) == 5
    with pytest.raises(InsufficientPartials):
        key2.decrypt_dot(fhe.dot_cells([tkey.encrypt(2)], [tkey.encrypt(3)], key2.be))


def test_q2_equal_to_s_times_g2_is_refused(keyset, keyset2, tkey):
    """Q2 = s·G2 gives a dictionary oracle e(G2, C2 - v·G1) == e(Q2, C1): refused in every form."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    from py_ecc.optimized_bn128 import G2, multiply
    from torussql.custody import PublicKey
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)   # test-only
    bad = cgt.g2_encode(multiply(G2, x))
    # (1) a Q2 argument / bundle field that is not key 2's public key
    with pytest.raises(FheError, match="does not match"):
        mk(keyset, keyset2, Q2=bad)
    b = tkey.bundle(); b["Q2"] = bad.hex()
    with pytest.raises(FheError, match="does not match"):
        ThresholdFheKey.from_bundle(b, pub, local_nodes(shares), pub2, local_nodes(shares2),
                                    expect_fingerprint=None)
    # (2) a key 2 whose public key IS s·G2 (a bn254g2 key built from the same secret)
    twin = PublicKey("bn254g2", 2, 3, (cgt.g2_decode(cgt.g2_encode(G2)), cgt.g2_decode(bad)), 0)
    with pytest.raises(FheError, match="Q2 equals s"):
        ThresholdFheKey(pub, local_nodes(shares), twin, None)
    # (3) the second key must live in G2 and differ from the first
    with pytest.raises(FheError, match="bn254g2"):
        ThresholdFheKey(pub, local_nodes(shares), pub, local_nodes(shares))
    other1 = run_local_ceremony(2, 3, "bn254")[1]
    with pytest.raises(FheError, match="bn254g2"):
        ThresholdFheKey(pub, local_nodes(shares), other1, None)


def test_q2_is_verified_against_the_public_key(keyset, keyset2, tkey):
    from py_ecc.optimized_bn128 import G2, multiply
    good = cgt.g2_decode(tkey._q2_raw)
    for bad in (cgt.g2_encode(multiply(G2, 5)), cgt.g2_encode(multiply(good, 2)), bytes(128),
                tkey._q2_raw[:-1] + bytes([tkey._q2_raw[-1] ^ 1]), b"short"):
        with pytest.raises(FheError, match="does not match"):
            mk(keyset, keyset2, Q2=bad)
    assert tkey._q2_raw == keyset2[1].g.encode(keyset2[1].X) and len(tkey._q2_raw) == 128


def _recover_with_g1_key(cells, X_g1_bytes, values):
    """The red-team attack (PoC 1): with a G1 point X = s2·G1 the plaintext of every cell is
    e(G1, D2) / e(X, D1) = g^v. Returns the recovered values (None where the guess table misses)."""
    from py_ecc.optimized_bn128 import G1, G2, FQ12, final_exponentiate, neg, pairing
    from torusdb_core import fhe_backend as fb
    be = fb.get("pyecc")
    X = be.g1_from(X_g1_bytes)
    gen = pairing(G2, G1)
    tab = {be.gt_to(gen ** (v % fb.N)): v for v in values}
    out = []
    for cell in cells:
        _c1, _c2, d1, d2 = fhe.parse_cell(cell, "pyecc")
        m = pairing(d2, G1, final_exponentiate=False) * pairing(d1, neg(X), final_exponentiate=False)
        out.append(tab.get(be.gt_to(final_exponentiate(m))))
    return out


def test_redteam_poc1_public_files_never_contain_a_g1_image_of_s2(keyset, keyset2, tkey):
    """The second secret s2 lives in G2. Nothing public (bundle, public2.json, RPC answers, audit log
    fields) contains s2·G1 or any other G1 point related to it; with such a point (positive control)
    every cell would decrypt."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    vals = [7, -42, 0]
    cells = [tkey.encrypt(v) for v in vals]
    guesses = range(-60, 61)
    # --- positive control: the OLD design's X2 = s2·G1 recovers everything -------------------------
    x2 = laurent.reconstruct([(s.index, s.y) for s in shares2[:3]], pub2.g.order)      # test-only
    from py_ecc.optimized_bn128 import G1, multiply
    from torusdb_core import fhe_backend as fb
    be = fb.get("pyecc")
    old_x2 = be.g1_to(multiply(G1, x2))
    assert _recover_with_g1_key(cells, old_x2, guesses) == vals                          # the attack works on it
    # --- every public G1 point available to an attacker is useless ---------------------------------
    for pt in (pub.g.encode(pub.X), pub.g.encode(pub.g.G)):                               # Q = s·G1, G1 itself
        assert _recover_with_g1_key(cells, pt, guesses) == [None] * len(vals)
    # --- structural: scan EVERYTHING public for G1-sized (64-byte) values -------------------------
    def hex_strings(o):
        if isinstance(o, str):
            yield o
        elif isinstance(o, dict):
            for v in o.values():
                yield from hex_strings(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                yield from hex_strings(v)

    def g1_like(h):
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            return False
        return len(raw) == 64

    pub2_json, bundle = pub2.to_json(), tkey.bundle()
    assert pub2_json["group"] == "bn254g2" and len(pub2_json["commitments"]) == pub2.k
    assert all(len(bytes.fromhex(c)) == 128 for c in pub2_json["commitments"])     # only G2 points
    assert len(bytes.fromhex(pub2_json["public_key"])) == 128
    assert not [h for h in hex_strings(pub2_json) if g1_like(h)]                    # no G1 point at all
    assert bundle["Q2"] == pub2_json["public_key"] and "X2" not in bundle
    assert [h for h in hex_strings({k: v for k, v in bundle.items() if k != "mac"}) if g1_like(h)] == \
        [bundle["Q"]]                                                                  # only key 1's Q
    assert bundle["Q"] == pub.g.hex(pub.X)
    for sh in shares2:                                                                  # share files: same
        assert not [h for h in hex_strings(sh.to_json()["public"]) if g1_like(h)]
    # --- the traffic of every key-2 operation contains no G1 point ---------------------------------
    seen = []

    class Rec(LocalNode):
        def call(self, method, args):
            out = super().call(method, args)
            seen.append((method, out))
            return out

    key = mk(keyset, keyset2, nodes2=local_nodes(shares2, cls=Rec), Q2=tkey._q2_raw, value_range=RANGE)
    assert key.decrypt_dot(fhe.dot_cells([key.encrypt(3)], [key.encrypt(5)], key.be)) == 15
    assert seen and all(m == "gt_partial_batch" for m, _ in seen)
    for _m, out in seen:
        assert not [h for h in hex_strings(out) if g1_like(h)]                         # D, R1 (G2), R2 (GT), z
    # --- the G1-style RPCs and the G2-share RPC do not exist for key 2 ----------------------------
    node = local_nodes(shares2[:1])[0].for_key(pub2)
    with pytest.raises(QuorumError, match="GT exponentiation only"):
        node.call("partial", [pub.g.hex(pub.g.G), "", pub2.key_id])
    with pytest.raises(QuorumError, match="unknown method"):
        node.call("g2_partial", [])


def test_second_key_group_roundtrip_and_validation(keyset2):
    """The bn254g2 custody group: 128-byte points, subgroup-checked, usable by the generic DKG."""
    shares2, pub2, _ = keyset2
    g = get_group_("bn254g2")
    assert all(s.verify() for s in shares2)
    assert g.decode(g.encode(pub2.X)) is not None and len(g.encode(g.G)) == 128
    raw = bytearray(g.encode(g.G)); raw[-1] ^= 1
    with pytest.raises(InvalidPoint):
        g.decode(bytes(raw))                                       # off the twist
    with pytest.raises(InvalidPoint):
        g.decode(b"\x01" * 64)                                     # wrong length (a G1 point)
    PK = pub2.__class__
    assert PK.from_json(pub2.to_json()).fingerprint == pub2.fingerprint


# ── GT proofs (unit level) ───────────────────────────────────────────────────
def test_gt_partial_proofs_are_sound(keyset):
    shares, pub, _ = keyset
    from py_ecc.optimized_bn128 import FQ12, G1, G2, pairing
    c = cgt.gt_encode(pairing(G2, G1) ** 123456789)
    other = cgt.gt_encode(pairing(G2, G1) ** 987654321)
    part = cgt.gt_partial(shares[0], [c], b"ctx")[0]
    assert cgt.verify_gt_partial(pub, c, part, b"ctx")
    assert cgt.gt_decode(part.D) == cgt.gt_decode(c) ** shares[0].y
    assert not cgt.verify_gt_partial(pub, c, part, b"other-ctx")          # context bound
    assert not cgt.verify_gt_partial(pub, other, part, b"ctx")           # statement bound
    forged = cgt.GtPartial(part.index, cgt.gt_encode(cgt.gt_decode(part.D) * cgt.gt_decode(c)),
                           part.proof)
    assert not cgt.verify_gt_partial(pub, c, forged, b"ctx")
    wrong_index = cgt.GtPartial(2, part.D, part.proof)
    assert not cgt.verify_gt_partial(pub, c, wrong_index, b"ctx")
    # a D outside the order-q subgroup is refused even with an otherwise consistent transcript
    twisted = cgt.GtPartial(part.index, cgt.gt_encode(FQ12([2] + [0] * 11)), part.proof)
    assert not cgt.verify_gt_partial(pub, c, twisted, b"ctx")
    # combining k verified partials gives c^x without x; fewer than k do not
    parts = {s.index: cgt.gt_partial(s, [c], b"")[0] for s in shares[:3]}
    got = cgt.combine_gt(pub, {i: p.D for i, p in parts.items()})
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)
    assert cgt.gt_decode(got) == cgt.gt_decode(c) ** x
    with pytest.raises(Exception):
        cgt.combine_gt(pub, {i: p.D for i, p in list(parts.items())[:2]})


def test_custodians_refuse_gt_elements_outside_the_subgroup(keyset, keyset2):
    """Small-subgroup / foreign-element defence: c must satisfy c^q = 1."""
    shares, pub, _ = keyset
    from py_ecc.optimized_bn128 import FQ12
    node = local_nodes(shares[:1])[0]
    junk = cgt.gt_encode(FQ12([3, 1] + [0] * 10))
    for bad in (junk, bytes(384), b"\xff" * 384, b"\x00" * 383):
        with pytest.raises(QuorumError, match="malformed"):
            node.gt_partial_batch([bad], b"")
    with pytest.raises(QuorumError, match="malformed"):
        node.call("gt_partial_batch", [["zz"], ""])
    with pytest.raises(QuorumError, match="malformed"):
        node.call("gt_partial_batch", [[], ""])
    with pytest.raises(QuorumError, match="batch too large"):
        node.call("gt_partial_batch", [["00"] * (cgt.MAX_GT_BATCH + 1), ""])
    # and the owner side refuses to even ask for them
    key = mk(keyset, keyset2)
    blob = b"\x01" + junk + junk + junk + junk
    with pytest.raises(FheError):
        key.decrypt_dot(blob)


# ── custodian policy: validation, canonicalisation, approve, rate limits ──────
def test_custodian_validates_points_and_enforces_policy_and_rate(keyset, tmp_path):
    shares, pub, _ = keyset
    g = pub.g
    seen = []
    state = {"deny": False}

    def approve(caller, E_hex, ctx):
        seen.append((caller, E_hex))
        return not state["deny"]

    cust = Custodian(shares[0], {"owner": TOKEN}, rate_per_minute=100, approve=approve,
                     item_budget_per_minute=1000, max_batch=50, audit_path=str(tmp_path / "a.log"))
    node = LocalNode(cust, caller="owner", label="c1")
    E = g.mul(g.G, 777)
    # canonical, validated: junk / off-curve / identity / non-canonical are all refused
    for bad in ("00" * 63 + "01", "zz", "", g.hex(g.identity), g.hex(E)[:-2],
                format(g.order, "064x") * 2, 12345):
        with pytest.raises(QuorumError, match="malformed"):
            node.call("partial_batch", [[bad], ""])
    with pytest.raises(QuorumError, match="malformed"):
        node.call("partial_batch", [[], ""])
    cust._hits.clear()
    # approve sees the CANONICAL encoding of every item, upper-case or not
    parts = node.call("partial_batch", [[g.hex(E).upper(), g.hex(E)], ""])
    assert len(parts) == 2
    assert [h for _c, h in seen[-2:]] == [g.hex(E), g.hex(E)] and seen[-1][0] == "owner"
    # GT items go through the same hook, tagged
    from py_ecc.optimized_bn128 import G1, G2, pairing
    craw = cgt.gt_encode(pairing(G2, G1) ** 5)
    node.gt_partial_batch([craw], b"")
    assert seen[-1] == ("owner", "gt:" + craw.hex())
    # a batch is ONE request for the request limit, but its items are charged to the item
    # budget; both limits give clear errors
    cust._hits.clear(); cust._items.clear()
    cust._item_cap = 6
    with pytest.raises(QuorumError, match="item budget exceeded"):
        node.call("partial_batch", [[g.hex(E)] * 7, ""])
    cust._hits.clear(); cust._items.clear()
    node.call("partial_batch", [[g.hex(E)] * 6, ""])
    with pytest.raises(QuorumError, match="item budget exceeded"):
        node.call("partial_batch", [[g.hex(E)], ""])
    with pytest.raises(QuorumError, match="item budget exceeded"):
        node.gt_partial_batch([craw], b"")
    cust._hits.clear(); cust._items.clear()
    cust._rate = 2                                            # the per-request limit is kept
    node.call("partial_batch", [[g.hex(E)], ""]); node.call("partial_batch", [[g.hex(E)], ""])
    with pytest.raises(QuorumError, match="rate limit exceeded"):
        node.call("partial_batch", [[g.hex(E)], ""])
    cust._hits.clear(); cust._items.clear()
    cust._rate, cust._item_cap = 100, 1000
    with pytest.raises(QuorumError, match="batch too large"):
        node.call("partial_batch", [[g.hex(E)] * 51, ""])
    # policy denial applies to the whole batch, before anything is computed
    state["deny"] = True
    with pytest.raises(QuorumError, match="policy"):
        node.call("partial_batch", [[g.hex(E), g.hex(g.mul(g.G, 5))], ""])
    with pytest.raises(QuorumError, match="policy"):
        node.gt_partial_batch([craw], b"")
    state["deny"] = False
    lines = [json.loads(l) for l in open(tmp_path / "a.log")]
    assert any("item budget" in l["outcome"] for l in lines)
    assert any(l["outcome"] == "served" for l in lines)
    assert str(shares[0].y) not in open(tmp_path / "a.log").read()
    # a caller without the 'key' permission cannot use any of the new methods
    ro = Custodian(shares[0], {"reader": TOKEN}, permissions={"reader": {"mask_read"}})
    rnode = LocalNode(ro, caller="reader")
    for m, a in (("partial_batch", [[g.hex(E)], ""]), ("gt_partial_batch", [[craw.hex()], ""])):
        with pytest.raises(QuorumError, match="lacks permission"):
            rnode.call(m, a)


def test_approve_can_refuse_threshold_fhe_requests(keyset, keyset2):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    state = {"ok": True}
    key = mk(keyset, keyset2, nodes=local_nodes(shares, approve=lambda caller, E, ctx: state["ok"]),
             nodes2=local_nodes(shares2, approve=lambda caller, E, ctx: state["ok"]))
    cell = key.encrypt(3)
    assert key.decrypt_cell(cell) == 3
    state["ok"] = False
    with pytest.raises(InsufficientPartials, match="policy"):
        key.decrypt_cell(cell)
    with pytest.raises(InsufficientPartials, match="policy"):
        key.decrypt_dot(fhe.dot_cells([cell], [cell], key.be))


# ── DOT: two sequential rounds, s·s2 is never formed ────────────────────────
def test_dot_uses_two_sequential_rounds_and_never_forms_s_times_s2(keyset, keyset2, tkey):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    calls = []

    def spy(tag):
        class Spy(LocalNode):
            def gt_partial_batch(self, cs, context=b""):
                calls.append((tag, [bytes(c) for c in cs]))
                return super().gt_partial_batch(cs, context)
        return Spy

    key = mk(keyset, keyset2, nodes=local_nodes(shares, cls=spy("s")),
             nodes2=local_nodes(shares2, cls=spy("s2")), Q2=tkey._q2_raw, value_range=RANGE)
    blob = fhe.dot_cells([key.encrypt(3)], [key.encrypt(4)], key.be)
    assert key.decrypt_dot(blob) == 12
    r1 = [c for c in calls if c[0] == "s"]
    r2 = [c for c in calls if c[0] == "s2"]
    assert r1 and r2 and len({tuple(c[1]) for c in r1}) == 1 and len({tuple(c[1]) for c in r2}) == 1
    raw = [blob[1 + i * 384:1 + (i + 1) * 384] for i in range(4)]
    c00, c01, c10, c11 = raw
    # round 1 (key s) asks for c00 and c10; round 2 (key s2) for c01 and the OUTPUT of round 1 on c00
    assert r1[0][1] == [c00, c10]
    assert r2[0][1][0] == c01 and r2[0][1][1] not in raw
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)     # test-only
    assert cgt.gt_decode(r2[0][1][1]) == cgt.gt_decode(c00) ** x                    # second-round input is c00^s


# ── bundle, MAC secret, integrity ────────────────────────────────────────────
def test_bundle_roundtrip_and_tamper_checks(keyset, keyset2, tkey, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    path = str(tmp_path / "b.json")
    tkey.save_bundle(path)
    assert (os.stat(path).st_mode & 0o777) == 0o644
    fp = tkey.bundle_fingerprint
    key2 = ThresholdFheKey.load(path, pub, local_nodes(shares), pub2, local_nodes(shares2),
                                expect_fingerprint=fp)
    assert key2.range == RANGE and key2.decrypt_cell(tkey.encrypt(9)) == 9
    assert key2.alpha == tkey.alpha and key2.gamma("t", "c", 3, 7) == tkey.gamma("t", "c", 3, 7)
    good = json.loads(open(path).read())
    assert good["v"] == 3 and set(good) == {"v", "kind", "key_id", "key_id2", "range", "Q", "Q2", "mac"}
    other_shares, other_pub, _ = run_local_ceremony(2, 3, "bn254")
    other_shares2, other_pub2, _ = run_local_ceremony(2, 3, "bn254g2")
    B = lambda b, **kw: ThresholdFheKey.from_bundle(b, pub, local_nodes(shares), pub2,
                                                     local_nodes(shares2), expect_fingerprint=fp, **kw)
    with pytest.raises(FheError, match="different custody keys"):
        ThresholdFheKey.from_bundle(good, other_pub, local_nodes(other_shares), pub2,
                                    local_nodes(shares2), expect_fingerprint=fp)
    with pytest.raises(FheError, match="different custody keys"):
        ThresholdFheKey.from_bundle(good, pub, local_nodes(shares), other_pub2,
                                    local_nodes(other_shares2), expect_fingerprint=fp)
    nf = lambda b: ThresholdFheKey.from_bundle(b, pub, local_nodes(shares), pub2, local_nodes(shares2),
                                               expect_fingerprint=bundle_fingerprint(b))
    for field, value in (("Q", pub.g.hex(pub.g.mul(pub.g.G, 3))), ("kind", "x"), ("Q2", "00" * 128),
                         ("X2", pub.g.hex(pub.g.mul(pub.g.G, 3))), ("extra", 1)):
        bad = dict(good); bad[field] = value
        with pytest.raises(FheError):
            nf(bad)
    # old bundles are rejected with explicit messages (v2 published X2 = s2·G1: total break)
    for ver, msg in ((1, "version-1.*no longer accepted"), (2, "version-2.*VULNERABLE.*regenerate")):
        old = dict(good); old["v"] = ver
        with pytest.raises(FheError, match=msg):
            nf(old)
    # a tampered sealed MAC (valid length, wrong bytes) is refused by the authenticated envelope ...
    bad = json.loads(json.dumps(good))
    s_ = bad["mac"]["sealed"]
    bad["mac"]["sealed"] = s_[:-2] + ("00" if s_[-2:] != "00" else "01")
    with pytest.raises(FheError, match="fingerprint"):
        B(bad)                                                   # ... and the pinned fingerprint catches it first
    k3 = nf(bad)
    with pytest.raises(FheError, match="tampered|damaged"):
        k3.alpha
    # a swapped envelope for another purpose is refused
    bad = json.loads(json.dumps(good)); bad["mac"]["header"]["ctx"] = "00"
    with pytest.raises(FheError, match="different purpose"):
        nf(bad).alpha


def test_bundle_fingerprint_stops_the_mac_envelope_swap_and_range_dos(keyset, keyset2, tkey, tmp_path,
                                                                      recwarn):
    """Red-team F4: an attacker who edits the public bundle replaces the MAC envelope by one wrapped to
    the PUBLIC key with a secret HE chose. With a pinned fingerprint the load is refused."""
    import copy
    from torussql import seal
    from torussql.custody import wrap_key
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    good = tkey.bundle()
    fp = tkey.bundle_fingerprint
    assert len(fp.replace("-", "")) == 64
    evil = os.urandom(32)
    ctx = b"torussql/fhe/mac-secret/v1\x00" + bytes.fromhex(pub.key_id)
    K, header = wrap_key(pub, ctx)
    tampered = copy.deepcopy(good)
    tampered["mac"] = {"header": header, "sealed": seal.seal(K, evil, aad=ctx).hex()}
    assert bundle_fingerprint(tampered) != fp
    args = (pub, local_nodes(shares), pub2, local_nodes(shares2))
    with pytest.raises(FheError, match="expected fingerprint"):
        ThresholdFheKey.from_bundle(tampered, *args, expect_fingerprint=fp)
    # fingerprint covers key ids, range, Q, Q2 and the whole envelope
    for field, val in (("range", 5), ("key_id", "0" * 32), ("key_id2", "0" * 32), ("Q", "00" * 64),
                       ("Q2", "00" * 128)):
        t = copy.deepcopy(good); t[field] = val
        assert bundle_fingerprint(t) != fp
    for sub in ("header", "sealed"):
        t = copy.deepcopy(good)
        t["mac"][sub] = {**t["mac"][sub], "x": 1} if isinstance(t["mac"][sub], dict) else t["mac"][sub][:-2] + "ab"
        assert bundle_fingerprint(t) != fp
    # formatting of the pinned value does not matter
    assert ThresholdFheKey.from_bundle(good, *args, expect_fingerprint=fp.upper().replace("-", " ")).range == RANGE
    # loading WITHOUT a pin works but warns
    recwarn.clear()
    ThresholdFheKey.from_bundle(good, *args)
    assert any("WITHOUT a pinned fingerprint" in str(w.message) for w in recwarn.list)
    # range is bounded to [1, 2^40] at load (the BSGS table is O(sqrt(range)))
    for bad_range in (0, -5, 10 ** 30, 2 ** 40 + 1, True, "5", 1.5):
        t = copy.deepcopy(good); t["range"] = bad_range
        with pytest.raises(FheError, match="range"):
            ThresholdFheKey.from_bundle(t, *args, expect_fingerprint=bundle_fingerprint(t))
    with pytest.raises(FheError, match="range"):
        ThresholdFheKey(*args, value_range=10 ** 30)
    assert ThresholdFheKey(*args, Q2=None, value_range=2 ** 40).range == 2 ** 40


def test_mac_secret_is_independent_of_s_and_lazy(keyset, keyset2):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    mkc = lambda **kw: ThresholdFheKey.create(pub, local_nodes(shares), pub2, local_nodes(shares2), **kw)
    a = mkc(value_range=RANGE)
    b = mkc(value_range=RANGE)
    assert a.alpha != b.alpha                                  # fresh secret each ceremony
    opened = []

    class Spy(LocalNode):
        def call(self, method, args):
            opened.append(method)
            return super().call(method, args)

    c = ThresholdFheKey.from_bundle(a.bundle(), pub, local_nodes(shares, cls=Spy), pub2,
                                    local_nodes(shares2))
    c.decrypt_cell(c.encrypt(1))
    n_before = len(opened)
    assert c._mac_secret_cache is None                         # unauthenticated use never opens it
    _ = c.alpha
    assert c._mac_secret_cache is not None and len(opened) > n_before
    c.forget_mac_secret()
    assert c._mac_secret_cache is None
    # without a MAC secret authenticated mode is unavailable, with a clear error
    nm = mkc(with_mac=False)
    assert nm.decrypt_cell(nm.encrypt(2)) == 2
    cl = NoKeyClient(NoKeyServer(), fhe=nm, authenticated=True)
    with pytest.raises(FheError, match="no MAC secret"):
        cl.execute(SCHEMA)
        cl.execute("INSERT INTO emp (id, dept, rate, hours) VALUES (1, 5, 1, 2)")


def test_authenticated_mode_in_memory_and_lying_server(tkey):
    srv = NoKeyServer()
    c = NoKeyClient(srv, fhe=tkey, authenticated=True)
    seed(c)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    assert c.execute("SELECT 3 * SUM(rate) FROM emp").rows == [[435]]
    assert c.execute("SELECT id, rate FROM emp WHERE id = 3").rows == [[3, 30]]
    assert c.execute("SELECT rate FROM emp").rows == [[40], [55], [30], [20]]
    store = srv._rows["emp"]
    good = store.row(1)["rate"]
    store.set_cell(1, "rate", tkey.encrypt(999))                 # a swapped value
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT SUM(rate) FROM emp")
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT rate FROM emp")
    store.set_cell(1, "rate", good)
    real = srv.fhe_sum
    for lie in (lambda t, col, ids, k=1: real(t, col, ids, k * 2),
                lambda t, col, ids, k=1: real(t, col, ids[:-1], k)):
        srv.fhe_sum = lie
        with pytest.raises(CoreIntegrity):
            c.execute("SELECT SUM(rate) FROM emp")
    srv.fhe_sum = real
    assert c.execute("SELECT SUM(hours) FROM emp").rows == [[530]]
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[DOT_ALL]]    # auto -> local, tag-verified
    c.fhe_dot_mode = "delegated"                                                 # the server's ★_ct product
    assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[DOT_ALL]]


# ── the full SQL path through torussql.connect ───────────────────────────────
def test_sql_over_tcp_with_in_process_custodians(tkey):
    s = Running()
    try:
        with s.connect(fhe_key=tkey) as c:
            run_sql_suite(c)
        with s.connect(fhe_key=tkey) as c2:                      # a second client, same threshold key
            assert c2.execute("SELECT SUM(hours) FROM emp WHERE dept = 5").rows == [[310]]
    finally:
        s.stop()


def test_sql_authenticated_over_tcp_with_in_process_custodians(tkey):
    s = Running()
    try:
        with s.connect(fhe_key=tkey, authenticated=True) as c:
            run_sql_suite(c, authenticated=True)
    finally:
        s.stop()


def test_sql_over_tcp_with_network_custodians_and_failures(keyset, keyset2, net, net2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    q = Quorum(pub, net.remotes(), timeout=15)
    q2 = Quorum(pub2, net2.remotes(), timeout=15)
    key = ThresholdFheKey.create(pub, q, pub2, q2, value_range=RANGE)
    s = Running()
    try:
        with s.connect(fhe_key=key) as c:
            run_sql_suite(c)
        net.kill(0); net.kill(4)                                 # 3 of 5 left == the quorum
        net2.kill(2); net2.kill(3)
        key2 = ThresholdFheKey.from_bundle(key.bundle(), pub, Quorum(pub, net.remotes(), timeout=15),
                                           pub2, Quorum(pub2, net2.remotes(), timeout=15))
        with s.connect(fhe_key=key2) as c:
            assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
            assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[60 * 160 + 55 * 150 + 30 * 120]]
        net.kill(1)                                              # below quorum
        key3 = ThresholdFheKey.from_bundle(key.bundle(), pub, Quorum(pub, net.remotes(), timeout=4),
                                           pub2, Quorum(pub2, net2.remotes(), timeout=4))
        with s.connect(fhe_key=key3) as c:
            with pytest.raises(Exception, match="need 3 valid"):
                c.execute("SELECT SUM(rate) FROM emp")
            with pytest.raises(Exception, match="need 3 valid"):
                c.execute("SELECT id, rate FROM emp")
    finally:
        s.stop()


def test_network_authenticated_sql_and_audit_log(keyset, keyset2, net, net2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    key = ThresholdFheKey.create(pub, Quorum(pub, net.remotes(), timeout=15), pub2,
                                 Quorum(pub2, net2.remotes(), timeout=15), value_range=RANGE)
    s = Running()
    try:
        with s.connect(fhe_key=key, authenticated=True) as c:
            run_sql_suite(c, authenticated=True)
    finally:
        s.stop()
    text = open(tmp_path / "audit1.log").read()
    assert '"partial_batch"' in text and '"served"' in text
    key.decrypt_dot(fhe.dot_cells([key.encrypt(2)], [key.encrypt(3)], key.be))   # delegated-style DOT: GT rounds
    assert '"gt_partial_batch"' in open(tmp_path / "k2" / "audit1.log").read()   # s2 only does GT
    x = laurent.reconstruct([(sh.index, sh.y) for sh in shares[:3]], pub.g.order)
    assert hex(x)[2:] not in text and hex(shares[0].y)[2:] not in text


def test_network_item_budget_applies_to_fhe_reads(keyset, keyset2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    nodes = []
    for sh in shares:
        c = Custodian(sh, {"owner": TOKEN}, rate_per_minute=4, item_budget_per_minute=4)
        srv = CustodianServer("127.0.0.1", 0, c)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        nodes.append((srv, RemoteCustodian("127.0.0.1", srv.address[1], TOKEN, group=pub.g)))
    try:
        # Q2 comes from the s2 custodians (local nodes); reading 5 cells costs 5 items > 4: refused
        key = mk(keyset, keyset2, nodes=[r for _s, r in nodes])
        cells = [key.encrypt(i) for i in range(5)]
        with pytest.raises(InsufficientPartials, match="item budget"):
            key.decrypt_cells(cells)
        assert key.decrypt_cells(cells[:2]) == [0, 1]              # within the budget: one request
    finally:
        for srv, _r in nodes:
            srv.shutdown(); srv.server_close()


# ── back ends ────────────────────────────────────────────────────────────────
@pytest.mark.skipif(not HAVE_MCL, reason="native mclbn256 back end not available")
@pytest.mark.parametrize("key_be,eval_be", [("pyecc", "mcl"), ("mcl", "pyecc"), ("mcl", "mcl"),
                                            ("pyecc", "pyecc")])
def test_backends_interoperate(keyset, keyset2, tkey, key_be, eval_be):
    key = mk(keyset, keyset2, Q2=tkey._q2_raw, backend=key_be, value_range=RANGE)
    enc = [tkey.encrypt(v) for v in (6, 7)]                         # ciphertexts are back-end independent
    assert key.decrypt_cells(enc) == [6, 7]
    d = fhe.dot_cells(enc[:1], enc[1:], eval_be)
    assert key.decrypt_dot(d) == 42


# ── the CLI ceremony step ────────────────────────────────────────────────────
def _env():
    paths = [str(ROOT / "drivers" / "python"), str(ROOT / "core"), str(ROOT / "parser")]
    e = dict(os.environ)
    e["PYTHONPATH"] = os.pathsep.join(paths + [e.get("PYTHONPATH", "")])
    return e


def test_cli_one_daemon_per_host_serves_both_keys(keyset, keyset2, tmp_path):
    """`serve --share A --share B`: ONE daemon per custodian host holds the s and s2 shares;
    --custodian2 is omitted so the same endpoints serve key 2."""
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    d = tmp_path
    pub.save(str(d / "pub.json")); pub2.save(str(d / "pub2.json"))
    (d / "tokens").write_text(f"owner:{TOKEN}\n")
    os.chmod(d / "tokens", 0o600)
    procs, specs = [], []
    try:
        for s1, s2 in zip(shares[:3], shares2[:3]):
            f1, f2 = d / f"s{s1.index}.json", d / f"t{s2.index}.json"
            s1.save(str(f1), None); s2.save(str(f2), None)
            p = subprocess.Popen([sys.executable, "-m", "torussql.custody", "serve", "--share", str(f1),
                                  "--share", str(f2), "--no-passphrase", "--item-budget", "5000",
                                  "--listen", "127.0.0.1:0", "--token-file", str(d / "tokens"),
                                  "--audit", str(d / f"audit{s1.index}.log")],
                                 env=_env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(p)
            line = p.stdout.readline()
            assert line.count("key share") == 2
            specs.append("127.0.0.1:" + re.search(r"on 127\.0\.0\.1:(\d+)", line).group(1))
        base = ["--public", str(d / "pub.json"), "--public2", str(d / "pub2.json"), "--token-env", "CT"]
        for sp in specs:
            base += ["--custodian", sp]
        run = lambda *a, env=None, **k: subprocess.run(
            [sys.executable, "-m", "torussql.custody", *a], env=_env() | (env or {"CT": TOKEN}),
            capture_output=True, text=True, timeout=300, **k)
        fp = ["--expect-fingerprint", pub.fingerprint, "--expect-fingerprint2", pub2.fingerprint]
        r = run("fhe-keygen-threshold", *base, *fp, "--out", str(d / "fhe.json"), "--range", "5000")
        assert r.returncode == 0, r.stderr
        assert "holds NO secret" in r.stdout
        bundle = json.loads((d / "fhe.json").read_text())
        assert bundle["kind"] == "torussql-fhe-threshold" and bundle["range"] == 5000 and bundle["v"] == 3
        for sh, pb in ((shares, pub), (shares2, pub2)):
            x = laurent.reconstruct([(q.index, q.y) for q in sh[:3]], pb.g.order)
            assert hex(x)[2:] not in json.dumps(bundle)
        assert set(bundle) == {"v", "kind", "key_id", "key_id2", "range", "Q", "Q2", "mac"}
        bfp = re.search(r"BUNDLE FINGERPRINT: (\S+)", r.stdout).group(1)
        assert bfp == bundle_fingerprint(bundle)
        assert run("fhe-keygen-threshold", *base, "--out", str(d / "fhe.json")).returncode != 0   # no overwrite
        same = ["--public", str(d / "pub.json"), "--public2", str(d / "pub.json"), "--token-env", "CT"]
        for sp in specs:
            same += ["--custodian", sp]
        assert run("fhe-keygen-threshold", *same, "--out", str(d / "x.json")).returncode != 0
        r = run("fhe-open-test", *base, *fp, "--bundle", str(d / "fhe.json"), "--mac",
                "--expect-bundle-fingerprint", bfp)
        assert r.returncode == 0 and "DOT" in r.stdout and "MAC" in r.stdout, r.stderr
        r = run("fhe-open-test", *base, *fp, "--bundle", str(d / "fhe.json"), "--expect-bundle-fingerprint", "00" * 32)
        assert r.returncode != 0 and "fingerprint" in r.stderr
        # a wrong pinned fingerprint is refused before anything is contacted
        bad = ["--expect-fingerprint", "00" * 32]
        for cmd in (("fhe-open-test", "--bundle", str(d / "fhe.json")),
                    ("fhe-keygen-threshold", "--out", str(d / "y.json")),
                    ("open-test",)):
            args = base if cmd[0] != "open-test" else ["--public", str(d / "pub.json"), "--token-env", "CT",
                                                       "--custodian", specs[0]]
            r = run(cmd[0], *args, *bad, *cmd[1:])
            assert r.returncode != 0 and "fingerprint" in r.stderr, (cmd, r.stderr)
        assert run("public-show", "--public", str(d / "pub.json")).stdout.count(pub.fingerprint) == 1
        assert run("public-show", "--public", str(d / "pub.json"), "--expect-fingerprint", "ab").returncode != 0
        # the Python client: same endpoints for both keys (custodians2 omitted)
        key = ThresholdFheKey.load(
            str(d / "fhe.json"), pub,
            [RemoteCustodian("127.0.0.1", int(sp.split(":")[1]), TOKEN, group=pub.g) for sp in specs], pub2,
            expect_fingerprint=bfp)
        assert key.decrypt_cell(key.encrypt(41)) == 41
        assert key.decrypt_dot(fhe.dot_cells([key.encrypt(6)], [key.encrypt(7)], key.be)) == 42
        r = run("fhe-open-test", *base, "--bundle", str(d / "fhe.json"), env={"CT": "wrong-token-0123456789abc"})
        assert r.returncode != 0 and TOKEN not in r.stdout + r.stderr
        assert '"key_id"' in (d / "audit1.log").read_text()
    finally:
        for p in procs:
            p.terminate()


# ── one daemon, several keys ─────────────────────────────────────────────────
class MultiNet:
    """n daemons (threads), each holding BOTH the s and the s2 share."""

    def __init__(self, shares, shares2, tmp_path, **kw):
        self.servers, self.custodians, self.ports = [], [], []
        for s1, s2 in zip(shares, shares2):
            c = Custodian([s1, s2], {"owner": TOKEN, "ops": "ops-token-0123456789abcd"},
                          audit_path=str(tmp_path / f"m_audit{s1.index}.log"), **kw)
            srv = CustodianServer("127.0.0.1", 0, c)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv); self.custodians.append(c); self.ports.append(srv.address[1])
        self.g = shares[0].public.g

    def remotes(self, token=TOKEN):
        return [RemoteCustodian("127.0.0.1", p, token, group=self.g) for p in self.ports]

    def stop(self):
        for s in self.servers:
            s.shutdown(); s.server_close()


def test_one_daemon_serves_both_keys_full_sql(keyset, keyset2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    mn = MultiNet(shares, shares2, tmp_path)
    s = Running()
    try:
        key = ThresholdFheKey.create(pub, mn.remotes(), pub2, value_range=RANGE)     # custodians2 omitted
        with s.connect(fhe_key=key) as c:
            run_sql_suite(c)
        s2 = Running()
        try:
            with s2.connect(fhe_key=key, authenticated=True) as c:
                run_sql_suite(c, authenticated=True)
        finally:
            s2.stop()
        key_b = ThresholdFheKey.from_bundle(key.bundle(), pub, mn.remotes(), pub2)
        assert key_b.decrypt_dot(fhe.dot_cells([key.encrypt(5)], [key.encrypt(8)], key_b.be)) == 40
    finally:
        s.stop(); mn.stop()


def test_a_key_one_request_is_never_answered_with_the_key_two_share(keyset, keyset2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    mn = MultiNet(shares, shares2, tmp_path)
    try:
        r = mn.remotes()[0]
        g = pub.g
        E = g.mul(g.G, 4242)
        k1, k2 = pub.key_id, pub2.key_id
        from py_ecc.optimized_bn128 import G1, G2, pairing
        from torussql.custody import Partial, verify_partial
        craw = cgt.gt_encode(pairing(G2, G1) ** 4242)
        p1 = Partial.from_json(g, r.call("partial", [g.hex(E), "", k1]))
        assert verify_partial(pub, E, p1)
        # the same GT element, exponentiated by the key-1 and the key-2 share: both verify, only
        # against THEIR key, and never interchangeably
        j1 = r.call("gt_partial_batch", [[craw.hex()], "", k1])[0]
        j2 = r.call("gt_partial_batch", [[craw.hex()], "", k2])[0]
        q1, q2 = cgt.GtPartial.from_json(pub.g, j1), cgt.GtPartial.from_json(pub2.g, j2)
        assert cgt.verify_gt_partial(pub, craw, q1) and cgt.verify_gt_partial(pub2, craw, q2)
        assert q1.D != q2.D and q1.index == q2.index == shares[0].index
        with pytest.raises(Exception):
            cgt.verify_gt_partial(pub2, craw, q1)
        with pytest.raises(Exception):
            cgt.verify_gt_partial(pub, craw, q2)
        # key 2 (group G2) serves GT exponentiation ONLY: no G1 decryption oracle on s2
        for m, a in (("partial", [g.hex(E), "", k2]), ("partial_batch", [[g.hex(E)], "", k2])):
            with pytest.raises(QuorumError, match="GT exponentiation only"):
                r.call(m, a)
        # no key_id on a multi-key daemon: refused; unknown key id: refused; same for every method
        for m, a in (("partial", [g.hex(E), ""]), ("partial_batch", [[g.hex(E)], ""]),
                     ("gt_partial_batch", [[craw.hex()], ""])):
            with pytest.raises(QuorumError, match="must name a key_id"):
                r.call(m, a)
        for m, a in (("partial", [g.hex(E), "", "ff" * 16]), ("partial_batch", [[g.hex(E)], "", "ff" * 16]),
                     ("gt_partial_batch", [[craw.hex()], "", "ff" * 16]), ("partial", [g.hex(E), "", 5])):
            with pytest.raises(QuorumError, match="no share of that key"):
                r.call(m, a)
        # the removed G2-share RPC is gone (it would hand out s·G2 for key 1)
        with pytest.raises(QuorumError, match="unknown method"):
            r.call("g2_partial", [k1])
        # the typed clients carry the key id (and the key's group): for_key() routes correctly
        c2 = r.for_key(pub2)
        got = c2.gt_partial_batch([craw], b"")[0]
        assert cgt.verify_gt_partial(pub2, craw, got)
        # a single-share (legacy) daemon: requests without key_id still work, a WRONG key_id is refused
        legacy = Custodian(shares[0], {"owner": TOKEN})
        ln = LocalNode(legacy, caller="owner")
        assert verify_partial(pub, E, ln.partial(E, b""))
        with pytest.raises(QuorumError, match="no share of that key"):
            ln.for_key(pub2).gt_partial_batch([craw], b"")
        info = mn.custodians[0].info()
        assert len(info["keys"]) == 2 and "key_id" not in info
        assert {k["group"] for k in info["keys"]} == {"bn254", "bn254g2"}
    finally:
        mn.stop()


def test_per_key_access_rate_limits_and_approve(keyset, keyset2, tmp_path):
    shares, pub, _ = keyset
    shares2, pub2, _ = keyset2
    g = pub.g
    E = g.mul(g.G, 99)
    k1, k2 = pub.key_id, pub2.key_id
    from py_ecc.optimized_bn128 import G1, G2, pairing
    craw = cgt.gt_encode(pairing(G2, G1) ** 99).hex()
    seen = []
    c = Custodian([shares[0], shares2[0]], {"owner": TOKEN, "ops": "ops-token-0123456789abcd"},
                  key_access={k2: {"ops"}}, rate_per_minute=3, item_budget_per_minute=1000,
                  approve={k1: lambda caller, e, ctx: seen.append(("k1", caller)) or True,
                           k2: lambda caller, e, ctx: False})
    own = LocalNode(c, caller="owner")
    ops = LocalNode(c, caller="ops")
    own.call("partial", [g.hex(E), "", k1])
    # key access: the owner may not use key 2 at all; ops may (but key 2's own approve declines)
    with pytest.raises(QuorumError, match="no access to that key"):
        own.call("gt_partial_batch", [[craw], "", k2])
    with pytest.raises(QuorumError, match="policy"):
        ops.call("gt_partial_batch", [[craw], "", k2])
    assert seen == [("k1", "owner")]                          # approve hooks are per key
    # rate limits are per (caller, key): exhausting key 1 does not touch key 2's budget
    own.call("partial", [g.hex(E), "", k1]); own.call("partial", [g.hex(E), "", k1])
    with pytest.raises(QuorumError, match="rate limit exceeded"):
        own.call("partial", [g.hex(E), "", k1])
    for _ in range(2):
        with pytest.raises(QuorumError, match="policy"):
            ops.call("gt_partial_batch", [[craw], "", k2])
    with pytest.raises(Exception, match="key_access"):
        Custodian([shares[0]], {"owner": TOKEN}, key_access={k2: {"owner"}})
    with pytest.raises(Exception, match="same key"):
        Custodian([shares[0], shares[0]], {"owner": TOKEN})
    # the item budget is COST-WEIGHTED: one GT element = 100 units, one G1 point = 1
    c2 = Custodian([shares[0], shares2[0]], {"owner": TOKEN}, item_budget_per_minute=250,
                   max_batch=50)
    n2 = LocalNode(c2, caller="owner")
    n2.call("gt_partial_batch", [[craw, craw], "", k2])                 # 200 units
    with pytest.raises(QuorumError, match="item budget exceeded.*GT element = 100"):
        n2.call("gt_partial_batch", [[craw, craw], "", k2])             # 400 > 250
    n2.call("partial_batch", [[g.hex(E)] * 40, "", k1])                 # other key: its own budget
    for _ in range(4):
        n2.call("partial_batch", [[g.hex(E)] * 50, "", k1])             # 40 + 4*50 = 240 units
    with pytest.raises(QuorumError, match="item budget exceeded"):
        n2.call("partial_batch", [[g.hex(E)] * 11, "", k1])             # 251 > 250



