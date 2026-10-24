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
from torusdb_core.fhe_threshold import ThresholdFheKey
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torusdb_core.errors import IntegrityError as CoreIntegrity
from torussql.custody import (InsufficientPartials, LocalCustodian, Quorum, QuorumError,
                              laurent, run_local_ceremony)
from torussql.custody import gt as cgt
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
def tkey(keyset):
    """A threshold key whose quorum is five in-process custodians (full dispatch path)."""
    shares, pub, _ = keyset
    return ThresholdFheKey.create(pub, local_nodes(shares), value_range=RANGE)


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
    if authenticated:
        with pytest.raises(Exception, match="no integrity protection"):
            c.execute("SELECT DOT(rate, hours) FROM emp")
    else:
        assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[60 * 160 + 55 * 150 + 30 * 120]]
        assert c.execute("SELECT DOT(rate, hours) FROM emp WHERE dept = 5").rows == \
            [[60 * 160 + 55 * 150]]


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
def test_the_secret_is_never_reassembled_by_any_operation(keyset, monkeypatch):
    shares, pub, _ = keyset
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)   # for the checks below
    boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("key reassembled!"))
    monkeypatch.setattr(laurent, "reconstruct", boom)
    monkeypatch.setattr(laurent, "robust_reconstruct", boom)
    key = ThresholdFheKey.create(pub, local_nodes(shares[1:4]), value_range=RANGE)
    assert key.decrypt_cells([key.encrypt(5)]) == [5]
    assert key.decrypt_dot(fhe.dot_cells([key.encrypt(6)], [key.encrypt(7)], key.be)) == 42
    c = NoKeyClient(NoKeyServer(), fhe=key, authenticated=True)
    seed(c)
    assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
    # nothing the owner process holds is, or is derived from, the secret exponent
    forbidden = {x, pub.g.order - x}
    seen = []

    def walk(o, depth=0):
        if depth > 4 or id(o) in {id(s) for s in seen}:
            return
        seen.append(o)
        if isinstance(o, int) and o in forbidden:
            raise AssertionError("the key's secret is held in memory")
        if isinstance(o, (bytes, bytearray)) and int(x).to_bytes(32, "big") in o:
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
    for attr in ("_s", "secret_bytes"):
        assert not hasattr(key, attr)
    assert "secret" not in repr(key)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(key)
    # the public bundle holds no secret
    blob = json.dumps(key.bundle())
    assert hex(x)[2:] not in blob and format(x, "064x") not in blob


# ── below quorum / failing and lying custodians ──────────────────────────────
def test_below_quorum_cannot_decrypt(keyset, tkey):
    shares, pub, _ = keyset
    weak = ThresholdFheKey(pub, local_nodes(shares[:2]), Q2=tkey._q2_raw, value_range=RANGE)
    cell = tkey.encrypt(5)
    with pytest.raises(InsufficientPartials):
        weak.decrypt_cell(cell)
    with pytest.raises(InsufficientPartials):
        weak.decrypt_dot(fhe.dot_cells([cell], [cell], weak.be))
    # two shares do not even give Q2 or the MAC secret
    with pytest.raises(InsufficientPartials):
        ThresholdFheKey(pub, local_nodes(shares[:2]), value_range=RANGE)
    weak_mac = ThresholdFheKey(pub, local_nodes(shares[:2]), Q2=tkey._q2_raw,
                               mac=tkey.bundle()["mac"], value_range=RANGE)
    with pytest.raises(InsufficientPartials):
        weak_mac.alpha
    # the minimum quorum works, whichever k custodians answer
    for sel in ([0, 1, 2], [2, 3, 4], [0, 2, 4]):
        k3 = ThresholdFheKey(pub, local_nodes([shares[i] for i in sel]), Q2=tkey._q2_raw,
                             value_range=RANGE)
        assert k3.decrypt_cell(cell) == 5
        assert k3.decrypt_dot(fhe.dot_cells([cell], [tkey.encrypt(9)], k3.be)) == 45


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

    def g2_partial(self):
        idx, raw = super().g2_partial()
        pt = cgt.g2_decode(raw)
        from py_ecc.optimized_bn128 import G2, add
        return idx, cgt.g2_encode(add(pt, G2))


class Slow(LocalNode):
    """An honest custodian that answers a little later, so a liar is examined first."""

    def partial_batch(self, *a, **k):
        time.sleep(0.3)
        return super().partial_batch(*a, **k)

    def gt_partial_batch(self, *a, **k):
        time.sleep(0.3)
        return super().gt_partial_batch(*a, **k)

    def g2_partial(self):
        time.sleep(0.3)
        return super().g2_partial()


@pytest.mark.parametrize("mode", ["d", "z", "index", "other-share"])
def test_a_lying_custodian_is_detected_and_excluded(keyset, tkey, mode):
    shares, pub, _ = keyset
    nodes = local_nodes(shares, cls=Slow)
    nodes[0] = Liar(nodes[0].custodian, label="liar")
    nodes[0].mode = mode
    key = ThresholdFheKey(pub, nodes, Q2=tkey._q2_raw, value_range=RANGE)
    cell = tkey.encrypt(77)
    assert key.decrypt_cell(cell) == 77                              # liar excluded, answer right
    assert "liar" in key.quorum.last_problems
    if mode != "other-share":
        a, b = tkey.encrypt(6), tkey.encrypt(7)
        assert key.decrypt_dot(fhe.dot_cells([a], [b], key.be)) == 42
        assert "liar" in key.quorum.last_problems


def test_liars_beyond_the_threshold_fail_closed_never_wrong(keyset, tkey):
    shares, pub, _ = keyset
    # 3 of 5 custodians lie: only 2 honest remain (< k=3). Must raise, not return garbage.
    nodes = local_nodes(shares)
    for i in (0, 1, 2):
        nodes[i] = Liar(nodes[i].custodian, label=f"liar{i}")
    key = ThresholdFheKey(pub, nodes, Q2=tkey._q2_raw, value_range=RANGE)
    with pytest.raises(InsufficientPartials) as ei:
        key.decrypt_cell(tkey.encrypt(5))
    assert "liar0" in str(ei.value)
    with pytest.raises(InsufficientPartials):
        key.decrypt_dot(fhe.dot_cells([tkey.encrypt(2)], [tkey.encrypt(3)], key.be))


def test_a_lying_g2_share_cannot_poison_the_public_key(keyset, tkey):
    shares, pub, _ = keyset
    nodes = local_nodes(shares, cls=Slow)
    nodes[0] = Liar(nodes[0].custodian, label="liar")
    nodes[1] = Liar(nodes[1].custodian, label="liar2")
    key = ThresholdFheKey(pub, nodes)                         # Q2 derived from the custodians
    assert key._q2_raw == tkey._q2_raw
    assert set(key.quorum.last_problems) >= {"liar"} or set(key.quorum.last_problems) >= {"liar2"}


def test_q2_is_verified_against_the_public_key(keyset, tkey):
    shares, pub, _ = keyset
    from py_ecc.optimized_bn128 import G2, multiply
    good = cgt.g2_decode(tkey._q2_raw)
    for bad in (cgt.g2_encode(multiply(G2, 5)),                # some other key's Q2
                cgt.g2_encode(multiply(good, 2)),              # a multiple of the right one
                bytes(128),                                    # identity
                tkey._q2_raw[:-1] + bytes([tkey._q2_raw[-1] ^ 1]),   # off curve
                b"short"):
        with pytest.raises(FheError, match="does not match|G2|128"):
            ThresholdFheKey(pub, local_nodes(shares), Q2=bad)


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


def test_custodians_refuse_gt_elements_outside_the_subgroup(keyset):
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
    with pytest.raises(QuorumError, match="malformed"):
        node.call("gt_partial_batch", [["00"] * (cgt.MAX_GT_BATCH + 1), ""])
    # and the owner side refuses to even ask for them
    key = ThresholdFheKey(pub, local_nodes(shares), Q2=None)
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
                     audit_path=str(tmp_path / "a.log"))
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
    # the rate limit is charged PER ITEM: a batch is not a way around it
    cust._hits.clear()
    cust._rate = 6
    with pytest.raises(QuorumError, match="rate limit"):
        node.call("partial_batch", [[g.hex(E)] * 7, ""])
    cust._hits.clear()
    node.call("partial_batch", [[g.hex(E)] * 6, ""])
    with pytest.raises(QuorumError, match="rate limit"):
        node.call("partial_batch", [[g.hex(E)], ""])
    with pytest.raises(QuorumError, match="rate limit"):
        node.gt_partial_batch([craw], b"")
    with pytest.raises(QuorumError, match="rate limit"):
        node.g2_partial()
    cust._hits.clear()
    cust._rate = 100
    # policy denial applies to the whole batch, before anything is computed
    state["deny"] = True
    with pytest.raises(QuorumError, match="policy"):
        node.call("partial_batch", [[g.hex(E), g.hex(g.mul(g.G, 5))], ""])
    with pytest.raises(QuorumError, match="policy"):
        node.gt_partial_batch([craw], b"")
    state["deny"] = False
    lines = [json.loads(l) for l in open(tmp_path / "a.log")]
    assert any("rate limit" in l["outcome"] for l in lines) and any(l["outcome"] == "served" for l in lines)
    assert str(shares[0].y) not in open(tmp_path / "a.log").read()
    # a caller without the 'key' permission cannot use any of the new methods
    ro = Custodian(shares[0], {"reader": TOKEN}, permissions={"reader": {"mask_read"}})
    rnode = LocalNode(ro, caller="reader")
    for m, a in (("partial_batch", [[g.hex(E)], ""]), ("gt_partial_batch", [[craw.hex()], ""]),
                 ("g2_partial", [])):
        with pytest.raises(QuorumError, match="lacks permission"):
            rnode.call(m, a)


def test_approve_can_refuse_threshold_fhe_requests(keyset):
    shares, pub, _ = keyset
    state = {"ok": True}
    nodes = local_nodes(shares, approve=lambda caller, E, ctx: state["ok"])
    key = ThresholdFheKey(pub, nodes)
    cell = key.encrypt(3)
    assert key.decrypt_cell(cell) == 3
    state["ok"] = False
    with pytest.raises(InsufficientPartials, match="policy"):
        key.decrypt_cell(cell)
    with pytest.raises(InsufficientPartials, match="policy"):
        key.decrypt_dot(fhe.dot_cells([cell], [cell], key.be))


# ── DOT really takes two sequential rounds; no custodian ever sees s² ────────
def test_dot_uses_two_sequential_gt_rounds(keyset, tkey):
    shares, pub, _ = keyset
    calls = []

    class Spy(LocalNode):
        def gt_partial_batch(self, cs, context=b""):
            calls.append((self.label, len(cs), [bytes(c) for c in cs]))
            return super().gt_partial_batch(cs, context)

    nodes = local_nodes(shares, cls=Spy)
    key = ThresholdFheKey(pub, nodes, Q2=tkey._q2_raw, value_range=RANGE)
    blob = fhe.dot_cells([key.encrypt(3)], [key.encrypt(4)], key.be)
    assert key.decrypt_dot(blob) == 12
    sizes = sorted({len(c[2]) for c in calls})
    assert sizes == [1, 3]                         # one round of 3 elements, then ONE element
    r1 = next(c for c in calls if c[1] == 3)
    r2 = next(c for c in calls if c[1] == 1)
    assert r1[2][0] != r2[2][0]                    # the 2nd round's input is c00^s, not c00
    c00 = cgt.gt_decode(r1[2][0])
    # r2's input is exactly c00^x  (combined from round 1), so round 2 yields c00^(x²)
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], pub.g.order)
    assert cgt.gt_decode(r2[2][0]) == c00 ** x


# ── bundle, MAC secret, integrity ────────────────────────────────────────────
def test_bundle_roundtrip_and_tamper_checks(keyset, tkey, tmp_path):
    shares, pub, _ = keyset
    path = str(tmp_path / "b.json")
    tkey.save_bundle(path)
    assert (os.stat(path).st_mode & 0o777) == 0o644
    key2 = ThresholdFheKey.load(path, pub, local_nodes(shares))
    assert key2.range == RANGE and key2.decrypt_cell(tkey.encrypt(9)) == 9
    assert key2.alpha == tkey.alpha and key2.gamma("t", "c", 3) == tkey.gamma("t", "c", 3)
    good = json.loads(open(path).read())
    other_shares, other_pub, _ = run_local_ceremony(2, 3, "bn254")
    with pytest.raises(FheError, match="different custody key"):
        ThresholdFheKey.from_bundle(good, other_pub, local_nodes(other_shares))
    for field, value in (("Q", pub.g.hex(pub.g.mul(pub.g.G, 3))), ("kind", "x"), ("Q2", "00" * 128)):
        bad = dict(good); bad[field] = value
        with pytest.raises(FheError):
            ThresholdFheKey.from_bundle(bad, pub, local_nodes(shares))
    # a tampered sealed MAC is refused (authenticated encryption under the threshold key)
    bad = json.loads(json.dumps(good))
    s = bad["mac"]["sealed"]
    bad["mac"]["sealed"] = s[:-2] + ("00" if s[-2:] != "00" else "01")
    k3 = ThresholdFheKey.from_bundle(bad, pub, local_nodes(shares))
    with pytest.raises(FheError, match="tampered|damaged"):
        k3.alpha
    # a swapped envelope for another purpose is refused
    bad = json.loads(json.dumps(good)); bad["mac"]["header"]["ctx"] = "00"
    with pytest.raises(FheError, match="different purpose"):
        ThresholdFheKey.from_bundle(bad, pub, local_nodes(shares)).alpha


def test_mac_secret_is_independent_of_s_and_lazy(keyset):
    shares, pub, _ = keyset
    a = ThresholdFheKey.create(pub, local_nodes(shares), value_range=RANGE)
    b = ThresholdFheKey.create(pub, local_nodes(shares), value_range=RANGE)
    assert a.alpha != b.alpha                                  # fresh secret each ceremony
    opened = []

    class Spy(LocalNode):
        def call(self, method, args):
            opened.append(method)
            return super().call(method, args)

    c = ThresholdFheKey.from_bundle(a.bundle(), pub, local_nodes(shares, cls=Spy))
    c.decrypt_cell(c.encrypt(1))
    n_before = len(opened)
    assert c._mac_secret_cache is None                         # unauthenticated use never opens it
    _ = c.alpha
    assert c._mac_secret_cache is not None and len(opened) > n_before
    c.forget_mac_secret()
    assert c._mac_secret_cache is None
    # without a MAC secret authenticated mode is unavailable, with a clear error
    nm = ThresholdFheKey.create(pub, local_nodes(shares), with_mac=False)
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
    with pytest.raises(Exception, match="no integrity protection"):
        c.execute("SELECT DOT(rate, hours) FROM emp")
    c.fhe_allow_unverified_dot = True
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


def test_sql_over_tcp_with_network_custodians_and_failures(keyset, net, tmp_path):
    shares, pub, _ = keyset
    q = Quorum(pub, net.remotes(), timeout=15)
    key = ThresholdFheKey.create(pub, q, value_range=RANGE)
    s = Running()
    try:
        with s.connect(fhe_key=key) as c:
            run_sql_suite(c)
        net.kill(0); net.kill(4)                                 # 3 of 5 left == the quorum
        key2 = ThresholdFheKey.from_bundle(key.bundle(), pub, Quorum(pub, net.remotes(), timeout=15))
        with s.connect(fhe_key=key2) as c:
            assert c.execute("SELECT SUM(rate) FROM emp").rows == [[145]]
            assert c.execute("SELECT DOT(rate, hours) FROM emp").rows == [[60 * 160 + 55 * 150 + 30 * 120]]
        net.kill(1)                                              # below quorum
        key3 = ThresholdFheKey.from_bundle(key.bundle(), pub, Quorum(pub, net.remotes(), timeout=4))
        with s.connect(fhe_key=key3) as c:
            with pytest.raises(Exception, match="need 3 valid"):
                c.execute("SELECT SUM(rate) FROM emp")
            with pytest.raises(Exception, match="need 3 valid"):
                c.execute("SELECT id, rate FROM emp")
    finally:
        s.stop()


def test_network_authenticated_sql_and_audit_log(keyset, net, tmp_path):
    shares, pub, _ = keyset
    key = ThresholdFheKey.create(pub, Quorum(pub, net.remotes(), timeout=15), value_range=RANGE)
    s = Running()
    try:
        with s.connect(fhe_key=key, authenticated=True) as c:
            run_sql_suite(c, authenticated=True)
    finally:
        s.stop()
    text = open(tmp_path / "audit1.log").read()
    assert '"partial_batch"' in text and '"served"' in text and '"g2_partial"' in text
    x = laurent.reconstruct([(sh.index, sh.y) for sh in shares[:3]], pub.g.order)
    assert hex(x)[2:] not in text and hex(shares[0].y)[2:] not in text


def test_network_rate_limit_applies_to_fhe_reads(keyset, tmp_path):
    shares, pub, _ = keyset
    n = Net(shares, tmp_path, rate=4)
    try:
        # Q2 costs 1 request per custodian: fine. Reading 5 cells at once costs 5: refused.
        key = ThresholdFheKey(pub, Quorum(pub, n.remotes(), timeout=10))
        cells = [key.encrypt(i) for i in range(5)]
        with pytest.raises(InsufficientPartials, match="rate limit"):
            key.decrypt_cells(cells)
    finally:
        n.stop()


# ── back ends ────────────────────────────────────────────────────────────────
@pytest.mark.skipif(not HAVE_MCL, reason="native mclbn256 back end not available")
@pytest.mark.parametrize("key_be,eval_be", [("pyecc", "mcl"), ("mcl", "pyecc"), ("mcl", "mcl"),
                                            ("pyecc", "pyecc")])
def test_backends_interoperate(keyset, tkey, key_be, eval_be):
    shares, pub, _ = keyset
    key = ThresholdFheKey(pub, local_nodes(shares), Q2=tkey._q2_raw, backend=key_be,
                          value_range=RANGE)
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


def test_cli_fhe_keygen_threshold_and_open_test(keyset, tmp_path):
    shares, pub, _ = keyset
    d = tmp_path
    pub.save(str(d / "pub.json"))
    (d / "tokens").write_text(f"owner:{TOKEN}\n")
    os.chmod(d / "tokens", 0o600)
    procs, specs = [], []
    try:
        for s in shares[:3]:
            s.save(str(d / f"share{s.index}.json"), None)
            p = subprocess.Popen([sys.executable, "-m", "torussql.custody", "serve", "--share",
                                  str(d / f"share{s.index}.json"), "--no-passphrase", "--rate", "5000",
                                  "--listen", "127.0.0.1:0", "--token-file", str(d / "tokens")],
                                 env=_env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(p)
            specs.append("127.0.0.1:" + re.search(r"on 127\.0\.0\.1:(\d+)", p.stdout.readline()).group(1))
        base = ["--public", str(d / "pub.json"), "--token-env", "CT"]
        for sp in specs:
            base += ["--custodian", sp]
        run = lambda *a, **k: subprocess.run([sys.executable, "-m", "torussql.custody", *a],
                                              env=_env() | {"CT": TOKEN}, capture_output=True,
                                              text=True, timeout=300, **k)
        r = run("fhe-keygen-threshold", *base, "--out", str(d / "fhe.json"), "--range", "5000")
        assert r.returncode == 0, r.stderr
        assert "holds NO secret" in r.stdout
        bundle = json.loads((d / "fhe.json").read_text())
        assert bundle["kind"] == "torussql-fhe-threshold" and bundle["range"] == 5000
        x = laurent.reconstruct([(sh.index, sh.y) for sh in shares[:3]], pub.g.order)
        assert hex(x)[2:] not in json.dumps(bundle) and set(bundle) >= {"Q", "Q2", "mac"}
        assert run("fhe-keygen-threshold", *base, "--out", str(d / "fhe.json")).returncode != 0   # no overwrite
        r = run("fhe-open-test", *base, "--bundle", str(d / "fhe.json"), "--mac")
        assert r.returncode == 0 and "DOT" in r.stdout and "MAC" in r.stdout, r.stderr
        # and the interactive client can use it
        key = ThresholdFheKey.load(str(d / "fhe.json"), pub, [
            RemoteCustodian("127.0.0.1", int(sp.split(":")[1]), TOKEN, group=pub.g) for sp in specs])
        assert key.decrypt_cell(key.encrypt(41)) == 41
        # a wrong token is refused
        r = subprocess.run([sys.executable, "-m", "torussql.custody", "fhe-open-test", *base,
                            "--bundle", str(d / "fhe.json")], env=_env() | {"CT": "wrong-token-0123456789abc"},
                           capture_output=True, text=True, timeout=300)
        assert r.returncode != 0 and TOKEN not in r.stdout + r.stderr
    finally:
        for p in procs:
            p.terminate()
