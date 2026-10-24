# SPDX-License-Identifier: Apache-2.0
"""Threshold key custody: math, DKG, threshold use, resharing, transport."""
from __future__ import annotations

import itertools
import json
import os
import random
import secrets
from dataclasses import replace

import pytest

from torussql.custody import (
    Broadcast, CustodyError, DKGError, InsufficientPartials, KeyShare, LocalCustodian,
    Participant, PublicKey, Quorum, ReshareSpec, ShareError, ThresholdCustody,
    combine, get_group, partial_decrypt, refresh, reshare_deal, reshare_finish,
    run_local_ceremony, run_local_reshare, unwrap_key, verify_partial, wrap_key,
)
from torussql.custody import laurent
from torussql.custody import identity as ident
from torussql.custody.dkg import Dealing, check_dealing, deal
from torussql.custody.group import InvalidPoint
from torussql.custody.proofs import (dleq_prove, dleq_verify, schnorr_prove,
                                     schnorr_verify)

GROUPS = ["secp256k1", "bn254", "bn254g2"]


def solve(A, b, q):
    """Independent Gaussian elimination mod q (oracle for the closed forms)."""
    n = len(b)
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for c in range(n):
        p = next(r for r in range(c, n) if M[r][c] % q)
        M[c], M[p] = M[p], M[c]
        iv = pow(M[c][c], -1, q)
        M[c] = [v * iv % q for v in M[c]]
        for r in range(n):
            if r != c and M[r][c] % q:
                f = M[r][c]
                M[r] = [(M[r][i] - f * M[c][i]) % q for i in range(n + 1)]
    return [M[i][n] for i in range(n)]


def opener(pub, shares):
    return Quorum(pub, [LocalCustodian(s) for s in shares], timeout=30).shared_point


@pytest.fixture(scope="module")
def key35():
    return run_local_ceremony(3, 5, "secp256k1")


# ── Laurent sharing math ─────────────────────────────────────────────────────
@pytest.mark.parametrize("name", GROUPS)
def test_lambda_closed_form_matches_gaussian_elimination(name):
    q = get_group(name).order
    rng = random.Random(5)
    for _ in range(40):
        k = rng.randint(2, 7)
        xs = rng.sample(range(1, 33), k)
        lam = laurent.lambdas(xs, q)
        # row i of the Vandermonde in u=1/x : (1, u, u², …); want Σ λ_i row_i = e_{u¹}
        A = [[pow(pow(x, -1, q), j, q) for x in xs] for j in range(k)]   # A·λ = target
        target = [0, 1] + [0] * (k - 2)
        assert [lam[x] for x in xs] == solve(A, target, q)


@pytest.mark.parametrize("k,n", [(2, 3), (3, 5), (4, 7), (5, 9), (2, 2)])
def test_every_quorum_reconstructs_the_residue(k, n):
    q = get_group("secp256k1").order
    s = secrets.randbelow(q)
    sh = laurent.split(s, laurent.Params(k, n, q))
    for S in itertools.combinations(sh, k):
        assert laurent.reconstruct(list(S), q) == s


@pytest.mark.parametrize("k,n", [(2, 6), (3, 8), (4, 9), (5, 10)])
def test_fewer_than_k_shares_are_perfectly_hiding(k, n):
    """For EVERY (k−1)-subset of holders and ANY candidate secret there is a
    consistent sharing — so those shares carry no information about the secret."""
    q = get_group("secp256k1").order
    p = laurent.Params(k, n, q)
    for S in itertools.combinations(p.points(), k - 1):
        A = [[pow(pow(x, -1, q), j, q) for j in range(k)] for x in S]
        A.append([0, 1] + [0] * (k - 2))                     # extra row: b₁ = candidate
        for candidate in (0, 1, secrets.randbelow(q)):
            b = [secrets.randbelow(q) for _ in S] + [candidate]
            solve(A, b, q)                                    # raises StopIteration if singular


def test_params_validation():
    q = get_group("secp256k1").order
    with pytest.raises(ValueError):
        laurent.Params(1, 3, q)
    with pytest.raises(ValueError):
        laurent.Params(4, 3, q)
    with pytest.raises(ValueError):
        laurent.Params(3, 33, q)
    with pytest.raises(ValueError):
        laurent.lambdas([1, 1, 2], q)


# ── groups & proofs ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", GROUPS)
def test_group_laws_and_codec(name):
    g = get_group(name)
    a, b = g.rand_scalar(), g.rand_scalar()
    A, B = g.mul(g.G, a), g.mul(g.G, b)
    assert g.eq(g.add(A, B), g.mul(g.G, a + b))
    assert g.eq(g.add(A, g.neg(A)), g.identity) and g.is_identity(g.mul(g.G, g.order))
    assert g.eq(g.mul_blinded(A, 12345), g.mul(A, 12345))
    for pt in (A, g.identity):
        assert g.eq(g.decode(g.encode(pt)), pt)


@pytest.mark.parametrize("name", GROUPS)
def test_decode_rejects_bad_points(name):
    g = get_group(name)
    good = bytearray(g.encode(g.mul(g.G, 7)))
    for bad in (bytes(10), bytes(65), bytes(31) + b"\x05" + bytes(32)):
        with pytest.raises(InvalidPoint):
            g.decode(bad)
    good[-1] ^= 1                                              # off the curve
    with pytest.raises(InvalidPoint):
        g.decode(bytes(good))
    with pytest.raises(InvalidPoint):
        g.from_hex("zz")


def test_schnorr_and_dleq_soundness():
    g = get_group("secp256k1")
    x = g.rand_scalar()
    P, pf = schnorr_prove(g, x, b"a")
    assert schnorr_verify(g, P, pf, b"a")
    assert not schnorr_verify(g, P, pf, b"b")                  # context-bound
    assert not schnorr_verify(g, g.mul(g.G, x + 1), pf, b"a")  # statement-bound
    E = g.mul(g.G, g.rand_scalar())
    Y, D = g.mul(g.G, x), g.mul(E, x)
    pr = dleq_prove(g, x, g.G, E, Y, D, b"c")
    assert dleq_verify(g, g.G, E, Y, D, pr, b"c")
    assert not dleq_verify(g, g.G, E, Y, g.mul(E, x + 1), pr, b"c")   # different exponent
    assert not dleq_verify(g, g.G, E, Y, D, pr, b"other")
    assert not dleq_verify(g, g.G, g.mul(E, 2), Y, D, pr, b"c")
    forged = dleq_prove(g, x + 1, g.G, E, Y, g.mul(E, x + 1), b"c")   # honest proof, wrong key
    assert not dleq_verify(g, g.G, E, Y, g.mul(E, x + 1), forged, b"c")


# ── DKG ──────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", GROUPS)
def test_dkg_produces_a_consistent_key(name):
    shares, pub, tx = run_local_ceremony(3, 5, name)
    g = pub.g
    assert pub.n == 5 and pub.k == 3 and pub.epoch == 0
    assert all(s.verify() for s in shares)
    # (test-only) the residue of any quorum equals the discrete log of X
    for S in ([1, 2, 3], [2, 4, 5], [1, 3, 5]):
        x = laurent.reconstruct([(i, shares[i - 1].y) for i in S], g.order)
        assert g.eq(g.mul(g.G, x), pub.X)
    # no single share (nor any dealer's secret) is the key
    x = laurent.reconstruct([(i, shares[i - 1].y) for i in (1, 2, 3)], g.order)
    assert all(s.y != x for s in shares)


def test_dkg_participants_agree_on_transcript_and_public_key():
    session = secrets.token_bytes(16)
    parts = [Participant("secp256k1", 2, 4, i, session) for i in range(1, 5)]
    d = {p.index: p.round1() for p in parts}
    bc = {i: x.broadcast for i, x in d.items()}
    outs = [p.finish(bc, {i: d[i].shares[p.index] for i in d}) for p in parts]
    assert len({o[2] for o in outs}) == 1
    assert len({json.dumps(o[1].to_json()) for o in outs}) == 1


def _ceremony(k=2, n=3):
    session = secrets.token_bytes(16)
    parts = [Participant("secp256k1", k, n, i, session) for i in range(1, n + 1)]
    d = {p.index: p.round1() for p in parts}
    return session, parts, d, {i: x.broadcast for i, x in d.items()}


def test_dkg_detects_a_bad_private_share_and_names_the_culprit():
    _, parts, d, bc = _ceremony()
    shares = {i: d[i].shares[1] for i in d}
    shares[2] = (shares[2] + 1) % get_group("secp256k1").order
    with pytest.raises(DKGError) as ei:
        parts[0].finish(bc, shares)
    assert ei.value.culprit == 2


def test_dkg_detects_tampered_commitments():
    _, parts, d, bc = _ceremony()
    g = parts[0].g
    b = bc[3]
    bad = Broadcast(3, (g.add(b.commitments[0], g.G),) + b.commitments[1:], b.proof)
    with pytest.raises(DKGError) as ei:
        parts[0].finish({**bc, 3: bad}, {i: d[i].shares[1] for i in d})
    assert ei.value.culprit == 3


def test_dkg_rejects_rogue_key_without_proof_of_knowledge():
    """A dealer cannot choose its residue commitment as a function of others'
    (e.g. to cancel them) without knowing its discrete log."""
    session, parts, d, bc = _ceremony()
    g = parts[0].g
    p = parts[0].p
    victim_x = g.add(bc[1].commitments[1], bc[2].commitments[1])
    # attacker (3) wants total X = target: sets C₃₁ = target − (C₁₁ + C₂₁), no PoK possible
    target = g.mul(g.G, 999)
    c31 = g.sub(target, victim_x)
    coeffs = laurent.new_coeffs(5, p)
    comms = [g.mul(g.G, c) for c in coeffs]
    comms[1] = c31
    forged = Broadcast(3, tuple(comms), bc[3].proof)           # reuses an old proof
    shares = {x: laurent.evaluate(coeffs, x, g.order) for x in p.points()}
    with pytest.raises(DKGError, match="proof of knowledge"):
        check_dealing(g, p, forged, 1, shares[1], session)


def test_dkg_requires_every_participant():
    _, parts, d, bc = _ceremony(2, 4)
    with pytest.raises(DKGError, match="all 4"):
        parts[0].finish({i: bc[i] for i in (1, 2, 3)}, {i: d[i].shares[1] for i in d})
    with pytest.raises(DKGError, match="private share from every"):
        parts[0].finish(bc, {i: d[i].shares[1] for i in (1, 2, 3)})


def test_dkg_proofs_are_bound_to_the_session():
    s1, parts, d, bc = _ceremony()
    g, p = parts[0].g, parts[0].p
    with pytest.raises(DKGError, match="proof of knowledge"):
        check_dealing(g, p, bc[2], 1, d[2].shares[1], secrets.token_bytes(16))


# ── threshold use of the key ─────────────────────────────────────────────────
def test_open_with_every_quorum_but_never_with_fewer(key35):
    shares, pub, _ = key35
    K, hdr = wrap_key(pub, b"ctx")
    for S in itertools.combinations(shares, 3):
        assert unwrap_key(pub, hdr, opener(pub, S)) == K
    for S in itertools.combinations(shares, 2):
        with pytest.raises(InsufficientPartials):
            unwrap_key(pub, hdr, opener(pub, S))


def test_envelope_binds_context_key_and_ephemeral(key35):
    shares, pub, _ = key35
    K1, h1 = wrap_key(pub, b"a")
    K2, h2 = wrap_key(pub, b"a")
    assert K1 != K2 and h1["E"] != h2["E"]                      # fresh ephemeral each time
    other_shares, other_pub, _ = run_local_ceremony(3, 5)
    with pytest.raises(CustodyError, match="different key"):
        unwrap_key(other_pub, h1, opener(other_pub, other_shares))
    forged = dict(h1, ctx=b"b".hex())
    assert unwrap_key(pub, forged, opener(pub, shares[:3])) != K1   # context is in the KDF


def test_a_wrong_partial_is_detected_and_excluded(key35):
    shares, pub, _ = key35
    g = pub.g
    K, hdr = wrap_key(pub, b"x")
    E = g.from_hex(hdr["E"])
    good = [partial_decrypt(s, E, b"x") for s in shares]
    # custodian 1 returns y·E + G (wrong) but keeps its (now false) proof
    evil = replace(good[0], D=g.add(good[0].D, g.G))
    assert not verify_partial(pub, E, evil, b"x")
    x_E = combine(pub, E, [evil] + good[1:], b"x")              # 4 honest remain → fine
    assert g.eq(x_E, combine(pub, E, good, b"x"))
    with pytest.raises(InsufficientPartials) as ei:
        combine(pub, E, [evil, good[1], good[2]], b"x")         # only 2 honest left
    assert 1 in ei.value.problems


def test_partial_for_another_context_or_key_is_rejected(key35):
    shares, pub, _ = key35
    g = pub.g
    E = g.mul(g.G, 77)
    p = partial_decrypt(shares[0], E, b"ctx-A")
    assert verify_partial(pub, E, p, b"ctx-A")
    assert not verify_partial(pub, E, p, b"ctx-B")
    assert not verify_partial(pub, g.mul(g.G, 78), p, b"ctx-A")
    assert not verify_partial(pub, E, replace(p, index=2), b"ctx-A")
    assert not verify_partial(pub, E, replace(p, index=99), b"ctx-A")


def test_custodian_refuses_the_identity_point(key35):
    shares, pub, _ = key35
    with pytest.raises(CustodyError):
        partial_decrypt(shares[0], pub.g.identity, b"")


def test_partial_never_contains_the_share_or_key(key35):
    shares, pub, _ = key35
    g = pub.g
    E = g.mul(g.G, secrets.randbelow(g.order))
    x = laurent.reconstruct([(s.index, s.y) for s in shares[:3]], g.order)
    for s in shares:
        p = partial_decrypt(s, E, b"")
        blob = json.dumps(p.to_json(g))
        for secret in (s.y, x):
            assert hex(secret)[2:] not in blob and format(secret, "064x") not in blob
        assert p.proof.z not in (s.y, x)


def test_the_key_is_never_reassembled_by_use_reshare_or_refresh(key35, monkeypatch):
    """Every threshold *use* path must work with the reconstruction function
    disabled — proof that the key is not assembled anywhere."""
    shares, pub, _ = key35
    boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("key reassembled!"))
    monkeypatch.setattr(laurent, "reconstruct", boom)
    K, hdr = wrap_key(pub, b"z")
    assert unwrap_key(pub, hdr, opener(pub, shares[1:4])) == K
    new, npub = refresh(shares)
    assert unwrap_key(npub, hdr, opener(npub, new[:3])) == K
    new2, p2 = run_local_reshare(shares, [1, 2, 3], 2, 4)
    assert unwrap_key(p2, hdr, opener(p2, new2[:2])) == K


def test_mixed_or_stale_epoch_partials_do_not_combine(key35):
    shares, pub, _ = key35
    g = pub.g
    new, npub = refresh(shares)
    K, hdr = wrap_key(pub, b"e")
    E = g.from_hex(hdr["E"])
    mixed = [partial_decrypt(shares[0], E, b"e"), partial_decrypt(shares[1], E, b"e"),
             partial_decrypt(new[2], E, b"e")]
    with pytest.raises(InsufficientPartials):
        combine(npub, E, mixed, b"e")                           # old-epoch partials fail the new keys
    with pytest.raises(InsufficientPartials):
        combine(pub, E, mixed, b"e")


def test_quorum_tolerates_unavailable_and_slow_custodians(key35):
    shares, pub, _ = key35
    K, hdr = wrap_key(pub, b"t")

    class Down:
        label = "down"
        def partial(self, E, ctx): raise ConnectionError("host unreachable")

    class Evil:
        label = "evil"
        def __init__(self, s): self.s = s
        def partial(self, E, ctx):
            p = partial_decrypt(self.s, E, ctx)
            return replace(p, D=pub.g.add(p.D, pub.g.G))

    cs = [Down(), Evil(shares[1]), LocalCustodian(shares[2]), LocalCustodian(shares[3]),
          LocalCustodian(shares[4])]
    assert unwrap_key(pub, hdr, Quorum(pub, cs, timeout=10).shared_point) == K
    with pytest.raises(InsufficientPartials) as ei:
        Quorum(pub, [Down(), Evil(shares[1]), LocalCustodian(shares[2])]).shared_point(pub.g.G, b"")
    assert any("invalid proof" in v or "unreachable" in v for v in ei.value.problems.values())


def test_wrap_needs_only_the_public_key(key35):
    _, pub, _ = key35
    c = ThresholdCustody(PublicKey.from_json(json.loads(json.dumps(pub.to_json()))))
    K, hdr = c.wrap(b"write-only")
    assert isinstance(K, int)
    with pytest.raises(CustodyError, match="requires a quorum"):
        c.unwrap(hdr)


# ── resharing / refresh / membership change ──────────────────────────────────
@pytest.mark.parametrize("quorum,k2,n2", [([1, 2, 3], 3, 5), ([2, 4, 5], 4, 7),
                                           ([1, 3, 4], 2, 3), ([3, 4, 5], 5, 9)])
def test_reshare_preserves_the_key_for_any_quorum_and_new_shape(key35, quorum, k2, n2):
    shares, pub, _ = key35
    K, hdr = wrap_key(pub, b"r")
    new, npub = run_local_reshare(shares, quorum, k2, n2)
    assert npub.X == pub.X or pub.g.eq(npub.X, pub.X)
    assert npub.key_id == pub.key_id and npub.epoch == 1
    assert npub.k == k2 and npub.n == n2 and all(s.verify() for s in new)
    for S in itertools.islice(itertools.combinations(new, k2), 6):
        assert unwrap_key(npub, hdr, opener(npub, S)) == K
    with pytest.raises(InsufficientPartials):
        unwrap_key(npub, hdr, opener(npub, new[:k2 - 1]))


def test_refresh_replaces_every_share(key35):
    shares, pub, _ = key35
    new, npub = refresh(shares)
    assert all(a.y != b.y for a, b in zip(shares, new))
    assert npub.epoch == 1 and refresh(new)[1].epoch == 2


def test_reshare_detects_a_dealer_who_reshares_the_wrong_value(key35):
    shares, pub, _ = key35
    g = pub.g
    spec = ReshareSpec(pub, (1, 2, 3), 3, 5, secrets.token_bytes(16))
    deals = {i: reshare_deal(spec, shares[i - 1]) for i in (1, 2, 3)}
    cheat = replace(shares[2], y=(shares[2].y + 1) % g.order)       # holder 3 lies
    deals[3] = deal(g, spec.new_params, 3, spec.lam()[3] * cheat.y % g.order, spec.session, with_pok=False)
    bc = {i: d.broadcast for i, d in deals.items()}
    with pytest.raises(DKGError) as ei:
        reshare_finish(spec, 1, bc, {i: deals[i].shares[1] for i in deals})
    assert ei.value.culprit == 3


def test_reshare_detects_a_bad_subshare_and_wrong_quorum(key35):
    shares, pub, _ = key35
    spec = ReshareSpec(pub, (1, 2, 3), 3, 5, secrets.token_bytes(16))
    deals = {i: reshare_deal(spec, shares[i - 1]) for i in (1, 2, 3)}
    bc = {i: d.broadcast for i, d in deals.items()}
    sh = {i: deals[i].shares[2] for i in deals}
    sh[1] = (sh[1] + 5) % pub.g.order
    with pytest.raises(DKGError) as ei:
        reshare_finish(spec, 2, bc, sh)
    assert ei.value.culprit == 1
    with pytest.raises(CustodyError):
        ReshareSpec(pub, (1, 2), 3, 5, b"s")                        # needs exactly k dealers
    with pytest.raises(CustodyError):
        reshare_deal(spec, shares[3])                                # holder 4 is not dealing


def test_old_quorum_cannot_open_after_reshare_to_a_new_committee(key35):
    """A custodian who was REMOVED holds a share of the old epoch only."""
    shares, pub, _ = key35
    new, npub = run_local_reshare(shares, [1, 2, 3], 3, 5)
    _, hdr = wrap_key(pub, b"q")
    E = pub.g.from_hex(hdr["E"])
    stale = [partial_decrypt(s, E, b"q") for s in shares[:3]]
    with pytest.raises(InsufficientPartials):
        combine(npub, E, stale, b"q")


# ── key & share files ────────────────────────────────────────────────────────
def test_public_key_roundtrip_and_integrity(key35, tmp_path):
    _, pub, _ = key35
    pub.save(str(tmp_path / "p.json"))
    assert PublicKey.load(str(tmp_path / "p.json")).key_id == pub.key_id
    d = pub.to_json()
    d["key_id"] = "0" * 32
    with pytest.raises(ShareError):
        PublicKey.from_json(d)
    d = pub.to_json()
    d["commitments"] = d["commitments"][:-1]
    with pytest.raises(ShareError):
        PublicKey.from_json(d)


def test_share_file_sealed_perms_and_tamper(key35, tmp_path):
    shares, pub, _ = key35
    p = str(tmp_path / "s.json")
    shares[0].save(p, "correct horse")
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    raw = open(p, "rb").read()
    assert hex(shares[0].y)[2:].encode() not in raw
    assert KeyShare.load(p, "correct horse").y == shares[0].y
    with pytest.raises(ShareError, match="wrong passphrase"):
        KeyShare.load(p, "wrong")
    with pytest.raises(ShareError, match="passphrase required"):
        KeyShare.load(p, None)
    flipped = bytearray(raw)
    flipped[-3] ^= 1
    open(p, "wb").write(bytes(flipped))
    with pytest.raises(ShareError):
        KeyShare.load(p, "correct horse")


def test_share_that_does_not_match_the_commitments_is_rejected_on_load(key35, tmp_path):
    shares, pub, _ = key35
    d = shares[0].to_json()
    d["y"] = hex(shares[0].y + 1)
    with pytest.raises(ShareError, match="does not match"):
        KeyShare.from_json(d)


# ── identities & transport ───────────────────────────────────────────────────
def test_signed_broadcasts_and_encrypted_shares(tmp_path):
    a, b = ident.Identity.new("secp256k1", 1), ident.Identity.new("secp256k1", 2)
    g = a.g
    session = b"S" * 16
    part = Participant("secp256k1", 2, 2, 1, session)
    dl = part.round1()
    msg = ident.sign_broadcast(a, "dkg", session, dl.broadcast)
    assert ident.open_broadcast(g, a.public, msg, "dkg", session).index == 1
    with pytest.raises(CustodyError, match="bad signature"):
        ident.open_broadcast(g, b.public, msg, "dkg", session)          # wrong signer
    with pytest.raises(CustodyError, match="different ceremony"):
        ident.open_broadcast(g, a.public, msg, "reshare", session)
    with pytest.raises(CustodyError, match="different ceremony"):
        ident.open_broadcast(g, a.public, msg, "dkg", b"T" * 16)
    tampered = json.loads(json.dumps(msg))
    tampered["body"]["bcast"]["commitments"][0] = g.hex(g.G)
    with pytest.raises(CustodyError, match="bad signature"):
        ident.open_broadcast(g, a.public, tampered, "dkg", session)
    enc = ident.encrypt_share(a, b.public, session, 2, 123456789)
    assert ident.decrypt_share(b, session, enc, a.public) == 123456789
    assert "123456789" not in json.dumps(enc)
    with pytest.raises(CustodyError):
        ident.decrypt_share(a, session, enc, a.public)                  # not addressed to a
    with pytest.raises(CustodyError, match="signature"):
        ident.decrypt_share(b, session, enc, b.public)                  # not signed by that dealer
    forged = dict(enc)
    forged["ct"] = enc["ct"][:-2] + ("00" if enc["ct"][-2:] != "00" else "01")
    with pytest.raises(CustodyError, match="signature"):               # tampering breaks the signature
        ident.decrypt_share(b, session, forged, a.public)


def test_identity_file_roundtrip_and_fingerprint(tmp_path):
    i = ident.Identity.new("secp256k1", 3)
    i.save(str(tmp_path / "id"), "pw")
    j = ident.Identity.load(str(tmp_path / "id"), "pw")
    assert j.secret == i.secret and j.fingerprint() == i.fingerprint()
    with pytest.raises(CustodyError):
        ident.Identity.load(str(tmp_path / "id"), "bad")
    assert len(i.fingerprint().split()) == 8


def test_file_based_ceremony_end_to_end_and_substitution_attacks(tmp_path):
    n, k = 4, 3
    ids = [ident.Identity.new("secp256k1", i) for i in range(1, n + 1)]
    pubs = {i.index: i.public for i in ids}
    session = secrets.token_bytes(16)
    parts = [Participant("secp256k1", k, n, i.index, session) for i in ids]
    box = str(tmp_path / "box")
    for idn, pt in zip(ids, parts):
        ident.export_dealing(idn, "dkg", session, pt.round1(), pubs, box)
    res = []
    for idn, pt in zip(ids, parts):
        bc, sh = ident.import_dealings(idn, "dkg", session, box, pubs, list(range(1, n + 1)))
        res.append(pt.finish(bc, sh))
    assert len({r[2] for r in res}) == 1 and all(r[0].verify() for r in res)
    # an attacker replaces participant 2's broadcast with their own dealing
    evil = ident.Identity.new("secp256k1", 2)
    ident.export_dealing(evil, "dkg", session, Participant("secp256k1", k, n, 2, session).round1(),
                         pubs, box)
    with pytest.raises(CustodyError, match="bad signature"):
        ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3, 4])
    # swapping two private-share files is caught by decryption/commitment checks
    ident.export_dealing(ids[1], "dkg", session, parts[1].round1(), pubs, box)
    a, b = tmp_path / "box" / "share_3_to_1.json", tmp_path / "box" / "share_4_to_1.json"
    ta, tb = a.read_text(), b.read_text()
    a.write_text(tb); b.write_text(ta)
    with pytest.raises(CustodyError, match="files swapped"):
        ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3, 4])
    a.write_text(ta); b.write_text(tb)                                   # swap back
    with pytest.raises(CustodyError, match="missing files"):
        ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3, 4, 5])


# ═══ hardening round: constant-time mul, audit rotation, C-15 residue, fingerprints ═══════════
def _have_mcl():
    try:
        from torusdb_core import fhe_backend
        return "mcl" in fhe_backend.available()
    except Exception:                                                  # noqa: BLE001
        return False


def test_bn254_secret_multiplication_matches_pure_python_and_reports_its_mode(monkeypatch):
    g = get_group("bn254")
    from py_ecc.optimized_bn128 import G1, multiply
    for k in [1, 2, 12345, g.order - 1, secrets.randbelow(g.order), 0, g.order]:
        want = g.identity if k % g.order == 0 else multiply(G1, k % g.order)
        assert g.eq(g.mul_secret(g.G, k), want) and g.eq(g.mul_blinded(g.G, k), want)
        P = g.mul(g.G, 777)
        assert g.eq(g.mul_secret(P, k), g.mul(P, k))
    assert g.is_identity(g.mul_secret(g.identity, 5))
    assert g.constant_time is _have_mcl()                              # native mulCT iff mclbn256 is there
    assert get_group("secp256k1").constant_time is False                # pure Python: documented, not CT
    # switching the accelerator off falls back to the (variable-time) blinded path, same results
    monkeypatch.setenv("TORUSSQL_CUSTODY_NATIVE", "0")
    from torussql.custody.group import _Bn254
    off = _Bn254()
    assert off.constant_time is False and off.eq(off.mul_secret(off.G, 99), multiply(G1, 99))


@pytest.mark.skipif(not _have_mcl(), reason="native mclbn256 back end not available")
def test_native_backend_constant_time_multiplication_agrees_with_py_ecc():
    from torusdb_core import fhe_backend as fb
    m, p = fb.get("mcl"), fb.get("pyecc")
    assert m.constant_time and not p.constant_time
    for k in [0, 1, fb.N - 1, secrets.randbelow(fb.N), secrets.randbelow(fb.N)]:
        assert m.g1_to(m.g1_mul_secret(m.G1, k)) == p.g1_to(p.g1_mul_secret(p.G1, k)) == m.g1_to(m.g1_mul(m.G1, k))
        assert m.g2_to(m.g2_mul_secret(m.G2, k)) == p.g2_to(p.g2_mul_secret(p.G2, k))
    # DLEQ / Schnorr proofs made through the CT path verify and shares verify
    shares, pub, _ = run_local_ceremony(2, 3, "bn254")
    assert all(s.verify() for s in shares)
    E = pub.g.mul(pub.g.G, 31337)
    part = partial_decrypt(shares[0], E, b"x")
    assert verify_partial(pub, E, part, b"x")


def test_audit_log_rotation_keeps_the_configured_number_of_files(tmp_path):
    from torussql.custody.net import Custodian, LocalNode
    shares, pub, _ = run_local_ceremony(2, 3, "secp256k1")
    g = pub.g
    E = g.mul(g.G, 5)
    for keep in (3, 1, 0):
        path = tmp_path / f"audit{keep}.log"
        c = Custodian(shares[0], {"owner": "owner-token-0123456789abc"}, audit_path=str(path),
                      audit_max_bytes=400, audit_keep=keep, rate_per_minute=100_000)
        node = LocalNode(c, caller="owner")
        for _ in range(60):
            node.partial(E, b"")
        files = sorted(f.name for f in tmp_path.glob(f"audit{keep}.log*"))
        assert files == sorted([f"audit{keep}.log"] + [f"audit{keep}.log.{i}" for i in range(1, keep + 1)])
        for f in tmp_path.glob(f"audit{keep}.log*"):
            assert (f.stat().st_mode & 0o777) == 0o600
            assert f.stat().st_size < 1200                     # bounded
    assert (tmp_path / "audit3.log.1").read_text().count("served") > 0


def test_dealings_that_contribute_nothing_are_rejected(key35):
    g = get_group("bn254")
    p = laurent.Params(2, 3, g.order)
    sess = b"s" * 16
    d = deal(g, p, 1, None, sess)
    b = d.broadcast
    check_dealing(g, p, b, 2, d.shares[2], sess)                       # an honest dealing is accepted
    for pos in (0, 1):                                                 # constant term / residue = identity
        comms = list(b.commitments); comms[pos] = g.identity
        with pytest.raises(DKGError, match="contributes nothing"):
            check_dealing(g, p, Broadcast(1, tuple(comms), b.proof), 2, d.shares[2], sess)
        with pytest.raises(DKGError, match="contributes nothing"):
            check_dealing(g, p, Broadcast(1, tuple(comms), b.proof), 2, d.shares[2], sess, need_pok=False)
    # a zero-residue dealer with a VALID proof of knowledge of 0 is also caught
    zd = deal(g, p, 2, 0, sess)
    with pytest.raises(DKGError, match="contributes nothing"):
        check_dealing(g, p, zd.broadcast, 1, zd.shares[1], sess)
    # through the participant API too
    parts = [Participant("bn254", 2, 3, i, sess) for i in (1, 2, 3)]
    ds = {pt.index: pt.round1() for pt in parts}
    bad = Broadcast(2, (ds[2].broadcast.commitments[0], g.identity), ds[2].broadcast.proof)
    bc = {i: ds[i].broadcast for i in ds}; bc[2] = bad
    with pytest.raises(DKGError, match="contributes nothing"):
        parts[0].finish(bc, {i: ds[i].shares[1] for i in ds})
    # reshare: never rejects honest dealers (fresh coefficients are never 0)
    shares, pub, _ = run_local_ceremony(2, 3, "bn254")
    new, npub = run_local_reshare(shares, [1, 2], 2, 3)
    assert npub.key_id == pub.key_id


def test_reshare_broadcasts_are_bound_to_both_committees_identity_lists(tmp_path):
    from torussql.custody.identity import Identity, export_dealing, ids_digest, import_dealings
    shares, pub, _ = run_local_ceremony(2, 3, "secp256k1")
    g = pub.g
    old = {i: Identity.new("secp256k1", i) for i in (1, 2, 3)}
    new = {i: Identity.new("secp256k1", i) for i in (1, 2, 3)}
    evil = {i: Identity.new("secp256k1", i) for i in (1, 2, 3)}
    pubs = lambda ids: {i: x.public for i, x in ids.items()}
    spec = ReshareSpec(pub, (1, 2), 2, 3, b"r" * 16)
    dig = lambda ids: ids_digest(g, pubs(ids))
    good = spec.params(dig(old), dig(new))
    assert good["new_ids"] == dig(new) and good["old_ids"] == dig(old)
    d1 = reshare_deal(spec, shares[0])
    export_dealing(old[1], "reshare", spec.session, d1, pubs(new), str(tmp_path / "ok"), good)
    # same files, but the recipient believes the new committee is someone else: refused
    with pytest.raises(CustodyError, match="different ceremony"):
        import_dealings(new[1], "reshare", spec.session, str(tmp_path / "ok"), pubs(old), [1],
                        spec.params(dig(old), dig(evil)))
    # an old-format broadcast (no new_ids in its signed params) is refused with a clear message
    legacy = {k: v for k, v in good.items() if k != "new_ids"}
    export_dealing(old[1], "reshare", spec.session, d1, pubs(new), str(tmp_path / "old"), legacy)
    with pytest.raises(CustodyError, match="OLD format"):
        import_dealings(new[1], "reshare", spec.session, str(tmp_path / "old"), pubs(old), [1], good)
    bc, sh = import_dealings(new[1], "reshare", spec.session, str(tmp_path / "ok"), pubs(old), [1], good)
    assert set(bc) == {1}


def test_public_key_fingerprint_is_a_trust_anchor():
    shares, pub, _ = run_local_ceremony(2, 3, "bn254")
    fp = pub.fingerprint
    assert len(fp.replace("-", "")) == 64 and fp == PublicKey.from_json(pub.to_json()).fingerprint
    pub.check_fingerprint(None)
    pub.check_fingerprint(fp)
    pub.check_fingerprint(fp.upper().replace("-", " "))                 # formatting is irrelevant
    pub.check_fingerprint(fp.replace("-", ":"))
    for bad in ("", "00" * 32, fp[:-1] + ("0" if fp[-1] != "0" else "1")):
        with pytest.raises(ShareError, match="fingerprint"):
            pub.check_fingerprint(bad)
    new, npub = refresh(shares)
    assert npub.key_id == pub.key_id and npub.fingerprint != fp          # re-pin after a refresh
    # a file with swapped non-X commitments (same key_id!) has a different fingerprint
    forged = PublicKey(pub.group, pub.k, pub.n, (pub.g.mul(pub.g.G, 3), pub.commitments[1]), pub.epoch)
    assert forged.key_id == pub.key_id and forged.fingerprint != fp
