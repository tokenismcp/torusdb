# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the second custody audit (findings C-03, C-05, C-07, C-09 ..
C-15). Each test pins a behaviour that was wrong before the fix."""
from __future__ import annotations

import copy
import json
import logging
import os
import pickle
import secrets
import socket
import stat
import struct
import threading
import time

import pytest

from torussql.custody import (CustodyError, DKGError, KeyShare, LocalCustodian, Participant,
                              PublicKey, ReshareSpec, ShareError, get_group, partial_decrypt,
                              reshare_deal, reshare_finish, run_local_ceremony,
                              transcript_hash)
from torussql.custody import identity as ident
from torussql.custody import keys as keysmod
from torussql.custody import seal as _seal
from torussql.custody.group import Group
from torussql.custody.net import Custodian, CustodianServer, RemoteCustodian
from torussql.custody.proofs import dleq_prove, schnorr_prove
from torussql.framing import read_frame, write_frame

TOKEN = "owner-token-0123456789abc"


@pytest.fixture(scope="module")
def key23():
    return run_local_ceremony(2, 3)


# ── C-03: mul_blinded is a real scalar split ─────────────────────────────────
@pytest.mark.parametrize("name", ["secp256k1", "bn254"])
def test_mul_blinded_splits_the_scalar_and_is_correct(name, monkeypatch):
    g = get_group(name)
    A = g.mul(g.G, 12345)
    k = secrets.randbelow(g.order)
    seen = []
    orig = type(g).mul
    monkeypatch.setattr(type(g), "mul", lambda self, a, kk: (seen.append(kk % g.order),
                                                              orig(self, a, kk))[1])
    res = g.mul_blinded(A, k)
    monkeypatch.undo()
    assert g.eq(res, g.mul(A, k))
    assert len(seen) == 2 and k not in seen                  # never the raw scalar
    assert (seen[0] + seen[1]) % g.order == k % g.order
    seen2 = []
    monkeypatch.setattr(type(g), "mul", lambda self, a, kk: (seen2.append(kk % g.order),
                                                               orig(self, a, kk))[1])
    g.mul_blinded(A, k)
    monkeypatch.undo()
    assert seen2 != seen                                     # fresh randomness per call
    assert g.is_identity(g.mul_blinded(A, 0)) and g.is_identity(g.mul_blinded(A, g.order))
    assert g.is_identity(g.mul_blinded(g.identity, 5))


def test_secret_scalars_never_reach_plain_mul(key23, monkeypatch):
    shares, pub, _ = key23
    g = pub.g
    E = g.mul(g.G, 777)
    sh = shares[0]
    idn = ident.Identity.new("secp256k1", 1)
    seen = []
    orig = type(g).mul
    monkeypatch.setattr(type(g), "mul", lambda self, a, kk: (seen.append(kk % g.order),
                                                              orig(self, a, kk))[1])
    partial_decrypt(sh, E, b"c")                             # D = y·E and the DLEQ nonce
    assert sh.y not in seen
    schnorr_prove(g, idn.secret, b"x")
    sh.verify()
    ident.encrypt_share(idn, idn.public, b"S" * 16, 1, 5)
    assert sh.y not in seen and idn.secret not in seen


# ── C-05: canonical E, one approve signature ─────────────────────────────────
def test_approve_sees_canonical_E_and_local_matches_network(key23):
    shares, pub, _ = key23
    g = pub.g
    E = g.mul(g.G, 4242)
    got = []
    c = Custodian(shares[0], {"owner": TOKEN}, approve=lambda caller, e, ctx: (got.append((caller, e, ctx)), True)[1])
    canon = g.hex(E)
    for variant in (canon.upper(), " ".join(canon[i:i + 8] for i in range(0, len(canon), 8))):
        c.dispatch("owner", "p", "partial", [variant, "6162"])
    assert [e for _, e, _ in got] == [canon, canon]          # case/whitespace aliases collapse
    assert got[0][0] == "owner" and got[0][2] == b"ab"
    loc = []
    lc = LocalCustodian(shares[1], approve=lambda caller, e, ctx: (loc.append((caller, e, ctx)), True)[1])
    lc.partial(E, b"zz")
    assert loc == [("local", canon, b"zz")]


# ── C-07: secrets never in repr, never pickled ───────────────────────────────
def test_secret_fields_not_in_repr_and_not_picklable(key23):
    shares, _, _ = key23
    sh = shares[0]
    idn = ident.Identity.new("secp256k1", 1)
    for obj, secret in ((sh, sh.y), (idn, idn.secret)):
        text = repr(obj) + str(obj) + f"{obj!r}"
        assert str(secret) not in text and hex(secret)[2:] not in text
        assert format(secret, "x") not in text
        for fn in (pickle.dumps, copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                fn(obj)


# ── C-09: dealer-signed private shares ───────────────────────────────────────
def test_share_files_are_dealer_signed_and_forgery_is_not_blamed_on_the_dealer(tmp_path):
    n, k = 3, 2
    ids = [ident.Identity.new("secp256k1", i) for i in range(1, n + 1)]
    pubs = {i.index: i.public for i in ids}
    session = secrets.token_bytes(16)
    parts = [Participant("secp256k1", k, n, i.index, session) for i in ids]
    box = str(tmp_path / "box")
    for idn, pt in zip(ids, parts):
        ident.export_dealing(idn, "dkg", session, pt.round1(), pubs, box)
    # an outsider replaces share_1_to_2.json with a well-formed encrypted share
    mallory = ident.Identity.new("secp256k1", 1)
    forged = ident.encrypt_share(mallory, pubs[2], session, 2, 123456)
    (tmp_path / "box" / "share_1_to_2.json").write_text(json.dumps(forged))
    with pytest.raises(CustodyError, match="signature") as ei:
        ident.import_dealings(ids[1], "dkg", session, box, pubs, [1, 2, 3])
    assert not isinstance(ei.value, DKGError)                 # not "participant 1: share does not match"
    # an unsigned / old-format file is refused as well
    old = dict(forged)
    del old["sig"]
    (tmp_path / "box" / "share_1_to_2.json").write_text(json.dumps(old))
    with pytest.raises(CustodyError):
        ident.import_dealings(ids[1], "dkg", session, box, pubs, [1, 2, 3])


# ── C-10 / C-15: reshare_finish validation ───────────────────────────────────
def _reshare_setup(key):
    shares, pub, _ = key
    spec = ReshareSpec(pub, (1, 2), 2, 3, b"R" * 16)
    deals = {i: reshare_deal(spec, shares[i - 1]) for i in (1, 2)}
    return spec, deals


def test_reshare_finish_short_commitments_is_a_clean_blame_not_indexerror(key23):
    spec, deals = _reshare_setup(key23)
    bc = {i: d.broadcast for i, d in deals.items()}
    b = bc[1]
    bc[1] = type(b)(b.index, b.commitments[:1], b.proof)
    with pytest.raises(DKGError, match="commitments") as ei:
        reshare_finish(spec, 1, bc, {i: deals[i].shares[1] for i in deals})
    assert ei.value.culprit == 1
    bc[1] = type(b)(b.index, (), b.proof)
    with pytest.raises(DKGError):
        reshare_finish(spec, 1, bc, {i: deals[i].shares[1] for i in deals})


def test_reshare_finish_range_checks_my_index(key23):
    spec, deals = _reshare_setup(key23)
    bc = {i: d.broadcast for i, d in deals.items()}
    for bad in (0, 4, -1):
        with pytest.raises(DKGError, match="my_index"):
            reshare_finish(spec, bad, bc, {i: deals[i].shares[1] for i in deals})
    ks, _ = reshare_finish(spec, 3, bc, {i: deals[i].shares[3] for i in deals})
    assert ks.verify()


# ── C-11: replace_share ──────────────────────────────────────────────────────
def test_replace_share_requires_same_index_and_newer_epoch(key23):
    from torussql.custody import refresh
    shares, pub, _ = key23
    c = Custodian(shares[0], {"owner": TOKEN})
    new, _ = refresh(shares)
    with pytest.raises(CustodyError, match="custodian"):
        c.replace_share(new[1])                              # a different custodian's share
    with pytest.raises(CustodyError, match="epoch"):
        c.replace_share(shares[0])                           # same epoch
    c.replace_share(new[0])
    assert c.info()["epoch"] == 1
    with pytest.raises(CustodyError, match="epoch"):
        c.replace_share(shares[0])                           # rollback to epoch 0
    with pytest.raises(CustodyError, match="epoch"):
        c.replace_share(new[0])                              # replay of the current one
    assert c.info()["epoch"] == 1


# ── C-12: daemon hardening ───────────────────────────────────────────────────
def _rpc(sock_f, obj, limit=1 << 20):
    rf, wf = sock_f
    write_frame(wf, json.dumps(obj).encode() if not isinstance(obj, bytes) else obj, 1 << 20)
    p = read_frame(rf, limit)
    return None if p is None else json.loads(p)


def _conn(port, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return s, (s.makefile("rb"), s.makefile("wb"))


def _serve(share, tmp_path, **kw):
    audit = str(tmp_path / f"audit_{secrets.token_hex(3)}.log")
    skw = {k: kw.pop(k) for k in list(kw) if k in ("idle_timeout", "auth_deadline",
                                                    "max_connections", "max_per_ip")}
    c = Custodian(share, {"owner": TOKEN}, audit_path=audit, **kw)
    srv = CustodianServer("127.0.0.1", 0, c, **skw)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return c, srv, audit


def _lines(path):
    return [json.loads(l) for l in open(path)]


def test_audit_file_is_0600_and_refuses_symlinks(key23, tmp_path):
    shares, _, _ = key23
    p = tmp_path / "a.log"
    p.write_text("")
    os.chmod(p, 0o666)
    Custodian(shares[0], {"owner": TOKEN}, audit_path=str(p))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600           # lax pre-existing file tightened
    fresh = tmp_path / "fresh.log"
    Custodian(shares[0], {"owner": TOKEN}, audit_path=str(fresh))
    assert stat.S_IMODE(os.stat(fresh).st_mode) == 0o600
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "link.log"
    os.symlink(target, link)
    with pytest.raises(OSError):
        Custodian(shares[0], {"owner": TOKEN}, audit_path=str(link))
    assert target.read_text() == "keep"


def test_failed_and_unauthenticated_attempts_are_audited(key23, tmp_path):
    shares, _, _ = key23
    c, srv, audit = _serve(shares[0], tmp_path)
    try:
        s, f = _conn(srv.address[1])
        assert "err" in _rpc(f, {"m": "auth", "a": ["wrong-token-0123456789"]})
        assert "err" in _rpc(f, {"m": "partial", "a": ["00", ""]})        # unauthenticated
        assert "err" in _rpc(f, b"[]")                                    # junk frame
        s.close()
        out = [l["outcome"] for l in _lines(audit)]
        assert any(o.startswith("denied: invalid token") for o in out)
        assert any(o == "denied: unauthenticated" for o in out)
        assert any(o == "rejected: malformed" for o in out)
        assert "wrong-token" not in open(audit).read()                    # never logs a token
    finally:
        srv.shutdown(); srv.server_close()


def test_unauthenticated_audit_is_rate_limited_and_bounded(key23, tmp_path):
    shares, _, _ = key23
    c = Custodian(shares[0], {"owner": TOKEN}, audit_path=str(tmp_path / "a.log"),
                  unauth_audit_per_minute=10)
    for i in range(500):
        c.audit_unauth("9.9.9.9:%d" % i, "request", "denied: unauthenticated")
    lines = _lines(tmp_path / "a.log")
    assert len(lines) <= 12                                              # per-IP budget, not 500
    c2 = Custodian(shares[0], {"owner": TOKEN}, audit_path=str(tmp_path / "b.log"),
                   audit_max_bytes=2000)
    for i in range(200):
        c2._audit("owner", "p", "partial", {"i": i}, "served")
    assert os.path.getsize(tmp_path / "b.log") <= 2000 + 400            # rotated, bounded
    assert os.path.exists(str(tmp_path / "b.log") + ".1")


def test_rate_limit_applies_before_malformed_requests_are_audited(key23, tmp_path):
    shares, _, _ = key23
    audit = str(tmp_path / "a.log")
    c = Custodian(shares[0], {"owner": TOKEN}, audit_path=audit, rate_per_minute=5)
    for _ in range(40):
        with pytest.raises(CustodyError):
            c.dispatch("owner", "p", "partial", ["zz-not-hex", ""])
    assert len(_lines(audit)) <= 8                                       # was 40


def test_no_traceback_spam_before_auth(key23, tmp_path, caplog):
    shares, _, _ = key23
    c, srv, audit = _serve(shares[0], tmp_path)
    try:
        with caplog.at_level(logging.DEBUG, logger="torusdb.custodian"):
            for junk in (b"[]", b'"x"', b'{"m": {}}', b"\xff\xfe", b'{"m":"auth","a":[]}',
                         b'{"m":"auth","a":[{"x":1}]}', b"null"):
                s, f = _conn(srv.address[1])
                r = _rpc(f, junk)
                assert r is None or "err" in r
                s.close()
        assert not [r for r in caplog.records if r.exc_info]
    finally:
        srv.shutdown(); srv.server_close()


def test_connection_cap_and_pre_auth_deadline(key23, tmp_path):
    shares, _, _ = key23
    c, srv, audit = _serve(shares[0], tmp_path, max_per_ip=2, auth_deadline=0.6)
    try:
        held = [_conn(srv.address[1]) for _ in range(2)]
        s3, f3 = _conn(srv.address[1], timeout=3)
        s3.settimeout(3)
        try:
            data = s3.recv(1)                                           # refused immediately
        except OSError:
            data = b""
        assert data == b""
        # silent peers are dropped at the pre-auth deadline
        t0 = time.monotonic()
        held[0][0].settimeout(5)
        assert held[0][0].recv(1) == b""
        assert time.monotonic() - t0 < 3
        # a trickling peer (1 byte / 0.2 s) cannot hold the slot past the deadline
        s, _ = _conn(srv.address[1])
        t0 = time.monotonic()
        try:
            for _ in range(30):
                s.sendall(b"\x00")
                time.sleep(0.2)
        except OSError:
            pass
        assert time.monotonic() - t0 < 4
        s.close()
    finally:
        srv.shutdown(); srv.server_close()


def test_lockout_is_per_ip_across_connections(key23, tmp_path):
    shares, _, _ = key23
    c, srv, audit = _serve(shares[0], tmp_path)
    try:
        for _ in range(5):                       # five different connections, one failure each
            s, f = _conn(srv.address[1])
            assert "err" in _rpc(f, {"m": "auth", "a": ["nope-nope-nope-nope-1"]})
            s.close()
        s, f = _conn(srv.address[1])
        r = _rpc(f, {"m": "auth", "a": [TOKEN]})                         # even the right token
        assert "too many failed attempts" in r["err"]
        s.close()
        assert any("too many failed" in l["outcome"] for l in _lines(audit))
    finally:
        srv.shutdown(); srv.server_close()


def test_weak_tokens_are_refused(key23):
    shares, _, _ = key23
    for bad in ("a" * 20, "abababababababab", "passwordpassword", "short"):
        with pytest.raises(CustodyError):
            Custodian(shares[0], {"x": bad})
    Custodian(shares[0], {"x": secrets.token_urlsafe(32)})


def test_remote_custodian_refuses_plaintext_to_non_loopback():
    with pytest.raises(CustodyError, match="plaintext"):
        RemoteCustodian("10.1.2.3", 8601, TOKEN)
    RemoteCustodian("127.0.0.1", 8601, TOKEN)
    RemoteCustodian("localhost", 8601, TOKEN)
    RemoteCustodian("10.1.2.3", 8601, TOKEN, tls=True)
    RemoteCustodian("10.1.2.3", 8601, TOKEN, allow_insecure=True)


def test_open_test_hostport_parsing_and_no_token_on_argv():
    from torussql.custody.__main__ import _hostport
    assert _hostport("127.0.0.1:8601") == ("127.0.0.1", 8601)
    assert _hostport("[::1]:8601") == ("::1", 8601)
    assert _hostport("::1:8601") == ("::1", 8601)
    with pytest.raises(SystemExit):
        _hostport("127.0.0.1:8601:SECRETTOKEN")          # a token smuggled on argv is rejected
    with pytest.raises(SystemExit):
        _hostport("nohost")


# ── C-13: file creation ──────────────────────────────────────────────────────
def test_atomic_never_reuses_a_planted_tmp_or_follows_symlinks(tmp_path):
    p = tmp_path / "share.json"
    tmp = tmp_path / "share.json.tmp"
    tmp.write_text("planted")
    os.chmod(tmp, 0o666)
    keysmod._atomic(str(p), b"secret", 0o600)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600 and p.read_bytes() == b"secret"
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.symlink(victim, tmp)
    keysmod._atomic(str(p), b"again", 0o600)
    assert victim.read_text() == "keep" and p.read_bytes() == b"again"
    assert not tmp.exists()


def test_export_dealing_files_are_0600_from_the_start(tmp_path, monkeypatch):
    ids = [ident.Identity.new("secp256k1", i) for i in (1, 2)]
    pubs = {i.index: i.public for i in ids}
    session = b"S" * 16
    pt = Participant("secp256k1", 2, 2, 1, session)
    monkeypatch.setattr(os, "chmod", lambda *a, **k: (_ for _ in ()).throw(AssertionError("chmod")))
    old = os.umask(0)
    try:
        files = ident.export_dealing(ids[0], "dkg", session, pt.round1(), pubs, str(tmp_path / "b"))
    finally:
        os.umask(old)
    for f in files:
        mode = stat.S_IMODE(os.stat(f).st_mode)
        assert mode == (0o644 if "broadcast" in f else 0o600)


# ── C-14: file-type separation ───────────────────────────────────────────────
def test_identity_file_is_not_a_share_file_and_loaders_raise_clean_errors(key23, tmp_path):
    shares, _, _ = key23
    idn = ident.Identity.new("secp256k1", 1)
    ip, sp = tmp_path / "id", tmp_path / "share"
    idn.save(str(ip), "pw")
    shares[0].save(str(sp), "pw")
    # relabel an identity blob as a share file and vice versa
    raw = ip.read_bytes()
    (tmp_path / "x").write_bytes(raw.replace(b"TORUSID2", b"TORUSSHARE2", 1))
    with pytest.raises(ShareError):
        KeyShare.load(str(tmp_path / "x"), "pw")
    raw = sp.read_bytes()
    (tmp_path / "y").write_bytes(raw.replace(b"TORUSSHARE2", b"TORUSID2", 1))
    with pytest.raises(CustodyError):
        ident.Identity.load(str(tmp_path / "y"), "pw")
    # a validly sealed identity body presented to the share loader
    salt = os.urandom(16)
    head = b"TORUSSHARE2 sealed " + salt.hex().encode()
    body = json.dumps({"group": "secp256k1", "index": 1, "secret": "0x1"}).encode()
    blob = head + b"\n" + _seal.seal(_seal.passphrase_key("pw", salt), body)
    (tmp_path / "z").write_bytes(blob)
    with pytest.raises(ShareError):
        KeyShare.load(str(tmp_path / "z"), "pw")
    # plain files with junk JSON shapes -> ShareError / CustodyError, never KeyError/TypeError
    for junk in (b"{}", b"[]", b'{"index": "x"}', b"\xff\xfe", b"null", b'{"public": 5}'):
        (tmp_path / "j").write_bytes(b"TORUSSHARE2 plain\n" + junk)
        with pytest.raises(ShareError):
            KeyShare.load(str(tmp_path / "j"), None)
        (tmp_path / "k").write_bytes(b"TORUSID2 plain\n" + junk)
        with pytest.raises(CustodyError):
            ident.Identity.load(str(tmp_path / "k"), None)
    # header is authenticated: changing the salt text is detected
    sealed = sp.read_bytes()
    h, _, rest = sealed.partition(b"\n")
    (tmp_path / "h").write_bytes(h[:-1] + (b"0" if h[-1:] != b"0" else b"1") + b"\n" + rest)
    with pytest.raises(ShareError):
        KeyShare.load(str(tmp_path / "h"), "pw")
    # old v1 files are refused with a clear message
    (tmp_path / "v1").write_bytes(b"TORUSSHARE1 plain\n{}")
    with pytest.raises(ShareError, match="v1"):
        KeyShare.load(str(tmp_path / "v1"), None)


# ── C-15: transcript / signature binding, public-key validation ──────────────
def test_signed_broadcast_binds_spec_signer_and_expected_index():
    a, b = ident.Identity.new("secp256k1", 1), ident.Identity.new("secp256k1", 2)
    g = a.g
    session = b"S" * 16
    dl = Participant("secp256k1", 2, 3, 1, session).round1()
    spec = {"group": "secp256k1", "k": 2, "n": 3, "ids": "abc"}
    msg = ident.sign_broadcast(a, "dkg", session, dl.broadcast, spec)
    assert ident.open_broadcast(g, a.public, msg, "dkg", session, params=spec,
                                expected_index=1).index == 1
    with pytest.raises(CustodyError, match="specification"):
        ident.open_broadcast(g, a.public, msg, "dkg", session, params={**spec, "k": 3})
    with pytest.raises(CustodyError, match="specification"):
        ident.open_broadcast(g, a.public, msg, "dkg", session)            # params omitted
    with pytest.raises(CustodyError, match="expected"):
        ident.open_broadcast(g, a.public, msg, "dkg", session, params=spec, expected_index=2)
    swapped = json.loads(json.dumps(msg))
    swapped["body"]["signer"] = 2                                          # signer is inside the signature
    with pytest.raises(CustodyError, match="signature"):
        ident.open_broadcast(g, a.public, swapped, "dkg", session, params=spec)


def test_file_ceremony_rejects_mismatched_spec_and_wrong_sender_slot(tmp_path):
    n, k = 3, 2
    ids = [ident.Identity.new("secp256k1", i) for i in range(1, n + 1)]
    pubs = {i.index: i.public for i in ids}
    g = ids[0].g
    session = secrets.token_bytes(16)
    from torussql.custody.dkg import dkg_params
    spec = dkg_params("secp256k1", k, n, ident.ids_digest(g, pubs))
    box = str(tmp_path / "box")
    for idn in ids:
        pt = Participant("secp256k1", k, n, idn.index, session)
        ident.export_dealing(idn, "dkg", session, pt.round1(), pubs, box, spec)
    bc, sh = ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3], spec)
    assert set(bc) == {1, 2, 3}
    with pytest.raises(CustodyError, match="specification"):
        ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3],
                              dkg_params("secp256k1", 3, n, ident.ids_digest(g, pubs)))
    with pytest.raises(CustodyError, match="specification"):
        ident.import_dealings(ids[0], "dkg", session, box, pubs, [1, 2, 3],
                              dkg_params("secp256k1", k, n, "different-ids"))


def test_transcript_hash_covers_ceremony_parameters(key23):
    g = get_group("secp256k1")
    session = b"T" * 16
    pts = [Participant("secp256k1", 2, 3, i, session) for i in (1, 2, 3)]
    bc = {p.index: p.round1().broadcast for p in pts}
    base = transcript_hash(g, session, bc, {"k": 2, "n": 3})
    assert base != transcript_hash(g, session, bc, {"k": 3, "n": 3})
    assert base != transcript_hash(g, session, bc, {"k": 2, "n": 3, "ids": "x"})
    assert base != transcript_hash(g, session, bc)
    # Participants configured with different identity lists disagree on the transcript
    out = []
    for dig in ("aa", "bb"):
        p = [Participant("secp256k1", 2, 3, i, session, dig) for i in (1, 2, 3)]
        for q in p:
            q._dealing = pts[q.index - 1]._dealing
        d = {q.index: q.round1() for q in p}
        out.append(p[0].finish(bc, {i: d[i].shares[1] for i in d})[2])
    assert out[0] != out[1]


def test_public_key_from_json_validates_bounds_and_binds_everything(key23):
    _, pub, _ = key23
    base = pub.to_json()
    assert PublicKey.from_json(base).digest == pub.digest

    def mut(**kw):
        d = json.loads(json.dumps(base))
        d.update(kw)
        d.pop("key_id", None) if kw.pop("_drop", False) else None
        return d

    for bad in ({"k": 1}, {"k": 3}, {"n": 33}, {"n": 1}, {"epoch": -1}, {"epoch": 2 ** 63},
                {"epoch": "0"}, {"k": True}, {"k": 2.0}, {"group": "nope"}, {"commitments": 5}):
        d = mut(**bad)
        for stale in ("key_id", "digest"):
            d.pop(stale, None)
        with pytest.raises(ShareError):
            PublicKey.from_json(d)
    d = json.loads(json.dumps(base))
    del d["k"]
    with pytest.raises(ShareError):
        PublicKey.from_json(d)
    # epoch/n are bound by the digest even though key_id is stable across epochs
    d = json.loads(json.dumps(base))
    d["epoch"] = 5
    with pytest.raises(ShareError, match="digest"):
        PublicKey.from_json(d)
    d = json.loads(json.dumps(base))
    d["commitments"][0] = pub.g.hex(pub.g.G)
    with pytest.raises(ShareError, match="digest"):
        PublicKey.from_json(d)
    from torussql.custody import refresh
    shares, _, _ = key23
    _, npub = refresh(shares)
    assert npub.key_id == pub.key_id and npub.digest != pub.digest
