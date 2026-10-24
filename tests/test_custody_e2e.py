# SPDX-License-Identifier: Apache-2.0
"""Threshold custody end to end: custodian daemons, sealed vaults, the CLI."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import torussql
from torussql.custody import (InsufficientPartials, LocalCustodian, Quorum, QuorumError,
                              ThresholdCustody, refresh, run_local_ceremony,
                              run_local_reshare, unwrap_key, wrap_key)
from torussql.custody.net import Custodian, CustodianServer, RemoteCustodian
from torussql.vault import VaultError, VaultLocked
from nokey_server import NoKeyTCPServer

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
TOKEN = "owner-token-0123456789abc"


def _env():
    paths = [str(ROOT / "drivers" / "python"), str(ROOT / "core"), str(ROOT / "parser")]
    e = dict(os.environ)
    e["PYTHONPATH"] = os.pathsep.join(paths + [e.get("PYTHONPATH", "")])
    return e


class Net:
    """n custodian daemons (threads) with audit logs."""

    def __init__(self, shares, tmp_path, rate=1000, approve=None):
        self.servers, self.custodians, self.audits, self.ports = [], [], [], []
        for s in shares:
            audit = str(tmp_path / f"audit_{s.index}_{secrets.token_hex(3)}.log")
            c = Custodian(s, {"owner": TOKEN, "ops": "ops-token-0123456789abcd"},
                          audit_path=audit, rate_per_minute=rate, approve=approve)
            srv = CustodianServer("127.0.0.1", 0, c)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv); self.custodians.append(c); self.audits.append(audit)
            self.ports.append(srv.address[1])
        self.g = shares[0].public.g

    def remote(self, i, token=TOKEN, **kw):
        return RemoteCustodian("127.0.0.1", self.ports[i], token, group=self.g, **kw)

    def quorum(self, pub, idx=None, **kw):
        idx = range(len(self.servers)) if idx is None else idx
        return Quorum(pub, [self.remote(i) for i in idx], **kw)

    def kill(self, i):
        self.servers[i].shutdown(); self.servers[i].server_close()

    def stop(self):
        for i, s in enumerate(self.servers):
            try:
                s.shutdown(); s.server_close()
            except Exception:                                    # noqa: BLE001
                pass


@pytest.fixture
def keyset():
    return run_local_ceremony(3, 5, "secp256k1")


@pytest.fixture
def net(keyset, tmp_path):
    n = Net(keyset[0], tmp_path)
    yield n
    n.stop()


@pytest.fixture
def db():
    srv = NoKeyTCPServer("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.address
    srv.shutdown(); srv.server_close()


# ── custodian daemon ─────────────────────────────────────────────────────────
def test_network_quorum_opens_with_two_custodians_down(keyset, net):
    shares, pub, _ = keyset
    K, hdr = wrap_key(pub, b"net")
    net.kill(0); net.kill(4)
    assert unwrap_key(pub, hdr, net.quorum(pub, timeout=10).shared_point) == K
    net.kill(2)                                          # now only 2 of 5 are alive
    with pytest.raises(InsufficientPartials):
        unwrap_key(pub, hdr, net.quorum(pub, timeout=3).shared_point)


def test_slow_custodian_does_not_delay_the_quorum(keyset, tmp_path):
    shares, pub, _ = keyset
    calls = []

    def approve(caller, E_hex, ctx):
        calls.append(1)
        if len(calls) == 1:
            time.sleep(4)                                # one very slow custodian
        return True
    n = Net(shares, tmp_path, approve=approve)
    try:
        K, hdr = wrap_key(pub, b"slow")
        t = time.time()
        assert unwrap_key(pub, hdr, n.quorum(pub, timeout=20).shared_point) == K
        assert time.time() - t < 3.5
    finally:
        n.stop()


def test_authentication_failures_and_lockout(net):
    bad = net.remote(0, token="wrong-token-0123456789abc")
    with pytest.raises(QuorumError, match="invalid token"):
        bad.partial(net.g.G, b"")
    with pytest.raises(QuorumError, match="authenticate first|invalid token"):
        r = RemoteCustodian("127.0.0.1", net.servers[0].address[1], "", group=net.g)
        r.partial(net.g.G, b"")
    # a raw client that skips auth gets nothing
    r = net.remote(1)
    assert r.info()["index"] == 2 and r.info()["auth_required"] is True


def test_unauthenticated_partial_is_refused(net):
    import socket, struct
    s = socket.create_connection(("127.0.0.1", net.servers[0].address[1]), timeout=5)
    body = json.dumps({"m": "partial", "a": [net.g.hex(net.g.G), ""]}).encode()
    s.sendall(struct.pack(">I", len(body)) + body)
    n = struct.unpack(">I", s.recv(4))[0]
    assert b"authenticate first" in s.recv(n)


def test_rate_limit_and_policy_and_audit(keyset, tmp_path):
    shares, pub, _ = keyset
    denied = {"on": False}
    n = Net(shares[:1], tmp_path, rate=3, approve=lambda c, E, ctx: not denied["on"])
    try:
        r = n.remote(0)
        E = pub.g.mul(pub.g.G, 9)
        for _ in range(3):
            r.partial(E, b"ok")
        with pytest.raises(QuorumError, match="rate limit"):
            r.partial(E, b"ok")
        n.custodians[0]._hits.clear(); denied["on"] = True
        with pytest.raises(QuorumError, match="policy"):
            r.partial(E, b"declined")
        lines = [json.loads(l) for l in open(n.audits[0])]
        outcomes = [l["outcome"] for l in lines]
        assert outcomes.count("served") == 3
        assert "denied: rate limit" in outcomes and "denied: policy" in outcomes
        assert all(l["caller"] == "owner" for l in lines)
        text = open(n.audits[0]).read()
        assert hex(shares[0].y)[2:] not in text and format(shares[0].y, "064x") not in text
    finally:
        n.stop()


def test_malformed_and_off_curve_requests_are_rejected(net):
    r = net.remote(0)
    g = net.g
    for bad in ("00" * 63 + "01", "zz", "", g.hex(g.identity)):
        with pytest.raises(QuorumError, match="malformed"):
            r.call("partial", [bad, ""])
    with pytest.raises(QuorumError, match="malformed"):
        r.call("partial", [g.hex(g.G), "00" * 2000])


def test_custodian_token_policy_and_share_swap(keyset, tmp_path):
    shares, pub, _ = keyset
    with pytest.raises(Exception, match="at least one"):
        Custodian(shares[0], {})
    with pytest.raises(Exception, match="16"):
        Custodian(shares[0], {"x": "short"})
    c = Custodian(shares[0], {"owner": TOKEN})
    new, npub = refresh(shares)
    c.replace_share(new[0])
    assert c.info()["epoch"] == 1
    other, _, _ = run_local_ceremony(3, 5)
    with pytest.raises(Exception, match="different key"):
        c.replace_share(other[0])


def test_tls_custodian(keyset, tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    cert, key = tmp_path / "c.crt", tmp_path / "c.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out",
                    str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                   check=True, capture_output=True)
    shares, pub, _ = keyset
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv = CustodianServer("127.0.0.1", 0, Custodian(shares[0], {"o": TOKEN}), ssl_ctx=ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.address[1]
        E = pub.g.mul(pub.g.G, 5)
        ok = RemoteCustodian("127.0.0.1", port, TOKEN, group=pub.g, tls=True, cafile=str(cert))
        assert ok.partial(E, b"").index == 1
        with pytest.raises(Exception):                                # default: verify → self-signed fails
            RemoteCustodian("127.0.0.1", port, TOKEN, group=pub.g, tls=True).partial(E, b"")
        assert RemoteCustodian("127.0.0.1", port, TOKEN, group=pub.g, tls=True,
                               tls_insecure=True).partial(E, b"").index == 1
        with pytest.raises(Exception):                                # plaintext to a TLS port
            RemoteCustodian("127.0.0.1", port, TOKEN, group=pub.g, timeout=2).partial(E, b"")
    finally:
        srv.shutdown(); srv.server_close()


# ── vault sealed under the threshold key ─────────────────────────────────────
def _seed(c):
    c.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary INT ENC)")
    for i, d, s in [(1, 5, 100), (2, 5, 200), (3, 9, 300)]:
        c.execute(f"INSERT INTO emp (id, dept, salary) VALUES ({i}, {d}, {s})")


def test_vault_sealed_by_threshold_key_end_to_end(keyset, net, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v.vault")
    cust = ThresholdCustody(pub, net.quorum(pub, timeout=15))
    with torussql.connect(*db, vault_path=vault, vault_custody=cust) as c:
        _seed(c)
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
    raw = Path(vault).read_bytes()
    assert raw.startswith(b"TORUSVAULT2 thr ")
    assert b"salary" not in raw and b'"r"' not in raw                  # nothing readable
    # reopen with ANY 3 of 5 custodians (two are offline)
    net.kill(1); net.kill(3)
    with torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
            pub, net.quorum(pub, timeout=15))) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (4, 1, 4)")
    with torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
            pub, net.quorum(pub, timeout=15))) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[604]]


def test_vault_cannot_be_opened_without_a_quorum(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v.vault")
    full = ThresholdCustody(pub, Quorum(pub, [LocalCustodian(s) for s in shares]))
    with torussql.connect(*db, vault_path=vault, vault_custody=full) as c:
        _seed(c)
    before = Path(vault).read_bytes()
    two = ThresholdCustody(pub, Quorum(pub, [LocalCustodian(s) for s in shares[:2]], timeout=5))
    with pytest.raises(VaultLocked, match="cannot open"):
        torussql.connect(*db, vault_path=vault, vault_custody=two)
    with pytest.raises(VaultLocked):                                  # public key only
        torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(pub))
    with pytest.raises(VaultLocked, match="threshold"):               # no custody at all
        torussql.connect(*db, vault_path=vault)
    with pytest.raises(VaultLocked):                                  # passphrase is not the key
        torussql.connect(*db, vault_path=vault, vault_passphrase="guess")
    assert Path(vault).read_bytes() == before                         # never modified / truncated


def test_a_custodian_that_declines_cannot_be_forced(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v.vault")
    with torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
            pub, Quorum(pub, [LocalCustodian(s) for s in shares]))) as c:
        _seed(c)
    refusing = [LocalCustodian(s, approve=lambda caller, E, ctx: False) for s in shares[:3]]
    with pytest.raises(VaultLocked):
        torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
            pub, Quorum(pub, refusing + [LocalCustodian(shares[3])], timeout=5)))


def test_vault_survives_refresh_and_reshare(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v.vault")
    q = lambda p, ss: ThresholdCustody(p, Quorum(p, [LocalCustodian(s) for s in ss], timeout=20))
    with torussql.connect(*db, vault_path=vault, vault_custody=q(pub, shares)) as c:
        _seed(c)
    n1, p1 = refresh(shares)                                           # epoch 1
    n2, p2 = run_local_reshare(n1, [2, 3, 5], 2, 3)                    # → 2-of-3, epoch 2
    assert (p2.k, p2.n, p2.epoch) == (2, 3, 2)
    for p, ss in ((p1, n1), (p2, n2)):
        with torussql.connect(*db, vault_path=vault, vault_custody=q(p, ss)) as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
    # a removed custodian's OLD-epoch share is useless against the new committee
    stale = ThresholdCustody(p2, Quorum(p2, [LocalCustodian(s) for s in shares[:3]], timeout=5))
    with pytest.raises(VaultLocked):
        torussql.connect(*db, vault_path=vault, vault_custody=stale)


def test_rotate_vault_key_needs_no_quorum_to_write(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v.vault")
    cust = ThresholdCustody(pub, Quorum(pub, [LocalCustodian(s) for s in shares]))
    with torussql.connect(*db, vault_path=vault, vault_custody=cust) as c:
        _seed(c)
        head1 = Path(vault).read_bytes().split(b"\n")[0]
        c.rotate_vault_key()
        head2 = Path(vault).read_bytes().split(b"\n")[0]
        assert head1 != head2 and head2.startswith(b"TORUSVAULT2 thr ")
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (4, 1, 4)")
    with torussql.connect(*db, vault_path=vault, vault_custody=cust) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[604]]


def test_tampered_envelope_header_is_refused_without_damage(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = tmp_path / "v.vault"
    cust = ThresholdCustody(pub, Quorum(pub, [LocalCustodian(s) for s in shares]))
    with torussql.connect(*db, vault_path=str(vault), vault_custody=cust) as c:
        _seed(c)
    import base64
    lines = vault.read_bytes().split(b"\n")
    hdr = json.loads(base64.urlsafe_b64decode(lines[0].split(b" ")[2]))
    hdr["E"] = pub.g.hex(pub.g.mul(pub.g.G, 12345))                    # swap the ephemeral
    lines[0] = b"TORUSVAULT2 thr " + base64.urlsafe_b64encode(json.dumps(hdr).encode())
    vault.write_bytes(b"\n".join(lines))
    before = vault.read_bytes()
    with pytest.raises(VaultLocked):
        torussql.connect(*db, vault_path=str(vault), vault_custody=cust)
    assert vault.read_bytes() == before


def test_passphrase_and_custody_are_mutually_exclusive(keyset, db, tmp_path):
    _, pub, _ = keyset
    with pytest.raises(VaultError, match="either"):
        torussql.connect(*db, vault_path=str(tmp_path / "v"), vault_passphrase="x",
                         vault_custody=ThresholdCustody(pub))


def test_existing_passphrase_vaults_still_work(db, tmp_path):
    vault = str(tmp_path / "old.vault")
    with torussql.connect(*db, vault_path=vault, vault_passphrase="pw") as c:
        _seed(c)
    with torussql.connect(*db, vault_path=vault, vault_passphrase="pw") as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]


def test_seal_format_is_compatible_with_the_engine_keymgmt():
    keymgmt = pytest.importorskip("ecfhe_query.keymgmt")   # proprietary engine, optional
    from torussql import seal
    k = secrets.randbits(250)
    assert seal.unseal(k, keymgmt.seal(k, b"hello")) == b"hello"
    assert keymgmt.unseal(k, seal.seal(k, b"world")) == b"world"


# ── the CLI as an operator would use it ──────────────────────────────────────
def cli(*args, env_extra=None, check=True):
    e = _env() | (env_extra or {})
    r = subprocess.run([PY, "-m", "torussql.custody", *args], env=e, capture_output=True,
                       text=True, timeout=120)
    if check and r.returncode:
        raise AssertionError(f"{args}: {r.stderr or r.stdout}")
    return r


def test_cli_three_host_ceremony_then_daemons_then_vault(db, tmp_path):
    k, n = 2, 3
    d = tmp_path
    pw = {"PW": "ceremony-passphrase"}
    for i in range(1, n + 1):
        cli("identity-new", "--index", str(i), "--out", str(d / f"id{i}.json"),
            "--passphrase-env", "PW", env_extra=pw)
    cli("ids-merge", *[str(d / f"id{i}.pub.json") for i in range(1, n + 1)], "--out", str(d / "ids.json"))
    session = cli("new-session").stdout.strip()
    for i in range(1, n + 1):
        cli("dkg-start", "--identity", str(d / f"id{i}.json"), "--ids", str(d / "ids.json"),
            "--k", str(k), "--n", str(n), "--session", session, "--out", str(d / "box"),
            "--passphrase-env", "PW", env_extra=pw)
    assert not list((d / "box").glob(".*")), "no hidden/plaintext leftovers in the outbox"
    txs = set()
    for i in range(1, n + 1):
        out = cli("dkg-finish", "--identity", str(d / f"id{i}.json"), "--ids", str(d / "ids.json"),
                  "--k", str(k), "--n", str(n), "--session", session, "--inbox", str(d / "box"),
                  "--out", str(d / f"share{i}.json"), "--public-out", str(d / f"pub{i}.json"),
                  "--passphrase-env", "PW", env_extra=pw).stdout
        txs.add(re.search(r"transcript: (\w+)", out).group(1))
    assert len(txs) == 1                                               # all agree
    assert (d / "pub1.json").read_text() == (d / "pub2.json").read_text()
    cli("share-check", "--share", str(d / "share1.json"), "--passphrase-env", "PW", env_extra=pw)
    assert "wrong passphrase" in cli("share-check", "--share", str(d / "share1.json"),
                                     "--passphrase-env", "BAD", env_extra={"BAD": "nope"},
                                     check=False).stderr

    # run the daemons as real processes
    (d / "tokens").write_text(f"owner:{TOKEN}\n")
    procs, ports = [], []
    for i in range(1, n + 1):
        p = subprocess.Popen([PY, "-m", "torussql.custody", "serve", "--share", str(d / f"share{i}.json"),
                              "--listen", "127.0.0.1:0", "--token-file", str(d / "tokens"),
                              "--audit", str(d / f"audit{i}.log"), "--passphrase-env", "PW"],
                             env=_env() | pw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        procs.append(p)
        ports.append(int(re.search(r"on 127\.0\.0\.1:(\d+)", p.stdout.readline()).group(1)))
    try:
        specs = [f"127.0.0.1:{pt}" for pt in ports]
        args = ["open-test", "--public", str(d / "pub1.json"), "--token-env", "CUST_TOKEN"]
        for sp in specs:
            args += ["--custodian", sp]
        assert "OK" in cli(*args, env_extra={"CUST_TOKEN": TOKEN}).stdout
        # tokens are never accepted on the command line
        r = cli("open-test", "--public", str(d / "pub1.json"), "--custodian",
                f"127.0.0.1:{ports[0]}:{TOKEN}", "--token-env", "NOPE", check=False)
        assert r.returncode != 0 and TOKEN not in (r.stdout + r.stderr)
        pub = __import__("torussql.custody", fromlist=["PublicKey"]).PublicKey.load(str(d / "pub1.json"))
        remotes = [RemoteCustodian("127.0.0.1", pt, TOKEN, group=pub.g) for pt in ports]
        vault = str(d / "owner.vault")
        with torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
                pub, Quorum(pub, remotes, timeout=15))) as c:
            _seed(c)
        procs[0].terminate(); procs[0].wait(timeout=10)                # lose one custodian (2-of-3)
        with torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
                pub, Quorum(pub, remotes, timeout=15))) as c:
            assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        procs[1].terminate(); procs[1].wait(timeout=10)                # lose a second: below quorum
        with pytest.raises(VaultLocked):
            torussql.connect(*db, vault_path=vault, vault_custody=ThresholdCustody(
                pub, Quorum(pub, remotes, timeout=5)))
        assert (d / "audit3.log").read_text().count('"served"') >= 2
    finally:
        for p in procs:
            p.terminate()


def test_cli_reshare_replaces_a_custodian(tmp_path):
    d = tmp_path
    pw = {"PW": "x-passphrase"}
    # old committee 2-of-3 (dev ceremony), new committee 2-of-3 with a brand-new member set
    cli("keygen-local", "--k", "2", "--n", "3", "--out", str(d / "old"), "--passphrase-env", "PW", env_extra=pw)
    for i in (1, 2, 3):
        cli("identity-new", "--index", str(i), "--out", str(d / f"old_id{i}.json"), "--passphrase-env", "PW", env_extra=pw)
        cli("identity-new", "--index", str(i), "--out", str(d / f"new_id{i}.json"), "--passphrase-env", "PW", env_extra=pw)
    cli("ids-merge", *[str(d / f"old_id{i}.pub.json") for i in (1, 2, 3)], "--out", str(d / "old_ids.json"))
    cli("ids-merge", *[str(d / f"new_id{i}.pub.json") for i in (1, 2, 3)], "--out", str(d / "new_ids.json"))
    session = cli("new-session").stdout.strip()
    common = ["--public", str(d / "old" / "public.json"), "--quorum", "1,3", "--new-k", "2",
              "--new-n", "3", "--session", session]
    for i in (1, 3):                                                   # custodian 2 is gone
        cli("reshare-start", *common, "--share", str(d / "old" / f"share_{i}.json"),
            "--identity", str(d / f"old_id{i}.json"), "--new-ids", str(d / "new_ids.json"),
            "--old-ids", str(d / "old_ids.json"),
            "--out", str(d / "rbox"), "--passphrase-env", "PW", env_extra=pw)
    for j in (1, 2, 3):
        cli("reshare-finish", *common, "--identity", str(d / f"new_id{j}.json"),
            "--old-ids", str(d / "old_ids.json"), "--new-ids", str(d / "new_ids.json"),
            "--inbox", str(d / "rbox"),
            "--out", str(d / f"new_share{j}.json"), "--public-out", str(d / f"new_pub{j}.json"),
            "--passphrase-env", "PW", env_extra=pw)
    from torussql.custody import KeyShare, PublicKey
    old = PublicKey.load(str(d / "old" / "public.json"))
    new = PublicKey.load(str(d / "new_pub1.json"))
    assert new.key_id == old.key_id and new.epoch == 1                 # same key, new epoch
    K, hdr = wrap_key(old, b"cli")
    ns = [KeyShare.load(str(d / f"new_share{j}.json"), "x-passphrase") for j in (1, 2, 3)]
    assert unwrap_key(new, hdr, Quorum(new, [LocalCustodian(s) for s in ns[1:]]).shared_point) == K


# ── migration between protections ────────────────────────────────────────────
def _local_cust(shares, pub):
    return ThresholdCustody(pub, Quorum(pub, [LocalCustodian(s) for s in shares], timeout=20))


def test_reseal_passphrase_vault_to_threshold_and_back(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v")
    with torussql.connect(*db, vault_path=vault, vault_passphrase="old-pass") as c:
        _seed(c)
        c.reseal_vault(custody=_local_cust(shares, pub))               # → threshold
    assert Path(vault).read_bytes().startswith(b"TORUSVAULT2 thr ")
    with pytest.raises(VaultLocked):
        torussql.connect(*db, vault_path=vault, vault_passphrase="old-pass")   # old key is dead
    with torussql.connect(*db, vault_path=vault, vault_custody=_local_cust(shares, pub)) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        c.reseal_vault(vault_passphrase="back-again")                  # → passphrase
    with torussql.connect(*db, vault_path=vault, vault_passphrase="back-again") as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[600]]
        c.reseal_vault()                                               # → unsealed
    assert Path(vault).read_bytes().startswith(b"TORUSVAULT2\n")


def test_reseal_onto_a_fresh_threshold_key_after_compromise(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v")
    with torussql.connect(*db, vault_path=vault, vault_custody=_local_cust(shares, pub)) as c:
        _seed(c)
        new_shares, new_pub, _ = run_local_ceremony(2, 3)              # brand-new key, new custodians
        c.reseal_vault(custody=_local_cust(new_shares, new_pub))
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (4, 1, 4)")
    with pytest.raises(VaultLocked):                                   # the compromised old quorum is locked out
        torussql.connect(*db, vault_path=vault, vault_custody=_local_cust(shares, pub))
    with torussql.connect(*db, vault_path=vault, vault_custody=_local_cust(new_shares, new_pub)) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[604]]


def test_failed_reseal_leaves_the_vault_untouched(keyset, db, tmp_path):
    shares, pub, _ = keyset
    vault = str(tmp_path / "v")
    cust = _local_cust(shares, pub)
    with torussql.connect(*db, vault_path=vault, vault_custody=cust) as c:
        _seed(c)
        before = Path(vault).read_bytes()
        with pytest.raises(VaultError):
            c.reseal_vault(custody=cust, vault_passphrase="both")
        assert Path(vault).read_bytes() == before
        c.execute("INSERT INTO emp (id, dept, salary) VALUES (9, 9, 9)")     # still fully usable
    with torussql.connect(*db, vault_path=vault, vault_custody=cust) as c:
        assert c.execute("SELECT SUM(salary) FROM emp").rows == [[609]]


def test_daemon_reloads_a_refreshed_share_on_sighup(keyset, tmp_path):
    import signal
    shares, pub, _ = keyset
    share_file = str(tmp_path / "s1.json")
    shares[0].save(share_file, "pw")
    (tmp_path / "tokens").write_text(f"owner:{TOKEN}\n")
    p = subprocess.Popen([PY, "-m", "torussql.custody", "serve", "--share", share_file,
                          "--listen", "127.0.0.1:0", "--token-file", str(tmp_path / "tokens"),
                          "--passphrase-env", "PW"], env=_env() | {"PW": "pw"},
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        port = int(re.search(r"on 127\.0\.0\.1:(\d+)", p.stdout.readline()).group(1))
        r = RemoteCustodian("127.0.0.1", port, TOKEN, group=pub.g)
        assert r.info()["epoch"] == 0
        new, npub = refresh(shares)
        new[0].save(share_file, "pw")                          # operator installs the new share
        p.send_signal(signal.SIGHUP)
        for _ in range(50):
            if r.info()["epoch"] == 1:
                break
            time.sleep(0.1)
        assert r.info()["epoch"] == 1
        E = npub.g.mul(npub.g.G, 3)
        from torussql.custody import verify_partial
        assert verify_partial(npub, E, r.partial(E, b""), b"")  # serves with the new epoch's share
    finally:
        p.terminate()
