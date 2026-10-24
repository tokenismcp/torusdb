# SPDX-License-Identifier: Apache-2.0
"""``python -m torussql.custody`` — threshold key ceremony and custodian tools.

Typical production flow (one command per custodian host):

  identity new         each custodian makes a long-term identity key
  ids-merge            collect the public identities into ids.json;
                       EVERYONE compares fingerprints out of band
  dkg-start / dkg-finish
                       dealerless key generation (exchange the files in ``--out``)
  serve                run the custodian daemon holding one share
  open-test            prove a quorum can open a fresh envelope
  fhe-keygen-threshold turn TWO independent bn254 keys (s and s2; two DKGs on the same
                       custodian hosts) into an FHE-column key: derive Q2 = s2*G2 from the
                       second key's custodians, seal a MAC secret, write the PUBLIC bundle
  fhe-open-test        encrypt/decrypt (cell, SUM, DOT, MAC) through a quorum with a bundle
  reshare-start / reshare-finish
                       proactive refresh / change k, n / replace a custodian

Passphrases are read from the environment variable named by ``--passphrase-env``
or prompted for — never taken from the command line.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import secrets
import signal
import ssl
import sys
import threading
from pathlib import Path

from . import (CustodyError, KeyShare, Participant, PublicKey, ReshareSpec, Quorum,
               ThresholdCustody, get_group, reshare_deal, reshare_finish,
               run_local_ceremony, transcript_hash, unwrap_key, wrap_key)
from .dkg import dkg_params
from .identity import (Identity, export_dealing, fingerprint, ids_digest, import_dealings)
from .net import Custodian, CustodianServer, RemoteCustodian


def _pass(args, prompt="Passphrase: ", confirm=False) -> str | None:
    env = getattr(args, "passphrase_env", None)
    if env:
        v = os.environ.get(env)
        if not v:
            raise SystemExit(f"environment variable {env} is not set or empty — "
                             f"refusing to fall back to an unprotected file "
                             f"(use --no-passphrase if that is really intended)")
        return v
    if getattr(args, "no_passphrase", False):
        print("WARNING: --no-passphrase: the secret file will be stored UNENCRYPTED "
              "(protect it with disk encryption and permissions)", file=sys.stderr)
        return None
    if not sys.stdin.isatty():
        raise SystemExit("no passphrase source: set --passphrase-env or --no-passphrase")
    v = getpass.getpass(prompt)
    if not v:
        raise SystemExit("an empty passphrase is not accepted (use --no-passphrase explicitly)")
    if confirm and getpass.getpass("Repeat: ") != v:
        raise SystemExit("passphrases differ")
    return v


def _load_ids(path: str):
    d = json.loads(Path(path).read_text())
    g = get_group(d["group"])
    pubs = {}
    for i, p in d["participants"].items():
        idx = int(i)
        pt = g.from_hex(p["public"])
        if g.is_identity(pt):
            raise SystemExit(f"{path}: participant {idx} has the identity as public key")
        if "fingerprint" in p and p["fingerprint"] != fingerprint(g, pt):
            raise SystemExit(f"{path}: participant {idx}'s fingerprint does not match its "
                             f"public key — the file was tampered with")
        pubs[idx] = pt
    if sorted(pubs) != list(range(1, len(pubs) + 1)):
        raise SystemExit(f"{path}: participant indices must be exactly 1..{len(pubs)}")
    if len({g.hex(p) for p in pubs.values()}) != len(pubs):
        raise SystemExit(f"{path}: two participants share a public key")
    return g, pubs, d


def _hostport(spec: str) -> tuple[str, int]:
    """``host:port`` / ``[v6]:port`` / bare ``v6:port`` -> (host, port)."""
    host, sep, port = spec.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise SystemExit(f"expected HOST:PORT (IPv6 as [addr]:port), got {spec!r}")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def _write_public(path: str, data: str) -> None:
    from .keys import _atomic
    _atomic(path, data.encode(), 0o644)


def _session(s: str) -> bytes:
    return bytes.fromhex(s)


def cmd_identity_new(a):
    idn = Identity.new(a.group, a.index)
    idn.save(a.out, _pass(a, "New identity passphrase: ", confirm=True))
    pub = Path(a.out).with_suffix(".pub.json")
    _write_public(str(pub), json.dumps(idn.public_json(), indent=1))
    print(f"identity {a.index} written to {a.out}; public part: {pub}")
    print(f"fingerprint: {idn.fingerprint()}")


def cmd_ids_merge(a):
    parts, group = {}, None
    for f in a.files:
        d = json.loads(Path(f).read_text())
        group = group or d["group"]
        if d["group"] != group:
            raise SystemExit("all identities must use the same group")
        g = get_group(group)
        pt = g.from_hex(d["public"])
        fp = fingerprint(g, pt)                      # ALWAYS recomputed from the key
        if d.get("fingerprint") not in (None, fp):
            raise SystemExit(f"{f}: the stated fingerprint does not match the public key")
        if str(d["index"]) in parts:
            raise SystemExit(f"duplicate participant index {d['index']}")
        parts[str(d["index"])] = {"public": d["public"], "fingerprint": fp}
    _write_public(a.out, json.dumps({"group": group, "participants": parts}, indent=1))
    _load_ids(a.out)                                 # validates the merged file
    whole = hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:32]
    print(f"wrote {a.out}. COMPARE THESE (computed from the keys) OUT OF BAND:")
    for i in sorted(parts, key=int):
        print(f"  {i}: {parts[i]['fingerprint']}")
    print(f"  whole-file digest: {whole}")


def cmd_new_session(_a):
    print(secrets.token_hex(16))


def cmd_dkg_start(a):
    g, pubs, _ = _load_ids(a.ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    dig = ids_digest(g, pubs)
    part = Participant(g.name, a.k, a.n, idn.index, _session(a.session), dig)
    # every private share (including our own, share_i_to_i) is written ENCRYPTED to
    # its recipient; nothing secret is left on disk in the clear
    files = export_dealing(idn, "dkg", _session(a.session), part.round1(), pubs, a.out,
                           dkg_params(g.name, a.k, a.n, dig))
    print(f"wrote {len(files)} files to {a.out}: send broadcast_{idn.index}.json to everyone "
          f"and share_{idn.index}_to_J.json to participant J only")


def cmd_dkg_finish(a):
    g, pubs, _ = _load_ids(a.ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    sess = _session(a.session)
    dig = ids_digest(g, pubs)
    if len(pubs) != a.n:
        raise SystemExit(f"ids file lists {len(pubs)} participants but --n is {a.n}")
    part = Participant(g.name, a.k, a.n, idn.index, sess, dig)
    bc, sh = import_dealings(idn, "dkg", sess, a.inbox, pubs, list(range(1, a.n + 1)),
                             dkg_params(g.name, a.k, a.n, dig))
    ks, pub, tx = part.finish(bc, sh)
    ks.save(a.out, _pass(a, "New share passphrase: ", confirm=True))
    pub.save(a.public_out)
    print(f"share written to {a.out}; public key file: {a.public_out}")
    print(f"key_id:     {pub.key_id}\npublic key: {g.hex(pub.X)}")
    print(f"transcript: {tx}\nCOMPARE THE TRANSCRIPT HASH WITH EVERY OTHER PARTICIPANT.")


def cmd_keygen_local(a):
    print("WARNING: this ran the whole ceremony in ONE process — that process saw every "
          "share. Use only for development/tests; production keys need dkg-start/dkg-finish "
          "on separate hosts.", file=sys.stderr)
    shares, pub, tx = run_local_ceremony(a.k, a.n, a.group)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pw = _pass(a, "Passphrase for every share: ", confirm=True)
    for s in shares:
        s.save(str(out / f"share_{s.index}.json"), pw)
    pub.save(str(out / "public.json"))
    print(f"wrote {len(shares)} shares and public.json to {out}; key_id {pub.key_id}")


def cmd_share_check(a):
    ks = KeyShare.load(a.share, _pass(a, "Share passphrase: "))
    print(f"share {ks.index}/{ks.public.n} (quorum {ks.public.k}) epoch {ks.epoch} key {ks.public.key_id}: OK")


def cmd_public_show(a):
    pub = PublicKey.load(a.public)
    print(json.dumps({k: v for k, v in pub.to_json().items() if k != "commitments"}, indent=1))


def _read_tokens(path: str):
    """``name:token[:perm,perm]`` lines; perms default to ``key`` (least privilege)."""
    tokens, perms = {}, {}
    try:
        if os.stat(path).st_mode & 0o077:
            print(f"WARNING: token file {path} is readable by other users (chmod 600)",
                  file=sys.stderr)
    except OSError:
        pass
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise SystemExit(f"{path}:{n}: expected name:token[:perms]")
        name, tok = parts[0], parts[1]
        if name in tokens:
            raise SystemExit(f"{path}:{n}: duplicate caller {name!r}")
        tokens[name] = tok
        if len(parts) > 2:
            p = {"key", "mask_write", "mask_read", "mask_admin"} if parts[2] == "all" \
                else set(filter(None, parts[2].split(",")))
            perms[name] = p
    return tokens, perms


def cmd_serve(a):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from .net import Limits
    from .shares import MaskShareStore
    share_pass = _pass(a, "Share/store passphrase: ")
    ks = KeyShare.load(a.share, share_pass) if a.share else None
    masks = MaskShareStore(a.mask_store, share_pass) if a.mask_store else None
    tokens, perms = _read_tokens(a.token_file)
    cust = Custodian(ks, tokens, permissions=perms, masks=masks, audit_path=a.audit,
                     rate_per_minute=a.rate,
                     limits=Limits(min_aggregate_rows=a.min_aggregate_rows,
                                   reveal_rows_per_minute=a.reveal_quota))
    ctx = None
    if a.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.cert, a.key or a.cert)
        if a.cafile:
            ctx.load_verify_locations(a.cafile)
            ctx.verify_mode = ssl.CERT_REQUIRED
    host, port = _hostport(a.listen)
    if host not in ("127.0.0.1", "localhost", "::1") and not a.tls and not a.insecure_no_tls:
        raise SystemExit("refusing a non-loopback listen without --tls (tokens are bearer secrets)")
    srv = CustodianServer(host, port, cust, ssl_ctx=ctx)
    what = ([f"key share {ks.index}/{ks.public.n} epoch {ks.epoch} key {ks.public.key_id}"] if ks else []) \
        + (["mask store"] if masks else [])
    print(f"custodian [{', '.join(what)}] on {srv.address[0]}:{srv.address[1]}", flush=True)

    def reload(*_):                      # SIGHUP: pick up a refreshed share file
        if not a.share:
            return
        try:
            cust.replace_share(KeyShare.load(a.share, share_pass))
            print(f"reloaded share, epoch {cust.info()['epoch']}", flush=True)
        except Exception as exc:                               # noqa: BLE001
            print(f"reload failed: {exc}", flush=True)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        if masks:
            masks.close()


# ── mask cluster administration ──────────────────────────────────────────────
def _cluster(path: str, token_env: str, gen=None):
    from .masks import ThresholdMaskStore
    d = json.loads(Path(path).read_text())
    tok = os.environ.get(token_env or "")
    if not tok:
        raise SystemExit("set the caller token in the environment variable named by --token-env")
    nodes = [RemoteCustodian(n["host"], int(n["port"]), tok, group=None, tls=d.get("tls", False),
                             cafile=d.get("cafile"), tls_insecure=d.get("tls_insecure", False),
                             allow_insecure=d.get("allow_insecure", False))
             for n in d["nodes"]]
    return ThresholdMaskStore(nodes, int(d["k"]), xs=[int(n["x"]) for n in d["nodes"]], gen=gen)


def cmd_mask_init(a):
    st = _cluster(a.cluster, a.token_env)
    st.initialize(authenticated=a.authenticated, force=a.force)
    print(f"mask cluster initialised (k={st.k}, n={st.n}, authenticated={a.authenticated})")


def cmd_mask_status(a):
    st = _cluster(a.cluster, a.token_env)
    for i, nd in enumerate(st.nodes):
        try:
            print(f"x={st.xs[i]} {nd.label}: {json.dumps(nd.call('mask_stats', []))}")
        except Exception as exc:                                       # noqa: BLE001
            print(f"x={st.xs[i]} {nd.label}: UNREACHABLE ({exc})")


def cmd_mask_repair(a):
    st = _cluster(a.cluster, a.token_env)
    st.config()
    print(st.repair())


def cmd_mask_gc(a):
    import torussql
    st = _cluster(a.cluster, a.token_env)
    db_tok = os.environ.get(a.db_token_env or "") if a.db_token_env else None
    with torussql.connect(a.db_host, a.db_port, token=db_tok, mask_cluster=st,
                          tls=a.db_tls) as conn:
        print(conn.mask_gc(min_age=a.min_age, dry_run=a.dry_run))


def cmd_mask_reshare(a):
    from .masks import reshare_masks
    old = _cluster(a.cluster, a.token_env)
    new = _cluster(a.new_cluster, a.token_env)
    res = reshare_masks(old, new.nodes, new.k, new_xs=new.xs)
    print(f"masks re-shared to generation {res.gen} (k={res.k}, n={res.n}); the old generation "
          f"is frozen — drop it with the admin RPC mask_drop_gen once clients have moved")


def cmd_open_test(a):
    pub = PublicKey.load(a.public)
    tok = os.environ.get(a.token_env or "")
    if not tok:
        raise SystemExit("set the caller token in the environment variable named by --token-env "
                         "(tokens are never accepted on the command line)")
    custs = []
    for spec in a.custodian:                 # HOST:PORT or [IPv6]:PORT — never a token on argv
        host, port = _hostport(spec)
        custs.append(RemoteCustodian(host, port, tok, group=pub.g, tls=a.tls,
                                     cafile=a.cafile, tls_insecure=a.tls_insecure,
                                     allow_insecure=a.allow_insecure))
    K, hdr = wrap_key(pub, b"open-test")
    got = unwrap_key(pub, hdr, Quorum(pub, custs).shared_point)
    print("quorum opened a fresh envelope: OK" if got == K else "MISMATCH")
    sys.exit(0 if got == K else 1)


def _fhe_custodians(a, pub: PublicKey, specs=None):
    tok = os.environ.get(a.token_env or "")
    if not tok:
        raise SystemExit("set the caller token in the environment variable named by --token-env "
                         "(tokens are never accepted on the command line)")
    custs = []
    for spec in (a.custodian if specs is None else specs):
        host, port = _hostport(spec)
        custs.append(RemoteCustodian(host, port, tok, group=pub.g, tls=a.tls, cafile=a.cafile,
                                     tls_insecure=a.tls_insecure, allow_insecure=a.allow_insecure))
    return custs


def _fhe_selftest(key, dot: bool) -> None:
    from torusdb_core import fhe
    cells = [key.encrypt(v) for v in (7, -3)]
    assert key.decrypt_cells(cells) == [7, -3], "cell decryption mismatch"
    assert key.decrypt_sum(fhe.sum_cells(cells, key.be)) == 4, "SUM mismatch"
    if dot:
        a, b = [key.encrypt(v) for v in (3, 4)], [key.encrypt(v) for v in (5, 6)]
        assert key.decrypt_dot(fhe.dot_cells(a, b, key.be)) == 39, "DOT mismatch"


def cmd_fhe_keygen_threshold(a):
    """After the bn254 DKG: Q2 from the custodians (pairing-verified), a MAC secret sealed
    under the threshold envelope, and one PUBLIC bundle file. No secret is written."""
    from torusdb_core.fhe_threshold import ThresholdFheKey
    pub, pub2 = PublicKey.load(a.public), PublicKey.load(a.public2)
    if pub.group != "bn254" or pub2.group != "bn254":
        raise SystemExit("an FHE key needs 'bn254' custody keys (run the DKGs with --group bn254)")
    if pub.key_id == pub2.key_id:
        raise SystemExit("--public and --public2 must be two DIFFERENT keys (two separate DKGs)")
    if os.path.exists(a.out):
        raise SystemExit(f"{a.out} already exists")
    key = ThresholdFheKey.create(pub, _fhe_custodians(a, pub), pub2,
                                 _fhe_custodians(a, pub2, a.custodian2), with_mac=not a.no_mac,
                                 value_range=a.range)
    _fhe_selftest(key, dot=False)
    key.save_bundle(a.out)
    print(f"threshold FHE bundle written to {a.out} (range +-{a.range}, key {pub.key_id}, "
          f"quorum {pub.k}-of-{pub.n}); it holds NO secret: s and s2 exist only as custodian shares")
    print("cell/SUM self-test through the quorum: OK")
    if not a.no_mac:
        print("NOTE: an owner process using authenticated=True holds the opened "
              "MAC secret in memory (not s); see docs/fhe-columns.md")


def cmd_fhe_open_test(a):
    from torusdb_core.fhe_threshold import ThresholdFheKey
    pub, pub2 = PublicKey.load(a.public), PublicKey.load(a.public2)
    key = ThresholdFheKey.load(a.bundle, pub, _fhe_custodians(a, pub), pub2,
                               _fhe_custodians(a, pub2, a.custodian2))
    _fhe_selftest(key, dot=not a.skip_dot)
    if a.mac:
        key.alpha
    print("threshold FHE key: cells, SUM" + ("" if a.skip_dot else ", DOT")
          + (", MAC" if a.mac else "") + " through the quorum: OK")


def _spec(a, old: PublicKey) -> ReshareSpec:
    return ReshareSpec(old, tuple(int(i) for i in a.quorum.split(",")), a.new_k, a.new_n,
                       _session(a.session))


def cmd_reshare_start(a):
    old = PublicKey.load(a.public)
    ks = KeyShare.load(a.share, _pass(a, "Share passphrase: "))
    g, new_pubs, _ = _load_ids(a.new_ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    spec = _spec(a, old)
    files = export_dealing(idn, "reshare", spec.session, reshare_deal(spec, ks), new_pubs, a.out,
                           spec.params())
    print(f"wrote {len(files)} files to {a.out}")


def cmd_reshare_finish(a):
    old = PublicKey.load(a.public)
    spec = _spec(a, old)
    g, old_pubs, _ = _load_ids(a.old_ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    bc, sh = import_dealings(idn, "reshare", spec.session, a.inbox, old_pubs, sorted(spec.quorum),
                             spec.params())
    ks, new = reshare_finish(spec, idn.index, bc, sh)
    ks.save(a.out, _pass(a, "New share passphrase: ", confirm=True))
    new.save(a.public_out)
    print(f"new share (epoch {new.epoch}) written; public key unchanged: {new.key_id}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m torussql.custody", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, **kw):
        p = sub.add_parser(name, **kw)
        p.set_defaults(fn=fn)
        p.add_argument("--passphrase-env", metavar="VAR")
        p.add_argument("--no-passphrase", action="store_true", help="store/read without a passphrase")
        return p

    p = add("identity-new", cmd_identity_new); p.add_argument("--group", default="secp256k1")
    p.add_argument("--index", type=int, required=True); p.add_argument("--out", required=True)
    p = add("ids-merge", cmd_ids_merge); p.add_argument("files", nargs="+"); p.add_argument("--out", required=True)
    add("new-session", cmd_new_session)
    for name, fn in (("dkg-start", cmd_dkg_start), ("dkg-finish", cmd_dkg_finish)):
        p = add(name, fn)
        p.add_argument("--identity", required=True); p.add_argument("--ids", required=True)
        p.add_argument("--k", type=int, required=True); p.add_argument("--n", type=int, required=True)
        p.add_argument("--session", required=True)
        if name == "dkg-start":
            p.add_argument("--out", required=True)
        else:
            p.add_argument("--inbox", required=True); p.add_argument("--out", required=True)
            p.add_argument("--public-out", required=True)
    p = add("keygen-local", cmd_keygen_local); p.add_argument("--k", type=int, required=True)
    p.add_argument("--n", type=int, required=True); p.add_argument("--group", default="secp256k1")
    p.add_argument("--out", required=True)
    p = add("share-check", cmd_share_check); p.add_argument("--share", required=True)
    p = add("public-show", cmd_public_show); p.add_argument("--public", required=True)
    p = add("serve", cmd_serve); p.add_argument("--share", help="key share file (optional)")
    p.add_argument("--mask-store", help="mask share store file (enables the mask service)")
    p.add_argument("--min-aggregate-rows", type=int, default=1)
    p.add_argument("--reveal-quota", type=int, default=None,
                   help="max mask cells returned per caller per minute")
    p.add_argument("--listen", default="127.0.0.1:8601"); p.add_argument("--token-file", required=True)
    p.add_argument("--audit"); p.add_argument("--rate", type=int, default=30)
    p.add_argument("--tls", action="store_true"); p.add_argument("--cert"); p.add_argument("--key")
    p.add_argument("--cafile"); p.add_argument("--insecure-no-tls", action="store_true")
    p = add("open-test", cmd_open_test); p.add_argument("--public", required=True)
    p.add_argument("--custodian", action="append", required=True, metavar="HOST:PORT")
    p.add_argument("--token-env", required=True, metavar="VAR",
                   help="environment variable holding the caller token")
    p.add_argument("--tls", action="store_true"); p.add_argument("--cafile")
    p.add_argument("--tls-insecure", action="store_true")
    p.add_argument("--allow-insecure", action="store_true",
                   help="allow plaintext TCP to a non-loopback host (trusted networks only)")
    for name, fn in (("fhe-keygen-threshold", cmd_fhe_keygen_threshold),
                     ("fhe-open-test", cmd_fhe_open_test)):
        p = add(name, fn)
        p.add_argument("--public", required=True, help="custody public key of the secret s (bn254)")
        p.add_argument("--custodian", action="append", required=True, metavar="HOST:PORT",
                       help="custodian daemon serving the share of s (repeat)")
        p.add_argument("--public2", required=True,
                       help="custody public key of the INDEPENDENT second secret s2 (bn254)")
        p.add_argument("--custodian2", action="append", required=True, metavar="HOST:PORT",
                       help="custodian daemon serving the share of s2 (repeat)")
        p.add_argument("--token-env", required=True, metavar="VAR",
                       help="environment variable holding the caller token")
        p.add_argument("--tls", action="store_true"); p.add_argument("--cafile")
        p.add_argument("--tls-insecure", action="store_true")
        p.add_argument("--allow-insecure", action="store_true",
                       help="allow plaintext TCP to a non-loopback host (trusted networks only)")
        if name == "fhe-keygen-threshold":
            p.add_argument("--out", required=True, help="public bundle to write")
            p.add_argument("--range", type=int, default=1_000_000,
                           help="largest |value| / result the key can decrypt")
            p.add_argument("--no-mac", action="store_true",
                           help="no integrity-tag secret (authenticated=True will be unavailable)")
        else:
            p.add_argument("--bundle", required=True)
            p.add_argument("--skip-dot", action="store_true")
            p.add_argument("--mac", action="store_true", help="also open the sealed MAC secret")
    for name, fn in (("reshare-start", cmd_reshare_start), ("reshare-finish", cmd_reshare_finish)):
        p = add(name, fn)
        p.add_argument("--public", required=True); p.add_argument("--quorum", required=True)
        p.add_argument("--new-k", type=int, required=True); p.add_argument("--new-n", type=int, required=True)
        p.add_argument("--session", required=True); p.add_argument("--identity", required=True)
        if name == "reshare-start":
            p.add_argument("--share", required=True); p.add_argument("--new-ids", required=True)
            p.add_argument("--out", required=True)
        else:
            p.add_argument("--old-ids", required=True); p.add_argument("--inbox", required=True)
            p.add_argument("--out", required=True); p.add_argument("--public-out", required=True)
    for name, fn in (("mask-init", cmd_mask_init), ("mask-status", cmd_mask_status),
                     ("mask-repair", cmd_mask_repair), ("mask-gc", cmd_mask_gc),
                     ("mask-reshare", cmd_mask_reshare)):
        p = add(name, fn)
        p.add_argument("--cluster", required=True, help="cluster.json (k, nodes[host,port,x], tls)")
        p.add_argument("--token-env", required=True, metavar="VAR")
        if name == "mask-init":
            p.add_argument("--authenticated", action="store_true")
            p.add_argument("--force", action="store_true")
        if name == "mask-gc":
            p.add_argument("--db-host", required=True); p.add_argument("--db-port", type=int, default=8533)
            p.add_argument("--db-token-env"); p.add_argument("--db-tls", action="store_true")
            p.add_argument("--min-age", type=int, default=3600); p.add_argument("--dry-run", action="store_true")
        if name == "mask-reshare":
            p.add_argument("--new-cluster", required=True)
    args = ap.parse_args(argv)
    errs = (CustodyError,)
    try:
        from torusdb_core.fhe import FheError
        errs += (FheError,)
    except ImportError:                                           # pragma: no cover
        pass
    try:
        args.fn(args)
    except errs as exc:
        raise SystemExit(f"error: {exc}")


if __name__ == "__main__":
    main()
