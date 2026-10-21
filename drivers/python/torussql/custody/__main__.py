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
  reshare-start / reshare-finish
                       proactive refresh / change k, n / replace a custodian

Passphrases are read from the environment variable named by ``--passphrase-env``
or prompted for — never taken from the command line.
"""
from __future__ import annotations

import argparse
import getpass
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
from .identity import (Identity, export_dealing, fingerprint, import_dealings)
from .net import Custodian, CustodianServer, RemoteCustodian


def _pass(args, prompt="Passphrase: ", confirm=False) -> str | None:
    env = getattr(args, "passphrase_env", None)
    if env:
        v = os.environ.get(env)
        if v is None:
            raise SystemExit(f"environment variable {env} is not set")
        return v or None
    if getattr(args, "no_passphrase", False):
        return None
    if not sys.stdin.isatty():
        raise SystemExit("no passphrase source: set --passphrase-env or --no-passphrase")
    v = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat: ") != v:
        raise SystemExit("passphrases differ")
    return v or None


def _load_ids(path: str):
    d = json.loads(Path(path).read_text())
    g = get_group(d["group"])
    return g, {int(i): g.from_hex(p["public"]) for i, p in d["participants"].items()}, d


def _session(s: str) -> bytes:
    return bytes.fromhex(s)


def cmd_identity_new(a):
    idn = Identity.new(a.group, a.index)
    idn.save(a.out, _pass(a, "New identity passphrase: ", confirm=True))
    pub = Path(a.out).with_suffix(".pub.json")
    pub.write_text(json.dumps(idn.public_json(), indent=1))
    print(f"identity {a.index} written to {a.out}; public part: {pub}")
    print(f"fingerprint: {idn.fingerprint()}")


def cmd_ids_merge(a):
    parts, group = {}, None
    for f in a.files:
        d = json.loads(Path(f).read_text())
        group = group or d["group"]
        if d["group"] != group:
            raise SystemExit("all identities must use the same group")
        parts[str(d["index"])] = {"public": d["public"], "fingerprint": d["fingerprint"]}
    Path(a.out).write_text(json.dumps({"group": group, "participants": parts}, indent=1))
    print(f"wrote {a.out}. COMPARE THESE FINGERPRINTS OUT OF BAND:")
    for i in sorted(parts, key=int):
        print(f"  {i}: {parts[i]['fingerprint']}")


def cmd_new_session(_a):
    print(secrets.token_hex(16))


def cmd_dkg_start(a):
    g, pubs, _ = _load_ids(a.ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    part = Participant(g.name, a.k, a.n, idn.index, _session(a.session))
    # every private share (including our own, share_i_to_i) is written ENCRYPTED to
    # its recipient; nothing secret is left on disk in the clear
    files = export_dealing(idn, "dkg", _session(a.session), part.round1(), pubs, a.out)
    print(f"wrote {len(files)} files to {a.out}: send broadcast_{idn.index}.json to everyone "
          f"and share_{idn.index}_to_J.json to participant J only")


def cmd_dkg_finish(a):
    g, pubs, _ = _load_ids(a.ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    sess = _session(a.session)
    part = Participant(g.name, a.k, a.n, idn.index, sess)
    bc, sh = import_dealings(idn, "dkg", sess, a.inbox, pubs, list(range(1, a.n + 1)))
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


def cmd_serve(a):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    share_pass = _pass(a, "Share passphrase: ")
    ks = KeyShare.load(a.share, share_pass)
    tokens = {}
    for line in Path(a.token_file).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, _, tok = line.partition(":")
            tokens[name] = tok
    cust = Custodian(ks, tokens, audit_path=a.audit, rate_per_minute=a.rate)
    ctx = None
    if a.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.cert, a.key or a.cert)
        if a.cafile:
            ctx.load_verify_locations(a.cafile)
            ctx.verify_mode = ssl.CERT_REQUIRED
    host, _, port = a.listen.rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1") and not a.tls and not a.insecure_no_tls:
        raise SystemExit("refusing a non-loopback listen without --tls (tokens are bearer secrets)")
    srv = CustodianServer(host or "127.0.0.1", int(port), cust, ssl_ctx=ctx)
    print(f"custodian {ks.index}/{ks.public.n} epoch {ks.epoch} key {ks.public.key_id} "
          f"on {srv.address[0]}:{srv.address[1]}", flush=True)

    def reload(*_):                      # SIGHUP: pick up a refreshed share file
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


def cmd_open_test(a):
    pub = PublicKey.load(a.public)
    custs = []
    for spec in a.custodian:                 # host:port:token
        host, port, tok = spec.split(":", 2)
        custs.append(RemoteCustodian(host, int(port), tok, group=pub.g, tls=a.tls,
                                     cafile=a.cafile, tls_insecure=a.tls_insecure))
    K, hdr = wrap_key(pub, b"open-test")
    got = unwrap_key(pub, hdr, Quorum(pub, custs).shared_point)
    print("quorum opened a fresh envelope: OK" if got == K else "MISMATCH")
    sys.exit(0 if got == K else 1)


def _spec(a, old: PublicKey) -> ReshareSpec:
    return ReshareSpec(old, tuple(int(i) for i in a.quorum.split(",")), a.new_k, a.new_n,
                       _session(a.session))


def cmd_reshare_start(a):
    old = PublicKey.load(a.public)
    ks = KeyShare.load(a.share, _pass(a, "Share passphrase: "))
    g, new_pubs, _ = _load_ids(a.new_ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    spec = _spec(a, old)
    files = export_dealing(idn, "reshare", spec.session, reshare_deal(spec, ks), new_pubs, a.out)
    print(f"wrote {len(files)} files to {a.out}")


def cmd_reshare_finish(a):
    old = PublicKey.load(a.public)
    spec = _spec(a, old)
    g, old_pubs, _ = _load_ids(a.old_ids)
    idn = Identity.load(a.identity, _pass(a, "Identity passphrase: "))
    bc, sh = import_dealings(idn, "reshare", spec.session, a.inbox, old_pubs, sorted(spec.quorum))
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
    p = add("serve", cmd_serve); p.add_argument("--share", required=True)
    p.add_argument("--listen", default="127.0.0.1:8601"); p.add_argument("--token-file", required=True)
    p.add_argument("--audit"); p.add_argument("--rate", type=int, default=30)
    p.add_argument("--tls", action="store_true"); p.add_argument("--cert"); p.add_argument("--key")
    p.add_argument("--cafile"); p.add_argument("--insecure-no-tls", action="store_true")
    p = add("open-test", cmd_open_test); p.add_argument("--public", required=True)
    p.add_argument("--custodian", action="append", required=True, metavar="HOST:PORT:TOKEN")
    p.add_argument("--tls", action="store_true"); p.add_argument("--cafile")
    p.add_argument("--tls-insecure", action="store_true")
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
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except CustodyError as exc:
        raise SystemExit(f"error: {exc}")


if __name__ == "__main__":
    main()
