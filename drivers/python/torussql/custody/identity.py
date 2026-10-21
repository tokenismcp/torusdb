# SPDX-License-Identifier: Apache-2.0
"""Participant identities and signed / encrypted ceremony messages.

A real DKG or reshare runs on separate hosts that exchange *files* (or any
channel). Each participant has a long-term identity key; broadcasts are
**signed** (authenticity) and each private share is **encrypted to its
recipient** (confidentiality), so the messages may travel over untrusted media.
Identity public keys must be exchanged and their fingerprints compared out of
band — that is the trust root of the ceremony.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from . import seal as _seal
from .dkg import Broadcast, Dealing
from .group import CustodyError, Group, get_group
from .keys import _atomic
from .proofs import SchnorrProof, schnorr_prove, schnorr_verify


@dataclass
class Identity:
    group: str
    index: int
    secret: int
    public: object

    @staticmethod
    def new(group: str, index: int) -> "Identity":
        g = get_group(group)
        x = g.rand_scalar()
        return Identity(group, index, x, g.mul(g.G, x))

    @property
    def g(self) -> Group:
        return get_group(self.group)

    def fingerprint(self) -> str:
        return fingerprint(self.g, self.public)

    def public_json(self) -> dict:
        return {"index": self.index, "group": self.group,
                "public": self.g.hex(self.public), "fingerprint": self.fingerprint()}

    def save(self, path: str, passphrase: str | None) -> None:
        body = json.dumps({"group": self.group, "index": self.index,
                           "secret": hex(self.secret)}).encode()
        if passphrase:
            salt = os.urandom(16)
            blob = (b"TORUSID1 sealed " + salt.hex().encode() + b"\n"
                    + _seal.seal(_seal.passphrase_key(passphrase, salt), body))
        else:
            blob = b"TORUSID1 plain\n" + body
        _atomic(path, blob, 0o600)

    @staticmethod
    def load(path: str, passphrase: str | None) -> "Identity":
        head, _, rest = Path(path).read_bytes().partition(b"\n")
        parts = head.split()
        if not parts or parts[0] != b"TORUSID1":
            raise CustodyError("not an identity file")
        if parts[1] == b"sealed":
            if not passphrase:
                raise CustodyError("identity is sealed — passphrase required")
            try:
                rest = _seal.unseal(_seal.passphrase_key(passphrase, bytes.fromhex(parts[2].decode())), rest)
            except ValueError:
                raise CustodyError("wrong passphrase") from None
        d = json.loads(rest)
        g = get_group(d["group"])
        x = int(d["secret"], 16)
        return Identity(d["group"], int(d["index"]), x, g.mul(g.G, x))


def fingerprint(g: Group, pub) -> str:
    h = hashlib.sha256(b"torussql/custody/idfp\x00" + g.encode(pub)).hexdigest()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ── signed broadcast ─────────────────────────────────────────────────────────
def sign_broadcast(idn: Identity, kind: str, session: bytes, b: Broadcast) -> dict:
    g = idn.g
    body = {"kind": kind, "session": session.hex(), "bcast": b.to_json(g)}
    _, sig = schnorr_prove(g, idn.secret, b"sig\x00" + _canon(body))
    return {"body": body, "sig": sig.to_json(g), "signer": idn.index}


def open_broadcast(g: Group, signer_pub, msg: dict, kind: str, session: bytes) -> Broadcast:
    body = msg["body"]
    if body.get("kind") != kind or body.get("session") != session.hex():
        raise CustodyError("broadcast belongs to a different ceremony")
    if not schnorr_verify(g, signer_pub, SchnorrProof.from_json(g, msg["sig"]),
                          b"sig\x00" + _canon(body)):
        raise CustodyError(f"bad signature on broadcast from participant {msg.get('signer')}")
    b = Broadcast.from_json(g, body["bcast"])
    if b.index != msg["signer"]:
        raise CustodyError("broadcast index does not match its signer")
    return b


# ── encrypted private share ──────────────────────────────────────────────────
def _share_key(g: Group, S, E, session: bytes, i: int, j: int) -> int:
    return _seal.key_from_secret(g.encode(S), g.encode(E), session,
                                 i.to_bytes(4, "big"), j.to_bytes(4, "big"),
                                 label=b"torussql/custody/share-transport/v1")


def encrypt_share(g: Group, recipient_pub, session: bytes, i: int, j: int, share: int) -> dict:
    e = g.rand_scalar()
    E = g.mul(g.G, e)
    key = _share_key(g, g.mul(recipient_pub, e), E, session, i, j)
    return {"from": i, "to": j, "session": session.hex(), "E": g.hex(E),
            "ct": _seal.seal(key, share.to_bytes(32, "big")).hex()}


def decrypt_share(idn: Identity, session: bytes, msg: dict) -> int:
    g = idn.g
    if msg["session"] != session.hex() or msg["to"] != idn.index:
        raise CustodyError("private share is not addressed to this participant/session")
    E = g.from_hex(msg["E"])
    key = _share_key(g, g.mul(E, idn.secret), E, session, int(msg["from"]), idn.index)
    try:
        return int.from_bytes(_seal.unseal(key, bytes.fromhex(msg["ct"])), "big")
    except ValueError:
        raise CustodyError(f"private share from participant {msg['from']} failed authentication") from None


# ── file-based ceremony helpers ──────────────────────────────────────────────
def export_dealing(idn: Identity, kind: str, session: bytes, dealing: Dealing,
                   recipient_pubs: dict[int, object], outdir: str) -> list[str]:
    """Write ``broadcast_<i>.json`` and one encrypted ``share_<i>_to_<j>.json`` per recipient."""
    g = idn.g
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    files = []
    p = out / f"broadcast_{idn.index}.json"
    p.write_text(json.dumps(sign_broadcast(idn, kind, session, dealing.broadcast), indent=1))
    files.append(str(p))
    for j, y in dealing.shares.items():
        if j not in recipient_pubs:
            continue
        p = out / f"share_{idn.index}_to_{j}.json"
        p.write_text(json.dumps(encrypt_share(g, recipient_pubs[j], session, idn.index, j, y)))
        os.chmod(p, 0o600)
        files.append(str(p))
    return files


def import_dealings(idn: Identity, kind: str, session: bytes, indir: str,
                    sender_pubs: dict[int, object], senders: list[int]
                    ) -> tuple[dict[int, Broadcast], dict[int, int]]:
    g = idn.g
    d = Path(indir)
    bcasts, shares = {}, {}
    for i in senders:
        bf, sf = d / f"broadcast_{i}.json", d / f"share_{i}_to_{idn.index}.json"
        if not bf.exists() or not sf.exists():
            raise CustodyError(f"missing files from participant {i}")
        bcasts[i] = open_broadcast(g, sender_pubs[i], json.loads(bf.read_text()), kind, session)
        msg = json.loads(sf.read_text())
        if int(msg.get("from", -1)) != i:
            raise CustodyError(f"{sf.name} claims to be from participant "
                               f"{msg.get('from')}, expected {i} (files swapped?)")
        shares[i] = decrypt_share(idn, session, msg)
    return bcasts, shares
