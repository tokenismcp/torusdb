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
from dataclasses import dataclass, field
from pathlib import Path

from . import seal as _seal
from .dkg import Broadcast, Dealing
from .group import CustodyError, Group, get_group
from .keys import _atomic
from .proofs import SchnorrProof, schnorr_prove, schnorr_verify


@dataclass
class Identity:
    """A participant's long-term key. NOTE (accepted design): this ONE secret is
    used both for Schnorr signatures and for the DH that decrypts private
    shares. The uses are domain-separated (signature contexts are prefixed
    ``sig\\0`` / ``share-sig\\0`` / ``dkg-pok\\0``; the DH key goes through a
    labelled KDF), and no oracle for either is exposed, so no cross-protocol
    attack is known; splitting it into two keys would be a cleaner design."""
    group: str
    index: int
    secret: int = field(repr=False)          # SECRET: never in repr/logs/tracebacks
    public: object

    def __repr__(self) -> str:
        return f"Identity(group={self.group!r}, index={self.index}, secret=<secret>)"

    def __reduce__(self):
        raise TypeError("Identity holds a secret key and cannot be pickled or copied; "
                        "use save()/load()")

    def __getstate__(self):
        raise TypeError("Identity holds a secret key and cannot be pickled or copied")

    @staticmethod
    def new(group: str, index: int) -> "Identity":
        g = get_group(group)
        x = g.rand_scalar()
        return Identity(group, index, x, g.mul_blinded(g.G, x))

    @property
    def g(self) -> Group:
        return get_group(self.group)

    def fingerprint(self) -> str:
        return fingerprint(self.g, self.public)

    def public_json(self) -> dict:
        return {"index": self.index, "group": self.group,
                "public": self.g.hex(self.public), "fingerprint": self.fingerprint()}

    _MAGIC = b"TORUSID2"
    _LABEL = b"torussql/custody/file/identity/v2"

    def save(self, path: str, passphrase: str | None) -> None:
        body = json.dumps({"group": self.group, "index": self.index,
                           "secret": hex(self.secret)}).encode()
        if passphrase is None:
            blob = self._MAGIC + b" plain\n" + body
        elif not passphrase:
            raise CustodyError("an empty passphrase is not accepted (pass None for a plain file)")
        else:
            salt = os.urandom(16)
            head = self._MAGIC + b" sealed " + salt.hex().encode()
            blob = head + b"\n" + _seal.seal(
                _seal.passphrase_key(passphrase, salt, self._LABEL), body, aad=head)
        _atomic(path, blob, 0o600)

    @staticmethod
    def load(path: str, passphrase: str | None) -> "Identity":
        head, _, rest = Path(path).read_bytes().partition(b"\n")
        parts = head.split()
        if parts and parts[0] == b"TORUSID1":
            raise CustodyError(f"{path}: old identity-file format (v1); create a new identity")
        if len(parts) < 2 or parts[0] != Identity._MAGIC:
            raise CustodyError("not an identity file")
        try:
            if parts[1] == b"sealed" and len(parts) == 3:
                if not passphrase:
                    raise CustodyError("identity is sealed — passphrase required")
                try:
                    key = _seal.passphrase_key(passphrase, bytes.fromhex(parts[2].decode()),
                                               Identity._LABEL)
                    rest = _seal.unseal(key, rest, aad=head)
                except ValueError:
                    raise CustodyError("wrong passphrase") from None
            elif parts[1] != b"plain":
                raise CustodyError(f"{path}: bad identity-file header")
            d = json.loads(rest)
            g = get_group(d["group"])
            x = int(d["secret"], 16)
            if not 0 < x < g.order:
                raise CustodyError("identity secret out of range")
            return Identity(d["group"], int(d["index"]), x, g.mul_blinded(g.G, x))
        except CustodyError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, UnicodeError) as exc:
            raise CustodyError(f"{path}: malformed identity file ({type(exc).__name__})") from None


def fingerprint(g: Group, pub) -> str:
    h = hashlib.sha256(b"torussql/custody/idfp\x00" + g.encode(pub)).hexdigest()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def ids_digest(g: Group, pubs: dict) -> str:
    """Digest of a whole participant list (index -> identity public key). Bound
    into every signed broadcast and the transcript, so participants who hold
    different ``ids.json`` files cannot complete a ceremony together."""
    h = hashlib.sha256(b"torussql/custody/ids/v1\x00" + g.name.encode())
    for i in sorted(pubs):
        h.update(int(i).to_bytes(4, "big") + g.encode(pubs[i]))
    return h.hexdigest()[:32]


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ── signed broadcast ─────────────────────────────────────────────────────────
def sign_broadcast(idn: Identity, kind: str, session: bytes, b: Broadcast,
                   params: dict | None = None, key_group: Group | None = None) -> dict:
    """Sign (kind, session, signer, ceremony ``params``, broadcast). ``params`` is
    the ceremony specification (group, k, n, participant-list digest; for a
    reshare also old key_id/epoch, quorum, new k/n): every participant must
    present the identical value or the broadcast is refused."""
    g = idn.g
    body = {"kind": kind, "session": session.hex(), "signer": idn.index,
            "params": params or {}, "bcast": b.to_json(key_group or g)}
    _, sig = schnorr_prove(g, idn.secret, b"sig\x00" + _canon(body))
    return {"body": body, "sig": sig.to_json(g), "signer": idn.index}


def open_broadcast(g: Group, signer_pub, msg: dict, kind: str, session: bytes, *,
                   expected_index: int | None = None, params: dict | None = None,
                   key_group: Group | None = None) -> Broadcast:
    """``g`` is the IDENTITY group (signatures); ``key_group`` the group the key's commitments
    live in (defaults to ``g``; ``bn254g2`` for the second FHE secret)."""
    try:
        body = msg["body"]
        if body.get("kind") != kind or body.get("session") != session.hex():
            raise CustodyError("broadcast belongs to a different ceremony")
        if not schnorr_verify(g, signer_pub, SchnorrProof.from_json(g, msg["sig"]),
                              b"sig\x00" + _canon(body)):
            raise CustodyError(f"bad signature on broadcast from participant {msg.get('signer')}")
        got, want = body.get("params", {}), (params or {})
        if got != want and "new_ids" in want and "new_ids" not in got:
            raise CustodyError("this reshare broadcast uses the OLD format: it is not bound to the "
                               "new committee's identity list. Re-run reshare-start with this "
                               "version (it needs --old-ids and --new-ids)")
        if got != want:
            raise CustodyError("broadcast was made for a different ceremony specification "
                               "(group/k/n/participants differ)")
        b = Broadcast.from_json(key_group or g, body["bcast"])
        signer = body.get("signer")
        if b.index != msg.get("signer") or b.index != signer:
            raise CustodyError("broadcast index does not match its signer")
        if expected_index is not None and b.index != expected_index:
            raise CustodyError(f"broadcast is from participant {b.index}, expected "
                               f"{expected_index}")
        return b
    except CustodyError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise CustodyError(f"malformed broadcast ({type(exc).__name__})") from None


# ── encrypted + signed private share ─────────────────────────────────────────
SHARE_FMT = "torussql-share/2"


def _share_key(g: Group, S, E, session: bytes, i: int, j: int) -> int:
    return _seal.key_from_secret(g.encode(S), g.encode(E), session,
                                 i.to_bytes(4, "big"), j.to_bytes(4, "big"),
                                 label=b"torussql/custody/share-transport/v1")


def _share_sig_ctx(msg: dict) -> bytes:
    return b"share-sig\x00" + _canon({k: msg[k] for k in
                                      ("fmt", "from", "to", "session", "E", "ct")})


def encrypt_share(dealer: Identity, recipient_pub, session: bytes, j: int, share: int) -> dict:
    """Encrypt ``share`` (dealer -> j) to ``recipient_pub`` and SIGN
    (session, i, j, E, ciphertext) with the dealer's identity key, so the
    recipient can tell a substituted file from an honest dealer's."""
    g, i = dealer.g, dealer.index
    e = g.rand_scalar()
    E = g.mul_blinded(g.G, e)
    key = _share_key(g, g.mul_blinded(recipient_pub, e), E, session, i, j)
    msg = {"fmt": SHARE_FMT, "from": i, "to": j, "session": session.hex(), "E": g.hex(E),
           "ct": _seal.seal(key, share.to_bytes(32, "big")).hex()}
    _, sig = schnorr_prove(g, dealer.secret, _share_sig_ctx(msg))
    msg["sig"] = sig.to_json(g)
    return msg


def decrypt_share(idn: Identity, session: bytes, msg: dict, sender_pub) -> int:
    """Verify the dealer's signature FIRST (a forged or substituted file is
    rejected as such, without blaming the honest dealer), then decrypt."""
    g = idn.g
    try:
        if msg.get("fmt") != SHARE_FMT:
            raise CustodyError("private share file has an unsupported format/version")
        if msg["session"] != session.hex() or msg["to"] != idn.index:
            raise CustodyError("private share is not addressed to this participant/session")
        if not schnorr_verify(g, sender_pub, SchnorrProof.from_json(g, msg["sig"]),
                              _share_sig_ctx(msg)):
            raise CustodyError(f"private share file 'from participant {msg.get('from')}' has "
                               f"an invalid dealer signature (forged or substituted file; "
                               f"the named dealer is NOT blamed)")
        E = g.from_hex(msg["E"])
        key = _share_key(g, g.mul_blinded(E, idn.secret), E, session, int(msg["from"]), idn.index)
        try:
            return int.from_bytes(_seal.unseal(key, bytes.fromhex(msg["ct"])), "big")
        except ValueError:
            raise CustodyError(f"private share from participant {msg['from']} failed "
                               f"authentication") from None
    except CustodyError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise CustodyError(f"malformed private share file ({type(exc).__name__})") from None


# ── file-based ceremony helpers ──────────────────────────────────────────────
def export_dealing(idn: Identity, kind: str, session: bytes, dealing: Dealing,
                   recipient_pubs: dict[int, object], outdir: str,
                   params: dict | None = None, key_group: Group | None = None) -> list[str]:
    """Write ``broadcast_<i>.json`` and one encrypted+signed ``share_<i>_to_<j>.json``
    per recipient. Files are created exclusively, mode 0600 for shares from the start."""
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    files = []
    p = out / f"broadcast_{idn.index}.json"
    _atomic(str(p), json.dumps(sign_broadcast(idn, kind, session, dealing.broadcast, params, key_group),
                               indent=1).encode(), 0o644)
    files.append(str(p))
    for j, y in dealing.shares.items():
        if j not in recipient_pubs:
            continue
        p = out / f"share_{idn.index}_to_{j}.json"
        _atomic(str(p), json.dumps(encrypt_share(idn, recipient_pubs[j], session, j, y)).encode(),
                0o600)
        files.append(str(p))
    return files


def import_dealings(idn: Identity, kind: str, session: bytes, indir: str,
                    sender_pubs: dict[int, object], senders: list[int],
                    params: dict | None = None, key_group: Group | None = None
                    ) -> tuple[dict[int, Broadcast], dict[int, int]]:
    g = idn.g
    d = Path(indir)
    bcasts, shares = {}, {}
    for i in senders:
        bf, sf = d / f"broadcast_{i}.json", d / f"share_{i}_to_{idn.index}.json"
        if not bf.exists() or not sf.exists():
            raise CustodyError(f"missing files from participant {i}")
        if i not in sender_pubs:
            raise CustodyError(f"no identity key known for participant {i}")
        try:
            bmsg, msg = json.loads(bf.read_text()), json.loads(sf.read_text())
        except (ValueError, UnicodeError) as exc:
            raise CustodyError(f"unreadable ceremony file from participant {i}") from None
        bcasts[i] = open_broadcast(g, sender_pubs[i], bmsg, kind, session,
                                   expected_index=i, params=params, key_group=key_group)
        if not isinstance(msg, dict) or msg.get("from") != i:
            raise CustodyError(f"{sf.name} claims to be from participant "
                               f"{msg.get('from') if isinstance(msg, dict) else None}, "
                               f"expected {i} (files swapped?)")
        shares[i] = decrypt_share(idn, session, msg, sender_pubs[i])
    return bcasts, shares
