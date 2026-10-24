# SPDX-License-Identifier: Apache-2.0
"""Dealerless distributed key generation (one round, no aggregator).

Every participant is a dealer of its own Laurent sharing; the key is the sum of
all residues, so **no party ever knows it**. This is Feldman-VSS DKG over the
Laurent structure with a proof of knowledge of each dealer's residue (the
FROST-style design), adapted to the Laurent weights:

  round 1 (all at once):  dealer i broadcasts   Cᵢ = (Cᵢ₀ … Cᵢt),  π_i
                          and privately sends   sᵢ→j = fᵢ(xⱼ)   to each j
  finish (local):          j checks  sᵢ→j·G = Σ_m xⱼ⁻ᵐ·Cᵢm  for every i,
                          verifies every π_i, then
                              yⱼ = Σᵢ sᵢ→j          (its share)
                              C̄m = Σᵢ Cᵢm           (public commitments)
                              X  = C̄₁              (public key)

If anything is wrong the ceremony **aborts and names the culprit** — a one-time
key ceremony is simply restarted without them. All ``n`` participants must deal.

Known limitation (shared with every Feldman-based DKG): an adversary who speaks
last can bias the *distribution* of X. That is harmless for an encryption key
(no security property of ECIES depends on X's distribution) but means this DKG
should not be used where uniformity of X matters.

Transport is out of scope here: private shares must travel over an
authenticated, confidential channel, broadcasts over an authenticated
broadcast, and participants should compare ``transcript`` hashes out of band.
``identity.py`` provides signed/encrypted envelopes for file-based ceremonies.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from . import laurent
from .group import CustodyError, Group, get_group
from .keys import KeyShare, PublicKey
from .proofs import SchnorrProof, schnorr_prove, schnorr_verify


class DKGError(CustodyError):
    def __init__(self, msg: str, culprit: int | None = None):
        super().__init__(msg if culprit is None else f"participant {culprit}: {msg}")
        self.culprit = culprit


@dataclass(frozen=True)
class Broadcast:
    """Public part of a dealing."""
    index: int
    commitments: tuple          # Cᵢ0 … Cᵢt
    proof: SchnorrProof         # knowledge of the residue behind Cᵢ1

    def to_json(self, g: Group) -> dict:
        return {"index": self.index, "commitments": [g.hex(c) for c in self.commitments],
                "pok": self.proof.to_json(g)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "Broadcast":
        return Broadcast(int(d["index"]), tuple(g.from_hex(c) for c in d["commitments"]),
                         SchnorrProof.from_json(g, d["pok"]))

    def digest(self, g: Group) -> bytes:
        h = hashlib.sha256(b"torussql/custody/bcast\x00" + self.index.to_bytes(4, "big"))
        for c in self.commitments:
            h.update(g.encode(c))
        h.update(g.encode(self.proof.R) + self.proof.z.to_bytes(32, "big"))
        return h.digest()


def _pok_ctx(session: bytes, index: int) -> bytes:
    return b"dkg-pok\x00" + session + index.to_bytes(4, "big")


def dkg_params(group: str, k: int, n: int, ids_digest: str = "") -> dict:
    """The ceremony specification that is signed into every broadcast and hashed
    into the transcript: group, quorum, size and (file ceremonies) the digest of
    the participant identity list."""
    return {"group": group, "k": k, "n": n, "ids": ids_digest}


def transcript_hash(g: Group, session: bytes, broadcasts: dict[int, Broadcast],
                    params: dict | None = None) -> str:
    """Compare this value across participants (out of band) before trusting the
    key. Covers the session, the ceremony specification (group, k, n, identity
    list digest) and every broadcast."""
    h = hashlib.sha256(b"torussql/custody/transcript/v2\x00" + session)
    spec = json.dumps(params or {}, sort_keys=True, separators=(",", ":")).encode()
    h.update(len(spec).to_bytes(4, "big") + spec)
    for i in sorted(broadcasts):
        h.update(broadcasts[i].digest(g))
    return h.hexdigest()


class Dealing:
    """One participant's round-1 output."""

    def __init__(self, broadcast: Broadcast, shares: dict[int, int]):
        self.broadcast = broadcast
        self.shares = shares            # recipient index -> share (SECRET, per recipient)


def deal(g: Group, p: laurent.Params, index: int, secret: int | None, session: bytes,
         *, with_pok: bool = True) -> Dealing:
    """Create a Laurent sharing of ``secret`` (random if None) and its
    commitments. Used by the DKG (random secret) and by resharing (given)."""
    coeffs = laurent.new_coeffs(g.rand_scalar() if secret is None else secret, p)
    comms = tuple(g.mul_blinded(g.G, c) for c in coeffs)
    if with_pok:
        _, pok = schnorr_prove(g, coeffs[1], _pok_ctx(session, index))
    else:
        pok = SchnorrProof(g.identity, 0)
    shares = {x: laurent.evaluate(coeffs, x, g.order) for x in p.points()}
    return Dealing(Broadcast(index, comms, pok), shares)


def check_dealing(g: Group, p: laurent.Params, b: Broadcast, my_x: int, my_share: int,
                  session: bytes, *, need_pok: bool = True) -> None:
    if len(b.commitments) != p.k:
        raise DKGError("wrong number of commitments", b.index)
    # a dealing with an identity constant term or residue commitment contributes nothing (the
    # coefficient would be 0 mod q; a random honest coefficient is 0 with probability 1/q, so
    # this never rejects an honest dealer)
    if g.is_identity(b.commitments[0]) or g.is_identity(b.commitments[1]):
        raise DKGError("dealing contributes nothing (identity constant-term / residue commitment)",
                       b.index)
    if need_pok and not schnorr_verify(g, b.commitments[1], b.proof, _pok_ctx(session, b.index)):
        raise DKGError("invalid proof of knowledge", b.index)
    w = laurent.commit_check_weights(my_x, p.t, g.order)
    if not g.eq(g.mul_blinded(g.G, my_share), g.msm(zip(w, b.commitments))):
        raise DKGError("share does not match its commitments", b.index)


class Participant:
    """One custodian's side of the ceremony."""

    def __init__(self, group: str, k: int, n: int, index: int, session: bytes,
                 ids_digest: str = ""):
        self.g = get_group(group)
        self.ids_digest = ids_digest
        self.p = laurent.Params(k, n, self.g.order)
        if not 1 <= index <= n:
            raise ValueError("index must be in 1..n")
        self.index, self.session = index, session
        self._dealing: Dealing | None = None

    def round1(self) -> Dealing:
        if self._dealing is None:
            self._dealing = deal(self.g, self.p, self.index, None, self.session)
        return self._dealing

    def finish(self, broadcasts: dict[int, Broadcast], shares_in: dict[int, int]
               ) -> tuple[KeyShare, PublicKey, str]:
        g, p = self.g, self.p
        if set(broadcasts) != set(p.points()):
            raise DKGError(f"expected broadcasts from all {p.n} participants, got "
                           f"{sorted(broadcasts)}")
        if set(shares_in) != set(p.points()):
            raise DKGError("expected a private share from every participant")
        for i in p.points():
            check_dealing(g, p, broadcasts[i], self.index, shares_in[i] % g.order, self.session)
        y = sum(shares_in.values()) % g.order
        agg = tuple(g.msm((1, broadcasts[i].commitments[m]) for i in p.points())
                    for m in range(p.k))
        pub = PublicKey(g.name, p.k, p.n, agg, 0)
        ks = KeyShare(self.index, y, pub)
        if not ks.verify():                                  # pragma: no cover
            raise DKGError("aggregate share failed verification")
        return ks, pub, transcript_hash(g, self.session, broadcasts,
                                        dkg_params(g.name, p.k, p.n, self.ids_digest))


def run_local_ceremony(k: int, n: int, group: str = "secp256k1") -> tuple[list[KeyShare], PublicKey, str]:
    """Run the whole DKG inside ONE process.

    The messages are exactly those of the real protocol, but a single process
    sees every share, so this gives **no** dealerless guarantee — it exists for
    tests, demos and development. Production keys come from a real ceremony
    (``python -m torussql.custody dkg-…``) with one participant per host."""
    import secrets
    session = secrets.token_bytes(16)
    parts = [Participant(group, k, n, i, session) for i in range(1, n + 1)]
    dealings = {pt.index: pt.round1() for pt in parts}
    bcasts = {i: d.broadcast for i, d in dealings.items()}
    shares, pub, tx = [], None, None
    for pt in parts:
        ks, pub, tx = pt.finish(bcasts, {i: dealings[i].shares[pt.index] for i in dealings})
        shares.append(ks)
    return shares, pub, tx
