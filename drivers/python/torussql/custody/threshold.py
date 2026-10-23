# SPDX-License-Identifier: Apache-2.0
"""Threshold use of the key: one-round, aggregator-free, verifiable decryption.

Key envelope (ECIES-style).  Anyone holding only the public key X can *wrap* a
fresh symmetric key:

    e ←$ F_q ;  E = e·G ;  S = e·X ;  K = KDF(S ‖ E ‖ X ‖ context)

Opening needs ``S = x·E`` where ``x`` is the threshold secret, and **x is never
assembled**:

    custodian i :  Dᵢ = yᵢ·E ,  πᵢ = DLEQ(logG Yᵢ = log_E Dᵢ)      (one message)
    anyone      :  verify πᵢ for each Dᵢ, pick a quorum S, then
                   S = Σ_{i∈S} λᵢ^S · Dᵢ

A wrong or malicious partial fails its proof and is excluded — it cannot
silently corrupt the result. Any participant can combine (no coordinator), and
no custodian ever sees another's share, a plaintext, or the final key.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from . import laurent, seal as _seal
from .group import CustodyError, Group
from .keys import KeyShare, PublicKey
from .proofs import DleqProof, dleq_prove, dleq_verify


class InsufficientPartials(CustodyError):
    def __init__(self, need: int, have: int, problems: dict):
        self.problems = problems
        super().__init__(f"need {need} valid partial results, have {have}"
                         + (f"; problems: {problems}" if problems else ""))


@dataclass(frozen=True)
class Partial:
    index: int
    D: object                  # yᵢ·E
    proof: DleqProof

    def to_json(self, g: Group) -> dict:
        return {"index": self.index, "D": g.hex(self.D), "proof": self.proof.to_json(g)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "Partial":
        return Partial(int(d["index"]), g.from_hex(d["D"]), DleqProof.from_json(g, d["proof"]))


def _ctx(pub: PublicKey, context: bytes) -> bytes:
    return (b"partial\x00" + bytes.fromhex(pub.key_id) + struct.pack(">Q", pub.epoch)
            + context)


def partial_decrypt(share: KeyShare, E, context: bytes = b"") -> Partial:
    """Custodian side. Never returns or logs the share."""
    pub = share.public
    g = pub.g
    if g.is_identity(E):
        raise CustodyError("refusing the identity point")
    D = g.mul_blinded(E, share.y)
    Y = pub.verification_key(share.index)
    return Partial(share.index, D,
                   dleq_prove(g, share.y, g.G, E, Y, D, _ctx(pub, context)))


def verify_partial(pub: PublicKey, E, part: Partial, context: bytes = b"") -> bool:
    g = pub.g
    if not 1 <= part.index <= pub.n:
        return False
    return dleq_verify(g, g.G, E, pub.verification_key(part.index), part.D,
                       part.proof, _ctx(pub, context))


def combine(pub: PublicKey, E, partials, context: bytes = b"", *, cross_check: bool = True):
    """Return x·E from any quorum of valid partials."""
    g = pub.g
    valid: dict[int, Partial] = {}
    problems: dict[int, str] = {}
    for part in partials:
        if part.index in valid:
            continue
        try:
            ok = verify_partial(pub, E, part, context)
        except CustodyError as exc:
            ok, problems[part.index] = False, str(exc)
        if ok:
            valid[part.index] = part
        else:
            problems.setdefault(part.index, "invalid proof")
    if len(valid) < pub.k:
        raise InsufficientPartials(pub.k, len(valid), problems)
    order = sorted(valid)

    def run(idx):
        lam = laurent.lambdas(idx, g.order)
        return g.msm((lam[i], valid[i].D) for i in idx)

    result = run(order[:pub.k])
    if cross_check and len(order) > pub.k:                     # independent quorum
        if not g.eq(result, run(order[-pub.k:])):
            raise CustodyError("inconsistent partial results (mixed epochs?)")
    return result


# ── key envelope ─────────────────────────────────────────────────────────────
def wrap_key(pub: PublicKey, context: bytes = b"") -> tuple[int, dict]:
    """Create a fresh sealing key for ``context``. Needs only the PUBLIC key."""
    g = pub.g
    e = g.rand_scalar()
    E = g.mul_blinded(g.G, e)
    S = g.mul_blinded(pub.X, e)
    return _derive(pub, S, E, context), {
        "v": 1, "group": pub.group, "key_id": pub.key_id, "k": pub.k, "n": pub.n,
        "E": g.hex(E), "ctx": context.hex()}


def unwrap_key(pub: PublicKey, header: dict, shared_point) -> int:
    """``shared_point(E, context)`` must return x·E (e.g. ``Quorum.shared_point``)."""
    g = pub.g
    if header.get("key_id") != pub.key_id:
        raise CustodyError("this envelope was made for a different key")
    E = g.from_hex(header["E"])
    context = bytes.fromhex(header["ctx"])
    return _derive(pub, shared_point(E, context), E, context)


def _derive(pub: PublicKey, S, E, context: bytes) -> int:
    g = pub.g
    return _seal.key_from_secret(g.encode(S), g.encode(E), g.encode(pub.X), context,
                                 label=b"torussql/custody/envelope/v1")
