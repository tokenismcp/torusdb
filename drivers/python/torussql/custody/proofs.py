# SPDX-License-Identifier: Apache-2.0
"""Zero-knowledge proofs (Fiat–Shamir, non-interactive).

* ``SchnorrProof`` — proof of knowledge of x with P = x·B. Used for the DKG
  residue commitment (stops rogue-key contributions) and, with the message in
  the context, as a signature under a participant identity key.
* ``DleqProof``   — Chaum–Pedersen: log_B1(P1) = log_B2(P2). A custodian proves
  that its partial result ``D = y·E`` uses the same secret ``y`` as its public
  verification key ``Y = y·G`` — so a wrong or malicious partial is *detected*
  and excluded instead of silently corrupting the combined key.

Every challenge hashes a domain label, caller context, all bases and all
commitments, so proofs cannot be replayed across sessions or statements.
"""
from __future__ import annotations

from dataclasses import dataclass

from .group import Group


def _ser(g: Group, *pts) -> list[bytes]:
    return [g.encode(p) for p in pts]


@dataclass(frozen=True)
class SchnorrProof:
    R: object
    z: int

    def to_json(self, g: Group) -> dict:
        return {"R": g.hex(self.R), "z": hex(self.z)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "SchnorrProof":
        return SchnorrProof(g.from_hex(d["R"]), int(d["z"], 16))


def schnorr_prove(g: Group, x: int, context: bytes, base=None) -> tuple[object, SchnorrProof]:
    base = g.G if base is None else base
    P = g.mul_blinded(base, x)                     # x, k are secret: split-scalar multiply
    k = g.rand_scalar()
    R = g.mul_blinded(base, k)
    c = g.hash_to_scalar(b"schnorr", context, *_ser(g, base, P, R))
    return P, SchnorrProof(R, (k + c * x) % g.order)


def schnorr_verify(g: Group, P, proof: SchnorrProof, context: bytes, base=None) -> bool:
    base = g.G if base is None else base
    if not (0 < proof.z < g.order):
        return False
    c = g.hash_to_scalar(b"schnorr", context, *_ser(g, base, P, proof.R))
    return g.eq(g.mul(base, proof.z), g.add(proof.R, g.mul(P, c)))


@dataclass(frozen=True)
class DleqProof:
    R1: object
    R2: object
    z: int

    def to_json(self, g: Group) -> dict:
        return {"R1": g.hex(self.R1), "R2": g.hex(self.R2), "z": hex(self.z)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "DleqProof":
        return DleqProof(g.from_hex(d["R1"]), g.from_hex(d["R2"]), int(d["z"], 16))


def dleq_prove(g: Group, x: int, B1, B2, P1, P2, context: bytes) -> DleqProof:
    k = g.rand_scalar()
    R1, R2 = g.mul_blinded(B1, k), g.mul_blinded(B2, k)   # secret nonce
    c = g.hash_to_scalar(b"dleq", context, *_ser(g, B1, P1, B2, P2, R1, R2))
    return DleqProof(R1, R2, (k + c * x) % g.order)


def dleq_verify(g: Group, B1, B2, P1, P2, proof: DleqProof, context: bytes) -> bool:
    if not (0 < proof.z < g.order):
        return False
    c = g.hash_to_scalar(b"dleq", context, *_ser(g, B1, P1, B2, P2, proof.R1, proof.R2))
    return (g.eq(g.mul(B1, proof.z), g.add(proof.R1, g.mul(P1, c)))
            and g.eq(g.mul(B2, proof.z), g.add(proof.R2, g.mul(P2, c))))
