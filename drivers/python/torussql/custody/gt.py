# SPDX-License-Identifier: Apache-2.0
"""Threshold use of a BN254 key in the target group GT (EC-FHE ``DOT``).

Two custody keys take part in the FHE scheme, in DIFFERENT groups:

* key 1, secret ``s``, group ``bn254``  (public ``X1 = s·G1`` — needed for encryption),
* key 2, secret ``s2``, group ``bn254g2`` (public ``Q2 = s2·G2`` — the public key IS the G2
  point; **no G1 image of ``s2`` exists anywhere**, because ``X2 = s2·G1`` together with a cell's
  halves gives ``e(G1, D2) / e(X2, D1) = g^v``, i.e. total plaintext recovery).

Both are Laurent-shared, so applying the secret to a GT element is linear in the exponent and
``x`` is never assembled: custodian ``i`` returns ``Dᵢ = c^{yᵢ}``; anyone combines
``c^x = Π_{i∈S} Dᵢ^{λᵢ}``.

Soundness of the GT power  (``GtProof``, Chaum–Pedersen across two groups of the SAME prime
order ``q`` — the key's group (G1 or G2) and the order-``q`` subgroup μ_q ⊂ GT)
    statement   Yᵢ = yᵢ·B  (public verification key, B = G1 or G2)   and   D = c^{yᵢ}
    prover      k ←$ F_q ;  R1 = k·B ,  R2 = c^k ;  h = H(ctx, B, Yᵢ, R1, c, D, R2) ;  z = k + h·yᵢ
    verifier    z·B = R1 + h·Yᵢ   and   c^z = R2 · D^h        (and  c, D ∈ μ_q)
  * completeness: both equations are the images of ``z = k + h·y``.
  * special soundness: two accepting transcripts (R1,R2) with challenges h ≠ h′ give
    ``y = (z − z′)/(h − h′)`` with ``Yᵢ = y·B`` (first equation) and ``D^{h−h′} = c^{z−z′} =
    c^{(h−h′)y}``. ``c ∈ μ_q`` makes the right side depend only on ``y mod q``; with
    ``D ∈ μ_q`` and ``gcd(h−h′, q) = 1`` the map ``u ↦ u^{h−h′}`` is injective on μ_q, so
    ``D = c^y``. In the random-oracle model a custodian cannot return any ``D`` other than
    ``c^{yᵢ}`` for the ``yᵢ`` committed to by its verification key ``Yᵢ``.
  * why the μ_q membership checks are mandatory: in Fp12* (order ≠ q) a ``D`` with an extra
    small-order factor would pass the equations, and a custodian answering for ``c`` outside μ_q
    would leak ``yᵢ`` modulo small primes (small-subgroup attack). Both ``c`` and ``D`` are
    tested with ``u^q = 1`` (one exponentiation each).
  * zero knowledge: honest-verifier simulatable in the standard way (pick z, h, set R1, R2).
No pairing is needed for the proofs.

This module uses ``py_ecc`` only (GT elements are exchanged in the canonical 384-byte
encoding of ``torusdb_core.fhe_backend``, identical for every back end). Exponentiation of GT by
a secret scalar has no constant-time primitive; it uses the same split-scalar blinding as
``Group.mul_blinded`` — a mitigation of repeated-measurement correlation, NOT constant-time
arithmetic (the G1/G2 multiplications inside the proof do use mcl's mulCT when available).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

try:
    from py_ecc.optimized_bn128 import (FQ2, FQ12, G1 as _G1, G2 as _G2, add as _add, b2 as _B2,
                                        curve_order as Q, field_modulus as P, final_exponentiate,
                                        is_inf, is_on_curve, multiply as _mul, neg as _neg,
                                        normalize, pairing)
except ImportError as _exc:                                   # pragma: no cover
    raise ImportError("threshold custody needs the 'py_ecc' package: "
                      "pip install 'torussql[custody]'") from _exc

from . import laurent
from .group import CustodyError, Group, InvalidPoint
from .keys import KeyShare, PublicKey
from .proofs import _ser

GT_BYTES = 384
G2_BYTES = 128
MAX_GT_BATCH = 64                    # elements per request (each costs ~5 exponentiations)


def need_bn254(pub: PublicKey) -> None:
    if pub.group not in ("bn254", "bn254g2"):
        raise CustodyError("GT operations need a 'bn254' (s) or 'bn254g2' (s2) key")


# ── GT elements (canonical 12 × 32-byte big-endian coefficients) ──────────────
def gt_decode(raw: bytes) -> FQ12:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != GT_BYTES:
        raise InvalidPoint("a GT element is 384 bytes")
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, GT_BYTES, 32)]
    if any(c >= P for c in v):
        raise InvalidPoint("GT coefficient out of range")
    return FQ12(v)


def gt_encode(x: FQ12) -> bytes:
    return b"".join(int(c.n if hasattr(c, "n") else c).to_bytes(32, "big") for c in x.coeffs)


def gt_in_subgroup(x: FQ12) -> bool:
    """x ∈ μ_q  (the order-q subgroup that pairings land in)."""
    return x ** Q == FQ12.one()


def gt_check(raw: bytes) -> FQ12:
    x = gt_decode(raw)
    if not gt_in_subgroup(x):
        raise InvalidPoint("not an element of the order-q subgroup of GT")
    return x


def _pow_blinded(c: FQ12, k: int) -> FQ12:
    """c^k as c^(k−r)·c^r with a fresh random r (see the module note)."""
    r = secrets.randbelow(Q - 1) + 1
    return (c ** ((k - r) % Q)) * (c ** r)


# ── GT power with proof ──────────────────────────────────────────────────────
@dataclass(frozen=True)
class GtProof:
    R1: object                 # k·B  (B = the generator of the key's group: G1 for s, G2 for s2)
    R2: bytes                  # c^k   (GT, canonical)
    z: int

    def to_json(self, g: Group) -> dict:
        return {"R1": g.hex(self.R1), "R2": self.R2.hex(), "z": hex(self.z)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "GtProof":
        return GtProof(g.from_hex(d["R1"]), bytes.fromhex(d["R2"]), int(d["z"], 16))


@dataclass(frozen=True)
class GtPartial:
    index: int
    D: bytes                   # c^{yᵢ}, canonical GT encoding
    proof: GtProof

    def to_json(self, g: Group) -> dict:
        return {"index": self.index, "D": self.D.hex(), "proof": self.proof.to_json(g)}

    @staticmethod
    def from_json(g: Group, d: dict) -> "GtPartial":
        return GtPartial(int(d["index"]), bytes.fromhex(d["D"]), GtProof.from_json(g, d["proof"]))


def _ctx(pub: PublicKey, context: bytes) -> bytes:
    import struct
    return (b"gtpartial\x00" + bytes.fromhex(pub.key_id) + struct.pack(">Q", pub.epoch)
            + context)


def _challenge(g: Group, ctx: bytes, Y, craw: bytes, Draw: bytes, R1, R2raw: bytes) -> int:
    return g.hash_to_scalar(b"dleq-gt", ctx, *_ser(g, g.G, Y, R1), craw, Draw, R2raw)


def gt_partial(share: KeyShare, cs: list[bytes], context: bytes = b"") -> list[GtPartial]:
    """Custodian side: ``c^{yᵢ}`` with a proof, for each (validated) GT element. Never
    returns or logs the share. Raises ``InvalidPoint`` for an element outside μ_q."""
    pub = share.public
    need_bn254(pub)
    if not cs or len(cs) > MAX_GT_BATCH:
        raise CustodyError(f"between 1 and {MAX_GT_BATCH} GT elements per request")
    g = pub.g
    Y = pub.verification_key(share.index)
    ctx = _ctx(pub, context)
    xs = [(bytes(raw), gt_check(raw)) for raw in cs]            # validate ALL before any work
    out = []
    for raw, c in xs:
        D = _pow_blinded(c, share.y)
        Draw = gt_encode(D)
        k = g.rand_scalar()
        R1 = g.mul_blinded(g.G, k)
        R2raw = gt_encode(_pow_blinded(c, k))
        h = _challenge(g, ctx, Y, raw, Draw, R1, R2raw)
        out.append(GtPartial(share.index, Draw, GtProof(R1, R2raw, (k + h * share.y) % Q)))
    return out


def verify_gt_partial(pub: PublicKey, craw: bytes, part: GtPartial, context: bytes = b"",
                      c: FQ12 | None = None) -> bool:
    """``c`` (already validated by the caller, e.g. via ``gt_check``) may be passed to
    avoid repeating the subgroup test."""
    need_bn254(pub)
    g = pub.g
    if not 1 <= part.index <= pub.n or not (0 < part.proof.z < Q):
        return False
    try:
        c = gt_check(craw) if c is None else c
        D = gt_check(part.D)                       # D ∈ μ_q is part of the statement
        R2 = gt_decode(part.proof.R2)
    except InvalidPoint:
        return False
    Y = pub.verification_key(part.index)
    h = _challenge(g, _ctx(pub, context), Y, craw, part.D, part.proof.R1, part.proof.R2)
    z = part.proof.z
    return (g.eq(g.mul(g.G, z), g.add(part.proof.R1, g.mul(Y, h)))
            and c ** z == R2 * (D ** h))


def combine_gt(pub: PublicKey, partials: dict[int, bytes]) -> bytes:
    """c^x from ``k`` VERIFIED partials ``{index: Dᵢ}``: Π Dᵢ^{λᵢ}."""
    need_bn254(pub)
    idx = sorted(partials)[:pub.k]
    if len(idx) < pub.k:
        raise CustodyError(f"need {pub.k} partial results")
    lam = laurent.lambdas(idx, Q)
    acc = FQ12.one()
    for i in idx:
        acc = acc * (gt_decode(partials[i]) ** lam[i])
    return gt_encode(acc)


def gt_power_local(pub: PublicKey, cs: list[bytes], share_partials: list[list[GtPartial]],
                   context: bytes = b"") -> list[bytes]:     # convenience for tests
    ok: dict[int, list[GtPartial]] = {}
    for plist in share_partials:
        if all(verify_gt_partial(pub, c, p, context) for c, p in zip(cs, plist)):
            ok[plist[0].index] = plist
    return [combine_gt(pub, {i: pl[j].D for i, pl in ok.items()}) for j in range(len(cs))]


# ── G2 points (the public key Q2 of the second secret) ───────────────────────
def g2_encode(pt) -> bytes:
    if is_inf(pt):
        return bytes(G2_BYTES)
    x, y = normalize(pt)
    return b"".join(int(c.n if hasattr(c, "n") else c).to_bytes(32, "big")
                    for c in (*x.coeffs, *y.coeffs))


def g2_decode(raw: bytes):
    """Validated G2 point: coordinates < p, on the twist AND in the prime-order subgroup.
    The identity is refused (never a legitimate public key)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != G2_BYTES:
        raise InvalidPoint("a G2 point is 128 bytes")
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, G2_BYTES, 32)]
    if any(c >= P for c in v):
        raise InvalidPoint("G2 coordinate out of range")
    pt = (FQ2([v[0], v[1]]), FQ2([v[2], v[3]]), FQ2([1, 0]))
    if not is_on_curve(pt, _B2):
        raise InvalidPoint("G2 point is not on the curve")
    if not is_inf(_mul(pt, Q)) or is_inf(pt):
        raise InvalidPoint("G2 point is not a non-identity element of the prime-order subgroup")
    return pt


def g1_image_matches(X1, raw_q2: bytes) -> bool:
    """True iff ``e(X1, G2) = e(G1, Q2)`` — i.e. Q2 would be ``s·G2`` for the G1 key X1 = s·G1.
    That combination is forbidden (it gives a dictionary oracle on every ciphertext)."""
    pt = g2_decode(raw_q2)
    m = pairing(_G2, X1, final_exponentiate=False) * pairing(pt, _neg(_G1), final_exponentiate=False)
    return final_exponentiate(m) == FQ12.one()
