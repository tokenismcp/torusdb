# SPDX-License-Identifier: Apache-2.0
"""Threshold use of a BN254 key in the pairing groups G2 and GT (EC-FHE ``DOT``).

The custody key is ``x`` with public ``X = x·G1`` (group ``bn254``). Two more owner
operations of the FHE scheme need ``x`` *applied* to elements of other groups, and the
Laurent sharing makes both linear in the exponent, so ``x`` is never assembled:

* **GT power** (decrypting a ``DOT``):  custodian ``i`` returns ``Dᵢ = c^{yᵢ}`` for a GT
  element ``c``; anyone combines ``c^x = Π_{i∈S} Dᵢ^{λᵢ}``.
* **G2 public share** (publishing ``Q2 = x·G2``): custodian ``i`` returns ``Y2ᵢ = yᵢ·G2``;
  anyone combines ``Q2 = Σ λᵢ·Y2ᵢ``.

Soundness of the GT power  (``GtProof``, Chaum–Pedersen across two groups of the SAME prime
order ``q`` — G1 and the order-``q`` subgroup μ_q ⊂ GT)
    statement   Yᵢ = yᵢ·G1  (public verification key)   and   D = c^{yᵢ}
    prover      k ←$ F_q ;  R1 = k·G1 ,  R2 = c^k ;  h = H(ctx, G1, Yᵢ, c, D, R1, R2) ;  z = k + h·yᵢ
    verifier    z·G1 = R1 + h·Yᵢ   and   c^z = R2 · D^h        (and  c, D ∈ μ_q)
  * completeness: both equations are the images of ``z = k + h·y``.
  * special soundness: two accepting transcripts (R1,R2) with challenges h ≠ h′ give
    ``y = (z − z′)/(h − h′)`` with ``Yᵢ = y·G1`` (first equation) and ``D^{h−h′} = c^{z−z′} =
    c^{(h−h′)y}``. ``c ∈ μ_q`` makes the right side depend only on ``y mod q``; with
    ``D ∈ μ_q`` and ``gcd(h−h′, q) = 1`` the map ``u ↦ u^{h−h′}`` is injective on μ_q, so
    ``D = c^y``. In the random-oracle model a custodian cannot return any ``D`` other than
    ``c^{yᵢ}`` for the ``yᵢ`` committed to by its verification key ``Yᵢ``.
  * why the μ_q membership checks are mandatory: in Fp12* (order ≠ q) a ``D`` with an extra
    small-order factor would pass the equations, and a custodian answering for ``c`` outside μ_q
    would leak ``yᵢ`` modulo small primes (small-subgroup attack). Both ``c`` and ``D`` are
    tested with ``u^q = 1`` (one exponentiation each).
  * zero knowledge: honest-verifier simulatable in the standard way (pick z, h, set R1, R2).
No pairing is needed for GT proofs. ``G2`` shares need none either: a pairing equation
``e(Yᵢ, G2) = e(G1, Y2ᵢ)`` plus a G2 subgroup check ties ``Y2ᵢ`` to the same ``yᵢ``.

This module uses ``py_ecc`` only (GT elements are exchanged in the canonical 384-byte
encoding of ``torusdb_core.fhe_backend``, identical for every back end). Exponentiations by
a secret scalar use the same split-scalar blinding as ``Group.mul_blinded`` — a mitigation
of repeated-measurement correlation, NOT constant-time arithmetic.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from py_ecc.optimized_bn128 import (FQ2, FQ12, G1 as _G1, G2 as _G2, add as _add, b2 as _B2,
                                    curve_order as Q, field_modulus as P, final_exponentiate,
                                    is_inf, is_on_curve, multiply as _mul, neg as _neg,
                                    normalize, pairing)

from . import laurent
from .group import CustodyError, Group, InvalidPoint
from .keys import KeyShare, PublicKey
from .proofs import _ser

GT_BYTES = 384
G2_BYTES = 128
MAX_GT_BATCH = 64                    # elements per request (each costs ~5 exponentiations)


def need_bn254(pub: PublicKey) -> None:
    if pub.group != "bn254":
        raise CustodyError("GT / G2 operations need a 'bn254' key (the group of the FHE scheme)")


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
    R1: object                 # k·G1
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


# ── G2 public key share ──────────────────────────────────────────────────────
def g2_encode(pt) -> bytes:
    if is_inf(pt):
        return bytes(G2_BYTES)
    x, y = normalize(pt)
    return b"".join(int(c.n if hasattr(c, "n") else c).to_bytes(32, "big")
                    for c in (*x.coeffs, *y.coeffs))


def g2_decode(raw: bytes):
    """Validated G2 point: coordinates < p, on the twist AND in the prime-order subgroup.
    The identity is refused (never a legitimate key share)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != G2_BYTES:
        raise InvalidPoint("a G2 point is 128 bytes")
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, G2_BYTES, 32)]
    if any(c >= P for c in v):
        raise InvalidPoint("G2 coordinate out of range")
    pt = (FQ2([v[0], v[1]]), FQ2([v[2], v[3]]), FQ2([1, 0]))
    if not is_on_curve(pt, _B2):
        raise InvalidPoint("G2 point is not on the curve")
    if not is_inf(_mul(pt, Q)):
        raise InvalidPoint("G2 point is not in the prime-order subgroup")
    return pt


def _g2_mul_blinded(pt, k: int):
    """yᵢ·G2 for the secret share: mcl's constant-time ladder when the native library is
    available (same switch as ``Group``), else split-scalar blinding (NOT constant time)."""
    be = _G1_GROUP_NATIVE()
    if be is not None:
        r = be.g2_mul_secret(be.g2_from(g2_encode(pt)), k % Q)
        return g2_decode_unchecked(be.g2_to(r))
    r = secrets.randbelow(Q - 1) + 1
    return _add(_mul(pt, (k - r) % Q), _mul(pt, r))


def _G1_GROUP_NATIVE():
    from .group import get_group
    return get_group("bn254")._native()


def g2_decode_unchecked(raw: bytes):
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, G2_BYTES, 32)]
    return (FQ2([v[0], v[1]]), FQ2([v[2], v[3]]), FQ2([1, 0]))


def g2_partial(share: KeyShare) -> bytes:
    """Custodian side: ``yᵢ·G2``. Public-key material (``yᵢ·G1`` is already public), so
    no proof is attached: the receiver checks it with a pairing."""
    need_bn254(share.public)
    return g2_encode(_g2_mul_blinded(_G2, share.y))


def pairing_equal(p1, q2_of_p1, p2, q2_of_p2) -> bool:
    """e(p1, q_a) == e(p2, q_b) for G1 points p* and G2 points q* (final exponentiation shared)."""
    m = pairing(q2_of_p1, p1, final_exponentiate=False) * \
        pairing(q2_of_p2, _neg(p2), final_exponentiate=False)
    return final_exponentiate(m) == FQ12.one()


def verify_g2_share(pub: PublicKey, index: int, raw: bytes):
    """Y2ᵢ is valid iff it is in the G2 subgroup and e(Yᵢ, G2) = e(G1, Y2ᵢ)."""
    need_bn254(pub)
    if not 1 <= index <= pub.n:
        raise InvalidPoint("bad custodian index")
    pt = g2_decode(raw)
    y_pt = pub.verification_key(index)
    if not pairing_equal(y_pt, _G2, _G1, pt):
        raise InvalidPoint("G2 share does not match the custodian's verification key")
    return pt


def combine_g2(pub: PublicKey, shares: dict[int, bytes]) -> bytes:
    """Q2 = x·G2 = Σ λᵢ·Y2ᵢ from ``k`` VERIFIED shares; checked against X by pairing."""
    need_bn254(pub)
    idx = sorted(shares)[:pub.k]
    if len(idx) < pub.k:
        raise CustodyError(f"need {pub.k} G2 shares")
    lam = laurent.lambdas(idx, Q)
    acc = None
    for i in idx:
        term = _mul(g2_decode(shares[i]), lam[i])
        acc = term if acc is None else _add(acc, term)
    check_q2(pub.X, g2_encode(acc))
    return g2_encode(acc)


def check_q2(X, raw_q2: bytes):
    """Public-key consistency: Q2 in the G2 subgroup and e(X, G2) = e(G1, Q2), i.e. the
    G2 and G1 public keys have the same discrete logarithm. Returns the point."""
    pt = g2_decode(raw_q2)
    if is_inf(X) or not pairing_equal(X, _G2, _G1, pt):
        raise InvalidPoint("Q2 is not the G2 image of the public key (pairing check failed)")
    return pt
