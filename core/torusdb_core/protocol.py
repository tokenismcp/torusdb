# SPDX-License-Identifier: Apache-2.0
"""No-key delegation protocol Π — Lee, "No-Key Delegation of Elliptic-Curve
Fully Homomorphic Encryption" (J1729 Labs).

The server holds **no key material whatsoever** — no secret key, no public
key, no evaluation key. It processes only information-theoretically *blinded*
elements of the ring Z/nZ. Confidentiality at the server is a one-time pad,
so the leakage is exactly zero, I(M; V_S) = 0 (Thm 30), unconditionally and
post-quantumly (Thm 31). This module REPLACES any "decrypt server-side, do
the arithmetic, re-encrypt" path — there is no decryption on the server.

Domain (paper §II.C, eq. 4). Values live in the cyclic-subgroup ring
⟨R⟩ ≅ Z/nZ, where ring multiplication is just multiplication mod n:

    encode(int v)      = v mod n
    encode(a/b)        = a · b⁻¹ mod n          (Q_E rational layer)
    decode(s)          = rational reconstruction of s  (recovers small a/b)

Homomorphisms used by the server (key-independent, Remark 4):
    encode(x) + encode(y) = encode(x + y)       (additive, in Z/nZ)
    k · encode(x)         = encode(k·x)          (Z-action)
    encode(x) · encode(y) = encode(x·y)          (ring mult on ⟨R⟩)

Protocols:
    Π_lin   (Construction 16) — non-interactive affine evaluation
    Π_mult  (Construction 18) — Beaver-triple masked multiplication
    Π_boot  (Construction 19) — owner-side mask refresh (re-mask), no key

The server side touches NO curve, pairing, or discrete-log machinery: every
server operation is integer arithmetic mod n. The elliptic-curve layer is the
owner's business (encryption at rest, behind the guarded boundary).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from fractions import Fraction
from math import isqrt
from typing import Sequence


# The modulus n is the prime order of the working subgroup (paper §II.D).
N: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254 group order


# ── Decode budget ────────────────────────────────────────────────────────────
# Wang's rational reconstruction is unique only when 2·|a|·b < n. Outside that
# budget it does not fail — it returns a *different*, plausible-looking
# fraction. To turn such silent corruption into a loud error we require every
# decoded (and encoded) value to satisfy |a|·b < n / 2^MARGIN_BITS: a
# genuinely out-of-budget element then decodes "successfully" with probability
# about 2^-MARGIN_BITS, instead of always.
MARGIN_BITS = 64
_RANGE: int = N >> MARGIN_BITS
_BOUND: int = isqrt(N // 2)          # Wang bound on |num| and on den (≈ 2^126)


class OutOfBudget(ValueError):
    """A value (or aggregate) exceeds the exactly-representable range:
    |numerator| ≤ 2^126, denominator ≤ 2^126 and |numerator|·denominator
    < 2^189. Reduce magnitudes, scale to integers, or aggregate in smaller
    groups."""


# ── Encoding: R/Q → Z/nZ and back ───────────────────────────────────────────
def encode(value) -> int:
    """enc: encode an int or Fraction into Z/nZ. Values that could never be
    decoded back exactly are rejected up front (OutOfBudget)."""
    if isinstance(value, bool):
        return int(value) % N
    if isinstance(value, int):
        if abs(value) > _BOUND:
            raise OutOfBudget(
                f"integer of {abs(value).bit_length()} bits exceeds the "
                f"encodable range (|v| ≤ 2^{_BOUND.bit_length() - 1})")
        return value % N
    if isinstance(value, Fraction):
        a, b = value.numerator, value.denominator
        if abs(a) > _BOUND or b > _BOUND or abs(a) * b >= _RANGE:
            raise OutOfBudget(
                f"fraction {a}/{b} exceeds the encodable range (|num|, den ≤ "
                f"2^{_BOUND.bit_length() - 1} and |num|·den < "
                f"2^{_RANGE.bit_length() - 1})")
        return (a % N) * pow(b % N, -1, N) % N
    raise TypeError(f"cannot encode {type(value).__name__}")


def _rational_reconstruct(s: int, bound: int) -> Fraction:
    """Recover a/b with |a|, b ≤ bound and a ≡ s·b (mod N) — Wang's
    algorithm via the extended Euclidean recurrence. Unique when
    2·|a|·b < N (paper's noise budget keeps values inside this)."""
    s %= N
    r0, r1 = N, s
    t0, t1 = 0, 1
    while r1 > bound:
        q = r0 // r1
        r0, r1, t0, t1 = r1, r0 - q * r1, t1, t0 - q * t1
    a, b = r1, t1
    if b < 0:
        a, b = -a, -b
    if b == 0:
        raise ValueError("rational reconstruction failed (out of budget)")
    return Fraction(a, b)


def decode(s: int, *, bound: int | None = None, strict: bool = True):
    """dec: recover the int/Fraction from a Z/nZ element. Returns an int
    when the denominator is 1, else a Fraction.

    ``strict`` (default) raises OutOfBudget when the reconstruction is not
    comfortably inside the uniqueness range — i.e. when the true value (e.g. a
    SUM that overflowed) was too large to recover, rather than returning a
    wrong number. Pass ``strict=False`` only for the raw algorithm."""
    if bound is None:
        bound = isqrt(N // 2)
    try:
        frac = _rational_reconstruct(s % N, bound)
    except ValueError as exc:
        raise OutOfBudget(str(exc)) from exc
    if strict and abs(frac.numerator) * frac.denominator >= _RANGE:
        raise OutOfBudget(
            "decoded value is outside the exactly-representable range — an "
            "aggregate probably overflowed (|num|·den ≥ 2^"
            f"{_RANGE.bit_length() - 1}); the result cannot be trusted")
    return int(frac) if frac.denominator == 1 else frac


# ── Owner (holds masks/triples; lives at the guarded boundary) ───────────────
@dataclass
class Triple:
    """Beaver multiplication triple (u, v, w=uv) over Z/nZ (Def 17)."""
    u: int
    v: int
    w: int


def gen_triple() -> Triple:
    u = secrets.randbelow(N)
    v = secrets.randbelow(N)
    return Triple(u=u, v=v, w=u * v % N)


@dataclass
class Owner:
    """The data owner. Generates masks and triples, blinds inputs, and
    unblinds results. The ONLY party that ever sees plaintext or keys."""

    def blind(self, s: int) -> tuple[int, int]:
        """One-time-pad a Z/nZ element: returns (blinded, mask). (P3: fresh
        mask each call.) Lemma 6: blinded is uniform on Z/nZ, ⟂ s."""
        r = secrets.randbelow(N)
        return (s + r) % N, r

    # Π_lin (Construction 16): unblind an affine result.
    def unblind_affine(self, blinded_y: int, coeffs: Sequence[int],
                       masks: Sequence[int]) -> int:
        """y = ỹ − Δf, where Δf = Σ aᵢ·rᵢ (mod n)."""
        delta = sum(a * r for a, r in zip(coeffs, masks)) % N
        return (blinded_y - delta) % N

    # Π_mult (Construction 18): open operands against a triple, reconstruct.
    def mult_open(self, s: int, s2: int, triple: Triple) -> tuple[int, int]:
        """Owner → Server: e = s−u, g = s'−v  (both uniform, hide s, s')."""
        return (s - triple.u) % N, (s2 - triple.v) % N

    def mult_reconstruct(self, e: int, g: int, eg: int, triple: Triple) -> int:
        """ss' = w + e·v + g·u + e·g  (mod n)  — eq. (6)."""
        return (triple.w + e * triple.v + g * triple.u + eg) % N


# ── Server (holds NO key material — only blinded Z/nZ elements) ──────────────
class Server:
    """The untrusted, always-online evaluator. Its entire interface takes
    blinded scalars and public circuit data; it has no key fields and never
    decodes. Every method is integer arithmetic mod n (Remark 4).

    The class deliberately exposes NO place to put a secret/public/eval key —
    zero key residency (P1) is structural, not a convention.
    """

    # Π_lin (Construction 16, step 2): evaluate the public affine form on
    # blinded inputs. b is a public Z/nZ constant.
    @staticmethod
    def affine(blinded: Sequence[int], coeffs: Sequence[int], b: int = 0) -> int:
        return (sum(a * x for a, x in zip(coeffs, blinded)) + b) % N

    # Convenience: blinded SUM is the all-ones affine form.
    @staticmethod
    def add(blinded: Sequence[int]) -> int:
        return sum(blinded) % N

    # Π_mult (Construction 18, step 2): combine the opened operands.
    @staticmethod
    def mult_combine(e: int, g: int) -> int:
        return e * g % N
