# SPDX-License-Identifier: Apache-2.0
"""Laurent-series secret sharing over F_q (q = the group order).

A quorum of ``k`` out of ``n`` uses a pure-pole Laurent series

    f(z) = a₀ + b₁·z⁻¹ + b₂·z⁻² + … + b_t·z⁻ᵗ ,   t = k − 1 ,

whose **residue** ``b₁`` is the secret. Participant ``i`` (evaluation point
``xᵢ ≠ 0``) holds ``yᵢ = f(xᵢ)``. Writing ``u = 1/z`` this is the polynomial
``g(u) = a₀ + b₁u + … + b_t uᵗ`` and the secret is ``g′(0)``, so reconstruction
from any ``k`` shares is the **fixed linear functional**

    b₁ = Σ_{i∈S} λᵢ^S · yᵢ ,   λᵢ^S = −xᵢ^{k−1}·(Σ_{j∈S, j≠i} xⱼ) / Π_{j∈S, j≠i}(xᵢ − xⱼ) .

The coefficients depend only on the (public) evaluation points of the chosen
quorum ``S``. This linearity is what makes *threshold use of the key* possible:
each holder applies its share to a group element, and anyone combines the
results with ``λ`` — the secret ``b₁`` itself is never assembled.

Fewer than ``k`` shares reveal nothing about ``b₁`` provided no ``k−1`` of the
points make the elementary symmetric polynomial e_{k−2}(1/x) vanish mod q.
With points ``1..n`` and ``n ≤ 32`` that numerator is a positive integer far
below q, so it cannot; larger ``n`` is rejected.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

MAX_N = 32


@dataclass(frozen=True)
class Params:
    k: int      # quorum: shares needed to use the key
    n: int      # number of share holders
    q: int      # field modulus (group order)

    def __post_init__(self) -> None:
        if not (2 <= self.k <= self.n):
            raise ValueError("require 2 ≤ quorum ≤ n")
        if self.n > MAX_N:
            raise ValueError(f"n ≤ {MAX_N} supported")

    @property
    def t(self) -> int:                      # number of poles
        return self.k - 1

    def points(self) -> list[int]:
        return list(range(1, self.n + 1))


def inv(a: int, q: int) -> int:
    return pow(a % q, -1, q)


def evaluate(coeffs: list[int], x: int, q: int) -> int:
    """coeffs = [a₀, b₁, …, b_t];  f(x) = a₀ + Σ bⱼ·x⁻ʲ."""
    xi = inv(x, q)
    acc, xp = coeffs[0] % q, 1
    for bj in coeffs[1:]:
        xp = xp * xi % q
        acc = (acc + bj * xp) % q
    return acc


def new_coeffs(secret: int, p: Params) -> list[int]:
    """[a₀ random, b₁ = secret, b₂…b_t random]."""
    return ([secrets.randbelow(p.q)] + [secret % p.q]
            + [secrets.randbelow(p.q) for _ in range(p.t - 1)])


def split(secret: int, p: Params) -> list[tuple[int, int]]:
    c = new_coeffs(secret, p)
    return [(x, evaluate(c, x, p.q)) for x in p.points()]


def lambdas(xs: list[int], q: int) -> dict[int, int]:
    """Reconstruction coefficients λᵢ for the quorum with points ``xs``."""
    k = len(xs)
    if len(set(xs)) != k or any(x % q == 0 for x in xs):
        raise ValueError("quorum points must be distinct and non-zero")
    out = {}
    for i, xi in enumerate(xs):
        num = pow(xi, k - 1, q) * sum(x for j, x in enumerate(xs) if j != i) % q
        den = 1
        for j, xj in enumerate(xs):
            if j != i:
                den = den * (xi - xj) % q
        out[xi] = (-num) * inv(den, q) % q
    return out


def reconstruct(shares: list[tuple[int, int]], q: int) -> int:
    """b₁ from ``k`` shares — TEST/RECOVERY ONLY. Threshold *use* of a key never
    calls this."""
    lam = lambdas([x for x, _ in shares], q)
    return sum(lam[x] * y for x, y in shares) % q


def commit_check_weights(x: int, t: int, q: int) -> list[int]:
    """[1, x⁻¹, x⁻², …, x⁻ᵗ] — the public weights tying a share to the
    commitments:  y·G = Σⱼ weightⱼ · Cⱼ."""
    xi, out, w = inv(x, q), [1], 1
    for _ in range(t):
        w = w * xi % q
        out.append(w)
    return out
