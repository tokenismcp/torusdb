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


# ── evaluation at another point & robust (fault-detecting) reconstruction ────
class InconsistentShares(ValueError):
    """The supplied shares do not lie on one Laurent series (a holder is faulty
    or malicious) and no strict majority agrees."""


def eval_coeffs(xs: list[int], x_new: int, q: int) -> list[int]:
    """μᵢ with  y(x_new) = Σ μᵢ·yᵢ  for the degree-(k−1) polynomial in u=1/x
    through the k known points ``xs``."""
    us = [inv(x, q) for x in xs]
    un = inv(x_new, q)
    out = []
    for i, ui in enumerate(us):
        num = den = 1
        for j, uj in enumerate(us):
            if j != i:
                num = num * (un - uj) % q
                den = den * (ui - uj) % q
        out.append(num * inv(den, q) % q)
    return out


def robust_reconstruct(shares: list[tuple[int, int]], k: int, q: int,
                       max_subsets: int = 4000) -> tuple[int, list[int]]:
    """Residue from ≥ k shares, with fault detection.

    * exactly ``k`` shares: reconstructed, nothing can be cross-checked;
    * more than ``k``: every extra share must lie on the polynomial. If they do
      not, the largest mutually consistent group wins provided it is a strict
      majority and holds at least k+1 shares; the shares outside it are returned
      as faulty. Otherwise ``InconsistentShares`` is raised — never a guess.

    Returns ``(secret, faulty_xs)``.
    """
    import itertools
    shares = sorted(set(shares))
    if len({x for x, _ in shares}) != len(shares):
        raise InconsistentShares("a holder supplied two different shares")
    m = len(shares)
    if m < k:
        raise ValueError(f"need {k} shares, have {m}")
    if m == k:
        return reconstruct(shares, q), []
    best = None                                  # (group_size, secret, bad_xs)
    groups: dict[int, int] = {}
    for n_tried, S in enumerate(itertools.combinations(range(m), k)):
        if n_tried >= max_subsets:
            break
        pts = [shares[i] for i in S]
        xs = [x for x, _ in pts]
        lam = lambdas(xs, q)
        secret = sum(lam[x] * y for x, y in pts) % q
        agree, bad = 0, []
        for j in range(m):
            if j in S:
                continue
            xj, yj = shares[j]
            mu = eval_coeffs(xs, xj, q)
            if sum(c * y for c, (_, y) in zip(mu, pts)) % q == yj % q:
                agree += 1
            else:
                bad.append(xj)
        size = k + agree
        groups[secret] = max(groups.get(secret, 0), size)
        if best is None or size > best[0]:
            best = (size, secret, bad)
        if agree == m - k:
            break                                # everything consistent
    size, secret, bad = best
    others = [s for s_, s in groups.items() if s_ != secret]
    if size < k + 1 or 2 * size <= m or (others and max(others) >= size):
        raise InconsistentShares(
            f"{m} shares are mutually inconsistent and no strict majority agrees")
    return secret, bad
