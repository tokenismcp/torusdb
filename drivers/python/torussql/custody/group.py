# SPDX-License-Identifier: Apache-2.0
"""Prime-order groups for threshold custody (curve-agnostic, like z-MPC).

Two groups are provided, both with cofactor 1 so every on-curve point is in the
prime-order subgroup:

  * ``secp256k1`` — default, ~128-bit security.
  * ``bn254``     — the G1 group of BN254 (same curve family as the engine;
                    ~100-bit security).

Only the vetted ``py_ecc`` arithmetic is used; no curve code is implemented
here. Points are opaque objects; ``encode``/``decode`` give a canonical 64-byte
form (``x ‖ y``, all-zero for the identity) and ``decode`` validates the curve
equation, so a malformed or off-curve point is always rejected.

Constant-time arithmetic is **not** available in pure Python: ``py_ecc`` uses
variable-time big-int double-and-add, so scalar-multiplication time depends on
the scalar. ``mul_blinded`` splits the scalar, k·P = (k−r)·P + r·P with a fresh
random r, so the two multiplications are individually decorrelated from k.
That is a mitigation of repeated-measurement correlation only — it does NOT
make the arithmetic constant time and it does not stop a local observer who
can measure both halves. For high-value deployments use a constant-time
library (libsecp256k1 / coincurve) and run custodians on isolated hosts.
"""
from __future__ import annotations

import hashlib
import secrets

try:
    from py_ecc.optimized_bn128 import (
        FQ, G1 as _BN_G, Z1 as _BN_Z, add as _bn_add, curve_order as _BN_N,
        eq as _bn_eq, field_modulus as _BN_P, is_inf as _bn_is_inf,
        multiply as _bn_mul, neg as _bn_neg, normalize as _bn_norm,
    )
    from py_ecc.secp256k1 import secp256k1 as _k1
    _HAVE = True
except ImportError:                                           # pragma: no cover
    _HAVE = False

_COORD = 32


from ..errors import CustodyError                          # noqa: E402  (shared base)


class InvalidPoint(CustodyError):
    pass


def _need() -> None:
    if not _HAVE:                                             # pragma: no cover
        raise CustodyError("threshold custody needs the 'py_ecc' package "
                           "(pip install 'torussql[custody]')")


class Group:
    name: str
    order: int
    G: object
    identity: object

    # — arithmetic —
    def add(self, a, b): raise NotImplementedError
    def mul(self, a, k: int): raise NotImplementedError
    def neg(self, a): raise NotImplementedError
    def eq(self, a, b) -> bool: raise NotImplementedError
    def is_identity(self, a) -> bool: raise NotImplementedError
    def _xy(self, a) -> tuple[int, int]: raise NotImplementedError
    def _from_xy(self, x: int, y: int): raise NotImplementedError
    def _on_curve(self, x: int, y: int) -> bool: raise NotImplementedError

    # — shared helpers —
    def sub(self, a, b):
        return self.add(a, self.neg(b))

    def mul_blinded(self, a, k: int):
        """k·a computed as (k−r)·a + r·a with a fresh random r in [1, q).

        (The previous k + r·q variant was a no-op: ``mul`` reduces mod q.)
        Use it for every multiplication by a secret scalar. This decorrelates
        the work from k across calls; it is NOT constant-time arithmetic."""
        q = self.order
        r = secrets.randbelow(q - 1) + 1
        return self.add(self.mul(a, (k - r) % q), self.mul(a, r))

    def msm(self, pairs):
        """Σ kᵢ·Pᵢ for (k, P) pairs."""
        acc = self.identity
        for k, p in pairs:
            acc = self.add(acc, self.mul(p, k))
        return acc

    def encode(self, a) -> bytes:
        if self.is_identity(a):
            return bytes(2 * _COORD)
        x, y = self._xy(a)
        return x.to_bytes(_COORD, "big") + y.to_bytes(_COORD, "big")

    def decode(self, b: bytes):
        if len(b) != 2 * _COORD:
            raise InvalidPoint("point must be 64 bytes")
        if b == bytes(2 * _COORD):
            return self.identity
        x = int.from_bytes(b[:_COORD], "big")
        y = int.from_bytes(b[_COORD:], "big")
        if not self._on_curve(x, y):
            raise InvalidPoint("point is not on the curve")
        return self._from_xy(x, y)

    def hex(self, a) -> str:
        return self.encode(a).hex()

    def from_hex(self, s: str):
        try:
            return self.decode(bytes.fromhex(s))
        except ValueError as exc:
            raise InvalidPoint("bad point encoding") from exc

    def rand_scalar(self) -> int:
        return secrets.randbelow(self.order - 1) + 1

    def hash_to_scalar(self, domain: bytes, *parts: bytes) -> int:
        h = hashlib.sha512()
        h.update(b"torussql/custody/h2s/v1\x00")
        h.update(len(domain).to_bytes(2, "big") + domain)
        for p in parts:
            h.update(len(p).to_bytes(4, "big") + p)
        return int.from_bytes(h.digest(), "big") % self.order


class _Secp256k1(Group):
    name = "secp256k1"

    def __init__(self) -> None:
        _need()
        self.order = _k1.N
        self.G = (_k1.Gx, _k1.Gy)
        self.identity = (0, 0)
        self._p = _k1.P

    def add(self, a, b): return _k1.add(a, b)
    def mul(self, a, k):
        k %= self.order
        return self.identity if (k == 0 or self.is_identity(a)) else _k1.multiply(a, k)
    def neg(self, a): return a if self.is_identity(a) else (a[0], (-a[1]) % self._p)
    def eq(self, a, b): return tuple(a) == tuple(b)
    def is_identity(self, a): return tuple(a) == (0, 0)
    def _xy(self, a): return a
    def _from_xy(self, x, y): return (x, y)
    def _on_curve(self, x, y):
        return 0 < x < self._p and 0 < y < self._p and (y * y - x * x * x - 7) % self._p == 0


class _Bn254(Group):
    name = "bn254"

    def __init__(self) -> None:
        _need()
        self.order = _BN_N
        self.G = _BN_G
        self.identity = _BN_Z

    def add(self, a, b): return _bn_add(a, b)
    def mul(self, a, k):
        k %= self.order
        return self.identity if (k == 0 or self.is_identity(a)) else _bn_mul(a, k)
    def neg(self, a): return _bn_neg(a)
    def eq(self, a, b): return _bn_eq(a, b)
    def is_identity(self, a): return _bn_is_inf(a)
    def _xy(self, a):
        x, y = _bn_norm(a)
        return int(x.n), int(y.n)
    def _from_xy(self, x, y): return (FQ(x), FQ(y), FQ.one())
    def _on_curve(self, x, y):
        return 0 < x < _BN_P and 0 < y < _BN_P and (y * y - x * x * x - 3) % _BN_P == 0


_CACHE: dict[str, Group] = {}


def get_group(name: str = "secp256k1") -> Group:
    if name not in _CACHE:
        if name == "secp256k1":
            _CACHE[name] = _Secp256k1()
        elif name == "bn254":
            _CACHE[name] = _Bn254()
        else:
            raise CustodyError(f"unknown group {name!r} (secp256k1 | bn254)")
    return _CACHE[name]
