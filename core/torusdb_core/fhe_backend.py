# SPDX-License-Identifier: Apache-2.0
"""Pairing back ends for FHE columns.

* ``pyecc`` — pure Python (``py_ecc``): always available, ≈100–200 ms per pairing.
* ``mcl``   — the native ``mclbn256`` library (herumi/mcl): ≈0.1 ms per pairing,
  ≈0.03 ms per G1 multiplication. Used automatically when importable
  (``pip install mclbn256``); force with ``TORUSDB_FHE_BACKEND=pyecc|mcl``.

Points are exchanged as fixed-width big-endian affine coordinates, identical for both
back ends, so cells written by one are readable by the other. **GT results (DOT) are
not interchangeable** — each back end's pairing is a different (bilinear) map — so a GT
blob carries a one-byte backend tag and is only decoded by the same back end.

``mcl`` note: the library keeps one process-wide curve; importing this back end
selects ``BN_SNARK1`` (= ``alt_bn128``/BN254, the curve ``py_ecc`` uses).
"""
from __future__ import annotations

import os

from py_ecc.fields import optimized_bn128_FQ as _FQ_cls
from py_ecc.optimized_bn128 import (
    FQ, FQ2, FQ12, G1 as PG1, G2 as PG2, Z1, Z2, add as p_add, b, b2, curve_order,
    final_exponentiate, is_inf, is_on_curve, multiply as p_mul, neg as p_neg, normalize,
    pairing as p_pairing,
)

N = curve_order
G1_BYTES, G2_BYTES, GT_BYTES = 64, 128, 384
P_MOD = _FQ_cls.field_modulus


class BackendError(ValueError):
    pass


def _i32(x: int) -> bytes:
    return int(x).to_bytes(32, "big")


def _rd(raw: bytes, n: int) -> list[int]:
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, 32 * n, 32)]
    if any(c >= P_MOD for c in v):
        raise BackendError("coordinate out of range")
    return v


# ── pure Python ──────────────────────────────────────────────────────────────
class PyEcc:
    name, tag = "pyecc", b"\x01"
    G1, G2 = PG1, PG2

    def g1_zero(self): return Z1
    def g2_zero(self): return Z2
    def g1_add(self, a, c): return p_add(a, c)
    def g1_neg(self, a): return p_neg(a)
    def g1_mul(self, a, k): return p_mul(a, k % N)
    def g2_add(self, a, c): return p_add(a, c)
    def g2_mul(self, a, k): return p_mul(a, k % N)
    def g1_is_zero(self, a): return is_inf(a)

    def g1_to(self, p) -> bytes:
        if is_inf(p):
            return bytes(G1_BYTES)
        x, y = normalize(p)
        return _i32(x.n) + _i32(y.n)

    def g1_from(self, raw: bytes):
        if raw == bytes(G1_BYTES):
            return Z1
        x, y = _rd(raw, 2)
        p = (FQ(x), FQ(y), FQ(1))
        if not is_on_curve(p, b):
            raise BackendError("G1 point is not on the curve")
        return p

    def g1_key(self, p) -> bytes:
        return self.g1_to(p)

    def g2_to(self, p) -> bytes:
        if is_inf(p):
            return bytes(G2_BYTES)
        x, y = normalize(p)
        return b"".join(_i32(c) for c in (*x.coeffs, *y.coeffs))

    def g2_from(self, raw: bytes):
        if raw == bytes(G2_BYTES):
            return Z2
        v = _rd(raw, 4)
        p = (FQ2([v[0], v[1]]), FQ2([v[2], v[3]]), FQ2([1, 0]))
        if not is_on_curve(p, b2):
            raise BackendError("G2 point is not on the curve")
        return p

    def miller(self, g2pt, g1pt):
        return p_pairing(g2pt, g1pt, final_exponentiate=False)

    def final(self, m): return final_exponentiate(m)
    def gt_one(self): return p_pairing(PG2, PG1) ** 0
    def gt_gen(self): return p_pairing(PG2, PG1)
    def gt_mul(self, a, c): return a * c
    def gt_pow(self, a, k): return a ** (k % N)
    def gt_to(self, g) -> bytes: return b"".join(_i32(c.n if hasattr(c, "n") else c) for c in g.coeffs)

    def gt_from(self, raw: bytes):
        return FQ12(_rd(raw, 12))

    def gt_key(self, g) -> bytes: return self.gt_to(g)


# ── native (mclbn256) ────────────────────────────────────────────────────────
class Mcl:
    name, tag = "mcl", b"\x02"

    def __init__(self):
        import mclbn256.mclbn256 as M
        from mclbn256 import Fr, G1, G2, GT
        # process-wide: use alt_bn128 (the BN254 curve py_ecc and Ethereum use)
        if M.lib.mclBn_init(4, M.MCLBN_COMPILED_TIME_VAR):
            raise BackendError("cannot initialise mcl for BN_SNARK1")
        M.disable_memoization()
        self._Fr, self._G1, self._G2, self._GT = Fr, G1, G2, GT
        x, y = normalize(PG1)
        self.G1 = G1().fromstr(f"1 {x.n:x} {y.n:x}".encode(), 16)
        (xa, xb), (ya, yb) = [tuple(int(c) for c in pt.coeffs) for pt in normalize(PG2)[:2]]
        self.G2 = G2().fromstr(f"1 {xa:x} {xb:x} {ya:x} {yb:x}".encode(), 16)
        # self-test: the library must agree with py_ecc on a scalar multiple
        k = 0x1234567890ABCDEF1234567890ABCDEF
        px, py = normalize(p_mul(PG1, k))
        if self.g1_to(self.g1_mul(self.G1, k)) != _i32(px.n) + _i32(py.n):
            raise BackendError("mcl and py_ecc disagree on the curve")

    def _fr(self, k: int):
        return self._Fr().fromstr(str(k % N).encode(), 10)

    def g1_zero(self): return self._G1().fromstr(b"0", 16)
    def g2_zero(self): return self._G2().fromstr(b"0", 16)
    def g1_add(self, a, c): return a + c
    def g1_neg(self, a): return -a
    def g1_mul(self, a, k): return a * self._fr(k)
    def g2_add(self, a, c): return a + c
    def g2_mul(self, a, k): return a * self._fr(k)
    def g1_is_zero(self, a): return a.tostr() == b"0"

    def g1_to(self, p) -> bytes:
        s = p.tostr().split()
        if s == [b"0"]:
            return bytes(G1_BYTES)
        return _i32(int(s[1], 16)) + _i32(int(s[2], 16))

    def g1_from(self, raw: bytes):
        if raw == bytes(G1_BYTES):
            return self.g1_zero()
        x, y = _rd(raw, 2)
        try:
            p = self._G1().fromstr(f"1 {x:x} {y:x}".encode(), 16)
            ok = p.valid() and p.valid_order()
        except ValueError:
            ok = False
        if not ok:
            raise BackendError("G1 point is not on the curve")
        return p

    def g1_key(self, p) -> bytes:
        return p.serialize()

    def g2_to(self, p) -> bytes:
        s = p.tostr().split()
        if s == [b"0"]:
            return bytes(G2_BYTES)
        return b"".join(_i32(int(t, 16)) for t in s[1:5])

    def g2_from(self, raw: bytes):
        if raw == bytes(G2_BYTES):
            return self.g2_zero()
        v = _rd(raw, 4)
        try:
            p = self._G2().fromstr(f"1 {v[0]:x} {v[1]:x} {v[2]:x} {v[3]:x}".encode(), 16)
            ok = p.valid() and p.valid_order()              # includes the subgroup check
        except ValueError:
            ok = False
        if not ok:
            raise BackendError("G2 point is not a valid subgroup element")
        return p

    def miller(self, g2pt, g1pt):
        return g1pt.pairing(g2pt, use_final_exp=False)

    def final(self, m): return m.final_exp()
    def gt_gen(self): return self.G1.pairing(self.G2)
    def gt_one(self): return self.gt_gen().pow(self._fr(0))
    def gt_mul(self, a, c): return a * c
    def gt_pow(self, a, k): return a.pow(self._fr(k))

    def gt_to(self, g) -> bytes:
        return b"".join(_i32(int(t, 16)) for t in g.tostr().split())

    def gt_from(self, raw: bytes):
        v = _rd(raw, 12)
        try:
            return self._GT().fromstr(" ".join(f"{c:x}" for c in v).encode(), 16)
        except ValueError:
            raise BackendError("not a GT element") from None

    def gt_key(self, g) -> bytes:
        return g.serialize()


_cache: dict[str, object] = {}


def get(name: str):
    """The back end called ``pyecc`` or ``mcl`` (raises BackendError if unavailable)."""
    if name not in _cache:
        if name == "pyecc":
            _cache[name] = PyEcc()
        elif name == "mcl":
            try:
                _cache[name] = Mcl()
            except ImportError as exc:
                raise BackendError("the 'mcl' back end needs `pip install mclbn256`") from exc
        else:
            raise BackendError(f"unknown FHE back end {name!r}")
    return _cache[name]


def by_tag(tag: bytes):
    return get({b"\x01": "pyecc", b"\x02": "mcl"}.get(bytes(tag), "?"))


def default():
    want = os.environ.get("TORUSDB_FHE_BACKEND", "auto").lower()
    if want in ("pyecc", "mcl"):
        return get(want)
    try:
        return get("mcl")
    except BackendError:
        return get("pyecc")


def available() -> list[str]:
    out = ["pyecc"]
    try:
        get("mcl")
        out.append("mcl")
    except BackendError:
        pass
    return out
