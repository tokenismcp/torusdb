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

    # GT elements travel in ONE canonical encoding for every back end: the 12 coefficients of
    # the py_ecc polynomial basis (w^12 = 18·w^6 − 82). mcl's tower basis
    # (Fp12 = Fp6[w]/(w²−v), Fp6 = Fp2[v]/(v³−(9+i)), Fp2 = Fp[i]/(i²+1)) maps onto it with
    # i = w^6 − 9 and v = w² — a ring isomorphism (checked in tests/test_fhe.py).
    def gt_to(self, g) -> bytes:
        v = [int(t, 16) for t in g.tostr().split()]
        c = [0] * 12
        for j in range(3):
            xa, ya = v[2 * j], v[2 * j + 1]                    # A_j = xa + ya·i  at  w^(2j)
            xb, yb = v[6 + 2 * j], v[7 + 2 * j]                # B_j = xb + yb·i  at  w^(2j+1)
            c[2 * j] = (xa - 9 * ya) % P_MOD
            c[2 * j + 6] = ya % P_MOD
            c[2 * j + 1] = (xb - 9 * yb) % P_MOD
            c[2 * j + 7] = yb % P_MOD
        return b"".join(_i32(x) for x in c)

    def gt_from(self, raw: bytes):
        c = _rd(raw, 12)
        v = [0] * 12
        for j in range(3):
            v[2 * j + 1] = c[2 * j + 6]
            v[2 * j] = (c[2 * j] + 9 * c[2 * j + 6]) % P_MOD
            v[7 + 2 * j] = c[2 * j + 7]
            v[6 + 2 * j] = (c[2 * j + 1] + 9 * c[2 * j + 7]) % P_MOD
        try:
            return self._GT().fromstr(" ".join(f"{x:x}" for x in v).encode(), 16)
        except ValueError:
            raise BackendError("not a GT element") from None

    def gt_key(self, g) -> bytes:
        return g.serialize()

    def gt_gen_bytes(self) -> bytes:
        return self.gt_to(self.gt_gen())


class McLDecodeOnly(PyEcc):
    """Reads (not produces) results of the native back end using only ``py_ecc``: the GT
    values are in the canonical encoding, and the native pairing differs from py_ecc's only
    by its generator ``e_mcl(P, G2)``, a public constant."""
    name, tag = "mcl-decode", b"\x02"

    def gt_gen(self):
        return FQ12(_rd(MCL_GT_GENERATOR, 12))


# e_mcl(P, G2) in the canonical encoding (computed with mclbn256 on BN_SNARK1; pinned by a test)
MCL_GT_GENERATOR = bytes.fromhex("0c498eace9669afdb2ac004a2bc3352ff31fa2b137a520190498891a96af31fb0f7abc6cd882a79148ae975c363201b64294a69c7da04b4dc0fcc4a6b77f99801fa5477cf344c578b943985d188016c90cfed95c39da64d34f7dab3bf29053a4189cc22058b17f919c91a5da449e1130585d76d6c852c08307a7355064d0e6682e5c373f19a914ff641dc62428638e6209a0f8ca64990df7966a7cce65903e150ae359efdcdc3ff0067fb863975a0289d468186d63f62e156aec452863c445d402e02d2cc795a2000a1b1f823879abbd397c4dea0918ed66b49d34b48efb8a4a14d3d6ca72d8a950a31dc10f7b4053c9e9ad9ebb590cb4a60f8215d4b99f2b4a040ba9fa500f1a5c4b31984a74e68659c4b420bd699ce630b130b08a6ea1162b0b53320e5a6488cb98a855ffc837d2a75ab90d61ac16cc1b7ab2cd3ed5e22b971c54a530398c9064bdc662d929e645cadda9a712cc5a8243f9cddbd2d98dd1f000f97b5221474526b601f3730a3afa965ceee1b343940c383e5314859e762c97")

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
    """Back end able to *read* a GT blob with this tag (the native library if present,
    otherwise a py_ecc-only decoder)."""
    t = bytes(tag)
    if t == b"\x01":
        return get("pyecc")
    if t == b"\x02":
        try:
            return get("mcl")
        except BackendError:
            if "mcl-decode" not in _cache:
                _cache["mcl-decode"] = McLDecodeOnly()
            return _cache["mcl-decode"]
    raise BackendError("unknown GT back-end tag")


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
