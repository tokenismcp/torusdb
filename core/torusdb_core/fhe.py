# SPDX-License-Identifier: Apache-2.0
"""FHE columns: server-side ``SUM`` and ``DOT`` on ciphertexts, with NO key at the server.

A BGN-style scheme over the BN254 pairing groups (G1, G2, GT), implemented on
``py_ecc`` only — nothing here depends on the proprietary engine.

    secret  s          public  Q = s·P (G1),  Q2 = s·G2 (G2)         e = pairing(G2, G1)

    encrypt(v)  =  G1 half  (C1, C2) = (r1·P,  v·P  + r1·Q )        independent
                   G2 half  (D1, D2) = (r2·G2, v·G2 + r2·Q2)        randomness r1 ≠ r2

* **SUM** (server): add the G1 halves of the chosen cells. Owner: ``ΣC2 − s·ΣC1 = (Σv)·P``,
  then a bounded discrete log.
* **DOT** (server): for each row pair the G2 half of cell a with the G1 half of cell b:
  ``c00=e(D1,C1′) c01=e(D1,C2′) c10=e(D2,C1′) c11=e(D2,C2′)`` and multiply the four GT
  values over all rows. Owner: ``c11·c01^−s·c10^−s·c00^(s²) = e(P,G2)^(Σ a·b)``.

The two halves of a cell use *independent* randomness. With a shared ``r`` (as in some
paired-ciphertext layouts) anyone holding the public key can test whether a cell encrypts a
guessed value: ``e(C2 − v·P, G2) == e(Q, D1)``. Independent randomness removes that
test (see ``tests/test_fhe.py``); security rests on SXDH in BN254 (≈100-bit).

Limits: plaintexts are integers; results must lie in ``[-range, range]`` (the discrete log
is a baby-step/giant-step search, memory ≈ √range table entries); ciphertexts are 512 bytes;
the server does ~4 pairings per DOT row (pure-Python ``py_ecc`` ≈ 0.1–0.2 s each — use it
for small tables or install a native backend); no integrity — a lying server can return a
wrong ciphertext (MAC columns are future work); no WHERE/ORDER/GROUP on FHE columns.
"""
from __future__ import annotations

import math
import secrets
from typing import Iterable

from py_ecc.optimized_bn128 import (
    FQ, FQ2, FQ12, G1, G2, Z1, Z2, add, b, b2, curve_order, is_inf, is_on_curve,
    final_exponentiate, multiply, neg, normalize, pairing,
)

N = curve_order
CELL_BYTES = 4 * 32 + 2 * 64 + 2 * 128 - 4 * 32          # see _enc_cell: 2 G1 + 2 G2 = 384
G1_BYTES, G2_BYTES, GT_BYTES = 64, 128, 384
SUM_BYTES = 2 * G1_BYTES                                  # (ΣC1, ΣC2)
DOT_BYTES = 4 * GT_BYTES                                  # (c00, c01, c10, c11)
CELL_BYTES = 2 * G1_BYTES + 2 * G2_BYTES                  # C1 C2 | D1 D2  = 384
DEFAULT_RANGE = 1_000_000


class FheError(ValueError):
    pass


# ── (de)serialisation: affine big-endian field elements, all-zero = infinity ──
def _i32(x: int) -> bytes:
    return int(x).to_bytes(32, "big")


def g1_to_bytes(p) -> bytes:
    if is_inf(p):
        return bytes(G1_BYTES)
    x, y = normalize(p)
    return _i32(x.n) + _i32(y.n)


def g1_from_bytes(raw: bytes):
    if len(raw) != G1_BYTES:
        raise FheError("bad G1 point length")
    if raw == bytes(G1_BYTES):
        return Z1
    x, y = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    from py_ecc.fields import optimized_bn128_FQ as _F
    if x >= _F.field_modulus or y >= _F.field_modulus:
        raise FheError("G1 coordinate out of range")
    p = (FQ(x), FQ(y), FQ(1))
    if not is_on_curve(p, b):
        raise FheError("G1 point is not on the curve")
    return p


def g2_to_bytes(p) -> bytes:
    if is_inf(p):
        return bytes(G2_BYTES)
    x, y = normalize(p)
    return b"".join(_i32(c) for c in (*x.coeffs, *y.coeffs))


def g2_from_bytes(raw: bytes):
    if len(raw) != G2_BYTES:
        raise FheError("bad G2 point length")
    if raw == bytes(G2_BYTES):
        return Z2
    v = [int.from_bytes(raw[i:i + 32], "big") for i in range(0, 128, 32)]
    from py_ecc.fields import optimized_bn128_FQ as _F
    if any(c >= _F.field_modulus for c in v):
        raise FheError("G2 coordinate out of range")
    p = (FQ2([v[0], v[1]]), FQ2([v[2], v[3]]), FQ2([1, 0]))
    if not is_on_curve(p, b2):
        raise FheError("G2 point is not on the curve")
    return p


def gt_to_bytes(g) -> bytes:
    return b"".join(_i32(c.n if hasattr(c, "n") else c) for c in g.coeffs)


def gt_from_bytes(raw: bytes):
    if len(raw) != GT_BYTES:
        raise FheError("bad GT element length")
    return FQ12([int.from_bytes(raw[i:i + 32], "big") for i in range(0, GT_BYTES, 32)])


def parse_cell(raw: bytes):
    """-> (C1, C2, D1, D2). Validates length and curve membership."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != CELL_BYTES:
        raise FheError(f"an FHE cell is exactly {CELL_BYTES} bytes")
    r = bytes(raw)
    return (g1_from_bytes(r[:64]), g1_from_bytes(r[64:128]),
            g2_from_bytes(r[128:256]), g2_from_bytes(r[256:384]))


# ── server-side evaluation (public data only) ────────────────────────────────
def sum_cells(cells: Iterable[bytes]) -> bytes:
    """Σ of the G1 halves → 128 bytes (ΣC1, ΣC2)."""
    c1, c2 = Z1, Z1
    for raw in cells:
        a, b_, _d1, _d2 = parse_cell(raw)
        c1, c2 = add(c1, a), add(c2, b_)
    return g1_to_bytes(c1) + g1_to_bytes(c2)


def dot_cells(left: Iterable[bytes], right: Iterable[bytes]) -> bytes:
    """Σ aᵢ·bᵢ as a GT ciphertext (4 × 384 bytes): pairs the G2 half of ``left[i]``
    with the G1 half of ``right[i]``."""
    # Miller loops are multiplied *before* the (expensive) final exponentiation, so the
    # cost is 4 Miller loops per row plus 4 final exponentiations in total.
    acc = [None, None, None, None]
    for la, rb in zip(left, right):
        _a1, _a2, d1, d2 = parse_cell(la)
        c1, c2, _b1, _b2 = parse_cell(rb)
        for k, (q, p_) in enumerate(((d1, c1), (d1, c2), (d2, c1), (d2, c2))):
            m = pairing(q, p_, final_exponentiate=False) if not (is_inf(q) or is_inf(p_)) else None
            if m is not None:
                acc[k] = m if acc[k] is None else acc[k] * m
    one = pairing(G2, G1) ** 0
    return b"".join(gt_to_bytes(final_exponentiate(x) if x is not None else one) for x in acc)


def add_sums(a: bytes, b: bytes) -> bytes:
    """Combine two partial SUM ciphertexts (public operation)."""
    if len(a) != SUM_BYTES or len(b) != SUM_BYTES:
        raise FheError("bad SUM ciphertext")
    return (g1_to_bytes(add(g1_from_bytes(a[:64]), g1_from_bytes(b[:64])))
            + g1_to_bytes(add(g1_from_bytes(a[64:]), g1_from_bytes(b[64:]))))


def mul_dots(a: bytes, b: bytes) -> bytes:
    """Combine two partial DOT ciphertexts (public operation)."""
    if len(a) != DOT_BYTES or len(b) != DOT_BYTES:
        raise FheError("bad DOT ciphertext")
    return b"".join(
        gt_to_bytes(gt_from_bytes(a[i * GT_BYTES:(i + 1) * GT_BYTES])
                    * gt_from_bytes(b[i * GT_BYTES:(i + 1) * GT_BYTES]))
        for i in range(4))


# ── the owner's side ─────────────────────────────────────────────────────────
class FheKey:
    """The secret scalar ``s`` and the derived public key. ``s`` never leaves the owner."""

    def __init__(self, s: int | None = None, value_range: int = DEFAULT_RANGE):
        self._s = s if s is not None else secrets.randbelow(N - 1) + 1
        if not 0 < self._s < N:
            raise FheError("secret out of range")
        self.range = value_range
        self.Q = multiply(G1, self._s)
        self.Q2 = multiply(G2, self._s)
        self._g1_table: dict[bytes, int] | None = None
        self._gt_table: dict[bytes, int] | None = None
        self._gt = None

    def __repr__(self) -> str:                      # never print the secret
        return f"<FheKey range={self.range} public={g1_to_bytes(self.Q)[:6].hex()}…>"

    def __reduce__(self):
        raise TypeError("FheKey holds a secret and cannot be pickled or copied")

    @property
    def secret_bytes(self) -> bytes:
        return _i32(self._s)

    @staticmethod
    def from_secret_bytes(raw: bytes, value_range: int = DEFAULT_RANGE) -> "FheKey":
        return FheKey(int.from_bytes(raw, "big"), value_range)

    # encryption needs only public data
    def encrypt(self, v: int) -> bytes:
        if isinstance(v, bool) or not isinstance(v, int):
            raise FheError("FHE columns hold integers")
        if abs(v) > self.range:
            raise FheError(f"|value| must be <= the key's range ({self.range})")
        r1, r2 = (secrets.randbelow(N - 1) + 1 for _ in range(2))
        vm = v % N
        c1 = multiply(G1, r1)
        c2 = add(multiply(G1, vm), multiply(self.Q, r1))
        d1 = multiply(G2, r2)
        d2 = add(multiply(G2, vm), multiply(self.Q2, r2))
        return g1_to_bytes(c1) + g1_to_bytes(c2) + g2_to_bytes(d1) + g2_to_bytes(d2)

    # decryption: bounded discrete logs
    def _g1_dlog(self, M) -> int:
        m = math.isqrt(self.range * 2 + 1) + 1
        if self._g1_table is None or self._g1_table.get(b"m") != m:
            tab = {}
            cur = Z1
            for j in range(m + 1):
                tab[g1_to_bytes(cur)] = j
                cur = add(cur, G1)
            tab[b"m"] = m
            self._g1_table = tab
        step = multiply(G1, m)
        cur = add(M, multiply(G1, self.range))              # shift so the answer is in [0, 2·range]
        for i in range(m + 1):
            j = self._g1_table.get(g1_to_bytes(cur))
            if j is not None and j != b"m":
                return i * m + j - self.range
            cur = add(cur, neg(step))
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")

    def decrypt_sum(self, blob: bytes) -> int:
        if len(blob) != SUM_BYTES:
            raise FheError("bad SUM ciphertext")
        c1, c2 = g1_from_bytes(blob[:64]), g1_from_bytes(blob[64:])
        return self._g1_dlog(add(c2, neg(multiply(c1, self._s))))

    def decrypt_cell(self, raw: bytes) -> int:
        c1, c2, _d1, _d2 = parse_cell(raw)
        return self._g1_dlog(add(c2, neg(multiply(c1, self._s))))

    def _gt_dlog(self, M) -> int:
        m = math.isqrt(self.range * 2 + 1) + 1
        if self._gt_table is None or self._gt_table.get(b"m") != m:
            g = pairing(G2, G1)
            tab, cur = {}, g ** 0
            for j in range(m + 1):
                tab[gt_to_bytes(cur)] = j
                cur = cur * g
            tab[b"m"] = m
            self._gt_table, self._gt = tab, g
        g = self._gt
        giant = g ** ((N - m) % N)                           # g^(-m)
        cur = M * (g ** (self.range % N))
        for i in range(m + 1):
            j = self._gt_table.get(gt_to_bytes(cur))
            if j is not None and j != b"m":
                return i * m + j - self.range
            cur = cur * giant
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")

    def decrypt_dot(self, blob: bytes) -> int:
        if len(blob) != DOT_BYTES:
            raise FheError("bad DOT ciphertext")
        c00, c01, c10, c11 = (gt_from_bytes(blob[i * GT_BYTES:(i + 1) * GT_BYTES]) for i in range(4))
        s = self._s
        M = c11 * (c01 ** ((N - s) % N)) * (c10 ** ((N - s) % N)) * (c00 ** (s * s % N))
        return self._gt_dlog(M)


# ── key files: sealed with a passphrase, never written in the clear by accident ──
def save_key(key: FheKey, path: str, passphrase: str | None) -> None:
    """Write the secret to ``path`` (mode 0600). With a passphrase it is sealed
    (scrypt + encrypt-then-MAC, torussql.seal); ``passphrase=None`` stores it
    unprotected and is meant for tests only."""
    import json
    import os
    body = json.dumps({"v": 1, "range": key.range, "s": key.secret_bytes.hex()}).encode()
    if passphrase:
        from torussql import seal
        salt = os.urandom(16)
        k = seal.passphrase_key(passphrase, salt, b"fhe-key")
        blob = b"TORUSFHEKEY1 sealed " + salt.hex().encode() + b"\n" + seal.seal(k, body, b"fhe-key").hex().encode()
    else:
        blob = b"TORUSFHEKEY1 plain\n" + body
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_key(path: str, passphrase: str | None) -> FheKey:
    import json
    raw = open(path, "rb").read()
    head, _, rest = raw.partition(b"\n")
    parts = head.split()
    if not parts or parts[0] != b"TORUSFHEKEY1":
        raise FheError(f"{path}: not an FHE key file")
    if parts[1] == b"plain":
        body = rest
    else:
        if not passphrase:
            raise FheError(f"{path} is sealed — a passphrase is required")
        from torussql import seal
        k = seal.passphrase_key(passphrase, bytes.fromhex(parts[2].decode()), b"fhe-key")
        try:
            body = seal.unseal(k, bytes.fromhex(rest.decode()), b"fhe-key")
        except Exception:
            raise FheError("wrong passphrase or damaged key file") from None
    d = json.loads(body)
    return FheKey.from_secret_bytes(bytes.fromhex(d["s"]), int(d["range"]))
