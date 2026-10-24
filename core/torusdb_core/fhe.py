# SPDX-License-Identifier: Apache-2.0
"""FHE columns: server-side ``SUM`` and ``DOT`` on ciphertexts, with NO key at the server.

An EC-FHE scheme (elliptic-curve based — not lattice-based; no noise, no bootstrapping) over
the BN254 pairing groups (G1, G2, GT), implemented on
``py_ecc`` (portable) with an optional native ``mclbn256`` back end — nothing here depends
on the proprietary engine.

    secret  s          public  Q = s·P (G1),  Q2 = s·G2 (G2)         e = pairing(G2, G1)

    encrypt(v)  =  G1 half  (C1, C2) = (r1·P,  v·P  + r1·Q )        independent
                   G2 half  (D1, D2) = (r2·G2, v·G2 + r2·Q2)        randomness r1 ≠ r2

* **SUM** (server): add the G1 halves of the chosen cells. Owner: ``ΣC2 − s·ΣC1 = (Σv)·P``,
  then a bounded discrete log.
* **DOT** (server): the ciphertext×ciphertext product ★_ct (pairing, NOT a scalar multiplication):
  for each row pair the G2 half of cell a with the G1 half of cell b:
  ``c00=e(D1,C1′) c01=e(D1,C2′) c10=e(D2,C1′) c11=e(D2,C2′)`` and multiply the four GT
  values over all rows. Owner: ``c11·c01^−s·c10^−s·c00^(s²) = e(P,G2)^(Σ a·b)``.

The two halves of a cell use *independent* randomness. With a shared ``r`` (as in some
paired-ciphertext layouts) anyone holding the public key can test whether a cell encrypts a
guessed value: ``e(C2 − v·P, G2) == e(Q, D1)``. Independent randomness removes that
test (see ``tests/test_fhe.py``); security rests on SXDH in BN254 (≈100-bit).

Limits: plaintexts are integers; results must lie in ``[-range, range]`` (the discrete log
is a baby-step/giant-step search, memory ≈ √range table entries); ciphertexts are 512 bytes;
the server does 4 pairings per DOT row (native back end ≈ 1 ms/row, pure-Python fallback
≈ 0.2 s/row — see ``fhe_backend``); no integrity — a lying server can return a
wrong ciphertext (MAC columns are future work); no WHERE/ORDER/GROUP on FHE columns.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from typing import Iterable

from . import fhe_backend as _fb
from .fhe_backend import G1_BYTES, G2_BYTES, GT_BYTES, N

SUM_BYTES = 2 * G1_BYTES                                  # (ΣC1, ΣC2)
DOT_BYTES = 1 + 4 * GT_BYTES                              # backend tag + (c00, c01, c10, c11)
CELL_BYTES = 2 * G1_BYTES + 2 * G2_BYTES                  # C1 C2 | D1 D2  = 384
DEFAULT_RANGE = 1_000_000


class FheError(ValueError):
    pass


from .errors import IntegrityError as _CoreIntegrityError


class IntegrityError(FheError, _CoreIntegrityError):
    """The server's answer does not match the authenticated data."""


def _be(backend=None):
    if backend is None:
        return _fb.default()
    return _fb.get(backend) if isinstance(backend, str) else backend


def available_backends() -> list[str]:
    return _fb.available()


def parse_cell(raw: bytes, backend=None):
    """-> (C1, C2, D1, D2) as points of ``backend``. Validates length and the points."""
    be = _be(backend)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != CELL_BYTES:
        raise FheError(f"an FHE cell is exactly {CELL_BYTES} bytes")
    r = bytes(raw)
    try:
        return (be.g1_from(r[:64]), be.g1_from(r[64:128]),
                be.g2_from(r[128:256]), be.g2_from(r[256:384]))
    except _fb.BackendError as exc:
        raise FheError(str(exc)) from None


# ── server-side evaluation (public data only) ────────────────────────────────
def sum_cells(cells: Iterable[bytes], backend=None, scale: int = 1) -> bytes:
    """Σ of the G1 halves → 128 bytes (ΣC1, ΣC2), optionally multiplied by the PUBLIC
    scalar ``scale`` (EC scalar multiplication of the ciphertext points — a different,
    cheap operation from ct×ct multiplication, which uses pairings). Back-end independent."""
    be = _be(backend)
    c1, c2 = be.g1_zero(), be.g1_zero()
    for raw in cells:
        a, b_, _d1, _d2 = parse_cell(raw, be)
        c1, c2 = be.g1_add(c1, a), be.g1_add(c2, b_)
    if scale != 1:
        c1, c2 = be.g1_mul(c1, scale), be.g1_mul(c2, scale)
    return be.g1_to(c1) + be.g1_to(c2)


def dot_cells(left: Iterable[bytes], right: Iterable[bytes], backend=None) -> bytes:
    """Σ aᵢ·bᵢ as a GT ciphertext: ``tag ‖ c00 ‖ c01 ‖ c10 ‖ c11`` (4 × 384 bytes), pairing
    the G2 half of ``left[i]`` with the G1 half of ``right[i]``. Miller loops are multiplied
    before one final exponentiation per component."""
    be = _be(backend)
    acc = [None, None, None, None]
    for la, rb in zip(left, right):
        _a1, _a2, d1, d2 = parse_cell(la, be)
        c1, c2, _b1, _b2 = parse_cell(rb, be)
        for k, (q, p_) in enumerate(((d1, c1), (d1, c2), (d2, c1), (d2, c2))):
            if be.g1_is_zero(p_) or q is None:
                continue
            m = be.miller(q, p_)
            acc[k] = m if acc[k] is None else be.gt_mul(acc[k], m)
    one = be.gt_one()
    return be.tag + b"".join(be.gt_to(be.final(x) if x is not None else one) for x in acc)


def add_sums(a: bytes, b: bytes, backend=None) -> bytes:
    """Combine two partial SUM ciphertexts (public operation)."""
    if len(a) != SUM_BYTES or len(b) != SUM_BYTES:
        raise FheError("bad SUM ciphertext")
    be = _be(backend)
    try:
        return (be.g1_to(be.g1_add(be.g1_from(a[:64]), be.g1_from(b[:64])))
                + be.g1_to(be.g1_add(be.g1_from(a[64:]), be.g1_from(b[64:]))))
    except _fb.BackendError as exc:
        raise FheError(str(exc)) from None


def mul_dots(a: bytes, b: bytes) -> bytes:
    """Combine two partial DOT ciphertexts made by the same back end."""
    if len(a) != DOT_BYTES or len(b) != DOT_BYTES or a[:1] != b[:1]:
        raise FheError("bad or mismatched DOT ciphertexts")
    be = _fb.by_tag(a[:1])
    return a[:1] + b"".join(
        be.gt_to(be.gt_mul(be.gt_from(a[1 + i * GT_BYTES:1 + (i + 1) * GT_BYTES]),
                           be.gt_from(b[1 + i * GT_BYTES:1 + (i + 1) * GT_BYTES])))
        for i in range(4))


# ── the owner's side ─────────────────────────────────────────────────────────
class FheKey:
    """The secret scalar ``s`` and the derived public key. ``s`` never leaves the owner."""

    def __init__(self, s: int | None = None, value_range: int = DEFAULT_RANGE, backend=None):
        self._s = s if s is not None else secrets.randbelow(N - 1) + 1
        if not 0 < self._s < N:
            raise FheError("secret out of range")
        self.range = value_range
        self.be = _be(backend)
        self.Q = self.be.g1_mul(self.be.G1, self._s)
        self.Q2 = self.be.g2_mul(self.be.G2, self._s)
        self._tables: dict[str, dict] = {}

    @property
    def backend(self) -> str:
        return self.be.name

    def __repr__(self) -> str:                      # never print the secret
        return f"<FheKey range={self.range} backend={self.be.name}>"

    def __reduce__(self):
        raise TypeError("FheKey holds a secret and cannot be pickled or copied")

    @property
    def secret_bytes(self) -> bytes:
        return int(self._s).to_bytes(32, "big")

    @staticmethod
    def from_secret_bytes(raw: bytes, value_range: int = DEFAULT_RANGE, backend=None) -> "FheKey":
        return FheKey(int.from_bytes(raw, "big"), value_range, backend)

    # encryption needs only public data
    def encrypt(self, v: int) -> bytes:
        if isinstance(v, bool) or not isinstance(v, int):
            raise FheError("FHE columns hold integers")
        if abs(v) > self.range:
            raise FheError(f"|value| must be <= the key's range ({self.range})")
        return self.encrypt_scalar(v)

    def encrypt_scalar(self, m: int) -> bytes:
        """Encrypt an arbitrary scalar mod the group order (no range limit: tags, not data)."""
        be = self.be
        r1, r2 = (secrets.randbelow(N - 1) + 1 for _ in range(2))
        vm = m % N
        c1 = be.g1_mul(be.G1, r1)
        c2 = be.g1_add(be.g1_mul(be.G1, vm), be.g1_mul(self.Q, r1))
        d1 = be.g2_mul(be.G2, r2)
        d2 = be.g2_add(be.g2_mul(be.G2, vm), be.g2_mul(self.Q2, r2))
        return be.g1_to(c1) + be.g1_to(c2) + be.g2_to(d1) + be.g2_to(d2)

    # ── integrity tags (optional, ``authenticated=True``) ─────────────────────
    # Next to the value ciphertext Enc(v) each cell carries a TAG ciphertext
    # Enc(α·v + γ) where α is a secret MAC key and γ = PRF(table, column, row id) is a
    # secret per-cell tweak; both derive from the owner's secret. For any set of rows I the
    # owner checks, in the exponent and without any discrete log,
    #       tag-sum point  ==  α · value-sum point  +  k · (Σ_{i∈I} γᵢ)·P
    # (k = public scalar multiplier). A server that alters a value, drops/duplicates/swaps a
    # row, or scales a result cannot satisfy it without α and γ (soundness ≈ 1/n per attempt).
    # Not covered: replaying an older version of the same cell; ct×ct (DOT) results.
    def _prf(self, label: bytes, *parts) -> int:
        h = hmac.new(self.secret_bytes, b"torussql/fhe/" + label, hashlib.sha256).digest()
        msg = b"\x00".join(str(p).encode() for p in parts)
        return int.from_bytes(hmac.new(h, msg, hashlib.sha512).digest(), "big") % N

    @property
    def alpha(self) -> int:
        return self._prf(b"alpha") or 1

    def gamma(self, table: str, col: str, rowid: int) -> int:
        return self._prf(b"gamma", table, col, rowid)

    def tag(self, v: int, table: str, col: str, rowid: int) -> bytes:
        return self.encrypt_scalar(self.alpha * v + self.gamma(table, col, rowid))

    def _opened(self, blob: bytes):
        """(ΣC2 − s·ΣC1) of a SUM blob — the plaintext times P, as a group element."""
        be = self.be
        c1, c2 = self._point_pair(blob)
        return be.g1_add(c2, be.g1_neg(be.g1_mul(c1, self._s)))

    def decrypt_sum_verified(self, value_blob: bytes, tag_blob: bytes, table: str, col: str,
                             rowids, scale: int = 1) -> int:
        be = self.be
        gam = sum(self.gamma(table, col, i) for i in rowids) % N
        mv, mt = self._opened(value_blob), self._opened(tag_blob)
        want = be.g1_add(be.g1_mul(mv, self.alpha), be.g1_mul(be.G1, scale * gam))
        if be.g1_key(mt) != be.g1_key(want):
            raise IntegrityError(f"integrity check failed for {table}.{col}: the server's "
                                 f"aggregate does not match the authenticated cells")
        return self._g1_dlog(mv)

    def decrypt_cell_verified(self, cell: bytes | None, tag: bytes | None, table: str,
                              col: str, rowid: int) -> int:
        if tag is None or cell is None:
            raise IntegrityError(f"{table}.{col} row {rowid} has no integrity tag "
                                 f"(written without authentication, or tampered)")
        return self.decrypt_sum_verified(sum_cells([cell], self.be), sum_cells([tag], self.be),
                                         table, col, [rowid])

    # decryption: bounded discrete logs (baby-step / giant-step)
    def _g1_dlog(self, M) -> int:
        be = self.be
        m = math.isqrt(self.range * 2 + 1) + 1
        tab = self._tables.get("g1")
        if tab is None or tab["m"] != m:
            t, cur = {}, be.g1_zero()
            for j in range(m + 1):
                t.setdefault(be.g1_key(cur), j)
                cur = be.g1_add(cur, be.G1)
            tab = self._tables["g1"] = {"m": m, "t": t}
        step = be.g1_neg(be.g1_mul(be.G1, m))
        cur = be.g1_add(M, be.g1_mul(be.G1, self.range))       # shift so the answer is in [0, 2·range]
        for i in range(m + 1):
            j = tab["t"].get(be.g1_key(cur))
            if j is not None:
                return i * m + j - self.range
            cur = be.g1_add(cur, step)
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")

    def _point_pair(self, blob: bytes):
        try:
            return self.be.g1_from(blob[:64]), self.be.g1_from(blob[64:128])
        except _fb.BackendError as exc:
            raise FheError(str(exc)) from None

    def decrypt_sum(self, blob: bytes) -> int:
        if len(blob) != SUM_BYTES:
            raise FheError("bad SUM ciphertext")
        be = self.be
        c1, c2 = self._point_pair(blob)
        return self._g1_dlog(be.g1_add(c2, be.g1_neg(be.g1_mul(c1, self._s))))

    def decrypt_cell(self, raw: bytes) -> int:
        be = self.be
        c1, c2, _d1, _d2 = parse_cell(raw, be)
        return self._g1_dlog(be.g1_add(c2, be.g1_neg(be.g1_mul(c1, self._s))))

    def _gt_dlog(self, be, M) -> int:
        m = math.isqrt(self.range * 2 + 1) + 1
        tab = self._tables.get("gt:" + be.name)
        g = be.gt_gen()
        if tab is None or tab["m"] != m:
            t, cur = {}, be.gt_one()
            for j in range(m + 1):
                t.setdefault(be.gt_key(cur), j)
                cur = be.gt_mul(cur, g)
            tab = self._tables["gt:" + be.name] = {"m": m, "t": t}
        giant = be.gt_pow(g, N - m)                              # g^(-m)
        cur = be.gt_mul(M, be.gt_pow(g, self.range))
        for i in range(m + 1):
            j = tab["t"].get(be.gt_key(cur))
            if j is not None:
                return i * m + j - self.range
            cur = be.gt_mul(cur, giant)
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")

    def decrypt_dot(self, blob: bytes) -> int:
        if len(blob) != DOT_BYTES:
            raise FheError("bad DOT ciphertext")
        try:
            be = _fb.by_tag(blob[:1])
        except _fb.BackendError:
            raise FheError("this DOT result was computed with a back end that is not "
                           "available here — install mclbn256 or ask for pyecc") from None
        try:
            c00, c01, c10, c11 = (be.gt_from(blob[1 + i * GT_BYTES:1 + (i + 1) * GT_BYTES])
                                  for i in range(4))
        except _fb.BackendError as exc:
            raise FheError(str(exc)) from None
        s = self._s
        M = be.gt_mul(be.gt_mul(c11, be.gt_pow(c01, N - s)),
                      be.gt_mul(be.gt_pow(c10, N - s), be.gt_pow(c00, s * s)))
        return self._gt_dlog(be, M)


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
