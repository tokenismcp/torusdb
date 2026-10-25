# SPDX-License-Identifier: Apache-2.0
"""FHE columns: server-side ``SUM`` and ``DOT`` on ciphertexts, with NO key at the server.

An EC-FHE scheme (elliptic-curve based — not lattice-based; no noise, no bootstrapping) over
the BN254 pairing groups (G1, G2, GT), implemented on
``py_ecc`` (portable) with an optional native ``mclbn256`` back end — nothing here depends
on the proprietary engine.

    secrets s, s2      public  Q = s·P (G1),  Q2 = s2·G2 (G2)        e = pairing(G2, G1)
                       (s2 is a SECOND secret, derived from s — never publish Q2 = s·G2, see below)

    encrypt(v)  =  G1 half  (C1, C2) = (r1·P,  v·P  + r1·Q )        independent
                   G2 half  (D1, D2) = (r2·G2, v·G2 + r2·Q2)        randomness r1 ≠ r2, secret s ≠ s2

* **SUM** (server): add the G1 halves of the chosen cells. Owner: ``ΣC2 − s·ΣC1 = (Σv)·P``,
  then a bounded discrete log.
* **DOT** (server): the ciphertext×ciphertext product ★_ct (pairing, NOT a scalar multiplication):
  for each row pair the G2 half of cell a with the G1 half of cell b:
  ``c00=e(D1,C1′) c01=e(D1,C2′) c10=e(D2,C1′) c11=e(D2,C2′)`` and multiply the four GT
  values over all rows. Owner: ``c11·c01^−s2·c10^−s·c00^(s·s2) = e(P,G2)^(Σ a·b)``.

Value-oracle defences (both are required; ``tests/test_fhe.py`` checks every pairing identity
between the public keys and a cell):
* the two halves use *independent* randomness — with a shared ``r`` anyone holding the public key
  can test a guessed value: ``e(C2 − v·P, G2) == e(Q, D1)``;
* the G2 half uses an independent *secret* ``s2`` (``Q2 = s2·G2``) — with ``Q2 = s·G2`` the test
  ``e(G2, C2 − v·P) == e(Q2, C1)`` still works even with independent randomness.
Security then rests on SXDH in BN254 (≈100-bit).

Limits: plaintexts are integers; results must lie in ``[-range, range]`` (the discrete log
is a baby-step/giant-step search, memory ≈ √range table entries); cells are 384 bytes;
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
MAX_RANGE = 1 << 40            # larger ranges would need a ~2^20-entry (and up) baby-step table


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


def parse_cell(raw: bytes, backend=None, strict: bool = False):
    """-> (C1, C2, D1, D2) as points of ``backend``. Validates length and the points;
    ``strict`` additionally proves the G2 points are in the prime-order subgroup (always done
    by the native back end; costs ≈0.1 s per cell in pure Python — used when a cell is WRITTEN)."""
    be = _be(backend)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != CELL_BYTES:
        raise FheError(f"an FHE cell is exactly {CELL_BYTES} bytes")
    r = bytes(raw)
    try:
        d1, d2 = be.g2_from(r[128:256]), be.g2_from(r[256:384])
        if strict:
            for q in (d1, d2):
                if not be.g2_in_subgroup(q):
                    raise _fb.BackendError("G2 point is not a valid subgroup element")
        return (be.g1_from(r[:64]), be.g1_from(r[64:128]), d1, d2)
    except _fb.BackendError as exc:
        raise FheError(str(exc)) from None


def parse_g1_half(raw: bytes, backend=None):
    """-> (C1, C2) of a cell, validating only the G1 half (what SUM / decryption use)."""
    be = _be(backend)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != CELL_BYTES:
        raise FheError(f"an FHE cell is exactly {CELL_BYTES} bytes")
    r = bytes(raw)
    try:
        return be.g1_from(r[:64]), be.g1_from(r[64:128])
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
        a, b_ = parse_g1_half(raw, be)
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
def derive_s2(s: int) -> int:
    """The G2-side secret. It MUST differ from ``s``: with ``Q = s·P`` and ``Q2 = s·G2`` both
    public, anyone can test a guessed value v with ``e(G2, C2 − v·P) == e(Q2, C1)`` even though
    the two halves use independent randomness. ``s2`` is derived (not stored) so key files hold
    only ``s``; a threshold key shares ``s2`` as a second secret instead."""
    h = hashlib.sha512(b"torussql/fhe/v2/g2-secret\x00" + int(s).to_bytes(32, "big")).digest()
    return int.from_bytes(h, "big") % (N - 1) + 1


class _OwnerOps:
    """Everything the owner does that needs only PUBLIC data (encryption), a MAC secret
    (integrity tags) and *some way to compute s·P* — supplied by the subclass:

    * ``FheKey`` holds ``s`` locally;
    * ``fhe_threshold.ThresholdFheKey`` obtains ``s·P`` from a quorum of custodians and
      never holds ``s`` at all.

    Subclass contract: ``self.be``, ``self.range``, ``self.Q``, ``self.Q2``,
    ``_mul_s_many(points) -> [s·P]`` (G1 points of ``self.be``), ``_mac_secret() -> bytes``
    and ``decrypt_dot``."""

    @property
    def backend(self) -> str:
        return self.be.name

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
        # r1, r2 (encryption randomness) and vm (the plaintext) are secrets: constant-time
        # multiplication on the native back end (mulCT); py_ecc has no constant-time path.
        c1 = be.g1_mul_secret(be.G1, r1)
        c2 = be.g1_add(be.g1_mul_secret(be.G1, vm), be.g1_mul_secret(self.Q, r1))
        d1 = be.g2_mul_secret(be.G2, r2)
        d2 = be.g2_add(be.g2_mul_secret(be.G2, vm), be.g2_mul_secret(self.Q2, r2))
        return be.g1_to(c1) + be.g1_to(c2) + be.g2_to(d1) + be.g2_to(d2)

    # ── integrity tags (optional, ``authenticated=True``) ─────────────────────
    # Next to the value ciphertext Enc(v) each cell carries a TAG ciphertext
    # Enc(α·v + γ) where α is a secret MAC key and γ = PRF(table, column, row id) is a
    # secret per-cell tweak; both derive from the owner's MAC secret (for a plain
    # ``FheKey`` that is ``s`` itself; for a threshold key a separate 32-byte secret).
    # For any set of rows I the owner checks, in the exponent and without any discrete log,
    #       tag-sum point  ==  α · value-sum point  +  k · (Σ_{i∈I} γᵢ)·P
    # (k = public scalar multiplier). A server that alters a value, drops/duplicates/swaps a
    # row, or scales a result cannot satisfy it without α and γ (soundness ≈ 1/n per attempt).
    # Not covered by the tags alone: replaying an older version of the same cell, the set of rows,
    # and ct×ct (DOT) results — the first two are covered in anchored mode (fhe_anchor.py).
    def _prf(self, label: bytes, *parts) -> int:
        h = hmac.new(self._mac_secret(), b"torussql/fhe/" + label, hashlib.sha256).digest()
        msg = b"\x00".join(str(p).encode() for p in parts)
        return int.from_bytes(hmac.new(h, msg, hashlib.sha512).digest(), "big") % N

    @property
    def alpha(self) -> int:
        return self._prf(b"alpha") or 1

    def anchor_leaf(self, table: str, rowid: int, material: bytes) -> int:
        """Leaf of one row for the anchored table state (``fhe_anchor``): a PRF of the table,
        the row id and the canonical row material, under a key derived from the MAC secret with
        its own domain label (``anchor-leaf``) — independent of α and γ. The server cannot
        compute it, so it cannot present a table state other than the anchored one."""
        k = hmac.new(self._mac_secret(), b"torussql/fhe/anchor-leaf", hashlib.sha256).digest()
        t = table.encode("utf-8")
        msg = len(t).to_bytes(4, "big") + t + int(rowid).to_bytes(8, "big") + material
        return int.from_bytes(hmac.new(k, msg, hashlib.sha512).digest(), "big") % N

    def gamma(self, table: str, col: str, rowid: int, nonce: int) -> int:
        """Per-WRITE tweak: ``nonce`` is a fresh random number stored next to the cell and
        changes with every write, so tags of different versions of one cell (or of a row id that
        is later reused) never share a γ — otherwise the server could mix an old and a new
        version affinely, λ·old + (1−λ)·new, and have any integer accepted."""
        if isinstance(nonce, bool) or not isinstance(nonce, int):
            raise IntegrityError(f"{table}.{col} row {rowid} has no write nonce "
                                 f"(written without authentication, or tampered)")
        return self._prf(b"gamma", table, col, rowid, nonce)

    def tag(self, v: int, table: str, col: str, rowid: int, nonce: int) -> bytes:
        return self.encrypt_scalar(self.alpha * v + self.gamma(table, col, rowid, nonce))

    def _in_range(self, x: int) -> int:
        """The baby-step grid overshoots ±range slightly; the contract is strict."""
        if abs(x) > self.range:
            raise FheError("result is outside the key's value range (or the ciphertext is invalid)")
        return x

    def _point_pair(self, blob: bytes):
        try:
            return self.be.g1_from(blob[:64]), self.be.g1_from(blob[64:128])
        except _fb.BackendError as exc:
            raise FheError(str(exc)) from None

    def _open_pairs(self, pairs):
        """[(C1, C2)] -> [C2 − s·C1] (the plaintext times P, as group elements)."""
        be = self.be
        sc = self._mul_s_many([c1 for c1, _c2 in pairs])
        return [be.g1_add(c2, be.g1_neg(x)) for (_c1, c2), x in zip(pairs, sc)]

    def _opened(self, blob: bytes):
        return self._open_pairs([self._point_pair(blob)])[0]

    def _verify_open(self, mv, mt, table, col, gam_sum, scale):
        be = self.be
        want = be.g1_add(be.g1_mul_secret(mv, self.alpha),
                         be.g1_mul_secret(be.G1, scale * gam_sum))
        if be.g1_key(mt) != be.g1_key(want):
            raise IntegrityError(f"integrity check failed for {table}.{col}: the server's "
                                 f"aggregate does not match the authenticated cells")

    def decrypt_sum_verified(self, value_blob: bytes, tag_blob: bytes, table: str, col: str,
                             rowids, scale: int = 1, nonces=None) -> int:
        rowids = list(rowids)
        if nonces is None or len(nonces) != len(rowids):
            raise IntegrityError(f"{table}.{col}: write nonces missing for the requested rows")
        gam = sum(self.gamma(table, col, i, n) for i, n in zip(rowids, nonces)) % N
        mv, mt = self._open_pairs([self._point_pair(value_blob), self._point_pair(tag_blob)])
        self._verify_open(mv, mt, table, col, gam, scale)
        return self._g1_dlog(mv)

    def decrypt_cell_verified(self, cell: bytes | None, tag: bytes | None, table: str,
                              col: str, rowid: int, nonce=None) -> int:
        return self.decrypt_cells_verified([cell], [tag], table, col, [rowid], [nonce])[0]

    def decrypt_cells_verified(self, cells, tags, table: str, col: str, rowids,
                               nonces=None) -> list[int]:
        """Verified read of many cells; a threshold key opens them in as few quorum
        rounds as possible."""
        for cell, tag, rowid in zip(cells, tags, rowids):
            if tag is None or cell is None:
                raise IntegrityError(f"{table}.{col} row {rowid} has no integrity tag "
                                     f"(written without authentication, or tampered)")
        rowids = list(rowids)
        if nonces is None or len(nonces) != len(rowids):
            raise IntegrityError(f"{table}.{col}: write nonces missing for the requested rows")
        pairs = []
        for cell, tag in zip(cells, tags):
            pairs += [parse_g1_half(cell, self.be), parse_g1_half(tag, self.be)]
        opened = self._open_pairs(pairs)
        out = []
        for j, rowid in enumerate(rowids):
            mv, mt = opened[2 * j], opened[2 * j + 1]
            self._verify_open(mv, mt, table, col, self.gamma(table, col, rowid, nonces[j]), 1)
            out.append(self._g1_dlog(mv))
        return out

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
        # Start the giant-step walk at a RANDOM position and wrap around: the number of steps
        # until a hit is then uniform and independent of the plaintext, so the time a decryption
        # takes does not depend on the value (a fixed start leaks it linearly).
        steps = m + 1
        i0 = secrets.randbelow(steps)
        base = be.g1_add(M, be.g1_mul(be.G1, self.range))               # shift into [0, 2·range]
        cur = be.g1_add(base, be.g1_mul(step, i0))
        for t_ in range(steps):
            i = (i0 + t_) % steps
            if i == 0 and t_:
                cur = base                                               # wrapped around
            j = tab["t"].get(be.g1_key(cur))
            if j is not None:
                return self._in_range(i * m + j - self.range)
            cur = be.g1_add(cur, step)
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")

    def decrypt_sum(self, blob: bytes) -> int:
        if len(blob) != SUM_BYTES:
            raise FheError("bad SUM ciphertext")
        return self._g1_dlog(self._opened(blob))

    def decrypt_cell(self, raw: bytes) -> int:
        return self.decrypt_cells([raw])[0]

    def decrypt_cells(self, raws) -> list[int]:
        pairs = []
        for raw in raws:
            c1, c2, _d1, _d2 = parse_cell(raw, self.be)
            pairs.append((c1, c2))
        return [self._g1_dlog(m) for m in self._open_pairs(pairs)]

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
        steps = m + 1
        i0 = secrets.randbelow(steps)                            # random start: see _g1_dlog
        base = be.gt_mul(M, be.gt_pow(g, self.range))
        cur = be.gt_mul(base, be.gt_pow(giant, i0))
        for t_ in range(steps):
            i = (i0 + t_) % steps
            if i == 0 and t_:
                cur = base
            j = tab["t"].get(be.gt_key(cur))
            if j is not None:
                return self._in_range(i * m + j - self.range)
            cur = be.gt_mul(cur, giant)
        raise FheError("result is outside the key's value range (or the ciphertext is invalid)")


class FheKey(_OwnerOps):
    """The secret scalar ``s`` and the derived public key. ``s`` never leaves the owner."""

    def __init__(self, s: int | None = None, value_range: int = DEFAULT_RANGE, backend=None):
        self._s = s if s is not None else secrets.randbelow(N - 1) + 1
        if not 0 < self._s < N:
            raise FheError("secret out of range")
        if isinstance(value_range, bool) or not isinstance(value_range, int) \
                or not 1 <= value_range <= MAX_RANGE:
            raise FheError(f"range must be an integer in [1, 2^40] (the discrete-log table "
                           f"grows with its square root)")
        self.range = value_range
        self.be = _be(backend)
        self._s2 = derive_s2(self._s)
        self.Q = self.be.g1_mul_secret(self.be.G1, self._s)
        self.Q2 = self.be.g2_mul_secret(self.be.G2, self._s2)
        self._tables: dict[str, dict] = {}

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

    def _mac_secret(self) -> bytes:                 # tags derive from s itself
        return self.secret_bytes

    def _mul_s_many(self, points):
        return [self.be.g1_mul_secret(p, self._s) for p in points]

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
        # The secret is used as an exponent below, so every base it touches must lie in the
        # order-n subgroup of GT. Otherwise a hostile server could send an element of small
        # order and learn s modulo that order from whether decryption succeeds.
        for x in (c00, c01, c10):                     # every base the secret is an exponent of
            if not be.gt_in_subgroup(x):
                raise FheError("invalid DOT ciphertext: component outside the GT subgroup")
        s, s2 = self._s, self._s2
        M = be.gt_mul(be.gt_mul(c11, be.gt_pow(c01, N - s2)),
                      be.gt_mul(be.gt_pow(c10, N - s), be.gt_pow(c00, s * s2)))
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
