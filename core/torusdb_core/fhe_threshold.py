# SPDX-License-Identifier: Apache-2.0
"""FHE columns under THRESHOLD custody: the secret ``s`` exists only as a k-of-n sharing.

A :class:`ThresholdFheKey` is a drop-in for :class:`~torusdb_core.fhe.FheKey`
(``torussql.connect(..., fhe_key=ThresholdFheKey(...))``) whose secret scalar is the
Laurent-series-shared key of ``torussql.custody`` (group ``bn254``, dealerless DKG). The
process that runs it — and the database server — never hold ``s``, and ``s`` is never
reassembled anywhere: every use is "ask a quorum to apply their share, verify the proofs,
combine in the exponent".

=====================  ==============================================================
owner operation        how it is done without ``s``
=====================  ==============================================================
encrypt                public data only: ``Q = s·G1`` (= custody key 1's public key ``X1``) and
                       ``Q2 = s2·G2`` where ``s2`` is a SECOND, independent threshold secret
                       (custody key 2, public ``X2 = s2·G1``). ``Q2`` is assembled from key 2's
                       G2 shares and pairing-checked ``e(X2, G2) = e(G1, Q2)``; ``Q2 = s·G2`` is
                       refused (it would give a dictionary oracle on every cell)
decrypt cell / SUM     ``s·C1`` = threshold G1 decryption (DLEQ-proved ``yᵢ·E``, one round)
decrypt DOT            ``M = c11·c01^-s2·c10^-s·c00^(s·s2)`` by threshold GT exponentiation
                       (Chaum-Pedersen proved ``c^yᵢ``, ``custody/gt.py``): round 1 on key 1
                       (``c00^s``, ``c10^s``), round 2 on key 2 (``c01^s2`` and ``(c00^s)^s2``).
                       ``s·s2`` is never computed anywhere; the two sequential rounds are the
                       product in the exponent
integrity tags         α and γ derive from a SEPARATE 32-byte MAC secret that lives in the
                       public bundle sealed under the threshold vault envelope and is opened
                       (lazily, only if ``authenticated=True`` is used) by a quorum
=====================  ==============================================================

Trust trade-off of the MAC secret (documented in docs/fhe-columns.md): the owner process
holds it in memory while tags are used. It is NOT ``s`` — knowing it lets an attacker forge
tags (defeating ``authenticated=True`` against a lying server), but not decrypt anything.
Without ``authenticated=True`` the MAC secret is never opened.
"""
from __future__ import annotations

import json
import os
import threading

from . import fhe as _fhe
from . import fhe_backend as _fb
from .fhe import DEFAULT_RANGE, DOT_BYTES, GT_BYTES, FheError, _OwnerOps

N = _fb.N
_G1_CONTEXT = b"torussql/fhe/g1-decrypt/v1"
_GT_CONTEXT = b"torussql/fhe/gt-decrypt/v1"
_MAC_CONTEXT = b"torussql/fhe/mac-secret/v1\x00"
_G1_CHUNK = 500
BUNDLE_KIND = "torussql-fhe-threshold"


def _custody():
    try:
        import torussql.custody as c
        return c
    except ImportError as exc:                                  # pragma: no cover
        raise FheError("threshold FHE keys need the torussql driver with the custody "
                       "extra (pip install 'torussql[custody]')") from exc


class ThresholdFheKey(_OwnerOps):
    """``public`` is the custody ``PublicKey`` (group ``bn254``); ``custodians`` is a list of
    ``RemoteCustodian`` / ``LocalNode`` / ``LocalCustodian`` objects or a ready ``Quorum``.

    ``Q2`` (128 bytes) and ``mac`` (``{"header", "sealed"}``) come from the public bundle
    (``bundle()`` / ``from_bundle``); without ``Q2`` it is computed from the custodians'
    G2 shares. Either way it is verified: G2 subgroup membership and the pairing
    equation ``e(Q, G2) = e(G1, Q2)`` — a wrong ``Q2`` can never be used."""

    def __init__(self, public, custodians, public2, custodians2=None, *, Q2: bytes | None = None,
                 mac: dict | None = None, value_range: int = DEFAULT_RANGE, backend=None,
                 context: bytes = b"", timeout: float = 20.0):
        """``public``/``custodians``: custody key 1 (the secret ``s``). ``public2``/``custodians2``:
        custody key 2 (the independent secret ``s2``, run by the same custodian hosts).
        ``custodians2=None`` is allowed when ``Q2`` is given: such a key can encrypt and read
        cells / SUMs but ``DOT`` raises (no quorum for ``s2``)."""
        C = _custody()
        for p_ in (public, public2):
            if p_.group != "bn254":
                raise FheError("an FHE threshold key needs 'bn254' custody keys "
                               f"(this one is {p_.group!r})")
        g = public.g
        if public.key_id == public2.key_id or g.eq(public.X, public2.X):
            raise FheError("the second secret must be an independent key (same key twice)")
        self.quorum = self._mk_quorum(C, public, custodians, timeout)
        self.quorum2 = (self._mk_quorum(C, public2, custodians2, timeout)
                        if custodians2 is not None else None)
        self.public, self.public2 = public, public2
        self.range = value_range
        self.be = _fhe._be(backend)
        self._tables: dict = {}
        self._ctx = bytes(context)
        self.Q = self.be.g1_from(g.encode(public.X))
        if Q2 is None:
            if self.quorum2 is None:
                raise FheError("Q2 is needed (a bundle) when there is no quorum for the second secret")
            Q2 = self.quorum2.shared_g2()
        raw_q2 = bytes(Q2)
        self.Q2 = self._checked_q2(public, public2, raw_q2)
        self._q2_raw = raw_q2
        self._mac = dict(mac) if mac else None
        self._mac_secret_cache: bytes | None = None
        self._mac_lock = threading.Lock()

    @staticmethod
    def _mk_quorum(C, public, custodians, timeout):
        if isinstance(custodians, C.Quorum):
            if custodians.public.key_id != public.key_id:
                raise FheError("the quorum belongs to a different custody key")
            return custodians
        return C.Quorum(public, list(custodians), timeout=timeout)

    # — public bundle ————————————————————————————————————————————————————————
    def _checked_q2(self, public, public2, raw: bytes):
        """Q2 must be s2·G2 (e(X2, G2) = e(G1, Q2), subgroup) and must NOT be s·G2."""
        C = _custody()
        from torussql.custody import gt as _gt
        try:
            _gt.check_q2(public.X, raw)
        except C.CustodyError:
            pass
        else:
            raise FheError("Q2 equals s·G2 (the first secret): that gives a dictionary oracle on "
                           "every ciphertext — the G2 half needs an independent secret")
        try:
            _gt.check_q2(public2.X, raw)
        except (C.CustodyError, _fb.BackendError) as exc:
            raise FheError(f"the G2 public key does not match the second custody key: {exc}") from None
        try:
            return self.be.g2_from(raw)
        except _fb.BackendError as exc:
            raise FheError(f"bad G2 public key: {exc}") from None

    @staticmethod
    def new_mac(public) -> dict:
        """A fresh MAC secret sealed under the threshold envelope of ``public`` (needs the
        PUBLIC key only). The secret is generated, sealed and dropped here; only a quorum
        can open it again."""
        C = _custody()
        from torussql import seal
        ctx = _MAC_CONTEXT + bytes.fromhex(public.key_id)
        secret = os.urandom(32)
        K, header = C.wrap_key(public, ctx)
        return {"header": header, "sealed": seal.seal(K, secret, aad=ctx).hex()}

    def bundle(self) -> dict:
        """Everything PUBLIC the owner needs, JSON-serialisable (no secret of any kind)."""
        g = self.public.g
        return {"v": 2, "kind": BUNDLE_KIND, "key_id": self.public.key_id,
                "key_id2": self.public2.key_id, "range": self.range,
                "Q": g.hex(self.public.X), "X2": g.hex(self.public2.X), "Q2": self._q2_raw.hex(),
                **({"mac": self._mac} if self._mac else {})}

    def save_bundle(self, path: str) -> None:
        from torussql.custody.keys import _atomic
        _atomic(path, json.dumps(self.bundle(), indent=1).encode(), 0o644)

    @classmethod
    def from_bundle(cls, bundle: dict, public, custodians, public2, custodians2=None,
                    **kw) -> "ThresholdFheKey":
        if not isinstance(bundle, dict) or bundle.get("kind") != BUNDLE_KIND:
            raise FheError("not a threshold FHE bundle")
        if bundle.get("v") == 1:
            raise FheError("this is a version-1 threshold FHE bundle (Q2 = s·G2, which leaks a "
                           "dictionary oracle on every cell); it is no longer accepted — create a "
                           "new key with a second secret (fhe-keygen-threshold --public2 ...) and "
                           "re-encrypt the data")
        if bundle.get("v") != 2:
            raise FheError("unsupported threshold FHE bundle version")
        if bundle.get("key_id") != public.key_id or bundle.get("key_id2") != public2.key_id:
            raise FheError("this bundle belongs to different custody keys")
        g = public.g
        try:
            if not g.eq(g.from_hex(bundle["Q"]), public.X):
                raise FheError("bundle Q does not equal the custody public key")
            if not g.eq(g.from_hex(bundle["X2"]), public2.X):
                raise FheError("bundle X2 does not equal the second custody public key")
            q2 = bytes.fromhex(bundle["Q2"])
            rng = int(bundle["range"])
        except (KeyError, ValueError, TypeError) as exc:
            raise FheError(f"malformed threshold FHE bundle ({type(exc).__name__})") from None
        kw.setdefault("value_range", rng)
        return cls(public, custodians, public2, custodians2, Q2=q2, mac=bundle.get("mac"), **kw)

    @classmethod
    def load(cls, path: str, public, custodians, public2, custodians2=None, **kw) -> "ThresholdFheKey":
        with open(path, "rb") as f:
            return cls.from_bundle(json.loads(f.read()), public, custodians, public2,
                                   custodians2, **kw)

    @classmethod
    def create(cls, public, custodians, public2, custodians2, *, with_mac: bool = True,
               **kw) -> "ThresholdFheKey":
        """Ceremony step after the two DKGs: derive Q2 from key 2's custodians and seal a MAC
        secret under key 1's envelope."""
        return cls(public, custodians, public2, custodians2,
                   mac=cls.new_mac(public) if with_mac else None, **kw)

    def __repr__(self) -> str:                      # never print tokens / secrets
        return (f"<ThresholdFheKey {self.public.k}-of-{self.public.n} range={self.range} "
                f"backend={self.be.name} keys={self.public.key_id}+{self.public2.key_id}>")

    def __reduce__(self):
        raise TypeError("ThresholdFheKey holds custodian credentials and cannot be pickled")

    # — integrity tags: the separate, sealed MAC secret ——————————————————————————
    def _mac_secret(self) -> bytes:
        with self._mac_lock:
            if self._mac_secret_cache is None:
                if not self._mac:
                    raise FheError("this threshold FHE key has no MAC secret — authenticated "
                                   "mode is unavailable (create the bundle with a MAC)")
                C = _custody()
                from torussql import seal
                ctx = _MAC_CONTEXT + bytes.fromhex(self.public.key_id)
                hdr = self._mac["header"]
                if bytes.fromhex(hdr.get("ctx", "")) != ctx:
                    raise FheError("the MAC envelope was made for a different purpose")
                K = C.unwrap_key(self.public, hdr, self.quorum.shared_point)
                try:
                    secret = seal.unseal(K, bytes.fromhex(self._mac["sealed"]), aad=ctx)
                except ValueError:
                    raise FheError("the sealed MAC secret is damaged or was tampered with") from None
                if len(secret) != 32:
                    raise FheError("bad MAC secret")
                self._mac_secret_cache = secret
            return self._mac_secret_cache

    def forget_mac_secret(self) -> None:
        """Drop the cached MAC secret (best effort; Python cannot scrub memory)."""
        with self._mac_lock:
            self._mac_secret_cache = None

    # — s·P by quorum (G1) ————————————————————————————————————————————————————
    def _mul_s_many(self, points):
        be, g = self.be, self.public.g
        out = [be.g1_zero() for _ in points]
        need = [i for i, p in enumerate(points) if not be.g1_is_zero(p)]
        for lo in range(0, len(need), _G1_CHUNK):
            part = need[lo:lo + _G1_CHUNK]
            Es = [g.decode(be.g1_to(points[i])) for i in part]
            for i, r in zip(part, self.quorum.shared_points(Es, _G1_CONTEXT)):
                out[i] = be.g1_from(g.encode(r))
        return out

    # — DOT: threshold GT exponentiation ———————————————————————————————————————
    def decrypt_dot(self, blob: bytes) -> int:
        C = _custody()
        from torussql.custody import gt as _gt
        if len(blob) != DOT_BYTES:
            raise FheError("bad DOT ciphertext")
        try:
            be = _fb.by_tag(blob[:1])
        except _fb.BackendError:
            raise FheError("this DOT result was computed with a back end that is not "
                           "available here — install mclbn256 or ask for pyecc") from None
        if self.quorum2 is None:
            raise FheError("DOT needs the second secret s2: this key has no custodian quorum for it")
        raw = [bytes(blob[1 + i * GT_BYTES:1 + (i + 1) * GT_BYTES]) for i in range(4)]
        c00, c01, c10, c11 = raw
        try:
            for r in raw:
                _gt.gt_check(r)                  # a hostile server cannot make us query foreign elements
            # M = c11 · c01^-s2 · c10^-s · c00^(s·s2); neither s·s2 nor any product of secrets is
            # formed. Round 1 (key 1): c00^s, c10^s.  Round 2 (key 2): c01^s2 and (c00^s)^s2.
            t00, t10 = self.quorum.shared_gt_powers([c00, c10], _GT_CONTEXT)
            t01, u00 = self.quorum2.shared_gt_powers([c01, t00], _GT_CONTEXT)
            M = (_gt.gt_decode(c11) * (_gt.gt_decode(t01) ** (N - 1))
                 * (_gt.gt_decode(t10) ** (N - 1)) * _gt.gt_decode(u00))   # inverse in μ_N = ^(N-1)
            Mbe = be.gt_from(_gt.gt_encode(M))
        except (C.CustodyError, _fb.BackendError) as exc:
            if isinstance(exc, C.InsufficientPartials):
                raise
            raise FheError(f"threshold DOT decryption failed: {exc}") from None
        return self._gt_dlog(be, Mbe)
