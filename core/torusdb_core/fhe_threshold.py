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
encrypt                public data only: ``Q = s·G1`` (= the custody public key ``X``) and
                       ``Q2 = s·G2`` (assembled from the custodians' G2 shares, pairing-
                       checked ``e(Q, G2) = e(G1, Q2)``, stored in the public bundle)
decrypt cell / SUM     ``s·C1`` = threshold G1 decryption (DLEQ-proved ``yᵢ·E``, one round)
decrypt DOT            ``M = c11·c01^-s·c10^-s·c00^(s²)`` by threshold GT exponentiation
                       (Chaum-Pedersen proved ``c^yᵢ``, ``custody/gt.py``); ``s²`` is two
                       SEQUENTIAL rounds (``u = c00^s`` then ``u^s``), never ``s*s``
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

    def __init__(self, public, custodians, *, Q2: bytes | None = None, mac: dict | None = None,
                 value_range: int = DEFAULT_RANGE, backend=None, context: bytes = b"",
                 timeout: float = 20.0):
        C = _custody()
        if public.group != "bn254":
            raise FheError("an FHE threshold key needs a 'bn254' custody key "
                           f"(this one is {public.group!r})")
        if isinstance(custodians, C.Quorum):
            if custodians.public.key_id != public.key_id:
                raise FheError("the quorum belongs to a different custody key")
            self.quorum = custodians
        else:
            self.quorum = C.Quorum(public, list(custodians), timeout=timeout)
        self.public = public
        self.range = value_range
        self.be = _fhe._be(backend)
        self._tables: dict = {}
        self._ctx = bytes(context)
        g = public.g
        self.Q = self.be.g1_from(g.encode(public.X))
        raw_q2 = bytes(Q2) if Q2 is not None else self.quorum.shared_g2()
        self.Q2 = self._checked_q2(public, raw_q2)
        self._q2_raw = raw_q2
        self._mac = dict(mac) if mac else None
        self._mac_secret_cache: bytes | None = None
        self._mac_lock = threading.Lock()

    # — public bundle ————————————————————————————————————————————————————————
    def _checked_q2(self, public, raw: bytes):
        C = _custody()
        from torussql.custody import gt as _gt
        try:
            _gt.check_q2(public.X, raw)           # subgroup + e(X, G2) = e(G1, Q2)  (py_ecc)
            return self.be.g2_from(raw)
        except (C.CustodyError, _fb.BackendError) as exc:
            raise FheError(f"the G2 public key does not match the custody key: {exc}") from None

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
        return {"v": 1, "kind": BUNDLE_KIND, "key_id": self.public.key_id,
                "range": self.range, "Q": g.hex(self.public.X), "Q2": self._q2_raw.hex(),
                **({"mac": self._mac} if self._mac else {})}

    def save_bundle(self, path: str) -> None:
        from torussql.custody.keys import _atomic
        _atomic(path, json.dumps(self.bundle(), indent=1).encode(), 0o644)

    @classmethod
    def from_bundle(cls, bundle: dict, public, custodians, **kw) -> "ThresholdFheKey":
        if not isinstance(bundle, dict) or bundle.get("kind") != BUNDLE_KIND or bundle.get("v") != 1:
            raise FheError("not a threshold FHE bundle")
        if bundle.get("key_id") != public.key_id:
            raise FheError("this bundle belongs to a different custody key")
        g = public.g
        try:
            if not g.eq(g.from_hex(bundle["Q"]), public.X):
                raise FheError("bundle Q does not equal the custody public key")
            q2 = bytes.fromhex(bundle["Q2"])
            rng = int(bundle["range"])
        except (KeyError, ValueError, TypeError) as exc:
            raise FheError(f"malformed threshold FHE bundle ({type(exc).__name__})") from None
        kw.setdefault("value_range", rng)
        return cls(public, custodians, Q2=q2, mac=bundle.get("mac"), **kw)

    @classmethod
    def load(cls, path: str, public, custodians, **kw) -> "ThresholdFheKey":
        with open(path, "rb") as f:
            return cls.from_bundle(json.loads(f.read()), public, custodians, **kw)

    @classmethod
    def create(cls, public, custodians, *, with_mac: bool = True, **kw) -> "ThresholdFheKey":
        """Ceremony step after the DKG: derive Q2 from the custodians and seal a MAC secret."""
        return cls(public, custodians, mac=cls.new_mac(public) if with_mac else None, **kw)

    def __repr__(self) -> str:                      # never print tokens / secrets
        return (f"<ThresholdFheKey {self.public.k}-of-{self.public.n} range={self.range} "
                f"backend={self.be.name} key={self.public.key_id}>")

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
        raw = [bytes(blob[1 + i * GT_BYTES:1 + (i + 1) * GT_BYTES]) for i in range(4)]
        c00, c01, c10, c11 = raw
        try:
            for r in raw:
                _gt.gt_check(r)                  # a hostile server cannot make us query foreign elements
            # round 1: c00^s, c01^s, c10^s      round 2: (c00^s)^s = c00^(s²)
            t00, t01, t10 = self.quorum.shared_gt_powers([c00, c01, c10], _GT_CONTEXT)
            (u00,) = self.quorum.shared_gt_powers([t00], _GT_CONTEXT)
            M = (_gt.gt_decode(c11) * (_gt.gt_decode(t01) ** (N - 1))
                 * (_gt.gt_decode(t10) ** (N - 1)) * _gt.gt_decode(u00))   # inverse in μ_N = ^(N-1)
            Mbe = be.gt_from(_gt.gt_encode(M))
        except (C.CustodyError, _fb.BackendError) as exc:
            if isinstance(exc, C.InsufficientPartials):
                raise
            raise FheError(f"threshold DOT decryption failed: {exc}") from None
        return self._gt_dlog(be, Mbe)
