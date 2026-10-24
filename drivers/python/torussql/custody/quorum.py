# SPDX-License-Identifier: Apache-2.0
"""Gathering a quorum and exposing the key as a vault custodian."""
from __future__ import annotations

import concurrent.futures as cf
from typing import Protocol

from .group import CustodyError
from .keys import KeyShare, PublicKey
from .threshold import (InsufficientPartials, Partial, combine, partial_decrypt,
                        unwrap_key, verify_partial, wrap_key)


class QuorumError(CustodyError):
    pass


class Custodian(Protocol):
    """Anything that can answer a partial-decryption request."""
    def partial(self, E, context: bytes) -> Partial: ...


class LocalCustodian:
    """A share held in this process (tests, single-host deployments).

    ``approve(caller, E, context) -> bool`` has the SAME signature as the
    network ``Custodian``: ``caller`` is ``"local"`` and ``E`` is the canonical
    hex encoding of the point. It is a service-level rate/human decision, not a
    per-vault policy; ``context`` is informational and authorizes nothing."""

    def __init__(self, share: KeyShare, approve=None):
        self.share = share
        self._approve = approve
        self.requests = 0

    def for_key(self, public) -> "LocalCustodian":
        if public.key_id != self.share.public.key_id:
            raise QuorumError("this custodian holds no share of that key")
        return self

    def partial(self, E, context: bytes = b"") -> Partial:
        g = self.share.public.g
        if self._approve and not self._approve("local", g.hex(E), context):
            raise QuorumError("custodian declined the request")
        self.requests += 1
        return partial_decrypt(self.share, E, context)

    # — batch / pairing-group operations (threshold FHE keys) —
    def partial_batch(self, Es, context: bytes = b"") -> list:
        g = self.share.public.g
        for E in Es:
            if g.is_identity(E):
                raise QuorumError("refusing the identity point")
            if self._approve and not self._approve("local", g.hex(E), context):
                raise QuorumError("custodian declined the request")
        self.requests += len(Es)
        return [partial_decrypt(self.share, E, context) for E in Es]

    def gt_partial_batch(self, cs, context: bytes = b""):
        from . import gt as _gt
        if self._approve:
            for c in cs:
                if not self._approve("local", "gt:" + bytes(c).hex(), context):
                    raise QuorumError("custodian declined the request")
        self.requests += len(cs)
        try:
            return _gt.gt_partial(self.share, list(cs), context)
        except CustodyError as exc:
            raise QuorumError(str(exc)) from None

    def g2_partial(self):
        from . import gt as _gt
        self.requests += 1
        return self.share.index, _gt.g2_partial(self.share)


class Quorum:
    """Ask custodians in parallel, verify every proof, combine the first ``k``
    valid answers. The opener is just another participant — there is no
    aggregator service to trust or to fail."""

    def __init__(self, public: PublicKey, custodians: list, timeout: float = 20.0):
        self.public = public
        self.custodians = list(custodians)
        self.timeout = timeout

    def shared_point(self, E, context: bytes = b""):
        pub = self.public
        valid: dict[int, Partial] = {}
        problems: dict[str, str] = {}
        ex = cf.ThreadPoolExecutor(max_workers=max(1, len(self.custodians)))
        futs = {ex.submit(c.partial, E, context): c for c in self.custodians}
        try:
            for fut in cf.as_completed(futs, timeout=self.timeout):
                c = futs[fut]
                label = getattr(c, "label", repr(c))
                try:
                    part = fut.result()
                    if verify_partial(pub, E, part, context):
                        valid[part.index] = part
                    else:
                        problems[label] = "invalid proof (excluded)"
                except Exception as exc:                               # noqa: BLE001
                    problems[label] = f"{type(exc).__name__}: {exc}"
                if len(valid) >= pub.k:
                    break
        except cf.TimeoutError:
            problems["<timeout>"] = f"only {len(valid)} answered in {self.timeout}s"
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        if len(valid) < pub.k:
            raise InsufficientPartials(pub.k, len(valid), problems)
        return combine(pub, E, list(valid.values()), context, cross_check=False)

    # ── batch operations for threshold FHE keys ──────────────────────────────
    last_problems: dict = {}

    def _collect(self, ask, verify) -> dict:
        """Ask every custodian in parallel; ``verify(answer) -> index`` returns None (or
        raises) for a bad answer. Returns ``{index: answer}`` for the first ``k`` valid
        answers; liars and failures are recorded in ``last_problems``."""
        pub = self.public
        valid: dict = {}
        problems: dict[str, str] = {}
        ex = cf.ThreadPoolExecutor(max_workers=max(1, len(self.custodians)))
        futs = {ex.submit(ask, c): c for c in self.custodians}
        try:
            for fut in cf.as_completed(futs, timeout=self.timeout):
                c = futs[fut]
                label = getattr(c, "label", repr(c))
                try:
                    ans = fut.result()
                    idx = verify(ans)
                    if idx is None:
                        problems[label] = "invalid proof (excluded)"
                    else:
                        valid[idx] = ans
                except Exception as exc:                               # noqa: BLE001
                    problems[label] = f"{type(exc).__name__}: {exc}"
                if len(valid) >= pub.k:
                    break
        except cf.TimeoutError:
            problems["<timeout>"] = f"only {len(valid)} answered in {self.timeout}s"
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        self.last_problems = problems
        if len(valid) < pub.k:
            raise InsufficientPartials(pub.k, len(valid), problems)
        return valid

    def shared_points(self, Es: list, context: bytes = b"") -> list:
        """``[x·E for E in Es]`` in ONE round: every custodian answers the whole batch
        and is excluded entirely if any of its proofs fails."""
        from . import laurent
        pub = self.public
        g = pub.g
        if not Es:
            return []

        def ask(c):
            fn = getattr(c, "partial_batch", None)
            if fn is not None:
                return fn(Es, context)
            return [c.partial(E, context) for E in Es]

        def verify(parts):
            if len(parts) != len(Es) or len({p.index for p in parts}) != 1:
                return None
            if not all(verify_partial(pub, E, p, context) for E, p in zip(Es, parts)):
                return None
            return parts[0].index

        valid = self._collect(ask, verify)
        order = sorted(valid)[:pub.k]
        lam = laurent.lambdas(order, g.order)
        return [g.msm((lam[i], valid[i][j].D) for i in order) for j in range(len(Es))]

    def shared_gt_powers(self, cs: list, context: bytes = b"") -> list:
        """``[c^x for c in cs]`` for GT elements (canonical 384-byte encodings) in one
        round, with GT Chaum-Pedersen proofs (see ``custody.gt``). Callers needing
        ``c^(x^2)`` apply it twice (two sequential rounds): the exponent is never formed."""
        from . import gt as _gt
        pub = self.public
        _gt.need_bn254(pub)
        if not cs:
            return []
        cs = [bytes(c) for c in cs]
        decoded = [_gt.gt_check(c) for c in cs]                 # refuse foreign elements early
        out: list = []
        for lo in range(0, len(cs), _gt.MAX_GT_BATCH):
            chunk = cs[lo:lo + _gt.MAX_GT_BATCH]
            dec = decoded[lo:lo + _gt.MAX_GT_BATCH]

            def ask(c, chunk=chunk):
                fn = getattr(c, "gt_partial_batch", None)
                if fn is None:
                    raise QuorumError("this custodian does not support GT operations")
                return fn(chunk, context)

            def verify(parts, chunk=chunk, dec=dec):
                if len(parts) != len(chunk) or len({p.index for p in parts}) != 1:
                    return None
                if not all(_gt.verify_gt_partial(pub, craw, p, context, c=c)
                           for craw, c, p in zip(chunk, dec, parts)):
                    return None
                return parts[0].index

            valid = self._collect(ask, verify)
            out += [_gt.combine_gt(pub, {i: pl[j].D for i, pl in valid.items()})
                    for j in range(len(chunk))]
        return out

    def shared_g2(self) -> bytes:
        """``Q2 = x*G2`` (x = the secret THIS quorum serves; for FHE columns the second
        secret s2) assembled from the custodians' pairing-verified G2 shares (the
        result is also checked against the public key ``X`` by a pairing)."""
        from . import gt as _gt
        pub = self.public
        _gt.need_bn254(pub)

        def ask(c):
            fn = getattr(c, "g2_partial", None)
            if fn is None:
                raise QuorumError("this custodian does not support G2 shares")
            return fn()

        def verify(ans):
            idx, raw = ans
            _gt.verify_g2_share(pub, int(idx), bytes(raw))
            return int(idx)

        valid = self._collect(ask, verify)
        return _gt.combine_g2(pub, {i: bytes(a[1]) for i, a in valid.items()})


LocalQuorum = Quorum          # alias: a Quorum over LocalCustodians


class ThresholdCustody:
    """Adapter used by the vault: wraps keys with the PUBLIC key; opens them
    with a quorum of custodians."""

    def __init__(self, public: PublicKey, quorum: Quorum | None = None):
        self.public = public
        self.quorum = quorum

    def wrap(self, context: bytes) -> tuple[int, dict]:
        return wrap_key(self.public, context)

    def unwrap(self, header: dict) -> int:
        if self.quorum is None:
            raise QuorumError("opening requires a quorum of custodians "
                              "(this handle only has the public key)")
        return unwrap_key(self.public, header, self.quorum.shared_point)
