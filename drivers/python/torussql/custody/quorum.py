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
    """A share held in this process (tests, single-host deployments)."""

    def __init__(self, share: KeyShare, approve=None):
        self.share = share
        self._approve = approve
        self.requests = 0

    def partial(self, E, context: bytes = b"") -> Partial:
        if self._approve and not self._approve(E, context):
            raise QuorumError("custodian declined the request")
        self.requests += 1
        return partial_decrypt(self.share, E, context)


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
