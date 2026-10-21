# SPDX-License-Identifier: Apache-2.0
"""Proactive refresh and membership change — the key and its public key stay
the same; every share is replaced.

A quorum S of current holders each *re-share* the one value they own, the
Lagrange-weighted share ``λᵢ·yᵢ``, with a fresh Laurent series (any new k′, n′):

    dealer i ∈ S :  sharing of λᵢ·yᵢ with commitments C′ᵢ, broadcast + private shares s′ᵢ→j
    new holder j :  checks  C′ᵢ1 = λᵢ·Yᵢ   (public — proves the dealer re-shared
                    its true share), checks s′ᵢ→j against C′ᵢ, then
                        y′ⱼ = Σ_{i∈S} s′ᵢ→j ,   C̄′m = Σ_{i∈S} C′ᵢm

and finally X′ = Σ C′ᵢ1 must equal the old X. The secret x is never assembled:
the new residue is Σ λᵢ yᵢ = x only *inside* the new sharing.

Use it to (a) refresh on a schedule so an attacker must break k custodians
within one epoch, (b) replace a lost/compromised custodian, (c) change k or n.
Old shares become useless against the new epoch, but note nothing can force a
custodian to *erase* its old share — a share stolen earlier is only neutralised
if the attacker never reached k of the same epoch.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import laurent
from .dkg import Broadcast, DKGError, Dealing, check_dealing, deal
from .group import CustodyError, get_group
from .keys import KeyShare, PublicKey


@dataclass
class ReshareSpec:
    old: PublicKey
    quorum: tuple          # indices of the old holders that deal (exactly old.k)
    new_k: int
    new_n: int
    session: bytes

    def __post_init__(self) -> None:
        if len(set(self.quorum)) != self.old.k or any(not 1 <= i <= self.old.n for i in self.quorum):
            raise CustodyError(f"resharing needs exactly {self.old.k} distinct current holders")
        laurent.Params(self.new_k, self.new_n, self.old.g.order)      # validates

    @property
    def new_params(self) -> laurent.Params:
        return laurent.Params(self.new_k, self.new_n, self.old.g.order)

    def lam(self) -> dict[int, int]:
        return laurent.lambdas(sorted(self.quorum), self.old.g.order)


def reshare_deal(spec: ReshareSpec, share: KeyShare) -> Dealing:
    """Old holder: re-share λᵢ·yᵢ to the new committee."""
    g = spec.old.g
    if share.index not in spec.quorum:
        raise CustodyError("this holder is not in the dealing quorum")
    if not share.verify():
        raise CustodyError("local share does not match the public commitments")
    secret = spec.lam()[share.index] * share.y % g.order
    return deal(g, spec.new_params, share.index, secret, spec.session, with_pok=False)


def reshare_finish(spec: ReshareSpec, my_index: int, broadcasts: dict[int, Broadcast],
                   shares_in: dict[int, int]) -> tuple[KeyShare, PublicKey]:
    """New holder ``my_index`` (1..new_n): combine the dealings into its share."""
    g = spec.old.g
    p = spec.new_params
    if set(broadcasts) != set(spec.quorum) or set(shares_in) != set(spec.quorum):
        raise DKGError("need a dealing from every member of the quorum")
    lam = spec.lam()
    for i in spec.quorum:
        b = broadcasts[i]
        if not g.eq(b.commitments[1], g.mul(spec.old.verification_key(i), lam[i])):
            raise DKGError("dealer did not re-share its true share", i)
        check_dealing(g, p, b, my_index, shares_in[i] % g.order, spec.session, need_pok=False)
    y = sum(shares_in.values()) % g.order
    agg = tuple(g.msm((1, broadcasts[i].commitments[m]) for i in spec.quorum)
                for m in range(p.k))
    new = PublicKey(g.name, p.k, p.n, agg, spec.old.epoch + 1)
    if not g.eq(new.X, spec.old.X):
        raise DKGError("resharing would change the public key — aborting")
    ks = KeyShare(my_index, y, new)
    if not ks.verify():                                          # pragma: no cover
        raise DKGError("new share failed verification")
    return ks, new


def run_local_reshare(shares: list[KeyShare], quorum: list[int], new_k: int, new_n: int
                      ) -> tuple[list[KeyShare], PublicKey]:
    """Single-process resharing (tests/dev), same messages as the real protocol."""
    import secrets
    old = shares[0].public
    spec = ReshareSpec(old, tuple(quorum), new_k, new_n, secrets.token_bytes(16))
    by_index = {s.index: s for s in shares}
    dealings = {i: reshare_deal(spec, by_index[i]) for i in quorum}
    bc = {i: d.broadcast for i, d in dealings.items()}
    out, pub = [], None
    for j in range(1, new_n + 1):
        ks, pub = reshare_finish(spec, j, bc, {i: dealings[i].shares[j] for i in quorum})
        out.append(ks)
    return out, pub


def refresh(shares: list[KeyShare], quorum: list[int] | None = None
            ) -> tuple[list[KeyShare], PublicKey]:
    """Same committee, fresh shares (proactive refresh)."""
    old = shares[0].public
    q = quorum or sorted(s.index for s in shares)[:old.k]
    return run_local_reshare(shares, q, old.k, old.n)
