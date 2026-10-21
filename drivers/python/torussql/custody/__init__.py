# SPDX-License-Identifier: Apache-2.0
"""Threshold key custody (z-MPC style Laurent-series sharing).

The owner's long-lived secret protection key is generated *without a dealer*
and used *without ever being reassembled*: any ``k`` of ``n`` custodians answer
one message each, and the opener combines their verified partial results.

    from torussql.custody import run_local_ceremony, ThresholdCustody, LocalQuorum
"""
from .group import CustodyError, InvalidPoint, get_group
from .keys import KeyShare, PublicKey, ShareError
from .dkg import (Broadcast, DKGError, Dealing, Participant, run_local_ceremony,
                  transcript_hash)
from .threshold import (InsufficientPartials, Partial, combine, partial_decrypt,
                        unwrap_key, verify_partial, wrap_key)
from .reshare import (ReshareSpec, refresh, reshare_deal, reshare_finish,
                      run_local_reshare)
from .quorum import (Custodian, LocalCustodian, LocalQuorum, Quorum, QuorumError,
                     ThresholdCustody)

__all__ = [n for n in dir() if not n.startswith("_")]
