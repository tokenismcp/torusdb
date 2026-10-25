# SPDX-License-Identifier: Apache-2.0
"""Custodian-side storage of the owner's integrity anchor (see ``torusdb_core.fhe_anchor``).

Each custodian keeps, per *anchor id*, one versioned register ``(seq, value)`` where ``value`` is the
owner's whole anchor document (canonical JSON text; the custodian does not interpret it). The register is
a compare-and-swap cell: ``cas(aid, expect_seq, value)`` succeeds only if the current ``seq`` equals
``expect_seq`` and then stores ``seq + 1``. ``repair`` lets a client bring a lagging copy forward (never
backwards). Durability: an append-only checksummed ``RecordLog`` (fsync per write, torn tail dropped,
corruption refuses to load); optionally sealed with a passphrase.

The values are not secret, but their integrity is the point: writing needs the ``anchor`` permission,
reading ``anchor`` or ``anchor_read`` — separate from the key-share and mask permissions. One custodian
alone is not trusted: ``QuorumAnchor`` (custody/anchor.py) only believes what k custodians agree on.
"""
from __future__ import annotations

import threading

from ..recordlog import RecordLog
from .group import CustodyError

MAX_VALUE = 4 << 20
MAX_ID = 128
MAX_IDS = 1000


class AnchorStore:
    def __init__(self, path: str | None = None, passphrase: str | None = None,
                 fsync: str = "always"):
        self._lock = threading.RLock()
        self._reg: dict[str, tuple[int, str]] = {}
        self._log: RecordLog | None = None
        if path:
            self._log = RecordLog(path, b"TORUSANCHOR1", passphrase, fsync)
            for rec in self._log.open():
                self._reg[rec["a"]] = (int(rec["s"]), rec["v"])

    @staticmethod
    def _check(aid, value=None, check_value=False) -> None:
        if not isinstance(aid, str) or not 0 < len(aid) <= MAX_ID:
            raise CustodyError("anchor id must be a short non-empty string")
        if check_value and (not isinstance(value, str) or len(value) > MAX_VALUE):
            raise CustodyError("anchor value must be a string of at most 4 MiB")

    def _put(self, aid: str, seq: int, value: str) -> None:
        if aid not in self._reg and len(self._reg) >= MAX_IDS:
            raise CustodyError("too many anchor ids on this custodian")
        if self._log is not None:
            self._log.append({"a": aid, "s": seq, "v": value})      # raises -> state unchanged
        self._reg[aid] = (seq, value)
        if self._log is not None and self._log.records > 1000 + 8 * len(self._reg):
            self._log.rewrite({"a": a, "s": s, "v": v} for a, (s, v) in self._reg.items())

    def get(self, aid: str) -> tuple[int, str | None]:
        self._check(aid)
        with self._lock:
            return self._reg.get(aid, (0, None))

    def cas(self, aid: str, expect_seq: int, value: str) -> tuple[bool, int, str | None]:
        """-> (ok, current seq, current value). Re-sending a write that already landed is ok."""
        self._check(aid, value, True)
        if isinstance(expect_seq, bool) or not isinstance(expect_seq, int) or expect_seq < 0:
            raise CustodyError("expect_seq must be a non-negative integer")
        with self._lock:
            seq, cur = self._reg.get(aid, (0, None))
            if seq == expect_seq + 1 and cur == value:
                return True, seq, cur
            if seq != expect_seq:
                return False, seq, cur
            self._put(aid, seq + 1, value)
            return True, seq + 1, value

    def repair(self, aid: str, seq: int, value: str) -> bool:
        """Install ``(seq, value)`` if it is newer than this copy, or the same version with different
        content (a divergent partial write). Never moves a copy backwards."""
        self._check(aid, value, True)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise CustodyError("seq must be a positive integer")
        with self._lock:
            cur_seq, cur = self._reg.get(aid, (0, None))
            if seq < cur_seq or (seq == cur_seq and value == cur):
                return False
            self._put(aid, seq, value)
            return True

    def stats(self) -> dict:
        with self._lock:
            return {"anchors": len(self._reg), "log_records": self._log.records if self._log else 0}

    def close(self) -> None:
        if self._log is not None:
            self._log.close()
