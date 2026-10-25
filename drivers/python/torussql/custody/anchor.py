# SPDX-License-Identifier: Apache-2.0
"""``QuorumAnchor``: the owner's integrity anchor replicated over n custodians (no single store to lose).

The whole anchor document (every table's ``{epoch, root, count, pending, history}``, encoded exactly like
a ``FileAnchor`` file) is one versioned register on each custodian (``custody/anchorstore.py``).

* **Read** (every ``get``): ask all custodians; the value is the one with the **highest ``seq`` that at least
  ``threshold`` (k) custodians report identically**. Answers that deviate (a lower or higher ``seq``, a
  different value) are never believed on their own — a liar, or a custodian that was rolled back, is
  outvoted as long as fewer than k custodians do the same. Lagging copies are repaired (``anchor_repair``).
  Fewer than k answers, or no value with k matching copies, is a hard failure (``AnchorQuorumError``):
  nothing is accepted.
* **Write** (compare-and-swap on the register ``seq``): sent to all custodians; it counts as done only when
  at least ``write_quorum`` (W) accept. Otherwise the call fails (a lost race against another owner is
  re-read and retried; unreachable custodians raise ``AnchorQuorumError``) and the owner does not commit.
  Two owners racing are serialised by the per-custodian CAS; at most one reaches W.
* The ``Anchor`` semantics on top (epoch compare-and-swap, ``pending``, history) are the very same code as
  ``FileAnchor`` (``_StateAnchor``), so the commit and crash-settlement flow is identical.

Parameters must satisfy ``k <= W <= n`` and ``n - W < k``: then a committed value (W copies) cannot be
outvoted by an older one (at most n - W < k stale copies exist). Defaults: ``W = max(k, n - k + 1)``.

Conditions for the guarantees (also in docs/fhe-columns.md): at least k custodians are honest and
reachable AND hold the latest value; at most k - 1 custodians lie, are rolled back or are compromised.
Unavailability fails closed (the owner cannot commit); it never yields a wrong state.
"""
from __future__ import annotations

import json
import random
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from torusdb_core.errors import ExecError
from torusdb_core.fhe_anchor import (FORMAT, FORMAT_VERSION, AnchorConflict, AnchorFileError,
                                     AnchorQuorumError, _dec_entry, _enc_entry, _StateAnchor)

MAX_VALUE = 4 << 20


def _dumps(state: dict) -> str:
    return json.dumps({"format": FORMAT, "v": FORMAT_VERSION,
                       "tables": {t: _enc_entry(e) for t, e in sorted(state.items())}},
                      sort_keys=True, separators=(",", ":"))


def _loads(text: str | None) -> dict:
    if text is None:
        return {}
    try:
        doc = json.loads(text)
        if doc.get("format") != FORMAT or doc.get("v") != FORMAT_VERSION:
            raise ValueError("not an anchor document of this version")
        return {t: _dec_entry(e) for t, e in doc["tables"].items()}
    except AnchorFileError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise AnchorFileError(f"the quorum's anchor value is malformed ({exc})") from None


class QuorumAnchor(_StateAnchor):
    def __init__(self, nodes, *, threshold: int, write_quorum: int | None = None,
                 anchor_id: str = "default", retries: int = 6):
        self.nodes = list(nodes)
        n, k = len(self.nodes), int(threshold)
        w = int(write_quorum) if write_quorum is not None else max(k, n - k + 1)
        if not 1 <= k <= n:
            raise ExecError(f"threshold must be in [1, {n}]")
        if not k <= w <= n:
            raise ExecError(f"write_quorum must be in [{k}, {n}]")
        if n - w >= k:
            raise ExecError(f"n - write_quorum ({n - w}) must be < threshold ({k}): otherwise an older "
                            f"value could gather {k} matching copies next to a committed newer one")
        if not isinstance(anchor_id, str) or not 0 < len(anchor_id) <= 128:
            raise ExecError("anchor_id must be a short non-empty string")
        self.n, self.k, self.w, self.aid, self.retries = n, k, w, anchor_id, int(retries)
        self.problems: list[str] = []              # what the last operations saw (liars, stale, unreachable)
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=max(1, n), thread_name_prefix="anchor-quorum")

    def __repr__(self) -> str:
        return f"<QuorumAnchor {self.k}-of-{self.n} W={self.w} id={self.aid!r}>"

    def close(self) -> None:
        self._pool.shutdown(wait=False)

    # — plumbing —
    def _fan(self, method: str, args: list):
        def one(node):
            try:
                return node, node.call(method, args), None
            except Exception as exc:                                     # noqa: BLE001
                return node, None, exc
        return list(self._pool.map(one, self.nodes))

    @staticmethod
    def _label(node) -> str:
        return getattr(node, "label", repr(node))

    def _read(self):
        """-> (seq, raw value or None, state). Raises AnchorQuorumError without k matching answers."""
        problems: list[str] = []
        good = []
        for node, r, exc in self._fan("anchor_get", [self.aid]):
            if exc is not None:
                problems.append(f"{self._label(node)}: unreachable ({exc})")
                continue
            try:
                s, v = r["s"], r["v"]
                if (isinstance(s, bool) or not isinstance(s, int) or s < 0
                        or not (v is None or (isinstance(v, str) and len(v) <= MAX_VALUE))
                        or (s == 0) != (v is None)):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                problems.append(f"{self._label(node)}: malformed answer")
                continue
            good.append((node, s, v))
        self.problems = problems
        if len(good) < self.k:
            raise AnchorQuorumError(
                f"only {len(good)} of {self.n} anchor custodians answered; {self.k} are required "
                f"({'; '.join(problems) or 'no detail'})")
        votes = Counter((s, v) for _n, s, v in good)
        winners = [key for key, c in votes.items() if c >= self.k]
        if not winners:
            raise AnchorQuorumError(
                f"no anchor value is reported identically by {self.k} custodians (answers: "
                f"{sorted(((s, c) for (s, _v), c in votes.items()), reverse=True)}); refusing — a "
                f"partial write, rolled-back or lying custodians; nothing was accepted")
        top = max(s for s, _v in winners)
        tops = [key for key in winners if key[0] == top]
        if len(tops) > 1:
            raise AnchorQuorumError("two different anchor values have a quorum at the same version")
        seq, val = tops[0]
        for node, s, v in good:
            if (s, v) != (seq, val):
                problems.append(f"{self._label(node)}: " + (
                    f"reports version {s}, quorum is {seq}" if s != seq else "differs at the quorum version"))
        stale = [node for node, s, v in good if (s, v) != (seq, val) and s <= seq]
        if stale and val is not None:
            self._repair(stale, seq, val)
        return seq, val, _loads(val)

    def _repair(self, nodes, seq: int, val: str) -> None:
        for node in nodes:
            try:
                node.call("anchor_repair", [self.aid, seq, val])
            except Exception:                                            # noqa: BLE001
                pass                                                     # read-only token, or down: fine

    def _write(self, seq: int, old_raw: str | None, new_state: dict) -> bool:
        new_raw = _dumps(new_state)
        if len(new_raw) > MAX_VALUE:
            raise AnchorQuorumError("the anchor document is too large")
        acked, conflicts, errors = [], 0, []
        for attempt in (0, 1):                      # one retry for lost replies: the CAS is idempotent
            pending = [nd for nd in self.nodes if nd not in acked and (attempt == 0 or nd in errors)]
            errors = []
            for node, r, exc in self._fan_nodes(pending, "anchor_cas", [self.aid, seq, new_raw]):
                if exc is not None:
                    errors.append(node)
                elif isinstance(r, dict) and r.get("ok") is True:
                    acked.append(node)
                else:
                    conflicts += 1
            if len(acked) >= self.w or not errors:
                break
        if len(acked) >= self.w:
            return True
        # Not durable. The copies we did write are left as they are (they sit at the same version as any
        # winning write and are repaired over by it; lowering them could erase a concurrent committed write).
        # If the write nevertheless landed on W nodes (lost replies), the commit protocol settles it: the
        # owner never sends tx_commit, so the next scan finds the OLD state and aborts the pending record.
        if conflicts:
            return False                            # another owner won: the caller re-reads and retries
        raise AnchorQuorumError(
            f"the anchor write reached only {len(acked)} of the {self.w} custodians it needs "
            f"({self.n - len(acked) - conflicts} unreachable); nothing was committed")

    def _fan_nodes(self, nodes, method, args):
        if not nodes:
            return []

        def one(node):
            try:
                return node, node.call(method, args), None
            except Exception as exc:                                     # noqa: BLE001
                return node, None, exc
        return list(self._pool.map(one, nodes))

    # — _StateAnchor hook —
    def _atomic(self, fn, write=True):
        with self._lock:
            for attempt in range(self.retries):
                seq, raw, state = self._read()
                work = dict(state)
                out = fn(work)
                if not write or work == state:
                    return out
                if self._write(seq, raw, work):
                    return out
                time.sleep(random.uniform(0, 0.02 * (attempt + 1)))      # lost a race: re-read, re-check
            raise AnchorConflict("anchor: lost the compare-and-swap race too many times (contention)")
