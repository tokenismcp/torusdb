# SPDX-License-Identifier: Apache-2.0
"""Where the data owner's masks live.

Every encrypted cell on the server is ``encode(v) + r (mod n)``; the mask ``r``
is the only thing that makes it readable, so *where masks live* decides who can
read the database. The client engine is written against this small interface:

* ``DictMaskStore`` (default) keeps masks in the owner process — the classic
  "mask vault" (optionally persisted by the driver's vault log).
* ``torussql.custody.masks.ThresholdMaskStore`` secret-shares every mask among
  ``n`` custodians (k-of-n): no single process, host or administrator holds the
  vault, and an aggregate is unblinded by combining *partial sums* so individual
  masks are not even revealed to the querier.

The contract that makes crash-safety possible without two-phase commit:

    stage_*   persist the new masks BEFORE the server row/cell exists;
    commit_*  called after the server accepted the write.

A crash between the two leaves harmless *orphan masks*, never a server cell
without its mask (which would be unreadable forever).
"""
from __future__ import annotations

from typing import Any

from .errors import ExecError


class MaskStore:
    """Interface + documentation. Mask keys are ``(table, rowid, col)``; MAC
    masks use the column name ``__mac__<col>``."""

    #: True when masks live in this process (vault export/import applies).
    local = False

    def bind(self, client) -> None:                     # noqa: D401
        """Called once with the owning NoKeyClient."""
        self.client = client

    def config(self) -> dict | None:
        """Cluster-wide settings shared by every client of a mask cluster:
        ``{"authenticated": bool, "alpha": int}`` or None (client decides)."""
        return None

    # — writes —
    def stage_insert(self, table: str, rows_masks: list[dict]) -> list[dict]:
        """Persist the masks of rows about to be inserted. Returns, per row,
        extra plaintext fields the server row must carry (hidden columns)."""
        raise NotImplementedError

    def commit_insert(self, table: str, rowids: list[int], rows_masks: list[dict],
                      extras: list[dict]) -> None:
        raise NotImplementedError

    def stage_update(self, table: str, items: list[tuple[int, dict]]) -> list[dict]:
        """``items`` = [(rowid, {col: new_mask})]. Returns per-item extra cell
        updates (``{hidden_col: value}``) to apply together with the new cells."""
        raise NotImplementedError

    def commit_update(self, table: str, items: list[tuple[int, dict]],
                      extras: list[dict]) -> None:
        raise NotImplementedError

    # — reads —
    def get(self, table: str, col: str, rowids: list[int]) -> list[int]:
        """The mask of each cell (reveals them to the caller)."""
        raise NotImplementedError

    def sum(self, table: str, col: str, rowids: list[int]) -> int:
        """Σ masks mod n over ``rowids`` (repeats count). Implementations may
        compute this without revealing any individual mask."""
        raise NotImplementedError

    def available(self, table: str, col: str, rowids: list[int]) -> list[bool]:
        """Whether each cell's mask can be recovered (orphan detection)."""
        raise NotImplementedError

    def forget_table(self, table: str) -> None:
        raise NotImplementedError


class DictMaskStore(MaskStore):
    """Masks held in the owner process (``client._masks``)."""

    local = True

    def bind(self, client) -> None:
        self.client = client

    @property
    def _m(self) -> dict:
        return self.client._masks            # looked up dynamically: the driver's
                                             # vault log swaps in a logging dict

    def stage_insert(self, table, rows_masks):
        return [{} for _ in rows_masks]

    def commit_insert(self, table, rowids, rows_masks, extras):
        m = self._m
        for rid, masks in zip(rowids, rows_masks):
            for col, r in masks.items():
                m[(table, rid, col)] = r

    def stage_update(self, table, items):
        return [{} for _ in items]

    def commit_update(self, table, items, extras):
        m = self._m
        for rid, masks in items:
            for col, r in masks.items():
                m[(table, rid, col)] = r

    def _one(self, table: str, rowid: int, col: str) -> int:
        try:
            return self._m[(table, rowid, col)]
        except KeyError:
            raise ExecError(
                f"this vault has no mask for {table}.{col} row {rowid} — the "
                f"row was written by a different vault (or an interrupted "
                f"write); it cannot be decrypted here") from None

    def get(self, table, col, rowids):
        return [self._one(table, i, col) for i in rowids]

    def sum(self, table, col, rowids):
        from .protocol import N
        return sum(self._one(table, i, col) for i in rowids) % N

    def available(self, table, col, rowids):
        m = self._m
        return [(table, i, col) in m for i in rowids]

    def forget_table(self, table):
        m = self._m
        for k in [k for k in m if k[0] == table]:
            del m[k]
