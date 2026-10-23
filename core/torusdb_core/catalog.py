# SPDX-License-Identifier: Apache-2.0
"""Catalog: schema with per-column encryption policy.

Policies expose what ECHC permits at the column level:

    plain      — native Python; supports any op including equality WHERE
    encrypted  — Ciphertext under EC_FHE Alg 9; supports SUM (Def 4.4)
                 and scalar*col (Q_E · int). Two encrypted columns can
                 be multiplied via ★_ct (LSL24 Thm 8) yielding either
                 a single ciphertext (if you bootstrap back to G1) or a
                 GT ciphertext (if you stay in pairing target).
    paired     — PairedCiphertext: same plaintext encoded in both G1
                 and G2 sides. Required as input for ★_ct. Columns
                 declared `paired` are encrypted twice but enable native
                 ciphertext × ciphertext multiplication without lifting.

The cost trade is explicit: paired columns are 2× storage but enable
formal ★_ct on demand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Policy = Literal["plain", "encrypted", "paired", "fhe"]
ColumnType = Literal["int", "str", "rational"]


@dataclass(frozen=True)
class ColumnSpec:
    name: str
    type: ColumnType
    policy: Policy


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: tuple[ColumnSpec, ...]

    def column(self, name: str) -> ColumnSpec:
        for c in self.columns:
            if c.name == name:
                return c
        raise KeyError(name)

    def has(self, name: str) -> bool:
        return any(c.name == name for c in self.columns)


@dataclass
class Catalog:
    tables: dict[str, TableSpec] = field(default_factory=dict)

    def create(self, spec: TableSpec) -> None:
        if spec.name in self.tables:
            raise ValueError(f"table {spec.name!r} already exists")
        if not spec.columns:
            raise ValueError("a table must declare at least one column")
        seen: set[str] = set()
        for c in spec.columns:
            if c.name.startswith("__"):
                raise ValueError(f"column names starting with '__' are reserved ({c.name!r})")
            if c.name in seen:
                raise ValueError(f"duplicate column {c.name!r}")
            seen.add(c.name)
            if c.policy not in ("plain", "encrypted", "paired", "fhe"):
                raise ValueError(f"bad policy {c.policy!r} on {c.name}")
            if c.policy == "fhe" and c.type != "int":
                raise ValueError(f"FHE columns must be INT (column {c.name!r})")
            if c.policy != "plain" and c.type == "str":
                raise ValueError(f"string columns must be plain (column {c.name!r})")
        self.tables[spec.name] = spec

    def drop(self, name: str) -> None:
        if name not in self.tables:
            raise KeyError(name)
        del self.tables[name]

    def get(self, name: str) -> TableSpec:
        return self.tables[name]
