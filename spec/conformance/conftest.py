# SPDX-License-Identifier: Apache-2.0
"""Conformance-suite fixtures.

The suite runs against the **no-key delegation engine** — the real engine,
whose server holds no keys and never decrypts. Everything goes through the
`engine` seam's `.run(sql)`, so a different conformant engine can be swapped in
by changing only this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
for _pkg in ("core", "parser"):
    _p = _REPO / _pkg
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from torusdb_core.errors import ParseError, PlanError       # noqa: E402
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer  # noqa: E402


class EngineSeam:
    """Thin adapter over a TorusDB engine. The conformance suite uses only
    this surface. Bound here to the no-key engine: a keyless `NoKeyServer`
    plus an owner-side `NoKeyClient` holding the masks."""

    PARSE = ParseError      # → wire ErrorKind PARSE
    POLICY = PlanError      # → wire ErrorKind POLICY

    def __init__(self):
        self._client = NoKeyClient(NoKeyServer())

    def run(self, sql: str):
        return self._client.execute(sql)

    def rows(self, sql: str):
        return self.run(sql).rows


@pytest.fixture
def engine() -> EngineSeam:
    return EngineSeam()
