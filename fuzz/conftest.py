# SPDX-License-Identifier: Apache-2.0
"""Path bootstrap for the fuzz suite."""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for _rel in ("core", "proto", "parser", "server", "drivers/python"):
    _p = _REPO / _rel
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
