# SPDX-License-Identifier: Apache-2.0
"""Root test bootstrap: make the source tree importable without installing."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE / "core", HERE / "parser", HERE / "drivers" / "python",
           HERE / "server", HERE / "proto"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
