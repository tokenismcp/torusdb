# SPDX-License-Identifier: Apache-2.0
"""Root test bootstrap: make the source tree importable without installing.

Order matters little because installed packages are appended-after: the open
packages (parser, driver, server) come from this checkout; the engine comes
from an installed ``ec-fhe-query`` or $TORUSDB_ENGINE_DIR, else the sibling
folders of a monorepo checkout.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_paths = [HERE / "parser", HERE / "drivers" / "python", HERE / "server",
          HERE / "proto"]
_roots = [Path(os.environ["TORUSDB_ENGINE_DIR"])] \
    if os.environ.get("TORUSDB_ENGINE_DIR") else []
_roots += list(HERE.parents)[:4]
for r in _roots:
    _paths += [r / "ec_fhe_query", r / "ec_fhe_engine"]
for p in _paths:
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
