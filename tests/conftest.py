# SPDX-License-Identifier: Apache-2.0
"""Path bootstrap for the end-to-end suite: server, driver, proto, engine."""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
for _rel in ("ec_fhe_query", "ec_fhe_engine",
             "torussql/proto", "torussql/server", "torussql/drivers/python"):
    _p = _REPO / _rel
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
