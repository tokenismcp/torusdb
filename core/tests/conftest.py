# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "core", ROOT / "parser"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
