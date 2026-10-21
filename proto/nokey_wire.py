# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim: the no-key wire codec now lives in the driver package
(``torussql.nokey_wire``) so that a pip-installed driver is self-contained."""
from torussql.nokey_wire import *                    # noqa: F401,F403
from torussql.nokey_wire import (                    # noqa: F401
    match_wire, uwv, wv, where_to_wire,
)
