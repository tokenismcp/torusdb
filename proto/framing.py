# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim: the wire framing now lives in the driver package
(``torussql.framing``) so that a pip-installed driver is self-contained."""
from torussql.framing import *                       # noqa: F401,F403
from torussql.framing import MAX_FRAME, read_frame, write_frame   # noqa: F401
