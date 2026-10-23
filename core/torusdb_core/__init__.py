# SPDX-License-Identifier: Apache-2.0
"""torusdb_core — TorusSQL keyless engine over the no-key delegation protocol.

The SQL engine runs the **no-key delegation protocol** (Lee, J1729 Labs):
the server holds NO key material and never decrypts — it processes only
information-theoretically blinded scalars in Z/nZ; the owner (client) holds
the masks and unblinds at its own boundary. See `nokey_engine`.

  - Π_lin   — non-interactive affine evaluation (SUM, AVG, scalar mul)
  - Π_mult  — Beaver-triple masked multiplication (DOT, ct×ct)

The dialect grammar/AST/validation is the open `torussql_parser`; this package
provides the planner (policy/type checks) and the no-key executor. The earlier
trusted-evaluator engine (a key-holding `Database` that decrypted server-side)
has been **removed** — that decrypt-then-re-encrypt structure is exactly what
the no-key protocol eliminates.
"""

from .catalog import Catalog, ColumnSpec, TableSpec
from .errors import ECFHEQueryError, TorusDBError, ExecError, ParseError, PlanError
from .planner import Plan, plan_query
from .parser import parse
from .nokey_engine import NoKeyClient, NoKeyServer, ResultSet

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "NoKeyClient", "NoKeyServer", "ResultSet",
    "Catalog", "ColumnSpec", "TableSpec",
    "parse", "plan_query", "Plan",
    "ECFHEQueryError", "TorusDBError", "ParseError", "PlanError", "ExecError",
]
