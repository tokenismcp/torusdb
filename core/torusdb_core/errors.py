# SPDX-License-Identifier: Apache-2.0
class TorusDBError(Exception):
    """Base class for all errors raised by ec_fhe_query."""


class ParseError(TorusDBError):
    """SQL parsing failed."""


class PlanError(TorusDBError):
    """Planner rejected the query (type mismatch, unsupported op, ...)."""


class ExecError(TorusDBError):
    """Runtime failure during query execution."""


class IntegrityError(TorusDBError):
    """A result failed its information-theoretic MAC check — the server
    returned a forged/incorrect value (no-key paper §IX)."""


ECFHEQueryError = TorusDBError          # legacy alias
