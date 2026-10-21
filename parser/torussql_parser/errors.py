# SPDX-License-Identifier: Apache-2.0
"""TorusSQL parser/validator errors.

These are the open, engine-free errors. They correspond to the wire
protocol's ErrorKind values (torussql.proto): ParseError → PARSE,
ValidationError → POLICY/UNSUPPORTED.
"""
from __future__ import annotations


class TorusSQLError(Exception):
    """Base for all TorusSQL parsing/validation errors."""


class ParseError(TorusSQLError):
    """The statement does not parse under the dialect grammar (wire: PARSE)."""


class ValidationError(TorusSQLError):
    """The statement parses but violates a policy/type/capability rule
    (wire: POLICY or UNSUPPORTED)."""
