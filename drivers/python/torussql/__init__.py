# SPDX-License-Identifier: Apache-2.0
"""torussql — PEP 249 DB-API 2.0 client driver for TorusDB.

The driver speaks the **no-key delegation protocol**: it connects to a keyless
server, holds the mask vault locally (the data owner's secret state), blinds on
INSERT, and unblinds + decodes results — the server never holds a key and never
decrypts.

PEP 249 usage:

    import torussql
    conn = torussql.connect("127.0.0.1", 8533)
    cur = conn.cursor()
    cur.execute("INSERT INTO t (id, v) VALUES (%s, FRAC(%s,1))", (1, 8000))
    cur.execute("SELECT SUM(v) FROM t")
    row = cur.fetchone()   # (Fraction(8000, 1),)
    conn.close()

TLS:

    conn = torussql.connect("db.example.com", 8533,
                            tls=True, cafile="/etc/torusdb/ca.pem")
"""
from __future__ import annotations

# The driver proper needs the TorusDB engine package; the key-custody tools
# (``torussql.custody``) and the wire codec do not. Driver names are therefore
# imported lazily, so a custodian host can run without the engine installed.
_DRIVER_NAMES = frozenset({
    "Connection", "Cursor", "Warning", "Error", "InterfaceError", "DatabaseError",
    "DataError", "OperationalError", "IntegrityError", "InternalError",
    "ProgrammingError", "NotSupportedError", "NoKeyError", "AuthenticationError",
    "ServerBusyError", "TransactionInDoubt", "ConnectionLost", "connect",
})


def __getattr__(name: str):
    if name in _DRIVER_NAMES:
        from . import nokey
        value = getattr(nokey, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module 'torussql' has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | _DRIVER_NAMES)


# ── PEP 249 §3 module-level attributes ───────────────────────────────────────

apilevel     = "2.0"     # supports DB-API 2.0
threadsafety = 2         # threads may share the module and connections (statements are serialized)
paramstyle   = "format"  # %s positional substitution

__version__ = "0.6.2"

__all__ = [
    "connect", "Connection", "Cursor",
    "apilevel", "threadsafety", "paramstyle",
    "Warning", "Error", "InterfaceError", "DatabaseError",
    "DataError", "OperationalError", "IntegrityError",
    "InternalError", "ProgrammingError", "NotSupportedError",
    "NoKeyError", "AuthenticationError", "ServerBusyError",
    "TransactionInDoubt", "ConnectionLost",
]
