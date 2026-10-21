# SPDX-License-Identifier: Apache-2.0
"""No-key TorusDB client driver — PEP 249 DB-API 2.0 compliant.

Connects to a keyless no-key server and drives the no-key delegation protocol.
The mask vault lives HERE (the data owner), never on the server.

PEP 249 usage:

    import torussql
    conn = torussql.connect("127.0.0.1", 8533)
    cur = conn.cursor()
    cur.execute("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
    cur.execute("INSERT INTO t (id, v) VALUES (%s, FRAC(%s,1))", (1, 8000))
    cur.execute("SELECT SUM(v) FROM t")
    print(cur.fetchall())    # [[Fraction(8000, 1)]]
    conn.close()

Legacy one-shot API (backward compat):

    conn.execute("SELECT SUM(v) FROM t").rows
"""
from __future__ import annotations

import json
import socket
import ssl
import sys
import threading
from fractions import Fraction
from pathlib import Path



def _find_engine() -> None:
    """Make the TorusDB engine importable. Prefers an installed ``ec-fhe-query``
    package; otherwise looks in $TORUSDB_ENGINE_DIR and then in the folders
    above this file (monorepo layout: engine next to ``torussql/``)."""
    try:
        import ecfhe_query  # noqa: F401
        return
    except ImportError:
        pass
    import os
    roots = [Path(os.environ["TORUSDB_ENGINE_DIR"])] \
        if os.environ.get("TORUSDB_ENGINE_DIR") else []
    roots += list(Path(__file__).resolve().parents)[:6]
    for root in roots:
        for rel in ("ec_fhe_query", "ec_fhe_engine"):
            p = root / rel
            if p.is_dir() and str(p) not in sys.path:
                sys.path.insert(0, str(p))


_find_engine()

from . import nokey_wire as w                                # noqa: E402
from .framing import read_frame, write_frame                 # noqa: E402
try:
    from ecfhe_query.nokey_engine import NoKeyClient         # noqa: E402
except ImportError as _exc:                                  # pragma: no cover
    raise ImportError(
        "the TorusDB engine (package 'ec-fhe-query') is required but was not "
        "found; install it or set TORUSDB_ENGINE_DIR") from _exc
from .vault import VaultLog                                  # noqa: E402

# ── DB-API 2.0 exception hierarchy (PEP 249 §3.1) ───────────────────────────

class Warning(Exception):           pass  # noqa: N818
class Error(Exception):             pass
class InterfaceError(Error):        pass
class DatabaseError(Error):         pass
class DataError(DatabaseError):     pass
class OperationalError(DatabaseError): pass
class IntegrityError(DatabaseError): pass
class InternalError(DatabaseError): pass
class ProgrammingError(DatabaseError): pass
class NotSupportedError(DatabaseError): pass

class AuthenticationError(OperationalError): pass
class ServerBusyError(OperationalError):      pass

# Legacy alias kept for backward compat
NoKeyError = OperationalError

_SERVER_ERR_MAP = {
    "ParseError":      ProgrammingError,
    "PlanError":       ProgrammingError,
    "IntegrityError":  IntegrityError,
    "ValidationError": ProgrammingError,
    "KeyError":        DataError,
    "ValueError":      DataError,
    "RuntimeError":    InternalError,
    "Unauthenticated": AuthenticationError,
    "Forbidden":       AuthenticationError,
    "Busy":            ServerBusyError,
    "BadRequest":      DataError,
    "InternalError":   InternalError,
    "ExecError":       DataError,
}

# Engine exception types — mapped by class name so we don't hard-import them
# (the engine may not be on sys.path in pure-client deployments).
_ENGINE_TYPE_MAP = {
    "ParseError":      ProgrammingError,
    "PlanError":       ProgrammingError,
    "ValidationError": ProgrammingError,
    "IntegrityError":  IntegrityError,
    "OutOfBudget":     DataError,
    "ExecError":       DataError,
}


def _translate_error(exc: Exception) -> DatabaseError:
    """Translate any engine or wire error into a DB-API 2.0 exception."""
    if isinstance(exc, DatabaseError):
        return exc
    # Local engine raises (ParseError / PlanError / ...) — match by class name
    type_name = type(exc).__name__
    if type_name in _ENGINE_TYPE_MAP:
        return _ENGINE_TYPE_MAP[type_name](str(exc))
    # Wire-level errors arrive as OperationalError with "TypeName: msg" text
    msg = str(exc)
    prefix = msg.split(":")[0].strip()
    cls = _SERVER_ERR_MAP.get(prefix, OperationalError)
    return cls(msg)


# ── wire transport ────────────────────────────────────────────────────────────

PROTOCOL_VERSION = 2          # newest wire protocol this driver speaks


class _Conn:
    """Length-prefixed binary JSON-RPC over TCP (optionally TLS)."""

    def __init__(self, host: str, port: int, *,
                 timeout: float | None = 30.0,
                 tls: bool = False,
                 cafile: str | None = None,
                 certfile: str | None = None,
                 keyfile: str | None = None,
                 tls_insecure: bool = False,
                 token: str | None = None):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise OperationalError(f"cannot connect to {host}:{port}: {exc}") from exc
        if tls:
            if tls_insecure:
                # explicit opt-in only: encrypted but UNAUTHENTICATED peer
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                # verify the server certificate and hostname (system CAs, or
                # `cafile` when given)
                ctx = ssl.create_default_context(cafile=cafile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if certfile:
                ctx.load_cert_chain(certfile, keyfile)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, OSError) as exc:
                sock.close()
                raise OperationalError(f"TLS handshake failed: {exc}") from exc
        self._sock = sock
        self._rf = sock.makefile("rb")
        self._wf = sock.makefile("wb")
        self._lock = threading.Lock()
        self.closed = False
        self.server_info: dict = {}
        try:
            self._handshake(token)
        except BaseException:
            self.close()
            raise

    def _handshake(self, token: str | None) -> None:
        try:
            self.server_info = self.call("hello", [])
        except Error as exc:
            if "unknown method" in str(exc) or "_rpc_hello" in str(exc):   # protocol-1 server
                self.server_info = {"protocol": 1, "auth_required": False}
            else:
                raise
        proto = self.server_info.get("protocol", 1)
        if proto > PROTOCOL_VERSION:
            raise InterfaceError(
                f"server speaks protocol {proto}; this driver supports up to "
                f"{PROTOCOL_VERSION} — upgrade the driver")
        if self.server_info.get("auth_required"):
            if token is None:
                raise AuthenticationError(
                    "the server requires a token (pass token=...)")
            self.call("auth", [token])

    def call(self, method: str, args: list):
        with self._lock:
            if self.closed:
                raise InterfaceError("connection is closed")
            try:
                write_frame(self._wf, json.dumps({"m": method, "a": args}).encode())
                payload = read_frame(self._rf)
            except (OSError, ssl.SSLError, EOFError, ValueError) as exc:
                self.close()
                raise OperationalError(f"connection lost: {exc}") from exc
        if payload is None:
            self.close()
            raise OperationalError("server closed the connection")
        resp = json.loads(payload)
        if "err" in resp:
            raise _translate_error(Exception(resp["err"]))
        return resp["ok"]

    def close(self):
        self.closed = True
        try:
            self._rf.close(); self._wf.close(); self._sock.close()
        except OSError:
            pass


# ── remote server proxy ───────────────────────────────────────────────────────

class RemoteNoKeyServer:
    """Proxy with the SAME interface as ecfhe_query.nokey_engine.NoKeyServer,
    forwarding each call to a remote keyless server. Holds no keys, no masks,
    no plaintext — only a socket."""

    def __init__(self, conn: _Conn):
        self._c = conn

    def create(self, table, columns):
        self._c.call("create", [table, [list(c) for c in columns]])

    def drop(self, table):
        self._c.call("drop", [table])

    def schema(self, table):
        return [tuple(c) for c in self._c.call("schema", [table])]

    def tables(self):
        return self._c.call("tables", [])

    def insert(self, table, row):
        return self._c.call("insert", [table, {k: w.wv(v) for k, v in row.items()}])

    def insert_many(self, table, rows):
        return self._c.call("insert_many", [table, [
            {k: w.wv(v) for k, v in row.items()} for row in rows]])

    def update_cell(self, table, idx, col, value):
        self._c.call("update_cell", [table, idx, col, w.wv(value)])

    def delete_rows(self, table, idxs):
        return self._c.call("delete_rows", [table, idxs])

    def matching_rowids(self, table, where):
        return self._c.call("matching_rowids", [table, w.where_to_wire(where)])

    def plain_cells(self, table, col, idxs):
        return [w.uwv(x) for x in self._c.call("plain_cells", [table, col, idxs])]

    def blinded_cell(self, table, col, idx):
        return w.uwv(self._c.call("blinded_cell", [table, col, idx]))

    def blinded_cells(self, table, col, idxs):
        return [w.uwv(x) for x in
                self._c.call("blinded_cells", [table, col, idxs])]

    def blinded_sum(self, table, col, idxs):
        return int(self._c.call("blinded_sum", [table, col, idxs]))

    def blinded_scaled_sum(self, table, col, idxs, k):
        return int(self._c.call("blinded_scaled_sum", [table, col, idxs, str(k)]))

    def blinded_per_row_scaled(self, table, col, idxs, k):
        return [int(x) for x in
                self._c.call("blinded_per_row_scaled", [table, col, idxs, str(k)])]

    def mult_combine_batch(self, openings):
        enc = [[str(e), str(g)] for (e, g) in openings]
        return [int(x) for x in self._c.call("mult_combine_batch", [enc])]


# ── DB-API 2.0 Cursor ─────────────────────────────────────────────────────────

def _sql_literal(v) -> str:
    """Render a Python value as a TorusSQL literal for %s substitution."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # represent as FRAC with integer num/den
        f = Fraction(v).limit_denominator(10 ** 9)
        return f"FRAC({f.numerator},{f.denominator})"
    if isinstance(v, Fraction):
        return f"FRAC({v.numerator},{v.denominator})"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    raise InterfaceError(f"unsupported parameter type: {type(v).__name__}")


class Cursor:
    """PEP 249 cursor. One cursor per logical statement stream; stateless
    between execute() calls (no server-side cursor/portal — TorusSQL is
    stateless at the statement level)."""

    arraysize: int = 1

    def __init__(self, connection: "Connection"):
        self._connection = connection
        self.description: tuple | None = None
        self.rowcount: int = -1
        self._rows: list[tuple] = []
        self._pos: int = 0

    # ── execution ──────────────────────────────────────────────────────────

    def execute(self, operation: str, parameters=None) -> "Cursor":
        if self._connection is None:
            raise InterfaceError("cursor is closed")
        sql = self._apply_params(operation, parameters)
        try:
            result = self._connection._run(sql)
        except DatabaseError:
            raise
        except Exception as exc:
            raise _translate_error(exc) from exc
        self._load(result)
        return self

    def executemany(self, operation: str, seq_of_parameters) -> None:
        """Execute one statement for each parameter set. A run of INSERTs into
        one table is blinded locally and sent in a single round trip."""
        if self._connection is None:
            raise InterfaceError("cursor is closed")
        sqls = [self._apply_params(operation, p) for p in seq_of_parameters]
        if sqls and operation.lstrip()[:6].upper() == "INSERT":
            n = self._connection._run_insert_many(sqls)
            self.description, self._rows, self._pos, self.rowcount = None, [], 0, n
            return
        total = 0
        for sql in sqls:
            self._load(self._connection._run(sql))
            total += max(self.rowcount, 0)
        self.rowcount = total

    # ── fetching ───────────────────────────────────────────────────────────

    def fetchone(self) -> tuple | None:
        if self.description is None:
            raise InterfaceError("no result set — call execute() first")
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        if self.description is None:
            raise InterfaceError("no result set — call execute() first")
        n = size if size is not None else self.arraysize
        chunk = self._rows[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def fetchall(self) -> list[tuple]:
        if self.description is None:
            raise InterfaceError("no result set — call execute() first")
        rows = self._rows[self._pos:]
        self._pos = len(self._rows)
        return rows

    # ── lifecycle ──────────────────────────────────────────────────────────

    def close(self) -> None:
        self._rows = []
        self._pos = 0
        self.description = None
        self.rowcount = -1
        self._connection = None

    def setinputsizes(self, sizes) -> None:   pass  # PEP 249 §7.2.8 no-op ok
    def setoutputsize(self, size, column=None) -> None: pass

    def __iter__(self):
        return self

    def __next__(self) -> tuple:
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    # ── internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _apply_params(operation: str, parameters) -> str:
        if parameters is None:
            return operation
        try:
            literals = tuple(_sql_literal(v) for v in parameters)
        except InterfaceError:
            raise
        except Exception as exc:
            raise InterfaceError(f"parameter error: {exc}") from exc
        try:
            return operation % literals
        except TypeError as exc:
            raise InterfaceError(f"parameter substitution failed: {exc}") from exc

    def _load(self, result) -> None:
        if hasattr(result, "rows"):
            # SELECT — build description and row buffer
            cols = result.columns or []
            self.description = tuple(
                (name, None, None, None, None, None, True) for name in cols
            )
            self._rows = [tuple(row) for row in result.rows]
            self._pos = 0
            self.rowcount = len(self._rows)
        else:
            # DML (UPDATE/DELETE return int; INSERT/CREATE/DROP return None)
            self.description = None
            self._rows = []
            self._pos = 0
            self.rowcount = result if isinstance(result, int) else -1


# ── DB-API 2.0 Connection ────────────────────────────────────────────────────

class Connection:
    """PEP 249 connection. Wraps NoKeyClient + RemoteNoKeyServer + TCP socket.

    Transactions. By default the connection is in *autocommit* mode: every
    statement is atomic (a multi-row UPDATE is wrapped in an implicit
    transaction so it can never half-apply). Call ``begin()`` — or use
    ``with conn.transaction():`` — for multi-statement atomicity; ``commit()``
    and ``rollback()`` end it. A rollback restores both the server state and
    the client's mask vault. Without an open transaction ``commit()`` and
    ``rollback()`` are no-ops, as PEP 249 permits.

    Durability. ``vault_path=`` persists the mask vault (the owner's secret)
    to an append-only, checksummed, 0600 log after every statement;
    ``vault_passphrase=`` additionally seals it. An existing vault is loaded
    on connect, so a restarted process keeps decrypting its data.
    """

    def __init__(self, host: str, port: int, *,
                 authenticated: bool = False,
                 tls: bool = False,
                 cafile: str | None = None,
                 certfile: str | None = None,
                 keyfile: str | None = None,
                 tls_insecure: bool = False,
                 token: str | None = None,
                 vault_path: str | None = None,
                 vault_passphrase: str | None = None,
                 sync_schema: bool = True,
                 timeout: float | None = 30.0):
        self._wire = _Conn(host, port, timeout=timeout, tls=tls,
                           cafile=cafile, certfile=certfile, keyfile=keyfile,
                           tls_insecure=tls_insecure, token=token)
        self._closed = False
        self._in_tx = False
        try:
            self.client = NoKeyClient(RemoteNoKeyServer(self._wire),
                                      authenticated=authenticated)
            self._vault = VaultLog(vault_path, vault_passphrase)
            self._vault.open_into(self.client)
            if sync_schema:
                self.sync_schema()
        except BaseException:
            self._wire.close()
            raise

    # ── PEP 249 interface ─────────────────────────────────────────────────

    def cursor(self) -> Cursor:
        self._check_open()
        return Cursor(self)

    def commit(self) -> None:
        self._check_open()
        if self._in_tx:
            self._end_tx(commit=True)

    def rollback(self) -> None:
        self._check_open()
        if self._in_tx:
            self._end_tx(commit=False)

    def close(self) -> None:
        if not self._closed:
            if self._in_tx:                      # never leave a tx dangling
                try:
                    self._end_tx(commit=False)
                except Error:
                    pass
            self._closed = True
            self._vault.close()
            self._wire.close()

    def _check_open(self) -> None:
        if self._closed:
            raise InterfaceError("connection is closed")

    def sync_schema(self) -> list[str]:
        """Learn tables that exist on the server but not in this client yet
        (e.g. a second reader, or a fresh vault). Only the schema is fetched —
        decrypting encrypted columns still requires the owner's vault.
        Returns the newly learned table names."""
        self._check_open()
        added = []
        for t in self._wire.call("tables", []):
            if t in self.client._schema:
                continue
            cols = [tuple(c) for c in self._wire.call("schema", [t])]
            self.client._schema[t] = cols
            for (name, typ, pol) in cols:
                dict.__setitem__(self.client._coltype, (t, name), typ)
                dict.__setitem__(self.client._colpolicy, (t, name), pol)
            added.append(t)
        return added

    # ── transactions ──────────────────────────────────────────────────────

    @property
    def in_transaction(self) -> bool:
        return self._in_tx

    def begin(self) -> None:
        self._check_open()
        if self._in_tx:
            raise ProgrammingError("a transaction is already open")
        self._vault.tx_begin(self.client)
        try:
            self._wire.call("tx_begin", [])
        except BaseException:
            self._vault.tx_commit()              # nothing happened: drop undo
            raise
        self._in_tx = True

    def _end_tx(self, *, commit: bool) -> None:
        try:
            self._wire.call("tx_commit" if commit else "tx_rollback", [])
        except Error:
            # the server did not commit (error, timeout, lost connection):
            # the only safe client state is the pre-transaction one
            self._in_tx = False
            self._vault.tx_rollback(self.client)
            raise
        self._in_tx = False
        if commit:
            self._vault.tx_commit()
        else:
            self._vault.tx_rollback(self.client)

    def transaction(self):
        """``with conn.transaction():`` — commit on success, roll back on error."""
        return _TxContext(self)

    # ── statement execution (shared by Cursor and Connection.execute) ─────

    def _run(self, sql: str):
        self._check_open()
        words = sql.split(None, 1)
        kind = words[0].upper() if words else ""
        try:
            if kind == "SELECT":
                return self.client.execute(sql)
            implicit = kind == "UPDATE" and not self._in_tx
            if implicit:
                self.begin()
            try:
                result = self.client.execute(sql)
            except BaseException:
                if implicit:
                    self.rollback()
                raise
            if implicit:
                self.commit()
            elif not self._in_tx:
                self._vault.sync()
            return result
        except DatabaseError:
            raise
        except Exception as exc:
            raise _translate_error(exc) from exc

    def _run_insert_many(self, sqls: list[str]) -> int:
        self._check_open()
        try:
            n = self.client.insert_many(sqls)
            if not self._in_tx:
                self._vault.sync()
            return n
        except DatabaseError:
            raise
        except Exception as exc:
            raise _translate_error(exc) from exc

    # ── convenience / legacy API ──────────────────────────────────────────

    def execute(self, sql: str):
        """One-shot execute returning the raw engine result (legacy API)."""
        return self._run(sql)

    def save_masks(self, path: str) -> None:
        self.client.save_masks(path)

    def load_masks(self, path: str) -> None:
        self.client.load_masks(path)

    # ── operations ────────────────────────────────────────────────────────

    @property
    def server_info(self) -> dict:
        return dict(self._wire.server_info)

    def ping(self) -> bool:
        self._check_open()
        return self._wire.call("ping", []) == "pong"

    def server_stats(self) -> dict:
        """Server counters (requires an ``admin`` token when auth is on)."""
        self._check_open()
        return self._wire.call("stats", [])

    def checkpoint(self) -> int:
        self._check_open()
        return self._wire.call("checkpoint", [])

    def backup(self) -> str:
        """Ask the server to write a checksummed backup; returns its path."""
        self._check_open()
        return self._wire.call("backup", [])

    def find_orphans(self) -> dict[str, list[int]]:
        """Rows on the server that this vault cannot decrypt (a crash between
        the server accepting an INSERT and the vault recording its mask).
        They are invisible to correct reads only if removed — see
        ``repair_orphans``."""
        self._check_open()
        orphans: dict[str, list[int]] = {}
        for table, cols in self.client._schema.items():
            enc = [c for (c, _t, pol) in cols if pol != "plain"]
            if not enc:
                continue
            info = self._wire.call("table_info", [table])
            dead = set(info["deleted"])
            bad = [i for i in range(info["rows"])
                   if i not in dead and any(
                       (table, i, c) not in self.client._masks for c in enc)]
            if bad:
                orphans[table] = bad
        return orphans

    def repair_orphans(self) -> int:
        """Tombstone every orphan row; returns how many were removed."""
        n = 0
        for table, ids in self.find_orphans().items():
            n += self._wire.call("delete_rows", [table, ids])
        return n

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exc_type, *exc) -> None:
        self.close()


class _TxContext:
    def __init__(self, conn: Connection):
        self._conn = conn

    def __enter__(self) -> Connection:
        self._conn.begin()
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self._conn.commit()
        else:
            try:
                self._conn.rollback()
            except Error:
                pass


# ── module-level constructor ──────────────────────────────────────────────────

def connect(host: str = "127.0.0.1", port: int = 8533, *,
            authenticated: bool = False,
            tls: bool = False,
            cafile: str | None = None,
            certfile: str | None = None,
            keyfile: str | None = None,
            tls_insecure: bool = False,
            token: str | None = None,
            vault_path: str | None = None,
            vault_passphrase: str | None = None,
            sync_schema: bool = True,
            timeout: float | None = 30.0) -> Connection:
    """Open a PEP 249 connection to a no-key TorusDB server.

    Args:
        host, port: server address (default 127.0.0.1:8533)
        authenticated: enable SPDZ-style integrity MAC (no-key §IX)
        tls: wrap the connection in TLS. The server certificate and hostname
            are VERIFIED (system CAs, or ``cafile``); pass ``tls_insecure=True``
            to skip verification for local development only.
        cafile: CA certificate file for server verification
        certfile / keyfile: client certificate for mutual TLS
        token: API token when the server runs with ``--token-file``
        vault_path: persist the mask vault here (append-only, 0600)
        vault_passphrase: seal the vault file under a passphrase
        sync_schema: learn tables that exist on the server (schema only)
        timeout: socket timeout in seconds (default 30; None = block forever)
    """
    return Connection(host, port, authenticated=authenticated,
                      tls=tls, cafile=cafile, certfile=certfile,
                      keyfile=keyfile, tls_insecure=tls_insecure, token=token,
                      vault_path=vault_path, vault_passphrase=vault_passphrase,
                      sync_schema=sync_schema, timeout=timeout)
