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
    print(cur.fetchall())    # [(8000,)]   (an int when the value is integral)
    conn.close()

Legacy one-shot API (backward compat):

    conn.execute("SELECT SUM(v) FROM t").rows
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import sys
import threading
from fractions import Fraction
from pathlib import Path



def _find_core() -> None:
    """In a source checkout, make ``torusdb_core`` (``core/`` next to
    ``drivers/``) importable. An installed ``torusdb-core`` always wins."""
    try:
        import torusdb_core  # noqa: F401
        return
    except ImportError:
        pass
    for root in list(Path(__file__).resolve().parents)[:5]:
        p = root / "core"
        if (p / "torusdb_core").is_dir() and str(p) not in sys.path:
            sys.path.append(str(p))
            return


_find_core()

from . import nokey_wire as w                                # noqa: E402
from .framing import read_frame, write_frame                 # noqa: E402
try:
    from torusdb_core.nokey_engine import NoKeyClient         # noqa: E402
except ImportError as _exc:                                  # pragma: no cover
    raise ImportError(
        "the 'torusdb-core' package is required but was not found "
        "(pip install torusdb-core)") from _exc
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
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ConnectionLost(OperationalError):
    """The transport failed (the server may or may not have processed the last
    request). Distinct from an error the server *answered* with."""


class TransactionInDoubt(OperationalError):
    """COMMIT was sent but its outcome could not be learned (connection lost and
    the server unreachable). The vault keeps both possibilities; the next
    connection to the same vault asks the server and settles it."""


class _Conn:
    """Length-prefixed binary JSON-RPC over TCP (optionally TLS)."""

    def __init__(self, host: str, port: int, *,
                 timeout: float | None = 30.0,
                 tls: bool = False,
                 cafile: str | None = None,
                 certfile: str | None = None,
                 keyfile: str | None = None,
                 tls_insecure: bool = False,
                 token: str | None = None,
                 allow_insecure_token: bool = False):
        if token is not None and not tls and host not in _LOOPBACK and not allow_insecure_token:
            raise InterfaceError(
                "refusing to send an API token over an unencrypted connection to a "
                "non-loopback host — use tls=True (or allow_insecure_token=True if the "
                "network is trusted)")
        self.closed = True            # until fully set up (so close() is always safe)
        self._sock = self._rf = self._wf = None
        self._lock = threading.Lock()
        self.server_info: dict = {}
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise OperationalError(f"cannot connect to {host}:{port}: {exc}") from exc
        try:
            if tls:
                if tls_insecure:
                    # explicit opt-in only: encrypted but UNAUTHENTICATED peer
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                else:
                    ctx = ssl.create_default_context(cafile=cafile)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                if certfile:
                    ctx.load_cert_chain(certfile, keyfile)
                sock = ctx.wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            if isinstance(exc, (FileNotFoundError, PermissionError)):
                raise InterfaceError(f"cannot read TLS file: {exc}") from exc
            raise OperationalError(f"TLS handshake failed: {exc}") from exc
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self._rf = sock.makefile("rb")
        self._wf = sock.makefile("wb")
        self.closed = False
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
                raise ConnectionLost(f"connection lost: {exc}") from exc
        if payload is None:
            self.close()
            raise ConnectionLost("server closed the connection")
        resp = json.loads(payload)
        if "err" in resp:
            raise _translate_error(Exception(resp["err"]))
        return resp["ok"]

    def close(self):
        self.closed = True
        for o in (self._wf, self._rf, self._sock):       # each independently: one
            try:                                           # failing flush must not
                if o is not None:                          # leak the socket
                    o.close()
            except (OSError, ValueError):
                pass


# ── remote server proxy ───────────────────────────────────────────────────────

def _b64d(v):
    import base64
    if not isinstance(v, str):
        raise OperationalError("malformed FHE reply from the server")
    return base64.b64decode(v.encode("ascii"), validate=True)


class RemoteNoKeyServer:
    """Proxy with the SAME interface as torusdb_core.nokey_engine.NoKeyServer,
    forwarding each call to a remote keyless server. Holds no keys, no masks,
    no plaintext — only a socket."""

    def __init__(self, conn: _Conn):
        self._c = conn

    def create(self, table, columns, if_not_exists=False):
        args = [table, [list(c) for c in columns]]
        if if_not_exists:
            args.append(True)
        return self._c.call("create", args) is not False

    def drop_if_exists(self, table):
        return self._c.call("drop", [table, True]) is not False

    def drop(self, table):
        self._c.call("drop", [table])

    def fhe_sum(self, table, col, idxs):
        return _b64d(self._c.call("fhe_sum", [table, col, idxs]))

    def fhe_dot(self, lt, lc, lids, rt, rc, rids):
        return _b64d(self._c.call("fhe_dot", [lt, lc, lids, rt, rc, rids]))

    def create_index(self, table, col):
        self._c.call("create_index", [table, col])

    def drop_index(self, table, col):
        self._c.call("drop_index", [table, col])

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
        if v != v or v in (float("inf"), float("-inf")):
            raise InterfaceError("NaN / infinity cannot be stored")
        f = Fraction(v)                 # EXACT binary value — never silently rounded;
        return f"FRAC({f.numerator},{f.denominator})"   # absurd magnitudes fail loudly (OutOfBudget)
    if isinstance(v, Fraction):
        return f"FRAC({v.numerator},{v.denominator})"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    raise InterfaceError(f"unsupported parameter type: {type(v).__name__}")


def _substitute(operation: str, literals: tuple) -> str:
    """DB-API 'format' substitution done by a scanner, not by ``%``:
    ``%s`` takes the next parameter, ``%%`` is a literal percent, anything else
    after a ``%`` is an error. A placeholder inside a quoted string is refused —
    quoting a parameter is the classic injection mistake (the driver already
    quotes string parameters)."""
    out, i, n, used = [], 0, len(operation), 0
    in_str = False
    while i < n:
        ch = operation[i]
        if in_str:
            if ch == "'":
                if operation[i + 1:i + 2] == "'":
                    out.append("''"); i += 2; continue
                in_str = False
            elif ch == "%":
                nxt = operation[i + 1:i + 2]
                if nxt == "s":
                    raise ProgrammingError(
                        "a placeholder inside a quoted string is not supported — write %s "
                        "without quotes (string parameters are quoted for you)")
                if nxt == "%":                       # escaped percent, even inside a string
                    out.append("%"); i += 2; continue
            out.append(ch); i += 1; continue
        if ch == "'":
            in_str = True; out.append(ch); i += 1; continue
        if ch == "-" and operation[i:i + 2] == "--":          # comment: verbatim
            j = operation.find("\n", i)
            j = n if j < 0 else j
            out.append(operation[i:j]); i = j; continue
        if ch == "/" and operation[i:i + 2] == "/*":
            j = operation.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(operation[i:j]); i = j; continue
        if ch == "%":
            nxt = operation[i + 1:i + 2]
            if nxt == "s":
                if used >= len(literals):
                    raise ProgrammingError("not enough parameters for the %s placeholders")
                out.append(literals[used]); used += 1; i += 2; continue
            if nxt == "%":
                out.append("%"); i += 2; continue
            raise ProgrammingError(
                f"unsupported placeholder %{nxt!s} — only %s and %% are allowed "
                f"(paramstyle 'format')")
        out.append(ch); i += 1
    if used != len(literals):
        raise ProgrammingError(f"{len(literals)} parameters supplied for {used} placeholders")
    return "".join(out)


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
        self._clear()                       # a failed execute must not leave stale rows
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
        self._clear()
        sqls = [self._apply_params(operation, p) for p in seq_of_parameters]
        if sqls and operation.lstrip()[:6].upper() == "INSERT":
            n = self._connection._run_insert_many(sqls)
            self.description, self._rows, self._pos, self.rowcount = None, [], 0, n
            return
        total = 0

        def run_all():
            nonlocal total
            for sql in sqls:
                self._load(self._connection._run(sql))
                total += max(self.rowcount, 0)
        if len(sqls) > 1 and not self._connection._in_tx:
            with self._connection.transaction():            # all-or-nothing batch
                run_all()
        else:
            run_all()
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

    def _clear(self) -> None:
        self.description, self._rows, self._pos, self.rowcount = None, [], 0, -1

    @staticmethod
    def _apply_params(operation: str, parameters) -> str:
        if parameters is None:
            return operation                  # no parameters: '%' is just a character
        if isinstance(parameters, (dict, str, bytes)):
            raise InterfaceError("parameters must be a sequence (paramstyle 'format')")
        try:
            literals = tuple(_sql_literal(v) for v in parameters)
        except Error:
            raise
        except Exception as exc:
            raise InterfaceError(f"parameter error: {exc}") from exc
        return _substitute(operation, literals)

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


def _synchronized(fn):
    """Serialize a Connection method (the connection is shared between threads
    — DB-API threadsafety 2 — but one statement runs at a time)."""
    import functools

    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        with self._mutex:
            return fn(self, *a, **kw)
    return wrapper


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
                 allow_insecure_token: bool = False,
                 vault_path: str | None = None,
                 vault_passphrase: str | None = None,
                 vault_custody=None,
                 mask_cluster=None,
                 sync_schema: bool = True,
                 trust_server_schema: bool = False,
                 fhe_key=None,
                 timeout: float | None = 30.0):
        if mask_cluster is not None and (vault_path or vault_passphrase or vault_custody):
            raise ProgrammingError(
                "mask_cluster replaces the local vault — do not combine it with "
                "vault_path / vault_passphrase / vault_custody")
        if vault_path:
            vault_path = os.path.expanduser(vault_path)
            Path(vault_path).parent.mkdir(parents=True, exist_ok=True)
        self._wire_args = dict(timeout=timeout, tls=tls, cafile=cafile, certfile=certfile,
                               keyfile=keyfile, tls_insecure=tls_insecure, token=token,
                               allow_insecure_token=allow_insecure_token)
        self._host, self._port = host, port
        self._wire = _Conn(host, port, **self._wire_args)
        self._trust_server_schema = trust_server_schema
        self._mutex = threading.RLock()
        self._closed = False
        self._in_tx = False
        self._txid: str | None = None
        self._tx_failed: str | None = None       # set when a statement failed mid-transaction
        self._vault = None
        self.client = None
        try:
            self.client = NoKeyClient(RemoteNoKeyServer(self._wire),
                                      authenticated=authenticated,
                                      maskstore=mask_cluster, fhe=fhe_key)
            if mask_cluster is not None:
                if authenticated and not self.client.authenticated:
                    raise ProgrammingError(
                        "authenticated=True but the mask cluster was initialised "
                        "without integrity protection")
                sync_schema = True            # a stateless owner re-learns the schema
            self._vault = VaultLog(vault_path, vault_passphrase, vault_custody)
            existing = self._vault.open_into(self.client)
            if authenticated and existing and not self.client.authenticated:
                raise ProgrammingError(
                    "authenticated=True, but this vault was created without integrity "
                    "protection (MAC) and its tables carry no MACs — refusing to silently "
                    "run unprotected; use a new vault for authenticated mode")
            for txid in list(self._vault.in_doubt):          # settle a lost COMMIT
                self._settle(txid)
            if sync_schema:
                self.sync_schema()
        except BaseException:
            self._cleanup()
            raise

    def _cleanup(self) -> None:
        """Release everything on a failed construction / close (never raises)."""
        self._closed = True
        for closer in (getattr(self._vault, "close", None),
                       getattr(getattr(self.client, "maskstore", None), "close", None),
                       self._wire.close):
            try:
                if closer:
                    closer()
            except Exception:                                    # noqa: BLE001
                pass

    def _settle(self, txid: str) -> None:
        """Ask the server what became of a transaction whose COMMIT reply was
        lost, then make the vault agree with the answer."""
        try:
            status = self._wire.call("tx_status", [txid])
        except Error as exc:
            raise TransactionInDoubt(
                f"transaction {txid} is unresolved and the server cannot say how it "
                f"ended ({exc}); the vault is kept as is — retry once the server "
                f"supports tx_status") from exc
        if status == "open":
            raise TransactionInDoubt(f"transaction {txid} is still open on the server")
        self._vault.resolve_in_doubt(self.client, txid, status == "committed")

    # ── PEP 249 interface ─────────────────────────────────────────────────

    def cursor(self) -> Cursor:
        self._check_open()
        return Cursor(self)

    @_synchronized
    def commit(self) -> None:
        self._check_open()
        if self._in_tx:
            self._end_tx(commit=True)

    @_synchronized
    def rollback(self) -> None:
        self._check_open()
        if self._in_tx:
            self._end_tx(commit=False)

    @_synchronized
    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._in_tx:                      # never leave a tx dangling
                try:
                    self._end_tx(commit=False)
                except Error:
                    pass
        finally:
            self._cleanup()

    def _check_open(self) -> None:
        if self._closed:
            raise InterfaceError("connection is closed")

    @_synchronized
    def sync_schema(self) -> list[str]:
        """Learn tables that exist on the server but not in this client yet
        (e.g. a second reader, or a fresh vault). Only the schema is fetched —
        decrypting encrypted columns still requires the owner's vault.
        Tables learned this way are READ-ONLY for the client unless the
        connection was opened with ``trust_server_schema=True``: a malicious
        server could relabel an encrypted column as plain and so receive
        plaintext on INSERT/UPDATE. Returns the newly learned table names."""
        self._check_open()
        added = []
        for t in self._wire.call("tables", []):
            if t in self.client._schema:
                continue
            cols = [tuple(c) for c in self._wire.call("schema", [t])]
            self.client._schema[t] = cols
            if not self._trust_server_schema:
                self.client._untrusted.add(t)
            for (name, typ, pol) in cols:
                dict.__setitem__(self.client._coltype, (t, name), typ)
                dict.__setitem__(self.client._colpolicy, (t, name), pol)
            added.append(t)
        return added

    # ── transactions ──────────────────────────────────────────────────────

    @property
    def in_transaction(self) -> bool:
        return self._in_tx

    @_synchronized
    def begin(self) -> None:
        self._check_open()
        if self._in_tx:
            raise ProgrammingError("a transaction is already open")
        txid = secrets.token_hex(16)
        self._vault.tx_begin(self.client, txid)       # provisional marker BEFORE the server
        try:
            self._wire.call("tx_begin", [txid])
        except BaseException:
            self._vault.tx_rollback(self.client)       # tx_begin failed ⇒ no tx exists
            raise
        self._in_tx, self._txid, self._tx_failed = True, txid, None

    def _abort_local(self) -> None:
        """The server has (definitively) rolled the transaction back."""
        if self._in_tx:
            self._in_tx, self._txid, self._tx_failed = False, None, None
            self._vault.tx_rollback(self.client)

    @_synchronized
    def _end_tx(self, *, commit: bool) -> None:
        txid = self._txid
        if commit and self._tx_failed:
            reason = self._tx_failed
            self._rollback_best_effort()
            raise ProgrammingError(f"the transaction was aborted by an earlier error "
                                   f"({reason}); it has been rolled back")
        try:
            self._wire.call("tx_commit" if commit else "tx_rollback", [])
        except ConnectionLost as exc:
            self._on_lost_reply(commit, txid, exc)         # indeterminate COMMIT
            return
        except Error:
            # the server ANSWERED with an error (e.g. "timed out and was rolled back",
            # "no transaction is open"): it holds no transaction ⇒ roll the vault back
            self._abort_local()
            raise
        self._in_tx, self._txid, self._tx_failed = False, None, None
        if commit:
            self._vault.tx_commit()
        else:
            self._vault.tx_rollback(self.client)

    def _rollback_best_effort(self) -> None:
        try:
            self._wire.call("tx_rollback", [])
        except Error:
            pass
        self._abort_local()

    def _on_lost_reply(self, commit: bool, txid: str, exc: Exception) -> None:
        """COMMIT/ROLLBACK was sent but the reply never arrived."""
        if not commit:
            self._abort_local()           # the server rolls back on disconnect
            raise exc
        # reconnect and ask the server how the transaction ended
        try:
            fresh = _Conn(self._host, self._port, **self._wire_args)
        except Error:
            self._in_tx = False
            self._vault.tx_in_doubt()
            self._closed = True
            self._vault.close()           # leaves the open `txb`; next connect settles it
            raise TransactionInDoubt(
                f"COMMIT of transaction {txid} was sent but the connection was lost and "
                f"the server is unreachable. Its outcome is unknown; the vault keeps both "
                f"possibilities and will settle it with the server on the next connect") from exc
        try:
            status = fresh.call("tx_status", [txid])
        except Error:
            fresh.close()
            self._in_tx = False
            self._vault.tx_in_doubt()
            self._closed = True
            self._vault.close()
            raise TransactionInDoubt(
                f"COMMIT of transaction {txid}: outcome unknown (server cannot report it)") from exc
        self._wire.close()
        self._wire = fresh
        self.client.server._c = fresh
        self._in_tx, self._txid, self._tx_failed = False, None, None
        if status == "committed":
            self._vault.tx_commit()       # it did commit: keep the new masks
            return
        self._vault.tx_rollback(self.client)
        raise OperationalError(f"COMMIT of transaction {txid} did not take effect "
                               f"(connection lost before it was processed); rolled back") from exc

    def transaction(self):
        """``with conn.transaction():`` — commit on success, roll back on error."""
        return _TxContext(self)

    # ── statement execution (shared by Cursor and Connection.execute) ─────

    _PLANNING_ERRORS = ("ParseError", "PlanError", "ValidationError")

    @staticmethod
    def _statement_kind(sql: str) -> str:
        """Kind from the parsed statement (not from the first word: a leading
        comment must not change how a statement is treated)."""
        try:
            from torussql_parser.parser import parse
            return type(parse(sql)).__name__
        except Exception:                                            # noqa: BLE001
            return ""                      # the engine will raise the proper error

    @_synchronized
    def _run(self, sql: str):
        self._check_open()
        if self._in_tx and self._tx_failed:
            raise ProgrammingError(
                f"the current transaction was aborted by an earlier error "
                f"({self._tx_failed}); issue ROLLBACK")
        kind = self._statement_kind(sql)
        try:
            if kind == "Select":
                return self.client.execute(sql)
            implicit = kind == "Update" and not self._in_tx
            if implicit:
                self.begin()
            try:
                result = self.client.execute(sql)
            except BaseException as exc:
                self._on_statement_error(exc, implicit)
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

    def _on_statement_error(self, exc: BaseException, implicit: bool) -> None:
        if isinstance(exc, ConnectionLost):
            # the server drops an open transaction when the connection dies
            self._abort_local()
            self._cleanup()
            return
        if isinstance(exc, ServerBusyError) and "timed out" in str(exc):
            self._abort_local()            # the server rolled it back: forget it NOW
            return
        if implicit:
            try:
                self.rollback()
            except Error:
                pass
        elif self._in_tx and type(exc).__name__ not in self._PLANNING_ERRORS:
            # a statement may have half-applied: like PostgreSQL, the transaction can
            # only be rolled back from here
            self._tx_failed = f"{type(exc).__name__}: {str(exc)[:120]}"

    @_synchronized
    def _run_insert_many(self, sqls: list[str]) -> int:
        self._check_open()
        if self._in_tx and self._tx_failed:
            raise ProgrammingError(f"the current transaction was aborted ({self._tx_failed})")
        try:
            n = self.client.insert_many(sqls)
            if not self._in_tx:
                self._vault.sync()
            return n
        except DatabaseError:
            raise
        except BaseException as exc:
            self._on_statement_error(exc, False)
            if isinstance(exc, Exception):
                raise _translate_error(exc) from exc
            raise

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

    def rotate_vault_key(self) -> None:
        """Re-seal the whole vault under a fresh key (threshold vaults: a fresh
        envelope to the same custodians — no quorum needed to *write*)."""
        self._check_open()
        if self._in_tx:
            raise ProgrammingError("finish the transaction first")
        self._vault.rebase(self.client)

    @_synchronized
    def reseal_vault(self, *, custody=None, vault_passphrase: str | None = None) -> None:
        """Move the vault to a different protection: ``custody=`` (threshold key)
        or ``vault_passphrase=`` (or neither, for an unsealed file). Use it to
        migrate a passphrase vault to threshold custody, or to leave a
        compromised threshold key for a fresh one."""
        self._check_open()
        if self._in_tx:
            raise ProgrammingError("finish the transaction first")
        self._vault.reseal(self.client, custody=custody, passphrase=vault_passphrase)

    @_synchronized
    def find_orphans(self) -> dict[str, list[int]]:
        """Rows whose masks cannot be recovered (a crash between the server
        accepting a write and the masks being durable — or a different vault).
        Raises if the masks are merely *unreachable*: absent ≠ unreachable."""
        self._check_open()
        ms = self.client.maskstore
        orphans: dict[str, list[int]] = {}
        for table, cols in self.client._schema.items():
            enc = [c for (c, _t, pol) in cols if pol not in ("plain", "fhe")]
            if not enc:
                continue
            if self.client.authenticated:
                enc += ["__mac__" + c for c in enc]
            info = self._wire.call("table_info", [table])
            dead = set(info["deleted"])
            live = [i for i in range(info["rows"]) if i not in dead]
            bad: set[int] = set()
            for c in enc:
                ok = ms.available(table, c, live)
                bad |= {i for i, a in zip(live, ok) if not a}
            if bad:
                orphans[table] = sorted(bad)
        return orphans

    def repair_orphans(self, *, max_fraction: float = 0.5) -> int:
        """Tombstone every orphan row; returns how many were removed. Refuses
        when more than ``max_fraction`` of a table would go (that points at a
        wrong vault / mask cluster, not at crash leftovers)."""
        n = 0
        for table, ids in self.find_orphans().items():
            info = self._wire.call("table_info", [table])
            live = info["rows"] - len(info["deleted"])
            if live and len(ids) / live > max_fraction:
                raise ProgrammingError(
                    f"{len(ids)} of {live} rows in {table!r} have no recoverable mask — "
                    f"this looks like the wrong vault or mask cluster, not crash "
                    f"leftovers; refusing to delete them")
            n += self._wire.call("delete_rows", [table, ids])
        return n

    # — threshold mask cluster maintenance (mask_cluster= connections) —
    @_synchronized
    def mask_gc(self, **kw) -> dict:
        """Delete masks no committed row refers to (needs ``mask_admin``)."""
        self._check_open()
        return self.client.maskstore.gc(**kw)

    def mask_repair(self, **kw) -> dict:
        """Restore shares a custodian missed while it was down."""
        self._check_open()
        return self.client.maskstore.repair(**kw)

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exc_type, *exc) -> None:
        self.close()


class _TxContext:
    def __init__(self, conn: Connection):
        self._conn = conn

    def __enter__(self) -> Connection:
        self._conn._mutex.acquire()           # other threads wait out the transaction
        try:
            self._conn.begin()
        except BaseException:
            self._conn._mutex.release()
            raise
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                try:
                    self._conn.rollback()
                except Error:
                    pass
        finally:
            self._conn._mutex.release()


# ── module-level constructor ──────────────────────────────────────────────────

def connect(host: str = "127.0.0.1", port: int = 8533, *,
            authenticated: bool = False,
            tls: bool = False,
            cafile: str | None = None,
            certfile: str | None = None,
            keyfile: str | None = None,
            tls_insecure: bool = False,
            token: str | None = None,
            allow_insecure_token: bool = False,
            vault_path: str | None = None,
            vault_passphrase: str | None = None,
            vault_custody=None,
            mask_cluster=None,
            sync_schema: bool = True,
            trust_server_schema: bool = False,
            fhe_key=None,
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
        token: API token when the server runs with ``--token-file``. Sending it
            over an unencrypted connection to a non-loopback host is refused
            unless ``allow_insecure_token=True``
        vault_path: persist the mask vault here (append-only, 0600)
        vault_passphrase: seal the vault file under a passphrase
        vault_custody: seal the vault under a THRESHOLD key
            (``torussql.custody.ThresholdCustody``): a quorum of custodians is
            needed to open it, and the key is never reassembled
        mask_cluster: hold NO local vault: the masks are secret-shared among the
            custodians of a ``torussql.custody.masks.ThresholdMaskStore`` (k-of-n);
            this process is then stateless
        sync_schema: learn tables that exist on the server (schema only)
        fhe_key: a ``torusdb_core.fhe.FheKey`` (or None) — the owner's secret for
            ``FHE`` columns; load one with ``torusdb_core.fhe.load_key(path, passphrase)``
        trust_server_schema: allow INSERT/UPDATE on tables whose column policies
            were learned from the server (default: they are read-only, because a
            malicious server could relabel an encrypted column "plain"). Tables
            created through / restored from this client's vault are always
            trusted. A stateless ``mask_cluster`` owner needs this flag.
        timeout: socket timeout in seconds (default 30; None = block forever)
    """
    return Connection(host, port, authenticated=authenticated,
                      tls=tls, cafile=cafile, certfile=certfile,
                      keyfile=keyfile, tls_insecure=tls_insecure, token=token,
                      allow_insecure_token=allow_insecure_token,
                      vault_path=vault_path, vault_passphrase=vault_passphrase,
                      vault_custody=vault_custody, mask_cluster=mask_cluster,
                      sync_schema=sync_schema, trust_server_schema=trust_server_schema,
                      fhe_key=fhe_key, timeout=timeout)
