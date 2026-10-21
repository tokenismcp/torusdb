#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-key TorusDB server — the untrusted, keyless evaluator over the wire.

It wraps a `NoKeyServer`: it holds schema, plaintext columns, and one-time-
padded scalars, and exposes the no-key operations as RPCs. It has **no key
material and no masks**, and never decrypts. Its persisted snapshot is a
one-time pad — a breach of this process reveals nothing (I(M;V_S)=0).

The driver (data owner) holds the mask vault and drives the protocol; see
`drivers/python/torussql/nokey.py`.

Operational features (all optional, all key-free):

  * token authentication with roles  ro < rw < admin   (--token-file)
  * connection cap, idle timeout, frame-size cap, failed-auth lockout
  * serializable transactions (tx_begin / tx_commit / tx_rollback) with an
    undo log; a dropped connection or a timeout rolls back automatically
  * crash-safe durability: checksummed snapshot + write-ahead journal with
    torn-write recovery and periodic checkpoints  (--db PATH)
  * online backup (admin RPC `backup`) and offline restore (--restore-from)
  * stats RPC, optional Prometheus /metrics + /healthz  (--metrics-port)
  * structured logging (--log-json), graceful SIGTERM/SIGINT shutdown

Usage:  python nokey_server.py [--host H] [--port P] [--db PATH]
        [--token-file F] [--tls --cert C [--key K] [--cafile CA]] ...
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import itertools
import json
import logging
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def _bootstrap_paths() -> None:
    """Make the engine and the torussql package importable when running from a
    source checkout. Installed packages (``ec-fhe-query``, ``torussql``) win;
    otherwise use $TORUSDB_ENGINE_DIR, then folders above this file."""
    import os
    here = Path(__file__).resolve().parent
    roots = [Path(os.environ["TORUSDB_ENGINE_DIR"])] \
        if os.environ.get("TORUSDB_ENGINE_DIR") else []
    roots += list(here.parents)[:6]
    cands = [here, here.parent / "drivers" / "python"]
    for root in roots:
        cands += [root / "ec_fhe_query", root / "ec_fhe_engine"]
    for p in cands:
        if p.is_dir() and str(p) not in sys.path:
            sys.path.append(str(p))          # append: installed packages win


_bootstrap_paths()

from torussql import nokey_wire as w                         # noqa: E402
from torussql.framing import read_frame, write_frame         # noqa: E402
from ecfhe.nokey import N                                    # noqa: E402
from ecfhe_query.nokey_engine import NoKeyServer             # noqa: E402
import durability as dur                                     # noqa: E402

SERVER_VERSION = "0.5.0"
PROTOCOL_VERSION = 2

log = logging.getLogger("torusdb.server")

# ── RPC surface and roles ────────────────────────────────────────────────────
READ_RPCS = frozenset({
    "schema", "tables", "table_info", "matching_rowids", "plain_cells", "blinded_cell",
    "blinded_cells", "blinded_sum", "blinded_scaled_sum",
    "blinded_per_row_scaled", "mult_combine_batch",
})
WRITE_RPCS = frozenset({
    "create", "insert", "insert_many", "update_cell", "delete_rows",
    "tx_begin", "tx_commit", "tx_rollback", "tx_status",
})
ADMIN_RPCS = frozenset({"drop", "stats", "checkpoint", "backup"})
PUBLIC_RPCS = frozenset({"hello", "ping", "auth"})
MUTATIONS = frozenset({"create", "insert", "insert_many", "drop",
                       "update_cell", "delete_rows"})
ROLE_RPCS = {
    "ro": READ_RPCS,
    "rw": READ_RPCS | WRITE_RPCS,
    "admin": READ_RPCS | WRITE_RPCS | ADMIN_RPCS,
}
_ALL_RPCS = READ_RPCS | WRITE_RPCS | ADMIN_RPCS | PUBLIC_RPCS


class ServerError(Exception):
    """An error whose text is safe and useful to return to the client."""


class Unauthenticated(ServerError): pass
class Forbidden(ServerError): pass
class BadRequest(ServerError): pass
class Busy(ServerError): pass


# ── configuration ────────────────────────────────────────────────────────────
@dataclass
class ServerConfig:
    tokens: dict | None = None        # token-or-"sha256:<hex>" -> role; None = no auth
    max_connections: int = 256
    idle_timeout: float = 300.0       # seconds without a request
    max_frame: int = 32 * 1024 * 1024
    tx_wait: float = 10.0             # how long others wait for an open tx
    tx_timeout: float = 60.0          # an open tx older than this is aborted
    checkpoint_every: int = 5000      # journal records between checkpoints
    fsync: str = "always"             # "always" | "never"
    auth_fail_delay: float = 0.25
    max_auth_failures: int = 5
    lockout_seconds: float = 30.0
    backup_dir: str | None = None
    backup_keep: int = 7
    slow_ms: float = 1000.0
    max_items: int = 200_000          # longest id/opening list accepted in one request
    auth_deadline: float = 10.0       # seconds an unauthenticated peer may stay connected
    pre_auth_frame: int = 8192        # largest frame accepted before authentication
    tx_ring: int = 100_000            # committed transaction ids remembered


def hash_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_token_file(path: str) -> dict:
    """Lines of ``role:token`` (token may be ``sha256:<hex>``); ``#`` comments."""
    tokens: dict[str, str] = {}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        role, sep, tok = line.partition(":")
        if not sep or role not in ROLE_RPCS or not tok:
            raise SystemExit(f"{path}:{n}: expected '<ro|rw|admin>:<token>'")
        if tok.startswith("sha256:"):
            tok = "sha256:" + tok[7:].lower()
            hexpart = tok[7:]
            if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
                raise SystemExit(f"{path}:{n}: sha256 token must be 64 hex characters")
        elif len(tok) < 16:
            raise SystemExit(f"{path}:{n}: token shorter than 16 characters")
        if tok in tokens:
            raise SystemExit(f"{path}:{n}: duplicate token (a token may belong to one role only)")
        tokens[tok] = role
    if not tokens:
        raise SystemExit(f"{path}: no tokens defined")
    return tokens


class _Stats:
    def __init__(self) -> None:
        self.started = time.time()
        self.lock = threading.Lock()
        self.requests: dict[str, int] = {}
        self.seconds: dict[str, float] = {}
        self.errors: dict[str, int] = {}
        self.connections_total = 0
        self.connections_active = 0
        self.connections_rejected = 0
        self.auth_failures = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.checkpoints = 0
        self.tx_commits = 0
        self.tx_rollbacks = 0
        self.checkpoint_failures = 0

    def record(self, method: str, secs: float, err: str | None) -> None:
        with self.lock:
            self.requests[method] = self.requests.get(method, 0) + 1
            self.seconds[method] = self.seconds.get(method, 0.0) + secs
            if err:
                self.errors[err] = self.errors.get(err, 0) + 1

    def bump(self, name: str, n: int = 1) -> None:
        with self.lock:
            setattr(self, name, getattr(self, name) + n)


@dataclass
class Session:
    id: int
    peer: str
    role: str | None = None
    in_tx: bool = False
    tx_id: str | None = None


_MISSING = object()


class Engine:
    """RPC handlers over a keyless NoKeyServer. Each handler takes/returns
    only blinded scalars, plaintext cells, or public circuit data.

    Lock order (never reversed): ``_cv`` -> ``_lock``."""

    def __init__(self, db_path: str | None = None,
                 cfg: ServerConfig | None = None):
        self.cfg = cfg or ServerConfig()
        self._path = db_path
        self._lock = threading.RLock()                 # guards the database
        self._cv = threading.Condition()               # guards tx ownership
        self._tx_owner: int | None = None
        self._tx_since = 0.0
        self._undo: list = []
        self._tx_ops: list = []
        self._tx_id: str | None = None
        self._txids: collections.OrderedDict[str, bool] = collections.OrderedDict()
        self._timed_out: set[int] = set()              # sessions whose tx was aborted
        self._ids = itertools.count(1)
        self._fail: dict[str, list] = {}               # ip -> [count, locked_until, window_end]
        self._fail_lock = threading.Lock()
        self._broken: str | None = None                # storage failure ⇒ read-only
        self._closing = False
        self.stats = _Stats()
        self._tokens = None
        if self.cfg.tokens is not None:
            self._tokens = {(t if t.startswith("sha256:") else hash_token(t)): r
                            for t, r in self.cfg.tokens.items()}
        self.srv = NoKeyServer()
        self._gen = 0
        self._journal: dur.Journal | None = None
        self._dblock: dur.DbLock | None = None
        if db_path:
            self._open_db(db_path)

    # ── durability ───────────────────────────────────────────────────────────
    def _open_db(self, path: str) -> None:
        self._dblock = dur.DbLock(path)
        self._dblock.acquire()
        try:
            jpath = path + ".journal"
            if Path(path).exists():
                body, self._gen, extra = dur.read_snapshot(path)
                self.srv = NoKeyServer.from_body(body)
                for t in extra.get("txids", []):
                    self._remember_tx(t)
            self._journal = dur.Journal(jpath, self._gen, self.cfg.fsync)
            replayed = 0
            for rec in self._journal.open():        # raises CorruptDatabase on damage
                for method, args in rec["ops"]:
                    self._mutate(method, args)
                if rec.get("tx"):
                    self._remember_tx(rec["tx"])
                replayed += 1
            if replayed:
                log.info("recovered %d journal commit(s) on top of snapshot "
                         "generation %d", replayed, self._gen)
        except BaseException:
            if self._journal:
                self._journal.close()
            self._dblock.release()
            raise

    def _remember_tx(self, txid: str) -> None:
        self._txids[txid] = True
        self._txids.move_to_end(txid)
        while len(self._txids) > self.cfg.tx_ring:
            self._txids.popitem(last=False)

    def checkpoint(self) -> int:
        """Fold the journal into a fresh snapshot (no-op without --db)."""
        if not self._path:
            return 0
        with self._lock:
            if self._broken:
                raise Busy(f"storage failure: {self._broken}")
            if self._tx_owner is not None:
                raise Busy("cannot checkpoint while a transaction is open")
            new_gen = self._gen + 1
            dur.write_snapshot(self._path, self.srv.to_body(), new_gen,
                               {"txids": list(self._txids)})
            try:
                self._journal.reset(new_gen)
            except BaseException as exc:
                # the new snapshot is already the truth on disk; commits appended to
                # the old-generation journal would be ignored on recovery, so stop
                # accepting writes instead of acknowledging data that could be lost
                self._broken = f"journal reset failed after checkpoint ({exc})"
                log.critical("%s — server is now read-only; restart to recover", self._broken)
                raise
            self._gen = new_gen
            self.stats.bump("checkpoints")
            return new_gen

    def backup(self) -> str:
        if not self.cfg.backup_dir:
            raise BadRequest("backups are not enabled (start with --backup-dir)")
        with self._lock:
            if self._tx_owner is not None:
                raise Busy("cannot back up while a transaction is open "
                           "(it would capture uncommitted data)")
            Path(self.cfg.backup_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
            base = Path(self._path).name if self._path else "memory"
            out = Path(self.cfg.backup_dir) / (
                f"{base}.{time.strftime('%Y%m%dT%H%M%S')}.g{self._gen}"
                f".{next(self._ids)}.bak")
            dur.write_snapshot(str(out), self.srv.to_body(), self._gen,
                               {"txids": list(self._txids)})
            keep = max(1, self.cfg.backup_keep)
            olds = sorted(Path(self.cfg.backup_dir).glob(f"{base}.*.bak"),
                          key=lambda p: p.stat().st_mtime)
            for old in olds[:-keep]:
                old.unlink(missing_ok=True)
            return str(out)

    def close(self) -> None:
        with self._lock:
            self._closing = True                       # no RPC may mutate from now on
            if self._path and self._journal and self._tx_owner is None and not self._broken:
                try:
                    self.checkpoint()
                except Exception:                      # noqa: BLE001
                    log.exception("final checkpoint failed")
            if self._journal:
                self._journal.close()
                self._journal = None
            if self._dblock:
                self._dblock.release()
                self._dblock = None

    # ── sessions / auth ──────────────────────────────────────────────────────
    def new_session(self, peer: str) -> Session:
        s = Session(id=next(self._ids), peer=peer)
        if self._tokens is None:
            s.role = "admin"                           # auth disabled
        return s

    def close_session(self, s: Session) -> None:
        with self._cv:
            if self._tx_owner == s.id:
                with self._lock:
                    self._rollback_locked()
                log.warning("session %d dropped mid-transaction; rolled back", s.id)
                self.stats.bump("tx_rollbacks")
                self._cv.notify_all()
            self._timed_out.discard(s.id)

    def _auth(self, s: Session, token) -> dict:
        if self._tokens is None:
            return {"role": s.role}
        ip = s.peer.rsplit(":", 1)[0]
        now = time.monotonic()
        with self._fail_lock:                          # decide BEFORE doing any work
            rec = self._fail.get(ip)
            if rec and rec[1] > now:
                raise Forbidden("too many failed authentication attempts; "
                                "try again later")
            if len(self._fail) > 10_000:               # bound memory
                self._fail = {k: v for k, v in self._fail.items() if v[1] > now or v[2] > now}
        digest = hash_token(token if isinstance(token, str) else "")
        role = None
        for stored, r in self._tokens.items():         # constant-time scan
            if hmac.compare_digest(stored, digest):
                role = r
        if role is None:
            time.sleep(self.cfg.auth_fail_delay)
            with self._fail_lock:
                rec = self._fail.setdefault(ip, [0, 0.0, now + 60])
                if rec[2] < now:
                    rec[:] = [0, 0.0, now + 60]
                rec[0] += 1
                if rec[0] >= self.cfg.max_auth_failures:
                    rec[:] = [0, now + self.cfg.lockout_seconds,
                              now + self.cfg.lockout_seconds + 60]
            self.stats.bump("auth_failures")
            log.warning("authentication failed from %s", ip)
            raise Unauthenticated("invalid token")
        with self._fail_lock:
            self._fail.pop(ip, None)
        s.role = role
        return {"role": role}

    # ── dispatch ─────────────────────────────────────────────────────────────
    def dispatch(self, method: str, args: list, session: Session | None = None):
        """Run one RPC. ``session`` defaults to an admin session so the engine
        can be driven directly (tests, embedding)."""
        s = session or Session(id=0, peer="local", role="admin")
        t0 = time.perf_counter()
        err = None
        try:
            return self._dispatch(s, method, args)
        except Exception as exc:                       # noqa: BLE001
            err = type(exc).__name__
            raise
        finally:
            dt = time.perf_counter() - t0
            self.stats.record(method if method in _ALL_RPCS else "<invalid>",
                              dt, err)
            if dt * 1000 > self.cfg.slow_ms:
                log.warning("slow request %s took %.0f ms", method, dt * 1000)

    def _dispatch(self, s: Session, method, args):
        if not isinstance(method, str) or method not in _ALL_RPCS:
            raise BadRequest("unknown method")
        if not isinstance(args, list):
            raise BadRequest("arguments must be a list")
        if method == "ping":
            return "pong"
        if method == "hello":
            return {"protocol": PROTOCOL_VERSION, "server": SERVER_VERSION,
                    "auth_required": self._tokens is not None,
                    "max_frame": self.cfg.max_frame,
                    "persistent": bool(self._path)}
        if method == "auth":
            if len(args) != 1:
                raise BadRequest("auth takes one argument")
            return self._auth(s, args[0])
        if s.role is None:
            raise Unauthenticated("authenticate first (method 'auth')")
        if method not in ROLE_RPCS[s.role]:
            raise Forbidden(f"role {s.role!r} may not call {method!r}")
        if method == "stats":
            return self.stats_snapshot()
        if method == "checkpoint":
            return self.checkpoint()
        if method == "backup":
            return self.backup()
        if method in ("tx_begin", "tx_commit", "tx_rollback"):
            return self._tx(s, method, args)
        if method == "tx_status":
            return self._tx_status(args)
        return self._run(s, method, args)

    # ── transactions: one open transaction at a time, serializable ───────────
    def _expire_stale_tx_locked(self) -> None:
        """Caller holds ``_cv``. Abort an open tx that exceeded tx_timeout."""
        if (self._tx_owner is not None
                and time.monotonic() - self._tx_since > self.cfg.tx_timeout):
            owner = self._tx_owner
            with self._lock:
                self._rollback_locked()
            self._timed_out.add(owner)
            self.stats.bump("tx_rollbacks")
            log.warning("transaction of session %s timed out; rolled back", owner)
            self._cv.notify_all()

    def _check_timed_out(self, s: Session) -> None:
        """A session whose transaction the server aborted stays in an aborted
        state: every statement fails until it issues ROLLBACK (it must not carry
        on as if it were still inside the transaction, nor autocommit)."""
        if s.id in self._timed_out:
            raise Busy("transaction timed out and was rolled back; "
                       "issue ROLLBACK before continuing")

    def _tx(self, s: Session, method: str, args: list):
        if method == "tx_status":
            return self._tx_status(args)
        deadline = time.monotonic() + self.cfg.tx_wait
        with self._cv:
            if s.id in self._timed_out and method != "tx_begin":
                self._timed_out.discard(s.id)           # ROLLBACK / COMMIT acknowledge it
                s.in_tx, s.tx_id = False, None
                if method == "tx_rollback":
                    return None
                raise Busy("transaction timed out and was rolled back")
            self._check_timed_out(s)
            if self._closing:
                raise Busy("server is shutting down")
            if method == "tx_begin":
                txid = args[0] if args else None
                if txid is not None and (not isinstance(txid, str) or not 0 < len(txid) <= 64):
                    raise BadRequest("transaction id must be a string of 1–64 characters")
                if self._broken:
                    raise Busy(f"storage failure: {self._broken}")
                if s.in_tx:
                    raise BadRequest("a transaction is already open")
                while self._tx_owner is not None:
                    self._expire_stale_tx_locked()
                    if self._tx_owner is None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Busy("database is locked by another transaction")
                    self._cv.wait(min(remaining, 0.5))
                with self._lock:
                    self._tx_owner = s.id
                    self._tx_since = time.monotonic()
                    self._tx_id = txid
                    self._undo, self._tx_ops = [], []
                s.in_tx, s.tx_id = True, txid
                return None
            if self._tx_owner != s.id:
                raise BadRequest("no transaction is open")
            with self._lock:
                if method == "tx_commit":
                    if self._journal and (self._tx_ops or self._tx_id):
                        try:
                            self._journal.append(self._tx_ops, self._tx_id)
                        except Exception as exc:        # noqa: BLE001
                            self._rollback_locked()
                            s.in_tx, s.tx_id = False, None
                            self.stats.bump("tx_rollbacks")
                            if not self._journal.usable:
                                self._broken = f"journal unusable ({exc})"
                            self._cv.notify_all()
                            raise BadRequest("commit failed (journal write); "
                                             "transaction rolled back")
                    if self._tx_id:
                        self._remember_tx(self._tx_id)
                    self._undo, self._tx_ops = [], []
                    self.stats.bump("tx_commits")
                else:
                    self._rollback_locked()
                    self.stats.bump("tx_rollbacks")
                self._tx_owner = None
                self._tx_id = None
            s.in_tx, s.tx_id = False, None
            self._cv.notify_all()
        if method == "tx_commit":
            self._maybe_checkpoint()
        return None

    def _tx_status(self, args: list) -> str:
        """Outcome of a transaction id: ``committed`` | ``open`` | ``unknown``.
        ``unknown`` means it never committed (aborted, or never began)."""
        if len(args) != 1 or not isinstance(args[0], str):
            raise BadRequest("tx_status takes one transaction id")
        with self._lock:
            if args[0] in self._txids:
                return "committed"
            if self._tx_id == args[0] and self._tx_owner is not None:
                return "open"
            return "unknown"

    def _rollback_locked(self) -> None:
        for undo in reversed(self._undo):
            undo()
        self._undo, self._tx_ops = [], []
        self._tx_owner = None
        self._tx_id = None

    # ── executing one RPC ────────────────────────────────────────────────────
    def _run(self, s: Session, method: str, args: list):
        deadline = time.monotonic() + self.cfg.tx_wait
        while True:
            with self._cv:                             # wait out foreign tx
                self._check_timed_out(s)
                while self._tx_owner not in (None, s.id):
                    self._expire_stale_tx_locked()
                    if self._tx_owner in (None, s.id):
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Busy("database is locked by another transaction")
                    self._cv.wait(min(remaining, 0.5))
            with self._lock:
                if self._tx_owner not in (None, s.id):
                    continue                           # lost a race; wait again
                if s.id in self._timed_out:
                    self._check_timed_out(s)           # raced with an expiry
                if method not in MUTATIONS:
                    return self._call(method, args)
                if self._closing:
                    raise Busy("server is shutting down")
                if self._broken:
                    raise Busy(f"storage failure — the server is read-only: {self._broken}")
                result, undo = self._mutate(method, args)
                if s.in_tx and self._tx_owner == s.id:
                    self._undo.append(undo)
                    self._tx_ops.append([method, args])
                elif self._journal:
                    try:
                        self._journal.append([[method, args]])
                    except Exception as exc:           # noqa: BLE001
                        undo()
                        if not self._journal.usable:
                            self._broken = f"journal unusable ({exc})"
                            log.critical("%s — server is now read-only", self._broken)
                        raise BadRequest(f"write failed (journal): {exc}")
                break
        if not s.in_tx:
            self._maybe_checkpoint()
        return result

    def _maybe_checkpoint(self) -> None:
        """Never lets a checkpoint problem fail an operation that is already
        durable in the journal."""
        if (self._journal and self._tx_owner is None and not self._broken
                and self._journal.records >= self.cfg.checkpoint_every):
            try:
                self.checkpoint()
            except Busy:
                pass
            except Exception:                          # noqa: BLE001
                self.stats.bump("checkpoint_failures")
                log.exception("checkpoint failed (data remains safe in the journal)")

    def _call(self, method: str, args: list):
        try:
            return getattr(self, f"_rpc_{method}")(*args)
        except TypeError as exc:
            raise BadRequest(f"bad arguments for {method}: {exc}")

    # — each mutation returns (result, undo) so a failed journal write or a
    #   rollback can restore the exact previous state —
    def _mutate(self, method: str, args: list):
        srv = self.srv
        try:
            if method == "create":
                table, columns = args
                self._rpc_create(table, columns)
                return None, lambda: srv.drop(table)
            if method == "drop":
                (table,) = args
                saved = (srv._schema.get(table), srv._rows.get(table),
                         srv._deleted.get(table))
                self._rpc_drop(table)

                def undo_drop(saved=saved, table=table):
                    if saved[0] is not None:
                        srv._schema[table], srv._rows[table], srv._deleted[table] = saved
                return None, undo_drop
            if method == "insert":
                table, row_wire = args
                before = len(srv._rows.get(table, ()))
                rid = self._rpc_insert(table, row_wire)
                return rid, lambda: srv._rows[table].__delitem__(slice(before, None))
            if method == "insert_many":
                table, rows_wire = args
                before = len(srv._rows.get(table, ()))
                try:
                    rids = [self._rpc_insert(table, r) for r in rows_wire]
                except Exception:
                    if table in srv._rows:
                        del srv._rows[table][before:]
                    raise
                return rids, lambda: srv._rows[table].__delitem__(slice(before, None))
            if method == "update_cell":
                table, idx, col, wire_value = args
                row = self._row(table, idx)
                old = row.get(col, _MISSING)
                self._rpc_update_cell(table, idx, col, wire_value)

                def undo_cell(row=row, col=col, old=old):
                    if old is _MISSING:
                        row.pop(col, None)
                    else:
                        row[col] = old
                return None, undo_cell
            if method == "delete_rows":
                table, idxs = args
                dead = srv._deleted.get(table, set())
                newly = [i for i in set(idxs) if i not in dead]
                n = self._rpc_delete_rows(table, idxs)
                return n, lambda: srv._deleted[table].difference_update(newly)
        except ValueError as exc:                       # wrong arity
            if "unpack" in str(exc) or "values to" in str(exc):
                raise BadRequest(f"bad arguments for {method}")
            raise
        raise BadRequest("unknown mutation")            # pragma: no cover

    def _row(self, table, idx) -> dict:
        rows = self.srv._rows.get(table)
        if rows is None:
            raise BadRequest(f"no such table: {table}")
        if not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < len(rows):
            raise BadRequest("row id out of range")
        return rows[idx]

    # ── RPC handlers ─────────────────────────────────────────────────────────
    def _cols(self, table) -> list:
        if table not in self.srv._schema:
            raise BadRequest(f"no such table: {table}")
        return self.srv._schema[table]

    def _rpc_create(self, table, columns):
        if not isinstance(table, str) or not table:
            raise BadRequest("table name must be a non-empty string")
        if not isinstance(columns, list) or not all(
                isinstance(c, (list, tuple)) and len(c) == 3
                and all(isinstance(x, str) for x in c) for c in columns):
            raise BadRequest("columns must be [[name, type, policy], …]")
        if not columns:
            raise BadRequest("a table needs at least one column")
        names = [c[0] for c in columns]
        if len(set(names)) != len(names):
            raise BadRequest("duplicate column name")
        if any(n.startswith("__") for n in names) or table.startswith("__"):
            raise BadRequest("names starting with '__' are reserved")
        for n, t, pol in columns:
            if t not in ("int", "str", "rational") or pol not in ("plain", "encrypted", "paired"):
                raise BadRequest(f"bad column definition for {n!r}")
            if t == "str" and pol != "plain":
                raise BadRequest(f"STR columns must be PLAIN (column {n!r})")
        self.srv.create(table, [tuple(c) for c in columns]); return None

    def _rpc_drop(self, table):
        self.srv.drop(table); return None

    def _rpc_tables(self):
        return sorted(self.srv._schema)

    def _rpc_schema(self, table):
        return [list(c) for c in self.srv.schema(table)]

    def _rpc_table_info(self, table):
        rows = self.srv._rows.get(table)
        if rows is None:
            raise BadRequest(f"no such table: {table}")
        return {"rows": len(rows),
                "deleted": sorted(self.srv._deleted.get(table, ()))}

    @staticmethod
    def _is_hidden(k: str) -> bool:
        """Owner-side bookkeeping columns: ``__cid__`` (random cell-group id of
        a threshold mask cluster) and ``__mv__<col>`` (mask version)."""
        return k == "__cid__" or k.startswith("__mv__")

    def _rpc_insert(self, table, row_wire):
        names = {c[0] for c in self._cols(table)}
        if not isinstance(row_wire, dict):
            raise BadRequest("row must be an object")
        keys = set(row_wire)
        macs = {k for k in keys if k.startswith("__mac__") and k[7:] in names}
        hidden = {k for k in keys if self._is_hidden(k)}
        if keys - macs - hidden != names:
            raise BadRequest("INSERT must provide exactly the table's columns")
        row = {k: w.uwv(v) for k, v in row_wire.items()}
        if "__cid__" in row and not (isinstance(row["__cid__"], str)
                                     and 0 < len(row["__cid__"]) <= 64):
            raise BadRequest("__cid__ must be a short string")
        if any(not isinstance(row[k], int) or isinstance(row[k], bool) or row[k] < 0
               for k in hidden if k != "__cid__"):
            raise BadRequest("mask versions must be non-negative integers")
        return self.srv.insert(table, row)

    def _rpc_update_cell(self, table, idx, col, wire_value):
        self._row(table, idx)
        known = {c[0] for c in self._cols(table)}
        if not isinstance(col, str):
            raise BadRequest("column must be a string")
        if (col not in known and not self._is_hidden(col)
                and not (col.startswith("__mac__") and col[7:] in known)):
            raise BadRequest(f"no such column: {col}")
        self.srv.update_cell(table, idx, col, w.uwv(wire_value)); return None

    def _check_ids(self, table, idxs) -> list:
        """Validated row-id list: bounded length, real ints, in range."""
        rows = self.srv._rows.get(table)
        if rows is None:
            raise BadRequest(f"no such table: {table}")
        if not isinstance(idxs, list) or len(idxs) > self.cfg.max_items:
            raise BadRequest(f"id list must be a list of at most {self.cfg.max_items} ids")
        n = len(rows)
        for i in idxs:
            if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < n:
                raise BadRequest("row id out of range")
        return idxs

    def _rpc_delete_rows(self, table, idxs):
        ids = sorted(set(self._check_ids(table, idxs)))       # duplicates count once
        return self.srv.delete_rows(table, ids)

    def _check_predicate(self, table, pred) -> None:
        """Predicates may only test PLAIN columns: comparing against a blinded
        scalar would silently match nothing. Defence in depth — the planner
        already rejects this, but raw RPC clients are not planned."""
        if pred is None:
            return
        policy = {c[0]: c[2] for c in self._cols(table)}
        try:
            atoms = [a for group in pred["or"] for a in group]
            cols = [a["c"] for a in atoms]
        except (KeyError, TypeError):
            raise BadRequest("malformed predicate")
        for c in cols:
            if c not in policy:
                raise BadRequest(f"no such column: {c}")
            if policy[c] != "plain":
                raise BadRequest(
                    f"predicates on encrypted column {c!r} are not supported")

    def _rpc_matching_rowids(self, table, pred):
        self._check_predicate(table, pred)
        rows = self.srv._rows[table]
        dead = self.srv._deleted.get(table, set())
        return [i for i, r in enumerate(rows)
                if i not in dead and w.match_wire(r, pred)]

    def _col(self, table, col) -> str:
        known = {c[0] for c in self._cols(table)}
        if not isinstance(col, str) or not (col in known or self._is_hidden(col)
                                            or (col.startswith("__mac__") and col[7:] in known)):
            raise BadRequest(f"no such column: {col!r}")
        return col

    def _rpc_plain_cells(self, table, col, idxs):
        self._col(table, col)
        return [w.wv(v) for v in self.srv.plain_cells(table, col, self._check_ids(table, idxs))]

    def _rpc_blinded_cell(self, table, col, idx):
        self._col(table, col)
        self._check_ids(table, [idx])
        return w.wv(self.srv.blinded_cell(table, col, idx))

    def _rpc_blinded_cells(self, table, col, idxs):
        self._col(table, col)
        return [w.wv(v) for v in self.srv.blinded_cells(table, col, self._check_ids(table, idxs))]

    @staticmethod
    def _scalar(k) -> int:
        if isinstance(k, bool) or not isinstance(k, (int, str)):
            raise BadRequest("scalar must be an integer (or its decimal string)")
        return int(k)

    # — Π_lin (affine on blinded scalars; no key) —
    def _rpc_blinded_sum(self, table, col, idxs):
        self._col(table, col)
        return str(self.srv.blinded_sum(table, col, self._check_ids(table, idxs)))

    def _rpc_blinded_scaled_sum(self, table, col, idxs, k):
        self._col(table, col)
        return str(self.srv.blinded_scaled_sum(table, col, self._check_ids(table, idxs),
                                               self._scalar(k)))

    def _rpc_blinded_per_row_scaled(self, table, col, idxs, k):
        self._col(table, col)
        return [str(x) for x in self.srv.blinded_per_row_scaled(
            table, col, self._check_ids(table, idxs), self._scalar(k))]

    # — Π_mult (combine opened operands; no key) —
    def _rpc_mult_combine_batch(self, openings):
        if not isinstance(openings, list) or len(openings) > self.cfg.max_items:
            raise BadRequest(f"at most {self.cfg.max_items} openings per request")
        pairs = []
        for o in openings:
            if not isinstance(o, (list, tuple)) or len(o) != 2:
                raise BadRequest("each opening must be a pair [e, g]")
            pairs.append((self._scalar(o[0]), self._scalar(o[1])))
        return [str(x) for x in self.srv.mult_combine_batch(pairs)]

    # ── introspection ────────────────────────────────────────────────────────
    def stats_snapshot(self) -> dict:
        st = self.stats
        with st.lock:
            snap = {
                "server": SERVER_VERSION, "protocol": PROTOCOL_VERSION,
                "uptime_s": round(time.time() - st.started, 1),
                "connections": {"active": st.connections_active,
                                "total": st.connections_total,
                                "rejected": st.connections_rejected},
                "auth_failures": st.auth_failures,
                "requests": dict(st.requests),
                "request_seconds": {k: round(v, 6) for k, v in st.seconds.items()},
                "errors": dict(st.errors),
                "bytes_in": st.bytes_in, "bytes_out": st.bytes_out,
                "transactions": {"commits": st.tx_commits,
                                 "rollbacks": st.tx_rollbacks},
                "checkpoints": st.checkpoints,
            }
        with self._lock:
            snap["tables"] = {t: {"rows": len(r),
                                  "deleted": len(self.srv._deleted.get(t, ()))}
                              for t, r in self.srv._rows.items()}
            snap["generation"] = self._gen
            snap["journal_records"] = self._journal.records if self._journal else 0
            snap["journal_bytes"] = self._journal.bytes if self._journal else 0
        return snap

    def prometheus(self) -> str:
        def esc(v: str) -> str:               # Prometheus label-value escaping
            return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        s = self.stats_snapshot()
        out = [
            "# TYPE torusdb_up gauge", "torusdb_up 1",
            "# TYPE torusdb_uptime_seconds gauge",
            f"torusdb_uptime_seconds {s['uptime_s']}",
            "# TYPE torusdb_connections_active gauge",
            f"torusdb_connections_active {s['connections']['active']}",
            "# TYPE torusdb_connections_total counter",
            f"torusdb_connections_total {s['connections']['total']}",
            "# TYPE torusdb_connections_rejected_total counter",
            f"torusdb_connections_rejected_total {s['connections']['rejected']}",
            "# TYPE torusdb_auth_failures_total counter",
            f"torusdb_auth_failures_total {s['auth_failures']}",
            "# TYPE torusdb_requests_total counter",
        ]
        out += [f'torusdb_requests_total{{method="{esc(m)}"}} {n}'
                for m, n in sorted(s["requests"].items())]
        out.append("# TYPE torusdb_request_seconds_total counter")
        out += [f'torusdb_request_seconds_total{{method="{esc(m)}"}} {v}'
                for m, v in sorted(s["request_seconds"].items())]
        out.append("# TYPE torusdb_errors_total counter")
        out += [f'torusdb_errors_total{{type="{esc(t)}"}} {n}'
                for t, n in sorted(s["errors"].items())]
        out += [
            "# TYPE torusdb_bytes_in_total counter",
            f"torusdb_bytes_in_total {s['bytes_in']}",
            "# TYPE torusdb_bytes_out_total counter",
            f"torusdb_bytes_out_total {s['bytes_out']}",
            "# TYPE torusdb_tx_commits_total counter",
            f"torusdb_tx_commits_total {s['transactions']['commits']}",
            "# TYPE torusdb_tx_rollbacks_total counter",
            f"torusdb_tx_rollbacks_total {s['transactions']['rollbacks']}",
            "# TYPE torusdb_journal_records gauge",
            f"torusdb_journal_records {s['journal_records']}",
            "# TYPE torusdb_table_rows gauge",
        ]
        out += [f'torusdb_table_rows{{table="{esc(t)}"}} {v["rows"]}'
                for t, v in sorted(s["tables"].items())]
        return "\n".join(out) + "\n"


def _client_error_text(exc: Exception) -> str:
    """Map an exception to the single-line error string returned on the wire.
    Unexpected exceptions are logged in full and reported only by reference,
    so internals never leak to a client."""
    if isinstance(exc, ServerError):
        return f"{type(exc).__name__}: {exc}"
    if type(exc).__name__ in ("PlanError", "ParseError", "ExecError"):
        return f"{type(exc).__name__}: {exc}"
    if isinstance(exc, (RecursionError, OverflowError, MemoryError)):
        return f"BadRequest: request too complex or too large ({type(exc).__name__})"
    if isinstance(exc, (KeyError, IndexError, ValueError, TypeError)):
        return f"BadRequest: {type(exc).__name__}: {exc}"
    ref = uuid.uuid4().hex[:8]
    log.error("internal error ref=%s\n%s", ref,
              "".join(traceback.format_exception(exc)))
    return f"InternalError: internal server error (ref={ref})"


class _Handler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        # until authenticated a peer gets a short deadline and a tiny frame budget
        cfg = self.server.cfg
        self.timeout = (cfg.auth_deadline if self.server.engine._tokens is not None
                        else (cfg.idle_timeout or None))
        super().setup()

    def handle(self) -> None:
        srv: NoKeyTCPServer = self.server                 # type: ignore[assignment]
        engine = srv.engine
        cfg = srv.cfg
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        st = engine.stats
        if not srv.admit():
            st.bump("connections_rejected")
            self._send({"err": "Busy: server connection limit reached"})
            return
        session = engine.new_session(peer)
        log.info("connect %s session=%d", peer, session.id)
        started = time.monotonic()
        try:
            while True:
                if session.role is None and time.monotonic() - started > cfg.auth_deadline:
                    return                                # did not authenticate in time
                limit = cfg.max_frame if session.role is not None else cfg.pre_auth_frame
                try:
                    payload = read_frame(self.rfile, limit)
                except ValueError as exc:                 # oversized frame
                    self._send({"err": f"BadRequest: {exc}"})
                    return
                except (EOFError, OSError, ssl.SSLError):
                    return
                if payload is None:
                    return
                st.bump("bytes_in", len(payload) + 4)
                try:
                    req = json.loads(payload)
                    if not isinstance(req, dict):
                        raise BadRequest("request must be a JSON object")
                    out = engine.dispatch(req.get("m"), req.get("a", []), session)
                    resp = {"ok": out}
                    if session.role is not None and self.connection.gettimeout() != (cfg.idle_timeout or None):
                        self.connection.settimeout(cfg.idle_timeout or None)
                except json.JSONDecodeError:
                    resp = {"err": "BadRequest: malformed JSON"}
                except Exception as exc:                  # noqa: BLE001
                    resp = {"err": _client_error_text(exc)}
                if not self._send(resp):
                    return
        finally:
            engine.close_session(session)
            srv.release()
            log.info("disconnect %s session=%d", peer, session.id)

    def _send(self, resp: dict) -> bool:
        srv = self.server
        try:
            data = json.dumps(resp).encode("utf-8")
            if len(data) > srv.cfg.max_frame:
                data = json.dumps(
                    {"err": "BadRequest: response exceeds frame limit"}).encode()
            write_frame(self.wfile, data, srv.cfg.max_frame)
            srv.engine.stats.bump("bytes_out", len(data) + 4)
            return True
        except (OSError, ssl.SSLError, ValueError):
            return False


class NoKeyTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, host: str, port: int, db_path: str | None = None,
                 ssl_ctx: ssl.SSLContext | None = None,
                 config: ServerConfig | None = None):
        if ":" in host:
            self.address_family = socket.AF_INET6      # e.g. --host ::1
        super().__init__((host, port), _Handler, bind_and_activate=False)
        self.cfg = config or ServerConfig()
        self._ssl_ctx = ssl_ctx
        self._conn_lock = threading.Lock()
        self.engine = None
        try:
            self.engine = Engine(db_path, self.cfg)
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def admit(self) -> bool:
        with self._conn_lock:
            st = self.engine.stats
            if st.connections_active >= self.cfg.max_connections:
                return False
            st.bump("connections_active")
            st.bump("connections_total")
        return True

    def release(self) -> None:
        self.engine.stats.bump("connections_active", -1)

    def finish_request(self, request, client_address) -> None:
        # TLS handshake happens here, in the per-connection worker thread, so a
        # slow or hostile peer can never stall the accept loop.
        if self._ssl_ctx is not None:
            request.settimeout(10.0)
            try:
                request = self._ssl_ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            request.settimeout(self.cfg.idle_timeout or None)
        self.RequestHandlerClass(request, client_address, self)

    def handle_error(self, request, client_address) -> None:
        log.debug("connection error from %s", client_address, exc_info=True)

    @property
    def address(self):
        return self.socket.getsockname()

    def server_close(self) -> None:
        super().server_close()
        eng = getattr(self, "engine", None)
        if eng is not None:
            eng.close()                      # handler threads still see a live object
                                             # that refuses further writes (Busy)


# ── metrics / health HTTP endpoint ───────────────────────────────────────────
def start_metrics_server(engine: Engine, host: str, port: int) -> HTTPServer:
    class H(BaseHTTPRequestHandler):
        def do_GET(self):                                # noqa: N802
            if self.path == "/healthz":
                body, ctype = b"ok\n", "text/plain"
            elif self.path == "/metrics":
                body, ctype = engine.prometheus().encode(), "text/plain; version=0.0.4"
            else:
                self.send_error(404); return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):                       # silence
            pass

    httpd = HTTPServer((host, port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


# ── CLI ──────────────────────────────────────────────────────────────────────
def _build_ssl_ctx(args) -> ssl.SSLContext | None:
    if not args.tls:
        return None
    if not args.cert:
        raise SystemExit("--tls requires --cert <certfile>")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key or args.cert)
    if args.cafile:
        ctx.load_verify_locations(args.cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
             "level": record.levelname, "msg": record.getMessage()}
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d)


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="No-key TorusDB server (keyless)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8533)
    ap.add_argument("--db", default=None, help="database path (enables durability)")
    ap.add_argument("--fsync", choices=("always", "never"), default="always")
    ap.add_argument("--checkpoint-every", type=int, default=5000)
    ap.add_argument("--backup-dir", default=None)
    ap.add_argument("--backup-keep", type=int, default=7,
                    help="how many backups to retain (≥1)")
    ap.add_argument("--restore-from", default=None,
                    help="restore --db from a backup file and exit")
    ap.add_argument("--token-file", default=None,
                    help="role:token lines (ro|rw|admin); enables authentication")
    ap.add_argument("--insecure-no-auth", action="store_true",
                    help="allow a non-loopback bind without authentication")
    ap.add_argument("--max-connections", type=int, default=256)
    ap.add_argument("--idle-timeout", type=float, default=300.0)
    ap.add_argument("--max-frame-mb", type=int, default=32)
    ap.add_argument("--metrics-port", type=int, default=None)
    ap.add_argument("--metrics-host", default="127.0.0.1")
    ap.add_argument("--log-level", default="INFO")
    ap.add_argument("--log-json", action="store_true")
    ap.add_argument("--tls", action="store_true", help="enable TLS")
    ap.add_argument("--cert", default=None, help="TLS certificate file (PEM)")
    ap.add_argument("--key", default=None, help="TLS private key (defaults to --cert)")
    ap.add_argument("--cafile", default=None, help="CA file for mutual TLS")
    args = ap.parse_args(argv)

    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter() if args.log_json else logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=args.log_level.upper(), handlers=[handler])

    if args.restore_from:
        if not args.db:
            raise SystemExit("--restore-from requires --db")
        try:
            gen = dur.restore_backup(args.db, args.restore_from)   # takes the DB lock
        except dur.DatabaseLocked as exc:
            raise SystemExit(f"{exc} — stop the server before restoring")
        except dur.CorruptDatabase as exc:
            raise SystemExit(f"backup rejected: {exc}")
        print(f"restored {args.db} from {args.restore_from} (generation {gen})")
        return

    tokens = load_token_file(args.token_file) if args.token_file else None
    if tokens is None and not _is_loopback(args.host) and not args.insecure_no_auth:
        raise SystemExit(
            f"refusing to listen on {args.host} without authentication: pass "
            f"--token-file (recommended) or --insecure-no-auth")
    if not args.tls and not _is_loopback(args.host):
        log.warning("listening on %s without TLS — blinded data and tokens "
                    "travel in the clear; use --tls", args.host)

    if args.backup_keep < 1:
        raise SystemExit("--backup-keep must be at least 1")
    cfg = ServerConfig(tokens=tokens, max_connections=args.max_connections,
                       idle_timeout=args.idle_timeout,
                       max_frame=args.max_frame_mb * 1024 * 1024,
                       checkpoint_every=args.checkpoint_every, fsync=args.fsync,
                       backup_dir=args.backup_dir, backup_keep=args.backup_keep)
    ssl_ctx = _build_ssl_ctx(args)
    try:
        srv = NoKeyTCPServer(args.host, args.port, args.db, ssl_ctx=ssl_ctx,
                             config=cfg)
    except dur.DatabaseLocked as exc:
        raise SystemExit(str(exc))
    except dur.CorruptDatabase as exc:
        raise SystemExit(f"{exc} — refusing to start on damaged data; restore from a "
                         f"backup with --restore-from")
    host, port = srv.address
    tags = ("  TLS" if ssl_ctx else "") + ("  AUTH" if tokens else "")
    print(f"no-key TorusDB server {SERVER_VERSION} (HOLDS NO KEYS) on "
          f"{host}:{port}  modulus≈2^{N.bit_length()}"
          + (f"  db={args.db}" if args.db else "  (in-memory)") + tags,
          flush=True)
    if args.metrics_port is not None:
        start_metrics_server(srv.engine, args.metrics_host, args.metrics_port)

    def _stop(_signum, _frame):
        threading.Thread(target=srv.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()                       # final checkpoint + unlock
        print("shut down cleanly", flush=True)


if __name__ == "__main__":
    main()
