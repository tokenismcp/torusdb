# SPDX-License-Identifier: Apache-2.0
"""Custodian daemon and client.

A custodian holds two kinds of secret slices and answers narrow questions:

* **key service** — its share of the threshold vault key: "give me yᵢ·E with a
  proof" (``partial``);
* **mask service** — its share of every encrypted cell's mask: store a share,
  add up shares over a set of cells (``mask_sum``), return shares (``mask_get``).

It never receives plaintext, other custodians' shares, or a combined key/mask.
Answers are checked by the caller (DLEQ proofs for the key service; cross-checks
across custodians for the mask service), so a faulty custodian can refuse
service but cannot corrupt a result undetected.

Access control: every caller has a named token and an explicit permission set
(``key``, ``mask_write``, ``mask_read``, ``mask_admin``; **default: ``key``
only**). Writers cannot read, readers cannot write, and administrative actions
need ``mask_admin``. Requests are rate/size limited, unauthenticated peers get a
tiny frame budget and a short deadline, repeated failures lock the source out,
and every decision is written to an append-only audit log. Use TLS on any
network you do not fully control (tokens are bearer secrets).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import socketserver
import ssl
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from ..framing import read_frame, write_frame
from .group import CustodyError, InvalidPoint
from .keys import KeyShare
from .quorum import QuorumError
from .shares import (Frozen, MaskShareStore, MissingShare, Q, ShareConflict)
from .threshold import Partial, partial_decrypt

log = logging.getLogger("torusdb.custodian")

PRE_AUTH_FRAME = 4096
ALL_PERMS = frozenset({"key", "mask_write", "mask_read", "mask_admin"})
_REQUIRES = {
    "partial": "key",
    "mask_put": "mask_write",
    "mask_sum": "mask_read", "mask_get": "mask_read", "mask_has": "mask_read",
    "mask_meta_get": "mask_read", "mask_tables": "mask_read",
    "mask_list": "mask_admin", "mask_delete": "mask_admin",
    "mask_drop_table": "mask_admin", "mask_drop_gen": "mask_admin",
    "mask_meta_put": "mask_admin", "mask_freeze": "mask_admin",
    "mask_stats": "mask_admin", "mask_compact": "mask_admin",
}


def _tok_hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


@dataclass
class Limits:
    """Hardening knobs for the mask service (all optional)."""
    max_items_per_request: int = 200_000
    reveal_rows_per_minute: int | None = None     # cap on rows returned by mask_get
    min_aggregate_rows: int = 1                   # refuse mask_sum over fewer cells


class Custodian:
    """Server-side state: shares, callers, policy, audit log."""

    def __init__(self, share: KeyShare | None, tokens: dict[str, str], *,
                 permissions: dict[str, set] | None = None,
                 masks: MaskShareStore | None = None, limits: Limits | None = None,
                 approve=None, audit_path: str | None = None,
                 rate_per_minute: int = 30):
        if not tokens:
            raise CustodyError("a custodian needs at least one caller token")
        for tok in tokens.values():
            if len(tok) < 16:
                raise CustodyError("caller tokens must be ≥16 characters")
        if share is None and masks is None:
            raise CustodyError("a custodian needs a key share, a mask store, or both")
        hashes = [_tok_hash(t) for t in tokens.values()]
        if len(set(hashes)) != len(hashes):
            raise CustodyError("two callers share the same token")
        self._share = share
        self._callers = {_tok_hash(t): name for name, t in tokens.items()}
        perms = permissions or {}
        for name, p in perms.items():
            if name not in tokens or not set(p) <= ALL_PERMS:
                raise CustodyError(f"bad permissions for {name!r}: {sorted(p)}")
        self._perms = {name: frozenset(perms.get(name, {"key"})) for name in tokens}
        self.masks = masks
        self.limits = limits or Limits()
        self._approve = approve
        self._audit_path = audit_path
        self._rate = rate_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._reveals: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._fail: dict[str, list] = {}
        self._fail_lock = threading.Lock()

    # ── admin ────────────────────────────────────────────────────────────────
    def replace_share(self, share: KeyShare) -> None:
        """Install the refreshed share (same key, new epoch)."""
        if self._share is None or share.public.key_id != self._share.public.key_id:
            raise CustodyError("refusing a share of a different key")
        with self._lock:
            self._share = share

    def info(self) -> dict:
        s = self._share
        out = {"auth_required": True, "has_key": s is not None,
               "has_masks": self.masks is not None}
        if s is not None:
            out |= {"key_id": s.public.key_id, "epoch": s.epoch, "index": s.index,
                    "group": s.public.group, "k": s.public.k, "n": s.public.n}
        return out

    # ── authentication (thread-safe, lockout before work) ────────────────────
    def authenticate(self, token, source: str = "") -> str:
        ip = source.rsplit(":", 1)[0]
        now = time.monotonic()
        with self._fail_lock:
            rec = self._fail.get(ip)
            if rec and rec[1] > now:
                raise CustodyError("too many failed attempts; try again later")
            if len(self._fail) > 10_000:                       # bound memory
                self._fail = {k: v for k, v in self._fail.items() if v[1] > now or v[2] > now}
        digest = _tok_hash(token if isinstance(token, str) else "")
        found = None
        for h, name in self._callers.items():                  # constant-time scan
            if hmac.compare_digest(h, digest):
                found = name
        if found is None:
            time.sleep(0.25)
            with self._fail_lock:
                rec = self._fail.setdefault(ip, [0, 0.0, now + 60])
                if rec[2] < now:
                    rec[:] = [0, 0.0, now + 60]
                rec[0] += 1
                if rec[0] >= 5:
                    rec[:] = [0, now + 30, now + 90]           # lock 30 s
            raise CustodyError("invalid token")
        with self._fail_lock:
            self._fail.pop(ip, None)
        return found

    # ── audit ────────────────────────────────────────────────────────────────
    def _audit(self, caller: str, peer: str, op: str, detail: dict, outcome: str) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "caller": caller, "peer": peer,
               "op": op, "outcome": outcome}
        if self._share is not None:
            rec |= {"key_id": self._share.public.key_id, "epoch": self._share.epoch}
        rec |= {k: (v if isinstance(v, (int, float, bool)) else str(v)[:64])
                for k, v in detail.items()}
        line = json.dumps(rec)                                  # json escapes newlines
        log.info("%s", line)
        if self._audit_path:
            with self._lock, open(self._audit_path, "a") as f:
                f.write(line + "\n")
                f.flush()

    def _rate_ok(self, table: dict, caller: str, cost: int, cap: int | None) -> bool:
        if cap is None:
            return True
        now = time.monotonic()
        with self._lock:
            q = table[caller]
            while q and now - q[0][0] > 60:
                q.popleft()
            if sum(c for _, c in q) + cost > cap:
                return False
            q.append((now, cost))
            return True

    # ── dispatch ─────────────────────────────────────────────────────────────
    def dispatch(self, caller: str, peer: str, method: str, args: list):
        need = _REQUIRES.get(method)
        if need is None:
            raise CustodyError("unknown method")
        if need not in self._perms.get(caller, frozenset()):
            self._audit(caller, peer, method, {}, f"denied: lacks {need}")
            raise CustodyError(f"caller {caller!r} lacks permission {need!r}")
        if not isinstance(args, list):
            raise CustodyError("arguments must be a list")
        try:
            return getattr(self, "_m_" + method)(caller, peer, *args)
        except TypeError as exc:
            raise CustodyError(f"bad arguments for {method}: {exc}") from None

    # — key service —
    def _m_partial(self, caller, peer, E_hex, ctx_hex=""):
        if self._share is None:
            raise CustodyError("this custodian holds no key share")
        g = self._share.public.g
        try:
            E = g.from_hex(E_hex)
            ctx = bytes.fromhex(ctx_hex)
            if len(ctx) > 1024 or g.is_identity(E):
                raise InvalidPoint("bad request")
        except (InvalidPoint, ValueError, TypeError):
            self._audit(caller, peer, "partial", {"E": str(E_hex)[:16]}, "rejected: malformed")
            raise CustodyError("malformed request")
        if not self._rate_ok(self._hits, caller, 1, self._rate):
            self._audit(caller, peer, "partial", {}, "denied: rate limit")
            raise CustodyError("rate limit exceeded")
        efp = hashlib.sha256(E_hex.encode()).hexdigest()[:16]
        if self._approve and not self._approve(caller, E_hex, ctx):
            self._audit(caller, peer, "partial", {"E": efp}, "denied: policy")
            raise CustodyError("request declined by custodian policy")
        part = partial_decrypt(self._share, E, ctx)
        self._audit(caller, peer, "partial", {"E": efp}, "served")
        return part.to_json(g)

    # — mask service —
    def _store(self) -> MaskShareStore:
        if self.masks is None:
            raise CustodyError("this custodian has no mask store")
        return self.masks

    def _check_items(self, items) -> None:
        if not isinstance(items, list) or len(items) > self.limits.max_items_per_request:
            raise CustodyError(
                f"too many items (limit {self.limits.max_items_per_request})")

    def _m_mask_put(self, caller, peer, gen, x, entries):
        self._check_items(entries)
        try:
            ent = [(str(t), str(c), str(l), int(v), int(s, 16)) for t, c, l, v, s in entries]
            n = self._store().put(int(gen), int(x), ent)
        except (ShareConflict, Frozen) as exc:
            self._audit(caller, peer, "mask_put", {"n": len(entries)}, f"refused: {exc}")
            raise CustodyError(str(exc)) from None
        except (ValueError, TypeError):
            raise CustodyError("malformed mask_put") from None
        self._audit(caller, peer, "mask_put", {"n": n}, "stored")
        return n

    def _m_mask_sum(self, caller, peer, gen, table, col, items):
        self._check_items(items)
        total = sum(int(c) for _, _, c in items) if items else 0
        if total < self.limits.min_aggregate_rows:
            self._audit(caller, peer, "mask_sum", {"rows": total}, "denied: too few rows")
            raise CustodyError(f"aggregates over fewer than "
                               f"{self.limits.min_aggregate_rows} cells are refused")
        try:
            s, x = self._store().sum(int(gen), str(table), str(col),
                                     [(str(c), int(v), int(n)) for c, v, n in items])
        except MissingShare as exc:
            raise CustodyError(f"missing: {exc.n}") from None
        except (ValueError, TypeError):
            raise CustodyError("malformed mask_sum") from None
        self._audit(caller, peer, "mask_sum", {"table": table, "col": col, "rows": total}, "served")
        return {"s": format(s, "x"), "x": x}

    def _m_mask_get(self, caller, peer, gen, table, col, items):
        self._check_items(items)
        if not self._rate_ok(self._reveals, caller, len(items), self.limits.reveal_rows_per_minute):
            self._audit(caller, peer, "mask_get", {"rows": len(items)}, "denied: reveal quota")
            raise CustodyError("reveal quota exceeded")
        try:
            vals, x = self._store().get(int(gen), str(table), str(col),
                                        [(str(c), int(v)) for c, v in items])
        except (ValueError, TypeError):
            raise CustodyError("malformed mask_get") from None
        self._audit(caller, peer, "mask_get", {"table": table, "col": col, "rows": len(items)}, "served")
        return {"x": x, "s": [None if v is None else format(v, "x") for v in vals]}

    def _m_mask_has(self, caller, peer, gen, table, col, items):
        self._check_items(items)
        return self._store().has(int(gen), str(table), str(col),
                                 [(str(c), int(v)) for c, v in items])

    def _m_mask_tables(self, caller, peer, gen):
        return self._store().tables(int(gen))

    def _m_mask_meta_get(self, caller, peer, gen, key):
        return self._store().meta_get(int(gen), str(key))

    def _m_mask_meta_put(self, caller, peer, gen, key, val, if_absent=False):
        ok = self._store().meta_put(int(gen), str(key), val, bool(if_absent))
        self._audit(caller, peer, "mask_meta_put", {"key": key}, "stored" if ok else "exists")
        return ok

    def _m_mask_list(self, caller, peer, gen, table, after, limit):
        return self._store().list_page(int(gen), str(table), after, min(int(limit), 50_000))

    def _m_mask_delete(self, caller, peer, gen, entries):
        self._check_items(entries)
        n = self._store().delete(int(gen), [tuple(e) for e in entries])
        self._audit(caller, peer, "mask_delete", {"n": n}, "deleted")
        return n

    def _m_mask_drop_table(self, caller, peer, gen, table):
        n = self._store().drop_table(int(gen), str(table))
        self._audit(caller, peer, "mask_drop_table", {"table": table, "n": n}, "dropped")
        return n

    def _m_mask_drop_gen(self, caller, peer, gen):
        self._store().drop_generation(int(gen))
        self._audit(caller, peer, "mask_drop_gen", {"gen": gen}, "dropped")
        return True

    def _m_mask_freeze(self, caller, peer, gen, on):
        self._store().set_frozen(int(gen), bool(on))
        self._audit(caller, peer, "mask_freeze", {"gen": gen, "on": bool(on)}, "set")
        return True

    def _m_mask_stats(self, caller, peer):
        return self._store().stats()

    def _m_mask_compact(self, caller, peer):
        self._store().compact()
        return True


class _Handler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        self.timeout = self.server.auth_deadline
        super().setup()

    def handle(self) -> None:
        srv = self.server
        cust: Custodian = srv.custodian
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        caller = None
        fails = 0
        started = time.monotonic()
        while True:
            limit = srv.max_frame if caller else PRE_AUTH_FRAME
            try:
                payload = read_frame(self.rfile, limit)
            except (ValueError, EOFError, OSError, ssl.SSLError):
                return
            if payload is None:
                return
            if caller is None and time.monotonic() - started > srv.auth_deadline:
                return
            try:
                req = json.loads(payload)
                m, a = req["m"], req.get("a", [])
                if m == "hello":
                    out = cust.info()
                elif m == "ping":
                    out = "pong"
                elif m == "auth":
                    try:
                        caller = cust.authenticate(a[0], peer)
                    except CustodyError:
                        fails += 1
                        raise
                    self.connection.settimeout(srv.idle_timeout)
                    out = {"caller": caller}
                else:
                    if caller is None:
                        raise CustodyError("authenticate first")
                    out = cust.dispatch(caller, peer, m, a)
                resp = {"ok": out}
            except CustodyError as exc:
                resp = {"err": f"{type(exc).__name__}: {exc}"}
            except (KeyError, IndexError, TypeError, ValueError, RecursionError, OverflowError):
                resp = {"err": "BadRequest: malformed request"}
            except Exception:                                          # noqa: BLE001
                log.exception("custodian internal error")
                resp = {"err": "InternalError: internal custodian error"}
            try:
                data = json.dumps(resp).encode()
                if len(data) > srv.max_frame:
                    data = json.dumps({"err": "BadRequest: response too large"}).encode()
                write_frame(self.wfile, data, srv.max_frame)
            except OSError:
                return
            if fails >= 5:
                return


class CustodianServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, custodian: Custodian, *,
                 ssl_ctx: ssl.SSLContext | None = None, idle_timeout: float = 60.0,
                 auth_deadline: float = 10.0, max_frame: int = 16 * 1024 * 1024,
                 max_connections: int = 128):
        super().__init__((host, port), _Handler)
        self.custodian = custodian
        self.idle_timeout, self.auth_deadline = idle_timeout, auth_deadline
        self.max_frame = max_frame
        self._ssl_ctx = ssl_ctx
        self._sem = threading.BoundedSemaphore(max_connections)

    def finish_request(self, request, client_address) -> None:
        if not self._sem.acquire(blocking=False):
            request.close()                                   # connection cap
            return
        try:
            if self._ssl_ctx is not None:
                request.settimeout(self.auth_deadline)
                try:
                    request = self._ssl_ctx.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError):
                    return
            self.RequestHandlerClass(request, client_address, self)
        finally:
            self._sem.release()

    @property
    def address(self):
        return self.socket.getsockname()


# ── clients ──────────────────────────────────────────────────────────────────
class RemoteCustodian:
    """Client for a ``CustodianServer``. Keeps one authenticated connection and
    transparently reconnects (all operations are idempotent)."""

    def __init__(self, host: str, port: int, token: str, *, group=None, tls: bool = False,
                 cafile: str | None = None, tls_insecure: bool = False,
                 certfile: str | None = None, keyfile: str | None = None,
                 timeout: float = 30.0):
        self.host, self.port, self.token, self.g = host, port, token, group
        self.tls, self.cafile, self.insecure = tls, cafile, tls_insecure
        self.certfile, self.keyfile, self.timeout = certfile, keyfile, timeout
        self.label = f"{host}:{port}"
        self._lock = threading.Lock()
        self._sock = self._rf = self._wf = None

    def __repr__(self) -> str:                    # never include the token
        return f"RemoteCustodian({self.label})"

    def _connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            if self.tls:
                if self.insecure:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                else:
                    ctx = ssl.create_default_context(cafile=self.cafile)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                if self.certfile:
                    ctx.load_cert_chain(self.certfile, self.keyfile)
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise
        self._sock, self._rf, self._wf = sock, sock.makefile("rb"), sock.makefile("wb")
        self._rpc("auth", [self.token])

    def _rpc(self, method: str, args: list):
        write_frame(self._wf, json.dumps({"m": method, "a": args}).encode(), 1 << 26)
        payload = read_frame(self._rf, 1 << 26)
        if payload is None:
            raise ConnectionError("connection closed")
        resp = json.loads(payload)
        if "err" in resp:
            raise QuorumError(f"{self.label}: {resp['err']}")
        return resp["ok"]

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _drop(self) -> None:
        for o in (self._rf, self._wf, self._sock):
            try:
                o and o.close()
            except OSError:
                pass
        self._sock = self._rf = self._wf = None

    def call(self, method: str, args: list):
        with self._lock:
            for attempt in (0, 1):
                try:
                    if self._sock is None:
                        self._connect()
                    return self._rpc(method, args)
                except QuorumError:
                    raise                                   # an application answer
                except (OSError, EOFError, ValueError, ssl.SSLError) as exc:
                    self._drop()
                    if attempt:
                        raise QuorumError(f"{self.label}: {type(exc).__name__}: {exc}") from exc
            raise AssertionError("unreachable")             # pragma: no cover

    def info(self) -> dict:
        # hello needs no authentication; use a throw-away connection
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            if self.tls:
                ctx = (ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) if self.insecure
                       else ssl.create_default_context(cafile=self.cafile))
                if self.insecure:
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            wf, rf = sock.makefile("wb"), sock.makefile("rb")
            write_frame(wf, b'{"m":"hello","a":[]}', PRE_AUTH_FRAME)
            resp = json.loads(read_frame(rf, 1 << 20))
            if "err" in resp:
                raise QuorumError(f"{self.label}: {resp['err']}")
            return resp["ok"]
        finally:
            sock.close()

    def partial(self, E, context: bytes = b"") -> Partial:
        return Partial.from_json(self.g, self.call("partial", [self.g.hex(E), context.hex()]))


class LocalNode:
    """In-process custodian (tests, single-host use) with the same interface as
    ``RemoteCustodian``."""

    def __init__(self, custodian: Custodian, caller: str = "local", label: str = "local"):
        self.custodian, self.caller, self.label = custodian, caller, label
        self.g = custodian._share.public.g if custodian._share else None

    def __repr__(self) -> str:
        return f"LocalNode({self.label})"

    def call(self, method: str, args: list):
        try:
            # round-trip through JSON so local behaves exactly like the wire
            args = json.loads(json.dumps(args))
            return json.loads(json.dumps(self.custodian.dispatch(self.caller, "local", method, args)))
        except CustodyError as exc:
            raise QuorumError(f"{self.label}: {type(exc).__name__}: {exc}") from None

    def info(self) -> dict:
        return self.custodian.info()

    def close(self) -> None:
        pass

    def partial(self, E, context: bytes = b"") -> Partial:
        return Partial.from_json(self.g, self.call("partial", [self.g.hex(E), context.hex()]))
