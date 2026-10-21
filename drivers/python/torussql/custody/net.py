# SPDX-License-Identifier: Apache-2.0
"""Custodian daemon and client.

A custodian holds exactly one secret — its key share — and answers exactly one
question: "give me yᵢ·E with a proof". It never receives plaintext, other
shares, or the combined key. Because the answer is verifiable, a compromised or
buggy custodian can refuse service but cannot corrupt a result undetected.

Access control: each caller has a named token; requests are rate limited per
caller; an optional ``approve`` callback can implement human/policy approval;
every decision is written to an append-only audit log. Use TLS on any network
you do not fully control (tokens are bearer secrets).
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

from ..framing import read_frame, write_frame
from .group import CustodyError, InvalidPoint
from .keys import KeyShare
from .quorum import QuorumError
from .threshold import Partial, partial_decrypt

log = logging.getLogger("torusdb.custodian")
MAX_FRAME = 64 * 1024


def _tok_hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


class Custodian:
    """Server-side state: the share, callers, policy, audit log."""

    def __init__(self, share: KeyShare, tokens: dict[str, str], *, approve=None,
                 audit_path: str | None = None, rate_per_minute: int = 30):
        if not tokens:
            raise CustodyError("a custodian needs at least one caller token")
        for tok in tokens.values():
            if len(tok) < 16:
                raise CustodyError("caller tokens must be ≥16 characters")
        self._share = share
        self._callers = {_tok_hash(t): name for name, t in tokens.items()}
        self._approve = approve
        self._audit_path = audit_path
        self._rate = rate_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def replace_share(self, share: KeyShare) -> None:
        """Install the refreshed share (same key, new epoch)."""
        if share.public.key_id != self._share.public.key_id:
            raise CustodyError("refusing a share of a different key")
        with self._lock:
            self._share = share

    def info(self) -> dict:
        s = self._share
        return {"key_id": s.public.key_id, "epoch": s.epoch, "index": s.index,
                "group": s.public.group, "k": s.public.k, "n": s.public.n}

    def authenticate(self, token) -> str | None:
        digest = _tok_hash(token if isinstance(token, str) else "")
        found = None
        for h, name in self._callers.items():                   # constant-time scan
            if hmac.compare_digest(h, digest):
                found = name
        return found

    def _audit(self, caller: str, peer: str, E_hex: str, ctx_hex: str, outcome: str) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "caller": caller, "peer": peer,
               "key_id": self._share.public.key_id, "epoch": self._share.epoch,
               "E": hashlib.sha256(E_hex.encode()).hexdigest()[:16],
               "ctx": ctx_hex[:64], "outcome": outcome}
        log.info("partial %s", json.dumps(rec))
        if self._audit_path:
            with self._lock, open(self._audit_path, "a") as f:
                f.write(json.dumps(rec) + "\n")
                f.flush()

    def partial(self, caller: str, peer: str, E_hex: str, ctx_hex: str) -> dict:
        g = self._share.public.g
        try:
            E = g.from_hex(E_hex)
            ctx = bytes.fromhex(ctx_hex)
            if len(ctx) > 1024 or g.is_identity(E):
                raise InvalidPoint("bad request")
        except (InvalidPoint, ValueError, TypeError):
            self._audit(caller, peer, str(E_hex)[:200], "", "rejected: malformed")
            raise CustodyError("malformed request")
        now = time.monotonic()
        with self._lock:
            q = self._hits[caller]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self._rate:
                limited = True
            else:
                limited = False
                q.append(now)
        if limited:
            self._audit(caller, peer, E_hex, ctx_hex, "denied: rate limit")
            raise CustodyError("rate limit exceeded")
        if self._approve and not self._approve(caller, E_hex, ctx):
            self._audit(caller, peer, E_hex, ctx_hex, "denied: policy")
            raise CustodyError("request declined by custodian policy")
        part = partial_decrypt(self._share, E, ctx)
        self._audit(caller, peer, E_hex, ctx_hex, "served")
        return part.to_json(g)


class _Handler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        self.timeout = self.server.idle_timeout
        super().setup()

    def handle(self) -> None:
        cust: Custodian = self.server.custodian
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        caller = None
        fails = 0
        while True:
            try:
                payload = read_frame(self.rfile, MAX_FRAME)
            except (ValueError, EOFError, OSError, ssl.SSLError):
                return
            if payload is None:
                return
            try:
                req = json.loads(payload)
                m, a = req["m"], req.get("a", [])
                if m == "hello":
                    out = cust.info() | {"auth_required": True}
                elif m == "ping":
                    out = "pong"
                elif m == "auth":
                    time.sleep(0 if cust.authenticate(a[0]) else 0.25)
                    caller = cust.authenticate(a[0])
                    if caller is None:
                        fails += 1
                        raise CustodyError("invalid token")
                    out = {"caller": caller}
                elif m == "partial":
                    if caller is None:
                        raise CustodyError("authenticate first")
                    out = cust.partial(caller, peer, a[0], a[1] if len(a) > 1 else "")
                else:
                    raise CustodyError("unknown method")
                resp = {"ok": out}
            except CustodyError as exc:
                resp = {"err": f"{type(exc).__name__}: {exc}"}
            except Exception:                                          # noqa: BLE001
                log.exception("custodian internal error")
                resp = {"err": "InternalError: internal custodian error"}
            try:
                write_frame(self.wfile, json.dumps(resp).encode(), MAX_FRAME)
            except OSError:
                return
            if fails >= 5:
                return


class CustodianServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, custodian: Custodian, *,
                 ssl_ctx: ssl.SSLContext | None = None, idle_timeout: float = 30.0):
        super().__init__((host, port), _Handler)
        self.custodian = custodian
        self.idle_timeout = idle_timeout
        self._ssl_ctx = ssl_ctx

    def finish_request(self, request, client_address) -> None:
        if self._ssl_ctx is not None:
            request.settimeout(10.0)
            try:
                request = self._ssl_ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            request.settimeout(self.idle_timeout)
        self.RequestHandlerClass(request, client_address, self)

    @property
    def address(self):
        return self.socket.getsockname()


class RemoteCustodian:
    """Client for a ``CustodianServer``; one short connection per request."""

    def __init__(self, host: str, port: int, token: str, *, group, tls: bool = False,
                 cafile: str | None = None, tls_insecure: bool = False,
                 certfile: str | None = None, keyfile: str | None = None,
                 timeout: float = 10.0):
        self.host, self.port, self.token, self.g = host, port, token, group
        self.tls, self.cafile, self.insecure = tls, cafile, tls_insecure
        self.certfile, self.keyfile, self.timeout = certfile, keyfile, timeout
        self.label = f"{host}:{port}"

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
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
        return sock

    def _call(self, calls: list[tuple[str, list]]):
        sock = self._connect()
        try:
            rf, wf = sock.makefile("rb"), sock.makefile("wb")
            out = None
            for m, a in calls:
                write_frame(wf, json.dumps({"m": m, "a": a}).encode(), MAX_FRAME)
                payload = read_frame(rf, MAX_FRAME)
                if payload is None:
                    raise QuorumError(f"{self.label}: connection closed")
                resp = json.loads(payload)
                if "err" in resp:
                    raise QuorumError(f"{self.label}: {resp['err']}")
                out = resp["ok"]
            return out
        finally:
            sock.close()

    def info(self) -> dict:
        return self._call([("hello", [])])

    def partial(self, E, context: bytes = b"") -> Partial:
        d = self._call([("auth", [self.token]),
                        ("partial", [self.g.hex(E), context.hex()])])
        return Partial.from_json(self.g, d)
