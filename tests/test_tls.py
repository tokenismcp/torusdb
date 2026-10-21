# SPDX-License-Identifier: Apache-2.0
"""TLS transport tests for the no-key server + driver.

Creates a temporary self-signed CA + server cert, starts a TLS-enabled
NoKeyTCPServer, and verifies that:
  - the driver connects via TLS and executes encrypted queries
  - plaintext (non-TLS) connections to a TLS server fail cleanly
"""
import ssl
import subprocess
import threading
import tempfile
from pathlib import Path
from fractions import Fraction

import pytest

import torussql
from torussql import OperationalError
from nokey_server import NoKeyTCPServer


# ── cert generation (stdlib + openssl CLI) ────────────────────────────────────

def _gen_selfsigned(tmp: Path) -> tuple[Path, Path]:
    """Generate a self-signed cert+key with IP SAN for 127.0.0.1."""
    cert = tmp / "server.crt"
    key  = tmp / "server.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes",
         "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True
    )
    return cert, key


def _has_openssl() -> bool:
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


pytestmark = pytest.mark.skipif(
    not _has_openssl(), reason="openssl CLI not available"
)


# ── fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tls_server(tmp_path):
    cert, key = _gen_selfsigned(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv = NoKeyTCPServer("127.0.0.1", 0, ssl_ctx=ctx)
    host, port = srv.address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield host, port, str(cert)
    srv.shutdown(); srv.server_close(); t.join(timeout=5)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_tls_encrypted_query(tls_server):
    host, port, cafile = tls_server
    with torussql.connect(host, port, tls=True, cafile=cafile) as conn:
        conn.execute("CREATE TABLE t (id INT PLAIN, v RATIONAL ENC)")
        conn.execute("INSERT INTO t (id, v) VALUES (1, FRAC(8000,1))")
        conn.execute("INSERT INTO t (id, v) VALUES (2, FRAC(9000,1))")
        assert conn.execute("SELECT SUM(v) FROM t").rows == [[Fraction(17000, 1)]]


def test_tls_cursor_api(tls_server):
    host, port, cafile = tls_server
    with torussql.connect(host, port, tls=True, cafile=cafile) as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN)")
        cur.executemany(
            "INSERT INTO emp (id, dept) VALUES (%s, %s)",
            [(1, 5), (2, 5), (3, 9)]
        )
        cur.execute("SELECT COUNT(*) FROM emp WHERE dept = %s", (5,))
        assert cur.fetchone() == (2,)


def test_tls_default_verifies_and_rejects_self_signed(tls_server):
    host, port, _ = tls_server
    # tls=True without a trusted CA must FAIL (secure by default)
    with pytest.raises(OperationalError, match="TLS handshake failed"):
        torussql.connect(host, port, tls=True)


def test_tls_insecure_dev_mode_is_explicit(tls_server):
    host, port, _ = tls_server
    # unverified TLS is available only by explicit opt-in
    with torussql.connect(host, port, tls=True, tls_insecure=True) as conn:
        conn.execute("CREATE TABLE t (x INT PLAIN)")
        conn.execute("INSERT INTO t (x) VALUES (42)")
        assert conn.execute("SELECT COUNT(*) FROM t").rows == [[1]]


def test_plaintext_to_tls_server_fails(tls_server):
    host, port, _ = tls_server
    # A plaintext client connecting to a TLS-only server should fail.
    # We use a short timeout so the test doesn't hang if the server
    # drops the connection silently instead of actively refusing.
    with pytest.raises((OperationalError, OSError, ssl.SSLError, Exception)):
        conn = torussql.connect(host, port, tls=False, timeout=2.0)
        try:
            conn.execute("CREATE TABLE t (x INT PLAIN)")
        finally:
            conn.close()
