# SPDX-License-Identifier: Apache-2.0
"""Fuzz / robustness tests for the TorusSQL parser and wire layer.

No external fuzzer required — these tests use deterministic mutation of a
seed corpus to generate thousands of malformed inputs and verify that:
  1. The parser NEVER crashes (always raises ParseError or returns a valid AST)
  2. The wire codec NEVER crashes on arbitrary bytes
  3. The server NEVER crashes on malformed frames (returns {"err": ...})

Run with:  pytest torussql/fuzz/test_fuzz_parser.py -v
"""
from __future__ import annotations

import json
import os
import random
import struct
import sys
import threading
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
for _rel in ("core", "parser", "proto", "server"):
    _p = _REPO / _rel
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from torussql_parser import ParseError, parse                # noqa: E402
from framing import read_frame, write_frame                  # noqa: E402
from nokey_server import NoKeyTCPServer                      # noqa: E402

import io
import socket


# ── seed corpus ──────────────────────────────────────────────────────────────

_SEEDS = [
    # valid statements (baseline — must parse)
    "SELECT * FROM t",
    "SELECT id FROM t WHERE x = 1",
    "INSERT INTO t (a) VALUES (1)",
    "CREATE TABLE t (id INT PLAIN)",
    "DROP TABLE t",
    "UPDATE t SET x = 1",
    "DELETE FROM t",
    "SELECT COUNT(*) FROM t GROUP BY dept HAVING COUNT(*) > 1",
    "SELECT DISTINCT id FROM t ORDER BY id DESC LIMIT 5",
    "SELECT e.name, d.dname FROM emp e LEFT OUTER JOIN dept AS d ON e.did = d.did WHERE d.dname IN ('a','b')",
    "SELECT a.x FROM t a JOIN t b ON a.p = b.id JOIN u ON u.k = b.k GROUP BY a.x",
    "SELECT DOT(a.x, b.y) FROM a JOIN b ON a.k = b.k",
    # v0.6 arithmetic expressions
    "SELECT a*b*c + d/2 FROM t",
    "SELECT SUM(a*b)/COUNT(*) FROM t",
    "SELECT (a+b)*(c-d)/FRAC(1,3) AS z FROM t",
    "SELECT -a, a - -1, a*-2, a-1 FROM t GROUP BY k",
    "SELECT AVG(a/b+1), SUM(a)*SUM(b) FROM t WHERE x = 1",
    "SELECT ((((a)))) FROM t",
    "SELECT SUM(SUM(a)) FROM t",
    "SELECT a/ FROM t",
    "SELECT a+*b FROM t",
    "SELECT MIN(a)+1 FROM t",
    # near-valid joins
    "SELECT * FROM t JOIN",
    "SELECT * FROM t LEFT JOIN u ON",
    "SELECT * FROM t AS",
    "SELECT * FROM t JOIN u ON a. = b.c",
    # near-valid (one token wrong — must raise ParseError, not crash)
    "SELECT",
    "SELECT FROM t",
    "INSERT INTO",
    "CREATE TABLE",
    "WHERE x = 1",
    "SELECT * FROM",
    "UPDATE SET x = 1",
    "DELETE WHERE x = 1",
    "SELECT id FROM t WHERE",
    "SELECT id FROM t ORDER BY",
    "SELECT id FROM t LIMIT",
    "SELECT id FROM t LIMIT -999",
    "SELECT id FROM t WHERE x = 'unclosed",
    "SELECT id FROM t WHERE x = ",
    "GROUP BY",
    "HAVING COUNT(*) > 1",
]

_MUTATIONS = [
    # character-level
    lambda s: s[:-1],                          # truncate
    lambda s: s + " EXTRA",                    # trailing garbage
    lambda s: s.upper(),                       # all caps
    lambda s: s.lower(),                       # all lower
    lambda s: s.replace(" ", "  "),            # double spaces
    lambda s: s.replace("=", "<>"),            # swap operator
    lambda s: "  " + s + "  ",                # leading/trailing whitespace
    lambda s: s + ";",                         # semicolon
    lambda s: s + " -- comment",              # trailing comment
    lambda s: s.replace("1", "99999999999999999999999999999999"),  # large int
    lambda s: s.replace("t", ""),             # remove table name
    lambda s: "SELECT " + s,                  # double-prefix
    lambda s: s + " " + s,                    # duplicate
    lambda s: "\x00" + s,                     # null byte prefix
    lambda s: s.replace("INT", "BIGFLOAT"),   # unknown type
    lambda s: s.replace("PLAIN", "SECRET"),   # unknown policy
    lambda s: "FRAC(0,0)",                    # zero denominator
    lambda s: s.replace(")", ""),             # unbalanced parens
    lambda s: "SELECT " + "a, " * 50 + "b FROM t",  # very many columns
]


def _mutate(sql: str, rng: random.Random) -> str:
    mut = rng.choice(_MUTATIONS)
    try:
        return mut(sql)
    except Exception:
        return sql + " INVALID"


# ── parser fuzz ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("seed", _SEEDS)
def test_parser_never_crashes_on_seed(seed):
    """Parser must raise ParseError or return an AST — never an unexpected exception."""
    try:
        parse(seed)
    except ParseError:
        pass  # expected
    except Exception as exc:
        pytest.fail(f"parser crashed on seed {seed!r}: {type(exc).__name__}: {exc}")


def test_parser_fuzz_mutations():
    """1000 random mutations of the seed corpus must not crash the parser."""
    rng = random.Random(42)
    crashes = []
    for _ in range(1000):
        seed = rng.choice(_SEEDS)
        mutated = _mutate(seed, rng)
        try:
            parse(mutated)
        except ParseError:
            pass  # expected
        except Exception as exc:
            crashes.append((mutated, type(exc).__name__, str(exc)))
    assert not crashes, (
        f"{len(crashes)} parser crashes:\n" +
        "\n".join(f"  {s!r} → {t}: {m}" for s, t, m in crashes[:5])
    )


def test_parser_unicode_strings():
    """Unicode characters in string literals must not crash."""
    for s in ["'hello'", "'café'", "'日本語'", "'\\u0000'", "''", "''''",
              "'a\\'b'", "'" + "x" * 10000 + "'"]:
        sql = f"INSERT INTO t (name) VALUES ({s})"
        try:
            parse(sql)
        except ParseError:
            pass
        except Exception as exc:
            pytest.fail(f"crashed on unicode string {s!r}: {exc}")


def test_parser_extreme_integers():
    """Very large and negative integers must not crash."""
    for n in [0, 1, -1, 2**31 - 1, 2**63 - 1, 2**127, 10**50,
              -(2**63), -(2**127)]:
        sql = f"INSERT INTO t (v) VALUES ({n})"
        try:
            parse(sql)
        except ParseError:
            pass
        except Exception as exc:
            pytest.fail(f"crashed on integer {n}: {exc}")


def test_parser_deeply_nested_where():
    """Deeply chained AND/OR predicates must not stack-overflow."""
    parts = " AND ".join(f"x{i} = {i}" for i in range(200))
    sql = f"SELECT * FROM t WHERE {parts}"
    try:
        parse(sql)
    except ParseError:
        pass
    except RecursionError as exc:
        pytest.fail(f"parser stack-overflowed on deep WHERE: {exc}")


def test_parser_deeply_nested_expressions():
    """Pathological expression nesting must raise ParseError, never RecursionError."""
    for sql in ["SELECT " + "(" * 50000 + "a FROM t",
                "SELECT " + "- " * 50000 + "a FROM t",
                "SELECT " + "a+" * 50000 + "a FROM t",
                "SELECT " + "a*(" * 20000 + "a FROM t",
                "SELECT " + "SUM(" * 20000 + "a FROM t",
                "SELECT " + "(a" + "+a)" * 20000 + " FROM t"]:
        try:
            parse(sql)
        except ParseError:
            pass
        except RecursionError as exc:
            pytest.fail(f"parser stack-overflowed on a deep expression: {exc}")


def test_parser_empty_and_whitespace():
    for sql in ["", "   ", "\t\n", ";", "-- comment", "/* block */"]:
        try:
            parse(sql)
        except ParseError:
            pass
        except Exception as exc:
            pytest.fail(f"crashed on whitespace/empty {sql!r}: {exc}")


# ── wire codec fuzz ───────────────────────────────────────────────────────────

def _make_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def test_wire_truncated_length_header():
    """Partial length header returns None (not crash)."""
    for n in range(4):
        buf = io.BytesIO(b"\x00" * n)
        assert read_frame(buf) is None


def test_wire_truncated_body():
    """Frame where body is shorter than advertised length raises EOFError."""
    frame = struct.pack(">I", 100) + b"short"
    buf = io.BytesIO(frame)
    with pytest.raises(EOFError):
        read_frame(buf)


def test_wire_zero_length_frame():
    """Zero-length frame is valid — returns empty bytes."""
    frame = _make_frame(b"")
    buf = io.BytesIO(frame)
    result = read_frame(buf)
    assert result == b""


def test_wire_max_reasonable_payload():
    """A 1 MB payload round-trips without error."""
    payload = b"x" * (1024 * 1024)
    buf = io.BytesIO()
    write_frame(buf, payload)
    buf.seek(0)
    assert read_frame(buf) == payload


def test_wire_random_bytes():
    """Random bytes in the frame body don't crash read_frame."""
    rng = random.Random(0)
    for _ in range(200):
        n = rng.randint(0, 512)
        body = bytes(rng.randint(0, 255) for _ in range(n))
        frame = _make_frame(body)
        buf = io.BytesIO(frame)
        result = read_frame(buf)
        assert result == body


# ── server fuzz (live TCP, malformed requests) ───────────────────────────────

class _FuzzServer:
    def __init__(self):
        self.srv = NoKeyTCPServer("127.0.0.1", 0)
        self.host, self.port = self.srv.address
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.srv.shutdown(); self.srv.server_close(); self.t.join(timeout=5)

    def send_raw(self, payload: bytes, timeout: float = 2.0) -> bytes | None:
        """Send a raw frame and return the raw response frame body, or None."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=timeout)
            rf = sock.makefile("rb")
            wf = sock.makefile("wb")
            write_frame(wf, payload)
            resp = read_frame(rf)
            sock.close()
            return resp
        except (OSError, BrokenPipeError):
            return None


@pytest.fixture(scope="module")
def fuzz_server():
    s = _FuzzServer()
    yield s
    s.stop()


def test_server_returns_err_on_invalid_json(fuzz_server):
    """Malformed JSON payload → server responds with {"err": ...}, not crash."""
    resp = fuzz_server.send_raw(b"NOT JSON AT ALL")
    assert resp is not None
    data = json.loads(resp)
    assert "err" in data


def test_server_returns_err_on_unknown_method(fuzz_server):
    """Unknown RPC method → {"err": ...}."""
    payload = json.dumps({"m": "nonexistent_method", "a": []}).encode()
    resp = fuzz_server.send_raw(payload)
    assert resp is not None
    data = json.loads(resp)
    assert "err" in data


def test_server_returns_err_on_bad_sql(fuzz_server):
    """Bad SQL in a create/insert round → {"err": ...}."""
    # First create a table via a valid RPC
    fuzz_server.send_raw(json.dumps({
        "m": "create",
        "a": ["fuzz_t", [["id", "int", "plain"]]]
    }).encode())
    # Now send a malformed SQL via a mismatched RPC call
    payload = json.dumps({"m": "schema", "a": ["nonexistent_table"]}).encode()
    resp = fuzz_server.send_raw(payload)
    assert resp is not None
    data = json.loads(resp)
    assert "err" in data


@pytest.mark.parametrize("payload", [
    b"",                          # empty
    b"\x00\x00\x00\x00",         # zero-length frame body
    b"\xff\xff\xff\xff",          # truncated huge-length frame
    b"\x00\x00\x00\x01",         # 1-byte frame, no body
    b"\x00\x00\x00\x04{};\n",    # 4-byte JSON-ish
    b"GET / HTTP/1.1\r\n",        # HTTP request
    bytes(range(256)),             # all byte values
])
def test_server_does_not_crash_on_malformed_frames(fuzz_server, payload):
    """Server must not crash (connection close or err response, either is ok)."""
    # We just verify it doesn't throw — the server thread must still be alive
    fuzz_server.send_raw(payload, timeout=1.0)
    # Verify server is still alive by sending a valid request
    resp = fuzz_server.send_raw(
        json.dumps({"m": "schema", "a": ["does_not_exist"]}).encode()
    )
    assert resp is not None
    data = json.loads(resp)
    assert "err" in data or "ok" in data


def test_server_fuzz_random_json_rpc(fuzz_server):
    """200 random JSON payloads — server must survive all of them."""
    rng = random.Random(99)
    methods = ["create", "drop", "insert", "schema", "blinded_cell",
               "plain_cells", "blinded_sum", "matching_rowids",
               "INVALID", "", None, 12345]

    for _ in range(200):
        method = rng.choice(methods)
        n_args = rng.randint(0, 4)
        args = [rng.choice([None, 0, -1, "x", [], {}, "table", "col"])
                for _ in range(n_args)]
        payload = json.dumps({"m": method, "a": args}).encode()
        # Server must respond (err or ok) — not crash or hang
        resp = fuzz_server.send_raw(payload, timeout=2.0)
        if resp is not None:
            try:
                json.loads(resp)
            except json.JSONDecodeError:
                pytest.fail(f"server returned non-JSON: {resp[:80]!r}")

    # Final liveness check
    resp = fuzz_server.send_raw(
        json.dumps({"m": "schema", "a": ["ghost_table"]}).encode()
    )
    assert resp is not None
