# SPDX-License-Identifier: Apache-2.0
"""The `torussql` shell: statement splitting, rendering, and a real session."""
from __future__ import annotations

import threading

import pytest

from torussql import cli


def test_split_respects_strings_and_comments():
    stmts, rest = cli.split_statements(
        "SELECT 'a;b' FROM t; -- c; d\nSELECT 'it''s'; /* x; */ SELECT 1")
    assert stmts == ["SELECT 'a;b' FROM t", "SELECT 'it''s'"]
    assert rest.strip() == "SELECT 1"


def test_format_table():
    out = cli.format_table(["a", "bb"], [(1, None), (22, "x")])
    assert out.splitlines()[0] == "a  | bb"
    assert "NULL" in out and out.endswith("(2 rows)")


@pytest.fixture
def server():
    from nokey_server import NoKeyTCPServer
    srv = NoKeyTCPServer("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.address
    srv.shutdown(); srv.server_close()


def test_shell_session_end_to_end(server, tmp_path, capsys):
    host, port = server
    vault = str(tmp_path / "v")
    base = ["-h", host, "-p", str(port), "--vault", vault]
    assert cli.main(base + ["-c", "CREATE TABLE t (id INT PLAIN, v INT ENC)",
                            "-c", "INSERT INTO t (id, v) VALUES (1, 10)",
                            "-c", "INSERT INTO t (id, v) VALUES (2, 32)"]) == 0
    capsys.readouterr()
    assert cli.main(base + ["-c", "SELECT SUM(v), COUNT(*) FROM t"]) == 0
    out = capsys.readouterr().out
    assert "42" in out and "(1 row)" in out
    # errors give a non-zero exit and a message, not a traceback
    assert cli.main(base + ["-c", "SELECT nope FROM t"]) == 1
    assert "ERROR" in capsys.readouterr().err


def test_missing_token_env_is_reported(monkeypatch, capsys):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    assert cli.main(["--token-env", "NOPE_TOKEN"]) == 2
