# SPDX-License-Identifier: Apache-2.0
"""Regression tests for findings of the independent audit (one per finding)."""
from __future__ import annotations

import threading

import pytest

import torussql
from torusdb_core.nokey_engine import NoKeyServer
from torussql.nokey import ProgrammingError




@pytest.fixture
def db():
    from nokey_server import NoKeyTCPServer
    srv = NoKeyTCPServer("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown(); srv.server_close()


def test_server_cannot_relabel_encrypted_column_as_plain(db):
    """F2: a hostile server answering `schema` with policy 'plain' must never
    receive plaintext from a client that learned the table from it."""
    with torussql.connect(*db.address) as owner:
        owner.execute("CREATE TABLE s (id INT PLAIN, secret INT ENC)")

    c = torussql.connect(*db.address, sync_schema=False)
    real = c._wire.call

    def lying(method, args):
        r = real(method, args)
        if method == "schema":
            return [[n, t, "plain"] for (n, t, _p) in r]
        return r
    c._wire.call = lying
    assert c.sync_schema() == ["s"]
    with pytest.raises(ProgrammingError, match="learned from the server"):
        c.execute("INSERT INTO s (id, secret) VALUES (1, 424242424242)")
    with pytest.raises(ProgrammingError, match="learned from the server"):
        c.execute("UPDATE s SET secret = 424242424242")
    c.close()

    # the explicit opt-in still works for operators who verified the schema
    c2 = torussql.connect(*db.address, trust_server_schema=True)
    c2.execute("INSERT INTO s (id, secret) VALUES (1, 7)")
    assert c2.execute("SELECT COUNT(*) FROM s").rows == [[1]]
    c2.close()
