# SPDX-License-Identifier: Apache-2.0
"""No-key TorusSQL engine — SQL over the no-key delegation protocol.

Proves the architecture the paper requires: the server holds no keys and
never decrypts; encrypted aggregation/scaling/products run on blinded
scalars; the client unblinds at its own boundary.
"""
from fractions import Fraction

import pytest

from torusdb_core.protocol import decode
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer


@pytest.fixture
def db():
    server = NoKeyServer()
    client = NoKeyClient(server)
    client.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, "
                   "salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)")
    for (i, d, s, r, h) in [(1, 5, 8000, 50, 40),
                            (2, 5, 9000, 60, 35),
                            (3, 9, 7000, 45, 40)]:
        client.execute(f"INSERT INTO emp (id, dept, salary, rate, hours) "
                       f"VALUES ({i}, {d}, FRAC({s},1), {r}, {h})")
    return client, server


# ── correctness through the no-key protocol ──────────────────────────────────
def test_sum_pi_lin(db):
    client, _ = db
    assert client.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
    assert client.execute("SELECT SUM(salary) FROM emp WHERE dept = 5").rows \
        == [[17000]]


def test_avg_pi_lin(db):
    client, _ = db
    assert client.execute("SELECT AVG(salary) FROM emp").rows == [[8000]]
    assert client.execute("SELECT AVG(salary) FROM emp WHERE dept = 5").rows \
        == [[8500]]


def test_count_and_plain_passthrough(db):
    client, _ = db
    assert client.execute("SELECT COUNT(*) FROM emp").rows == [[3]]
    assert client.execute("SELECT id, dept FROM emp ORDER BY id DESC").rows \
        == [[3, 9], [2, 5], [1, 5]]


def test_scalar_mul_per_row_and_scaled_sum(db):
    client, _ = db
    assert client.execute("SELECT 12 * salary FROM emp WHERE dept = 5").rows \
        == [[[96000, 108000]]]
    assert client.execute("SELECT 12 * SUM(salary) FROM emp").rows == [[288000]]


def test_dot_pi_mult(db):
    client, _ = db
    # 50*40 + 60*35 + 45*40 = 2000 + 2100 + 1800 = 5900
    assert client.execute("SELECT DOT(rate, hours) FROM emp").rows == [[5900]]


def test_per_row_ct_mul_pi_mult(db):
    client, _ = db
    assert client.execute("SELECT rate * hours FROM emp WHERE dept = 5").rows \
        == [[[2000, 2100]]]


def test_min_max_aliases(db):
    client, _ = db
    rs = client.execute("SELECT MIN(id) AS lo, MAX(dept) AS hi FROM emp")
    assert rs.columns == ["lo", "hi"] and rs.rows == [[1, 9]]


# ── the architecture itself: server is keyless and never sees plaintext ──────
def test_server_holds_no_keys_or_masks(db):
    _client, server = db
    blob = repr(vars(server))
    for forbidden in ("secret", "keypair", "_masks", "mask", "sk", "pk"):
        assert forbidden not in blob, f"server leaked {forbidden!r}"
    # masks live only on the client
    assert not hasattr(server, "_masks")


def test_server_stores_only_blinded_scalars_for_encrypted_columns(db):
    client, server = db
    # the raw stored cells for an ENC column must NOT equal the plaintext
    # encoding — they are one-time-padded scalars in Z/nZ.
    from torusdb_core.protocol import encode
    plain_codes = {encode(8000), encode(9000), encode(7000)}
    stored = {server.blinded_cell("emp", "salary", i) for i in range(3)}
    assert stored.isdisjoint(plain_codes), "stored cells are not blinded!"
    # and the server cannot recover the values (it has no mask/key); only the
    # client's reveal (which uses the mask) returns the plaintext.
    assert client._reveal("emp", "salary", 0) == 8000


def test_blinded_values_are_high_entropy(db):
    _client, server = db
    # blinded scalars are full-width mod n (one-time pad), not small encodings
    for i in range(3):
        assert server.blinded_cell("emp", "salary", i) > 2 ** 200
