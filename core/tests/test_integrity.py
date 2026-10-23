# SPDX-License-Identifier: Apache-2.0
"""Information-theoretic integrity (no-key paper §IX): a cheating server that
returns forged affine results is caught by the owner's SPDZ-style MAC check,
except with probability 1/n — no computational assumption."""
import pytest

from torusdb_core.errors import IntegrityError
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer


class CheatingServer(NoKeyServer):
    """A malicious server that tampers with results/storage. It cannot fix the
    parallel MAC column (no key), so the owner catches it."""
    cheat = False           # forge affine aggregates
    cheat_cell = False      # tamper a stored operand (caught on read/×)
    cheat_eg = False        # forge a product term e·g in DOT/×

    def blinded_sum(self, table, col, idxs):
        v = super().blinded_sum(table, col, idxs)
        return v + 1 if self.cheat else v

    def blinded_scaled_sum(self, table, col, idxs, k):
        v = super().blinded_scaled_sum(table, col, idxs, k)
        return v + 1 if self.cheat else v

    def blinded_per_row_scaled(self, table, col, idxs, k):
        v = super().blinded_per_row_scaled(table, col, idxs, k)
        return [x + 1 for x in v] if self.cheat else v

    def blinded_cell(self, table, col, idx):
        v = super().blinded_cell(table, col, idx)
        # tamper only the real value column, not its __mac__ companion
        return v + 1 if (self.cheat_cell and not col.startswith("__mac__")) else v

    def blinded_cells(self, table, col, idxs):
        v = super().blinded_cells(table, col, idxs)
        if self.cheat_cell and not col.startswith("__mac__"):
            return [x + 1 for x in v]
        return v

    def mult_combine_batch(self, openings):
        out = super().mult_combine_batch(openings)
        return [x + 1 for x in out] if self.cheat_eg else out


def _seed(client):
    client.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, "
                   "salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)")
    for (i, d, s, r, h) in [(1, 5, 8000, 50, 40), (2, 5, 9000, 60, 35),
                            (3, 9, 7000, 45, 40)]:
        client.execute(f"INSERT INTO emp (id, dept, salary, rate, hours) "
                       f"VALUES ({i}, {d}, FRAC({s},1), {r}, {h})")


# ── honest server: authenticated results are correct ─────────────────────────
def test_authenticated_results_are_correct():
    client = NoKeyClient(NoKeyServer(), authenticated=True)
    _seed(client)
    assert client.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]
    assert client.execute("SELECT AVG(salary) FROM emp WHERE dept = 5").rows \
        == [[8500]]
    assert client.execute("SELECT 12 * SUM(salary) FROM emp").rows == [[288000]]
    assert client.execute("SELECT 12 * salary FROM emp WHERE dept = 5").rows \
        == [[[96000, 108000]]]


# ── cheating server is detected ──────────────────────────────────────────────
def test_forged_sum_is_caught():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    assert client.execute("SELECT SUM(salary) FROM emp").rows == [[24000]]  # honest
    server.cheat = True
    with pytest.raises(IntegrityError):
        client.execute("SELECT SUM(salary) FROM emp")


def test_forged_scaled_sum_is_caught():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    server.cheat = True
    with pytest.raises(IntegrityError):
        client.execute("SELECT 12 * SUM(salary) FROM emp")


def test_forged_per_row_is_caught():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    server.cheat = True
    with pytest.raises(IntegrityError):
        client.execute("SELECT 12 * salary FROM emp")


# ── multiplication / DOT integrity (operand MACs + product-term check) ───────
def test_authenticated_dot_is_correct():
    client = NoKeyClient(NoKeyServer(), authenticated=True)
    _seed(client)
    # 50*40 + 60*35 + 45*40 = 5900
    assert client.execute("SELECT DOT(rate, hours) FROM emp").rows == [[5900]]
    assert client.execute("SELECT rate * hours FROM emp WHERE dept = 5").rows \
        == [[[2000, 2100]]]


def test_tampered_operand_is_caught_on_dot():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    server.cheat_cell = True                       # corrupt a stored operand
    with pytest.raises(IntegrityError, match="tampered"):
        client.execute("SELECT DOT(rate, hours) FROM emp")


def test_tampered_operand_is_caught_on_read():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    server.cheat_cell = True
    with pytest.raises(IntegrityError, match="tampered"):
        client.execute("SELECT salary FROM emp")


def test_forged_product_term_is_caught():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=True)
    _seed(client)
    server.cheat_eg = True                          # forge e·g in Π_mult
    with pytest.raises(IntegrityError, match="product term"):
        client.execute("SELECT DOT(rate, hours) FROM emp")


# ── unauthenticated mode: no MAC, a forgery passes silently (the threat) ─────
def test_unauthenticated_does_not_detect():
    server = CheatingServer()
    client = NoKeyClient(server, authenticated=False)
    _seed(client)
    server.cheat = True
    # without the MAC the forged result is returned as if correct — this is
    # exactly what the integrity add-on defends against.
    assert client.execute("SELECT SUM(salary) FROM emp").rows != [[24000]]
