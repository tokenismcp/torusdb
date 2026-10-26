# SPDX-License-Identifier: Apache-2.0
"""Shared-wire expressions (expr_mode="shared", the default) against a REAL keyless TCP server and
the Python driver: depth 2/3/5, mixed + - * /, SUM of products, division by an encrypted value,
transactions / rollback / disconnect freeing wires, cap and TTL errors, roles, tampering in
authenticated mode, the abort-oracle trace, and an audit of everything the server process is sent."""
import json
import threading
import time
from fractions import Fraction

import pytest

import torussql
from nokey_server import NoKeyTCPServer, ServerConfig
from torusdb_core.protocol import N, encode

F = Fraction

ROWS = [(1, 5, 2, 3, 4, 5, F(1, 2), 10), (2, 5, -5, 7, 2, -1, F(-3, 4), -3),
        (3, 9, 6, -4, 3, 8, F(2, 3), 7), (4, 9, 0, 11, -6, 2, F(5), 0),
        (5, 9, 13, -2, 5, -7, F(-1, 7), 4)]
NAMES = ["id", "dept", "a", "b", "c", "d", "r", "s"]


class Running:
    def __init__(self, db=None, **cfg):
        cfg.setdefault("auth_fail_delay", 0.0)
        self.srv = NoKeyTCPServer("127.0.0.1", 0, db, config=ServerConfig(**cfg))
        self.host, self.port = self.srv.address
        self.engine = self.srv.engine
        self.log = []                                    # (method, args) as the server receives them
        real = self.engine.dispatch

        def spy(method, args, session=None):
            self.log.append((method, args))
            out = real(method, args, session)
            hook = getattr(self, "reply_hook", None)
            return hook(method, args, out) if hook else out
        self.engine.dispatch = spy
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def wires(self):
        """(live wires, elements) summed over every session, and the server-wide budget in use."""
        w = e = 0
        for s in list(self.engine._sessions.values()):
            if s.wires is not None:
                st = s.wires.stats()
                w, e = w + st["wires"], e + st["elements"]
        return w, e, self.engine._wire_budget.used

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.t.join(timeout=5)


@pytest.fixture
def server():
    s = Running()
    yield s
    s.stop()


def _lit(v):
    return f"FRAC({v.numerator},{v.denominator})" if isinstance(v, F) and v.denominator != 1 else str(int(v))


def seed(conn):
    conn.execute("CREATE TABLE t (id INT PLAIN, dept INT PLAIN, a INT PAIRED, b INT PAIRED, "
                 "c INT PAIRED, d INT PAIRED, r RATIONAL PAIRED, s RATIONAL ENC)")
    for row in ROWS:
        conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES (" +
                     ", ".join(_lit(v) for v in row) + ")")


def col(name):
    k = NAMES.index(name)
    return [row[k] for row in ROWS]


def prod(*names):
    out = [1] * len(ROWS)
    for n in names:
        out = [x * y for x, y in zip(out, col(n))]
    return out


# ── results over the wire ────────────────────────────────────────────────────
@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_depth_2_3_5_products_mixed_operators_and_sums(server, auth):
    with torussql.connect(server.host, server.port, authenticated=auth) as conn:
        seed(conn)
        for names, depth in ((("a", "b", "c"), 2), (("a", "b", "c", "d"), 3),
                             (("a", "b", "c", "d", "a", "b"), 5)):
            assert conn.execute("SELECT " + "*".join(names) + " FROM t").rows == [[prod(*names)]]
            assert conn.client.last_expr_cost["mult_rounds"] == depth
            assert conn.client.last_expr_cost["mode"] == "shared"
            assert conn.client.last_expr_cost["requests"] == depth + 1
        a, b, c, d, s = (col(k) for k in "abcds")
        assert conn.execute("SELECT (a+b)*(c-d)*a - b*c/d + s/2 FROM t WHERE id <> 4").rows == \
            [[[(x + y) * (z - w) * x - F(y * z, w) + F(sv, 2) for i, (x, y, z, w, sv)
               in enumerate(zip(a, b, c, d, s)) if i != 3]]]
        assert conn.execute("SELECT SUM(a*b*c*d), SUM(a*b)*SUM(c) FROM t").rows == \
            [[sum(prod("a", "b", "c", "d")), sum(prod("a", "b")) * sum(c)]]
        assert conn.execute("SELECT dept, SUM(a*b*c)/COUNT(*) FROM t GROUP BY dept ORDER BY dept").rows == \
            [[5, F(sum(prod("a", "b", "c")[:2]), 2)], [9, F(sum(prod("a", "b", "c")[2:]), 3)]]


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_division_by_an_encrypted_value(server, auth):
    with torussql.connect(server.host, server.port, authenticated=auth) as conn:
        seed(conn)
        a, b, c, r = col("a"), col("b"), col("c"), col("r")
        assert conn.execute("SELECT a/b, r/c, 12/c FROM t").rows == \
            [[[F(x, y) for x, y in zip(a, b)], [x / y for x, y in zip(r, c)], [F(12, y) for y in c]]]
        assert conn.execute("SELECT a/(b*c)*r FROM t").rows == \
            [[[F(x, y * z) * w for x, y, z, w in zip(a, b, c, r)]]]
        assert conn.execute("SELECT SUM(a*b)/SUM(c) FROM t").rows == [[F(sum(prod("a", "b")), sum(c))]]
        assert conn.client.last_expr_cost["inversions"] == 1
        with pytest.raises(torussql.DataError, match="division by zero"):
            conn.execute("SELECT a/(d-d) FROM t")
    assert server.wires()[:2] == (0, 0)


# ── the wire store's lifecycle ───────────────────────────────────────────────
def test_wires_are_freed_after_every_query_success_or_error(server):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        conn.execute("SELECT a*b*c*d FROM t")
        assert server.wires() == (0, 0, 0)
        conn.execute("UPDATE t SET b = 0 WHERE id = 2")
        with pytest.raises(torussql.DataError, match="division by zero"):
            conn.execute("SELECT a/b FROM t")                        # runs to the end, then raises
        assert server.wires() == (0, 0, 0)
        conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES "
                     f"(9, 9, {2 ** 70}, {2 ** 70}, 1, 1, 1, 1)")
        with pytest.raises(torussql.DataError):                      # OutOfBudget at the final decode
            conn.execute("SELECT a*b*c FROM t WHERE id = 9")
        assert server.wires() == (0, 0, 0)
        # success and end-of-protocol errors free everything inside the last wire_exec; an abort in
        # mid-protocol (below) needs the explicit wire_free
        assert "wire_free" not in [m for m, _ in server.log]


def _raw_load(conn, wid="w1", rows=(0, 1, 2)):
    return conn._wire.call("wire_exec", [[["load", wid, "t", "a", list(rows), False]]])


def test_a_transaction_end_frees_the_sessions_wires_and_disconnect_too(server):
    conn = torussql.connect(server.host, server.port)
    seed(conn)
    conn.begin()
    _raw_load(conn)
    assert server.wires()[0] == 1
    conn.rollback()
    assert server.wires()[:2] == (0, 0)
    conn.begin()
    _raw_load(conn)
    conn.commit()
    assert server.wires()[:2] == (0, 0)
    with pytest.raises(torussql.OperationalError, match="unknown wire"):
        conn._wire.call("wire_exec", [[["reveal", "w1", 0, 3]]])
    _raw_load(conn)
    other = torussql.connect(server.host, server.port)
    _raw_load(other, "w2")
    assert server.wires()[0] == 2
    other.close()                                                    # disconnect: wires dropped
    deadline = time.time() + 5
    while server.wires()[0] != 1 and time.time() < deadline:
        time.sleep(0.02)
    assert server.wires()[0] == 1
    conn.close()
    deadline = time.time() + 5
    while server.wires() != (0, 0, 0) and time.time() < deadline:
        time.sleep(0.02)
    assert server.wires() == (0, 0, 0)


def test_wires_are_private_to_their_session(server):
    c1 = torussql.connect(server.host, server.port)
    seed(c1)
    c2 = torussql.connect(server.host, server.port)
    _raw_load(c1, "w1")
    with pytest.raises(torussql.OperationalError, match="unknown wire"):
        c2._wire.call("wire_exec", [[["reveal", "w1", 0, 3]]])
    assert c2._wire.call("wire_free", [["w1"]]) == 0                  # cannot free another session's wires
    assert server.wires()[0] == 1
    c1.close(); c2.close()


def test_a_timed_out_transaction_frees_its_wires():
    s = Running(tx_timeout=0.3, tx_idle_timeout=0.0)
    try:
        c1 = torussql.connect(s.host, s.port)
        seed(c1)
        c1.begin()
        _raw_load(c1)
        assert s.wires()[0] == 1
        time.sleep(0.5)
        c2 = torussql.connect(s.host, s.port)
        c2.execute("SELECT id FROM t")                               # any request expires the stale tx
        deadline = time.time() + 5
        while s.wires()[0] and time.time() < deadline:
            time.sleep(0.02)
        assert s.wires()[0] == 0
        c1.close(); c2.close()
    finally:
        s.stop()


def test_expressions_see_the_open_transaction_and_rollback_restores(server):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        before = conn.execute("SELECT SUM(a*b*c) FROM t").rows
        conn.begin()
        conn.execute("INSERT INTO t (id, dept, a, b, c, d, r, s) VALUES (6, 5, 10, 10, 10, 1, 1, 1)")
        assert conn.execute("SELECT SUM(a*b*c) FROM t").rows[0][0] == before[0][0] + 1000
        conn.rollback()
        assert conn.execute("SELECT SUM(a*b*c) FROM t").rows == before
        assert server.wires() == (0, 0, 0)


# ── caps, TTL, roles ─────────────────────────────────────────────────────────
def test_session_memory_cap_is_a_clear_error_and_leaves_nothing_behind():
    s = Running(wire_max_elements=14)
    try:
        with torussql.connect(s.host, s.port) as conn:
            seed(conn)
            assert conn.execute("SELECT SUM(a+b) FROM t").rows        # a few width-1 wires: fine
            with pytest.raises(torussql.OperationalError, match="memory cap"):
                conn.execute("SELECT a*b*c*d FROM t")
            assert s.wires() == (0, 0, 0)
    finally:
        s.stop()


def test_wire_count_cap_and_server_wide_cap():
    s = Running(wire_max_wires=3)
    try:
        with torussql.connect(s.host, s.port) as conn:
            seed(conn)
            with pytest.raises(torussql.OperationalError, match="too many live wires"):
                conn.execute("SELECT a*b*c*d + a*b - c*d FROM t")
    finally:
        s.stop()
    s = Running(wire_max_total_elements=12)
    try:
        with torussql.connect(s.host, s.port) as conn:
            seed(conn)
            with pytest.raises(torussql.OperationalError, match="server-wide"):
                conn.execute("SELECT a*b*c*d FROM t")
            assert s.wires() == (0, 0, 0)
    finally:
        s.stop()


def test_unused_wires_expire_after_the_ttl():
    s = Running(wire_ttl=0.3)
    try:
        with torussql.connect(s.host, s.port) as conn:
            seed(conn)
            _raw_load(conn)
            assert s.wires()[0] == 1
            time.sleep(0.6)
            with pytest.raises(torussql.OperationalError, match="expired"):
                conn._wire.call("wire_exec", [[["reveal", "w1", 0, 3]]])
            assert s.wires() == (0, 0, 0)
            _raw_load(conn, "w3")
            other = torussql.connect(s.host, s.port)
            time.sleep(1.4)
            other.execute("SELECT id FROM t")
            other._wire.call("wire_exec", [[["load", "x", "t", "a", [0], False]]])   # a wire request sweeps
            deadline = time.time() + 3
            while s.wires()[0] > 1 and time.time() < deadline:
                time.sleep(0.05)
            assert s.wires()[0] == 1                                    # w3 expired, only x is left
            other.close()
    finally:
        s.stop()


def test_chunking_by_the_servers_advertised_request_size():
    s = Running(wire_max_request_elements=200, wire_max_ops=12)
    try:
        with torussql.connect(s.host, s.port, authenticated=True) as conn:
            conn.execute("CREATE TABLE z (a INT PAIRED, b INT PAIRED, c INT PAIRED)")
            rows = [(i - 30, 3 * i + 1, 9 - i) for i in range(70)]
            conn.cursor().executemany("INSERT INTO z (a, b, c) VALUES (%s, %s, %s)", rows)
            assert conn.execute("SELECT a*b*c/b FROM z").rows == [[[F(a * b * c, b) for a, b, c in rows]]]
            assert conn.execute("SELECT SUM(a*b*c) FROM z").rows == [[sum(a * b * c for a, b, c in rows)]]
            assert conn.client.last_expr_cost["requests"] >= 4
        assert s.wires() == (0, 0, 0)
    finally:
        s.stop()


TOKENS = {"admin-token-0123456789": "admin", "rw-token-0123456789abc": "rw", "ro-token-0123456789abc": "ro"}


def test_roles_the_wire_rpcs_are_reads_and_need_authentication(tmp_path):
    s = Running(tokens=dict(TOKENS))
    try:
        vault = str(tmp_path / "v")
        with torussql.connect(s.host, s.port, token="rw-token-0123456789abc", vault_path=vault,
                              allow_insecure_token=True) as rw:
            seed(rw)
        with torussql.connect(s.host, s.port, token="ro-token-0123456789abc", vault_path=vault,
                              allow_insecure_token=True, trust_server_schema=True) as ro:
            assert ro.execute("SELECT a*b*c FROM t").rows == [[prod("a", "b", "c")]]    # a read-only role may
            with pytest.raises(torussql.AuthenticationError):                          # ... but not write
                ro.execute("UPDATE t SET a = 1 WHERE id = 1")
        import socket
        from torussql.framing import read_frame, write_frame
        with socket.create_connection((s.host, s.port), timeout=5) as sock:      # no token
            f = sock.makefile("rwb")
            write_frame(f, json.dumps({"m": "wire_exec", "a": [[]]}).encode(), 1 << 20)
            f.flush()
            assert json.loads(read_frame(f, 1 << 20))["err"].startswith("Unauthenticated")
    finally:
        s.stop()


def test_a_server_without_the_wire_rpcs_is_told_apart_from_the_hello_and_gets_a_clear_error(tmp_path):
    s = Running()
    s.engine._limits = lambda: {"max_items": 200000}               # what a pre-2.1 server publishes
    vault = str(tmp_path / "v")
    try:
        conn = torussql.connect(s.host, s.port, vault_path=vault)
        seed(conn)
        with pytest.raises(torussql.DataError, match="expr_mode='owner'"):
            conn.execute("SELECT a*b*c FROM t")
        conn.close()
        with torussql.connect(s.host, s.port, expr_mode="owner", vault_path=vault) as conn:
            assert conn.execute("SELECT a*b*c FROM t").rows == [[prod("a", "b", "c")]]
        with pytest.raises(torussql.ProgrammingError):
            torussql.connect(s.host, s.port, expr_mode="bogus")
    finally:
        s.stop()


# ── malicious server: integrity ──────────────────────────────────────────────
def _tamper_reveals(server, delta=1):
    def hook(method, args, out):
        if method == "wire_exec":
            for op, res in zip(args[0], out):
                if op[0] == "reveal":
                    res[0][0] = str((int(res[0][0]) + delta) % N)
        return out
    server.reply_hook = hook


def test_tampered_reply_is_detected_when_authenticated_and_silently_wrong_otherwise(server):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        _tamper_reveals(server)
        with pytest.raises(torussql.IntegrityError, match="MAC"):
            conn.execute("SELECT a*b*c FROM t")
        server.reply_hook = None
        assert conn.execute("SELECT a*b*c FROM t").rows == [[prod("a", "b", "c")]]
    server.log.clear()
    with torussql.connect(server.host, server.port) as conn:
        conn.execute("CREATE TABLE u (a INT PAIRED, b INT PAIRED)")
        conn.execute("INSERT INTO u (a, b) VALUES (6, 7)")
        _tamper_reveals(server, 100)
        # pinned limitation: without authenticated=True a lying server is NOT detected
        assert conn.execute("SELECT a*b*a FROM u").rows == [[[6 * 7 * 6 + 100]]]


def test_tampered_stored_cell_is_detected_end_to_end(server):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        tbl = server.engine.srv._rows["t"]
        tbl[1]["b"] = (tbl[1]["b"] + 9) % N
        with pytest.raises(torussql.IntegrityError):
            conn.execute("SELECT a*b*c*d FROM t")
        with pytest.raises(torussql.IntegrityError):
            conn.execute("SELECT a/b FROM t")
        assert server.wires() == (0, 0, 0)
        assert "wire_free" in [m for m, _ in server.log]          # aborted mid-protocol: explicit cleanup


# ── the abort oracle, at the server process ──────────────────────────────────
def _wire_shape(log):
    """Methods and, for wire_exec, each op's name and the LENGTHS / small ints of its arguments:
    everything except the ring values themselves."""
    out = []
    for m, args in log:
        if m != "wire_exec":
            out.append(m)
            continue
        ops = []
        for op in args[0]:
            sh = []
            for x in op[1:]:
                if isinstance(x, list):
                    sh.append(len(x))
                elif isinstance(x, dict):
                    sh.append({k: len(v) for k, v in sorted(x.items())})
                elif isinstance(x, bool) or x is None:
                    sh.append(x)
                elif isinstance(x, int) and x < 10 ** 6:
                    sh.append(x)
                else:
                    sh.append("*")                    # ids, names and ring scalars
            ops.append((op[0], tuple(sh)))
        out.append(ops)
    return out


@pytest.mark.parametrize("sql", ["SELECT a/b FROM t", "SELECT SUM(a/b*c) FROM t", "SELECT c*d/(a-a+b)*a FROM t"])
def test_zero_denominator_does_not_change_the_servers_view_structure(server, sql):
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)

        def trace(zero):
            n0 = len(server.log)
            if zero:
                with pytest.raises(torussql.DataError, match="division by zero"):
                    conn.execute(sql)
            else:
                conn.execute(sql)
            return _wire_shape(server.log[n0:])
        clean = trace(False)
        conn.execute("UPDATE t SET b = 0 WHERE id IN (2, 4)")
        assert trace(True) == clean
        assert sum(1 for x in clean if isinstance(x, list)) >= 3        # several wire exchanges happened


# ── everything the server process is sent ────────────────────────────────────
def test_server_process_gets_only_uniform_shares_and_public_data(server):
    """Raw JSON log of every wire request: no mask, no alpha, no encoded plaintext/intermediate/
    inverse, no read of an operand cell; the owner shares of the openings and the triple shares
    are huge uniform-looking residues."""
    with torussql.connect(server.host, server.port, authenticated=True) as conn:
        seed(conn)
        n0 = len(server.log)
        qs = ["SELECT a*b*c*d FROM t", "SELECT a/b FROM t", "SELECT SUM(a*b*c)/SUM(d) FROM t",
              "SELECT r/c*a + s/4 FROM t"]
        for q in qs:
            conn.execute(q)
        sent = server.log[n0:]
        masks = set(conn.client._masks.values())
        alpha = conn.client._alpha
    methods = {m for m, _ in sent}
    assert methods <= {"wire_exec", "wire_free", "matching_rowids", "plain_cells"}, methods
    seen = set()

    def ints(x):
        if isinstance(x, bool):
            return
        if isinstance(x, int):
            seen.add(x)
        elif isinstance(x, str):
            try:
                seen.add(int(x))
            except ValueError:
                pass
        elif isinstance(x, dict):
            for v in x.values():
                ints(v)
        elif isinstance(x, list):
            for v in x:
                ints(v)
    for _m, args in sent:
        ints(json.loads(json.dumps(args)))
    assert not (masks & seen) and alpha not in seen
    a, b, c, d, r, s = (col(k) for k in "abcdrs")
    secrets_ = set()
    for i in range(5):
        for v in (a[i], b[i], c[i], d[i], r[i], s[i], a[i] * b[i], a[i] * b[i] * c[i],
                  a[i] * b[i] * c[i] * d[i], F(a[i], b[i]), F(1, b[i]), r[i] / c[i],
                  r[i] / c[i] * a[i], F(s[i], 4), F(1, d[i]) if d[i] else 0):
            e = encode(v)
            if not 0 <= e < 1000:
                secrets_.add(e)
    secrets_ -= {encode(F(1, 4)), encode(F(-1, 4))}                 # public constant of the query
    assert not (secrets_ & seen), "an encoded plaintext/intermediate reached the server process"
    shares = []
    for m, args in sent:
        if m == "wire_exec":
            for op in args[0]:
                if op[0] == "mul":
                    shares += [int(x) for k in ("u", "v", "w", "eo", "go") for x in op[4][k]]
    assert shares and sum(1 for x in shares if x > N // 100) > 0.95 * len(shares)
    assert len(set(shares)) == len(shares)
