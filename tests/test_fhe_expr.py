# SPDX-License-Identifier: Apache-2.0
"""v0.6.1: arithmetic expressions over FHE columns, end to end against a real keyless server.

What is computed where (see core/torusdb_core/fhe_expr.py):
* delegated (default without authentication): the SERVER builds the operand ciphertexts by public linear
  combination and pairs them (SUM(L*R), SUM(..)*SUM(..)); the owner only decrypts GT results and applies
  the public affine part;
* local (default with authentication): the owner recomputes from verified cells / verified SUMs.
Differential tests compare every answer with exact int/Fraction arithmetic, on both pairing back ends."""
from __future__ import annotations

import base64
import json
import random
from fractions import Fraction as F

import pytest

import torussql
from torusdb_core import fhe
from torusdb_core.errors import IntegrityError as CoreIntegrity
from torusdb_core.fhe import FheError
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from test_ops import Running

HAVE_MCL = "mcl" in fhe.available_backends()
BACKENDS = ["pyecc"] + (["mcl"] if HAVE_MCL else [])
COLS = ["a", "b", "c", "d"]
SCHEMA = "CREATE TABLE t (id INT PLAIN, g INT PLAIN, a INT FHE, b INT FHE, c INT FHE, d INT FHE)"
_KEYS: dict = {}


def key_for(backend, rng=10 ** 6):
    k = (backend, rng)
    if k not in _KEYS:
        _KEYS[k] = fhe.FheKey(value_range=rng, backend=backend)
    return _KEYS[k]


@pytest.fixture(autouse=True)
def _clean_grammar(monkeypatch):
    """`SUM(x*y)` over two bare FHE columns (= DOT) stays rejected by default for v0.5 conformance; the grammar
    tests below switch that single spelling off (test_bare_sum_of_two_columns_stays_a_dot covers the default)."""
    from torussql_parser import fhe_expr
    monkeypatch.setattr(fhe_expr, "REJECT_BARE_COLUMN_PRODUCT", False)


@pytest.fixture(params=BACKENDS)
def backend(request, monkeypatch):
    """The pairing back end of the SERVER and of the owner's key."""
    monkeypatch.setenv("TORUSDB_FHE_BACKEND", request.param)
    return request.param


def rows_for(backend, seed=1):
    r = random.Random(seed)
    n = 8 if backend == "mcl" else 3
    return [(i + 1, 1 + (i % 2), *[r.randint(-12, 12) for _ in COLS]) for i in range(n)]


def load(c, rows):
    c.execute(SCHEMA)
    for row in rows:
        c.execute("INSERT INTO t (id, g, a, b, c, d) VALUES (" + ", ".join(str(v) for v in row) + ")")


def col(rows, name):
    return [r[2 + COLS.index(name)] for r in rows]


# ── a tiny reference: random FHE expressions with an exact int/Fraction evaluator ─────────────────────
class Ref:
    """Generates (sql, evaluator) pairs. Evaluators take the selected rows and return Fraction | None."""

    def __init__(self, rng):
        self.rng = rng

    def lin(self):
        r = self.rng
        cols = r.sample(COLS, r.randint(1, 3))
        coefs = {c: r.choice([-3, -2, -1, 1, 1, 2, 3]) for c in cols}
        const = r.choice([0, 0, 1, -2, 5])
        return coefs, const

    @staticmethod
    def row_sql(coefs, const):
        s = " + ".join(f"({k})*{c}" for c, k in coefs.items())
        return f"({s} + ({const}))" if const else f"({s})"

    @staticmethod
    def agg_sql(coefs, const):
        s = " + ".join(f"({k})*SUM({c})" for c, k in coefs.items())
        return f"({s} + ({const}))" if const else f"({s})"

    @staticmethod
    def row_val(coefs, const, row):
        return sum(k * row[2 + COLS.index(c)] for c, k in coefs.items()) + const

    def term(self):
        kind = self.rng.choice(["sumprod", "sumprod", "aggprod", "avgprod", "sumlin"])
        (lc, lk), (rc, rk) = self.lin(), self.lin()
        if kind == "sumprod":
            sql = f"SUM({self.row_sql(lc, lk)}*{self.row_sql(rc, rk)})"
            return sql, True, lambda rows: F(sum(self.row_val(lc, lk, r) * self.row_val(rc, rk, r) for r in rows))
        if kind == "avgprod":
            sql = f"AVG({self.row_sql(lc, lk)}*{self.row_sql(rc, rk)})"
            return sql, True, lambda rows: (F(sum(self.row_val(lc, lk, r) * self.row_val(rc, rk, r)
                                                  for r in rows), len(rows)) if rows else None)
        if kind == "aggprod":
            sql = f"{self.agg_sql(lc, lk)}*{self.agg_sql(rc, rk)}"
            # SUM(col) of the selection; the constant of an AGGREGATE operand is added once
            return sql, True, lambda rows: F((sum(k * sum(col_ for col_ in (r[2 + COLS.index(c)] for r in rows))
                                                   for c, k in lc.items()) + lk)
                                             * (sum(k * sum(r[2 + COLS.index(c)] for r in rows)
                                                    for c, k in rc.items()) + rk))
        sql = f"SUM({self.row_sql(lc, lk)})"
        return sql, False, lambda rows: F(sum(self.row_val(lc, lk, r) for r in rows))

    def expr(self):
        while True:
            parts = [self.term() for _ in range(self.rng.randint(1, 3))]
            if any(p[1] for p in parts):
                break
        sql, fns = "", []
        for i, (t, _p, fn) in enumerate(parts):
            m, d = self.rng.choice([1, 1, 2, -1, 3, -4]), self.rng.choice([1, 1, 2, 3, 4])
            sql += (" + " if i else "") + f"({m})*{t}" + (f"/{d}" if d != 1 else "")
            fns.append((F(m, d), fn))
        k0 = self.rng.choice([0, 0, 7, -3])
        if k0:
            sql += f" + ({k0})"

        def ev(rows):
            tot = F(k0)
            for coef, fn in fns:
                v = fn(rows)
                if v is None:
                    return None
                tot += coef * v
            return tot
        return sql, ev


def norm(x):
    if x is None:
        return None
    x = F(x)
    return int(x) if x.denominator == 1 else x


def check(c, where_rows, where_sql, seed, count, mode_tag=""):
    ref = Ref(random.Random(seed))
    for _ in range(count):
        sql, ev = ref.expr()
        want = norm(ev(where_rows))
        got = c.execute(f"SELECT {sql} FROM t{where_sql}").rows
        assert got == [[want]], (sql, got, want, mode_tag)


MODES = [  # (authenticated, fhe_dot_mode, who multiplies)
    (False, "auto", "server"),
    (True, "auto", "owner"),
    (True, "delegated", "server"),
    (False, "local", "owner"),
]


@pytest.mark.parametrize("auth,mode,who", MODES)
def test_randomized_differential_against_exact_arithmetic(backend, auth, mode, who):
    rows = rows_for(backend)
    s = Running()
    try:
        with s.connect(fhe_key=key_for(backend), authenticated=auth, fhe_dot_mode=mode) as c:
            load(c, rows)
            n = 14 if backend == "mcl" else 2
            tag = f"{backend}/{auth}/{mode}"
            check(c, rows, "", seed=11, count=n, mode_tag=tag)
            sel = [r for r in rows if r[0] % 2 == 1]
            check(c, sel, " WHERE id = 1 OR id = 3 OR id = 5 OR id = 7", seed=12, count=max(1, n // 3), mode_tag=tag)
    finally:
        s.stop()


def test_negative_zero_and_constants_exactly(backend):
    rows = [(1, 1, 0, 0, 0, 0), (2, 1, -7, 3, 0, -2), (3, 2, 5, -5, 4, 4)]
    s = Running()
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            a, b, cc, d = (col(rows, x) for x in "abcd")

            def q(sql):
                return c.execute(sql).rows
            assert q("SELECT SUM(a*b) FROM t") == [[sum(x * y for x, y in zip(a, b))]]
            assert q("SELECT SUM(a*a) FROM t") == [[sum(x * x for x in a)]]
            assert q("SELECT SUM(a*b) FROM t WHERE id = 1") == [[0]]              # zeros everywhere
            assert q("SELECT SUM((a-a+b)*(c-c+d)) FROM t") == [[sum(x * y for x, y in zip(b, d))]]
            assert q("SELECT SUM((-a)*(-b)) FROM t") == [[sum(x * y for x, y in zip(a, b))]]
            assert q("SELECT SUM((a+5)*(b-5)) FROM t") == [[sum((x + 5) * (y - 5) for x, y in zip(a, b))]]
            assert q("SELECT SUM(a)*SUM(b) FROM t") == [[sum(a) * sum(b)]]
            assert q("SELECT (SUM(a)+7)*(SUM(b)-1) FROM t") == [[(sum(a) + 7) * (sum(b) - 1)]]
            assert q("SELECT SUM(a+2)*SUM(b) FROM t") == [[(sum(a) + 2 * 3) * sum(b)]]
            assert q("SELECT 2*SUM(a*b)-SUM(c*d)/4+7 FROM t") == [[F(2 * sum(x * y for x, y in zip(a, b))
                                                                     - F(sum(x * y for x, y in zip(cc, d)), 4) + 7)]]
            assert q("SELECT AVG(a*b) FROM t") == [[F(sum(x * y for x, y in zip(a, b)), 3)]]
            # the same value through the dedicated DOT form
            assert q("SELECT DOT(a, b) FROM t") == q("SELECT SUM(a*b) FROM t")
    finally:
        s.stop()


def test_group_by_and_empty_selections(backend):
    rows = rows_for(backend, seed=5)
    s = Running()
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            got = dict(c.execute("SELECT g, SUM(a*b) FROM t GROUP BY g").rows)
            want = {}
            for r in rows:
                want[r[1]] = want.get(r[1], 0) + r[2] * r[3]
            assert got == want
            # empty selections: sums are 0, an average is NULL, a pure constant needs no server work
            assert c.execute("SELECT SUM(a*b) FROM t WHERE id > 999").rows == [[0]]
            assert c.execute("SELECT SUM(a)*SUM(b) FROM t WHERE id > 999").rows == [[0]]
            assert c.execute("SELECT SUM(a+1)*SUM(b-3) FROM t WHERE id > 999").rows == [[0]]
            assert c.execute("SELECT AVG(a*b) FROM t WHERE id > 999").rows == [[None]]
            assert c.execute("SELECT 2*SUM(a*b)+7 FROM t WHERE id > 999").rows == [[7]]
            assert c.execute("SELECT AVG(a*b)+7 FROM t WHERE id > 999").rows == [[None]]
    finally:
        s.stop()


def test_fhe_columns_hold_no_nulls_and_updates_are_seen(backend):
    rows = rows_for(backend, seed=2)
    s = Running()
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            with pytest.raises(Exception):
                c.execute("INSERT INTO t (id, g, a, b, c, d) VALUES (99, 1, NULL, 1, 1, 1)")
            with pytest.raises(Exception):
                c.execute("UPDATE t SET a = NULL WHERE id = 1")
            before = c.execute("SELECT SUM(a*b) FROM t").rows[0][0]
            c.execute("UPDATE t SET a = 11 WHERE id = 1")
            rows2 = [(r[0], r[1], 11, *r[3:]) if r[0] == 1 else r for r in rows]
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(r[2] * r[3] for r in rows2)]]
            assert before == sum(r[2] * r[3] for r in rows)
            c.execute("DELETE FROM t WHERE id = 2")
            rows3 = [r for r in rows2 if r[0] != 2]
            assert c.execute("SELECT SUM(a)*SUM(b) FROM t").rows == [[sum(r[2] for r in rows3) * sum(r[3] for r in rows3)]]
    finally:
        s.stop()


# ── out of range: an error, never a wrapped or garbage value ───────────────────────────────────────
@pytest.mark.parametrize("auth,mode", [(False, "auto"), (True, "auto"), (True, "delegated")])
def test_results_outside_the_dlog_range_raise(backend, auth, mode):
    key = fhe.FheKey(value_range=100, backend=backend)
    s = Running()
    try:
        with s.connect(fhe_key=key, authenticated=auth, fhe_dot_mode=mode) as c:
            c.execute("CREATE TABLE r (id INT PLAIN, a INT FHE, b INT FHE)")
            for i, a, b in [(1, 10, 10), (2, 1, 1), (3, -3, 4)]:
                c.execute(f"INSERT INTO r (id, a, b) VALUES ({i}, {a}, {b})")
            ok = lambda q: c.execute(q).rows                                           # noqa: E731
            assert ok("SELECT SUM(a*b) FROM r WHERE id = 1") == [[100]]                 # exactly the bound
            assert ok("SELECT SUM(a*b) FROM r WHERE id = 3") == [[-12]]
            for q in ("SELECT SUM(a*b) FROM r WHERE id < 3",                            # 101
                      "SELECT SUM((a+1)*(b+1)) FROM r WHERE id = 1",                     # 121
                      "SELECT SUM(a)*SUM(b) FROM r WHERE id < 3"):                       # 11*11 = 121
                with pytest.raises(Exception, match="range"):
                    c.execute(q)
            # a scaled RESULT may leave the range: the scale is a public factor applied after decryption
            assert ok("SELECT 5*SUM(a*b) FROM r WHERE id = 1") == [[500]]
            # the failed queries did not poison the connection
            assert ok("SELECT SUM(a*b) FROM r WHERE id = 2") == [[1]]
    finally:
        s.stop()


# ── who computes what, observed on the server ───────────────────────────────────────────────────────
class Spy:
    """Records every call and result as the server receives / returns them."""

    def __init__(self, running):
        self.log, self.out = [], []
        real = running.srv.engine.dispatch

        def spy(method, args, session=None):
            res = real(method, args, session)
            self.log.append((method, json.loads(json.dumps(args))))
            self.out.append((method, res))
            return res
        running.srv.engine.dispatch = spy

    def methods(self):
        return [m for m, _a in self.log]

    def clear(self):
        self.log.clear(); self.out.clear()


def test_delegated_the_server_pairs_and_the_owner_reads_no_cell(backend):
    rows = rows_for(backend)
    s = Running()
    spy = Spy(s)
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            spy.clear()
            a, b = col(rows, "a"), col(rows, "b")
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(x * y for x, y in zip(a, b))]]
            m = spy.methods()
            assert m.count("fhe_mul") == 1 and "fhe_sum" not in m
            # the owner fetched no FHE cell: plain_cells is only used for the PLAIN id column (or not at all)
            assert not any(mm == "plain_cells" and a_[1] in ("a", "b", "c", "d") for mm, a_ in spy.log)
            spy.clear()
            assert c.execute("SELECT SUM(a)*SUM(b) FROM t").rows == [[sum(a) * sum(b)]]
            assert spy.methods().count("fhe_mul") == 1 and "fhe_sum" not in spy.methods()
            spy.clear()
            c.execute("SELECT 2*SUM(a*b)-SUM(c*d)/4+7 FROM t")
            assert spy.methods().count("fhe_mul") == 2          # one server product per product term
            cost = c.client.last_expr_cost
            assert cost["server_products"] == 2 and cost["mult_rounds"] == 0 and cost["depth"] == 0
            assert cost["pairings"] == 4 * len(rows) * 2 and cost["decrypted_cells"] == 0
    finally:
        s.stop()


def test_authenticated_default_is_local_the_owner_recomputes_from_verified_cells(backend):
    rows = rows_for(backend)
    s = Running()
    spy = Spy(s)
    try:
        with s.connect(fhe_key=key_for(backend), authenticated=True) as c:
            load(c, rows)
            spy.clear()
            a, b = col(rows, "a"), col(rows, "b")
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(x * y for x, y in zip(a, b))]]
            assert "fhe_mul" not in spy.methods()                       # the server paired nothing
            assert c.client.last_expr_cost["decrypted_cells"] == 2 * len(rows)
            spy.clear()
            assert c.execute("SELECT SUM(a)*SUM(b) FROM t").rows == [[sum(a) * sum(b)]]
            assert "fhe_mul" not in spy.methods() and "fhe_sum" in spy.methods()
    finally:
        s.stop()


def test_authenticated_catches_tampering_where_delegated_cannot():
    srv = NoKeyServer()
    key = key_for("pyecc")
    c = NoKeyClient(srv, fhe=key, authenticated=True)
    load_inproc(c)
    store = srv._rows["t"]
    want = sum(r[2] * r[3] for r in ROWS_SMALL)
    assert c.execute("SELECT SUM(a*b) FROM t").rows == [[want]]
    good = store.row(1)["a"]
    store.set_cell(1, "a", key.encrypt(999))                           # a valid ciphertext of another value
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT SUM(a*b) FROM t")                            # local: the cell fails its tag
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT SUM(a)*SUM(b) FROM t")                       # local: the SUM fails its tag
    c.fhe_dot_mode = "delegated"                                       # explicit opt-in: NO integrity
    assert c.execute("SELECT SUM(a*b) FROM t").rows != [[want]]        # silently wrong -- documented
    store.set_cell(1, "a", good)
    c.fhe_dot_mode = "auto"
    assert c.execute("SELECT SUM(a*b) FROM t").rows == [[want]]
    # a lying SUM (fewer rows) is caught in the aggregate product as in any SUM
    real = srv.fhe_sum
    srv.fhe_sum = lambda t, col_, ids, k=1: real(t, col_, ids[:-1], k)
    with pytest.raises(CoreIntegrity):
        c.execute("SELECT SUM(a)*SUM(b) FROM t")
    srv.fhe_sum = real


ROWS_SMALL = [(1, 1, 4, -3, 2, 5), (2, 1, -6, 7, 0, 1), (3, 2, 9, 2, -4, 3)]


def load_inproc(c):
    c.execute(SCHEMA)
    for row in ROWS_SMALL:
        c.execute("INSERT INTO t (id, g, a, b, c, d) VALUES (" + ", ".join(str(v) for v in row) + ")")


def test_delegated_unauthenticated_has_no_integrity_like_dot():
    """The documented negative control: a lying server changes a delegated product silently."""
    srv = NoKeyServer()
    key = key_for("pyecc")
    c = NoKeyClient(srv, fhe=key)
    load_inproc(c)
    want = sum(r[2] * r[3] for r in ROWS_SMALL)
    assert c.execute("SELECT SUM(a*b) FROM t").rows == [[want]]
    real = srv.fhe_mul
    srv.fhe_mul = lambda t, mode, ids, ids_r, lt, lc, rt, rc, be=None: real(t, mode, ids[:-1], ids_r, lt, lc, rt, rc, be)
    assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(r[2] * r[3] for r in ROWS_SMALL[:-1])]]


# ── chunking: a server with tiny limits ──────────────────────────────────────────────────────────────
def test_requests_are_chunked_to_the_servers_limits(backend):
    rows = rows_for(backend, seed=9)
    cfg = dict(fhe_max_dot_rows=2, fhe_max_dot_rows_native=3, fhe_max_sum_rows=2,
               fhe_max_mul_agg_rows_native=3, fhe_max_mul_work=10, fhe_max_mul_work_native=12)
    s = Running(**cfg)
    spy = Spy(s)
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            a, b, cc, d = (col(rows, x) for x in "abcd")
            spy.clear()
            got = c.execute("SELECT SUM((a+b)*(c-d)) FROM t").rows
            assert got == [[sum((x + y) * (z - w) for x, y, z, w in zip(a, b, cc, d))]]
            sizes = [len(args[2]) for m, args in spy.log if m == "fhe_mul"]
            cap = 3 if backend == "mcl" else 2                  # min(max rows, work budget // 4 terms)
            assert max(sizes) <= cap and len(sizes) == -(-len(rows) // cap) > 1
            spy.clear()
            got = c.execute("SELECT (SUM(a)+SUM(b))*(SUM(c)-1) FROM t").rows
            assert got == [[(sum(a) + sum(b)) * (sum(cc) - 1)]]
            calls = [args for m, args in spy.log if m == "fhe_mul"]
            m = -(-len(rows) // (3 if backend == "mcl" else 2))
            assert len(calls) == m * m and all(len(x[2]) <= (3 if backend == "mcl" else 2) for x in calls)
            # the constant of an operand rides on its FIRST chunk only: right constant -1 appears once per
            # left chunk (m calls with v == 0), never in the other m*(m-1) calls
            assert sum(1 for x in calls if x[7] != 0) == m and all(x[5] == 0 for x in calls)
    finally:
        s.stop()


# ── the RPC: every bound is enforced by the SERVER, not trusted from the client ──────────────────────
def test_server_rejects_malformed_and_oversized_fhe_mul(backend):
    r_ = random.Random(4)
    rows = [(i + 1, 1, *[r_.randint(-9, 9) for _ in COLS]) for i in range(6)]
    s = Running(fhe_max_dot_rows=3, fhe_max_dot_rows_native=3, fhe_max_sum_rows=3, fhe_max_mul_agg_rows_native=3)
    try:
        with s.connect(fhe_key=key_for(backend)) as c:
            load(c, rows)
            call = lambda *args: c._wire.call("fhe_mul", list(args))                    # noqa: E731
            good = ["t", "sum", [0, 1], None, [["a", 1]], 0, [["b", 2]], 3]
            assert isinstance(call(*good), str)
            base_len = len(base64.b64decode(call(*good)))
            assert base_len == 1 + 4 * 384
            bad = [
                (["t", "bogus", [0], None, [["a", 1]], 0, [["b", 1]], 0], "mode"),
                (["t", "sum", [0], [0], [["a", 1]], 0, [["b", 1]], 0], "one id list"),
                (["t", "sum", [0, 0], None, [["a", 1]], 0, [["b", 1]], 0], "distinct"),
                (["t", "sum", [0, 99], None, [["a", 1]], 0, [["b", 1]], 0], "out of range"),
                (["t", "sum", [0, 1, 2, 3], None, [["a", 1]], 0, [["b", 1]], 0], "at most"),
                (["t", "sum", [0], None, [["id", 1]], 0, [["b", 1]], 0], "not an FHE column"),
                (["t", "sum", [0], None, [["g", 1]], 0, [["b", 1]], 0], "not an FHE column"),
                (["t", "sum", [0], None, [["__fmac__a", 1]], 0, [["b", 1]], 0], "internal"),
                (["t", "sum", [0], None, [["a", 1], ["a", 2]], 0, [["b", 1]], 0], "twice"),
                (["t", "sum", [0], None, [["a", 0]], 0, [["b", 1]], 0], "non-zero"),
                (["t", "sum", [0], None, [["a", (1 << 40) + 1]], 0, [["b", 1]], 0], "coefficient"),
                (["t", "sum", [0], None, [["a", True]], 0, [["b", 1]], 0], "integer"),
                (["t", "sum", [0], None, [["a", 1.5]], 0, [["b", 1]], 0], "integer"),
                (["t", "sum", [0], None, [["a", "5"]], 0, [["b", 1]], 0], "integer"),
                (["t", "sum", [0], None, [["a", 1]], 1 << 41, [["b", 1]], 0], "constant"),
                (["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 1.0], "constant"),
                (["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0, "nope"], "backend"),
                (["t", "sum", [0], None, [["a", 1]] * 2, 0, [["b", 1]], 0], "twice"),
                (["t", "sum", [0], None, "a", 0, [["b", 1]], 0], "list"),
                (["t", "sum", [0], None, [["a", 1]], 0, [[x, 1] for x in "abcdabcdabcdabcdabcd"], 0], "at most"),
                (["nope", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0], "nope|table"),
                (["t", "agg", [0, 1, 2, 3], [0], [["a", 1]], 0, [["b", 1]], 0], "at most"),
                (["t", "agg", [0], [0, 0], [["a", 1]], 0, [["b", 1]], 0], "distinct"),
            ]
            for args, frag in bad:
                with pytest.raises(Exception, match=frag):
                    call(*args)
    finally:
        s.stop()


def test_fhe_mul_is_a_read_rpc_and_needs_no_write_role():
    from nokey_server import READ_RPCS, WRITE_RPCS
    assert "fhe_mul" in READ_RPCS and "fhe_mul" not in WRITE_RPCS


# ── the rejection matrix, through the whole stack ──────────────────────────────────────────────────
REJECT = [
    ("SELECT SUM(a*b)*SUM(c*d) FROM t", "FHE"),
    ("SELECT SUM(a*b*c) FROM t", "FHE"),
    ("SELECT SUM(a*b)/SUM(c) FROM t", "FHE"),
    ("SELECT SUM(a*b)/COUNT(*) FROM t", "FHE"),
    ("SELECT SUM(a*b)+SUM(p) FROM t", "FHE"),
    ("SELECT SUM(a*p) FROM t", "FHE"),
    ("SELECT SUM(a)*SUM(e) FROM t", "FHE"),
    ("SELECT a+1 FROM t", "FHE"),
    ("SELECT SUM(a)+SUM(b) FROM t", "FHE"),
    ("SELECT SUM(a/2*b) FROM t", "FHE"),
    ("SELECT SUM((a+1099511627777)*b) FROM t", "FHE"),
    ("SELECT (a+1)*(b+1) FROM t", "FHE"),
    ("SELECT a * b FROM t", "(?i)paired"),
]


def test_rejection_matrix_through_planner_and_wire():
    s = Running()
    try:
        with s.connect(fhe_key=key_for("pyecc")) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE, c INT FHE, d INT FHE, "
                      "p INT PAIRED, e INT ENC)")
            c.execute("INSERT INTO t (id, a, b, c, d, p, e) VALUES (1, 2, 3, 4, 5, 6, 7)")
            for sql, frag in REJECT:
                with pytest.raises(torussql.ProgrammingError, match=frag):
                    c.cursor().execute(sql)
            c.execute("CREATE TABLE u (id INT PLAIN, a INT FHE)")
            with pytest.raises(torussql.ProgrammingError, match="FHE"):          # FHE columns cannot be joined
                c.cursor().execute("SELECT SUM(x.a*y.a) FROM t x JOIN u y ON x.id = y.id")
    finally:
        s.stop()


# ── wire audit: the server receives only names, row ids, small public integers ───────────────────────
def audit(log, out, *, names, allowed_methods, secrets_, plaintexts, n_rows):
    """-> list of violations. ``log``: [(method, args)] as the SERVER received them, ``out`` the replies.

    * methods: only reads (an FHE expression writes nothing);
    * strings: only table / column names, the two modes and the back end hint -- never a ciphertext or
      anything derived from one;
    * integers: row ids < n_rows, or |k| <= 2^40 (coefficients / constants of the query); never a secret
      scalar (key, MAC key, nonce), never a plaintext value or a product of plaintexts;
    * bytes / floats: none;
    * replies: standard-size base64 blobs only."""
    bad = []
    allowed_str = set(names) | {"sum", "agg", "pyecc", "mcl"}

    def walk(x, where):
        if isinstance(x, bool) or x is None:
            return
        if isinstance(x, int):
            if abs(x) > (1 << 40):
                bad.append(f"{where}: integer too large to be a coefficient or a row id")
            if x in secrets_:
                bad.append(f"{where}: a secret scalar")
            if x in plaintexts:
                bad.append(f"{where}: equals a plaintext / intermediate")
        elif isinstance(x, str):
            if x not in allowed_str:
                bad.append(f"{where}: unexpected string {x[:24]!r}")
        elif isinstance(x, (list, tuple)):
            for y in x:
                walk(y, where)
        elif isinstance(x, dict):
            for k, y in x.items():
                walk(k, where); walk(y, where)
        else:
            bad.append(f"{where}: unexpected type {type(x).__name__}")
    for m, args in log:
        if m not in allowed_methods:
            bad.append(f"method {m}")
            continue
        if m == "fhe_mul":
            walk(args, m)
    for m, res in out:
        if m == "fhe_mul":
            raw = base64.b64decode(res)
            if len(raw) != 1 + 4 * 384:
                bad.append("reply size")
    return bad


def secret_forms(key):
    s2 = fhe.derive_s2(key._s)
    return {key._s, s2, key._s % (1 << 128)}


def test_wire_audit_the_server_sees_only_public_data(backend):
    key = key_for(backend)
    r = random.Random(77)
    n = 3
    # distinctive plaintexts (never equal to a literal or a row id of the query)
    rows = [(i + 1, 1, *[r.choice([-1, 1]) * r.randint(100, 180) for _ in COLS]) for i in range(n)]
    s = Running()
    spy = Spy(s)
    try:
        with s.connect(fhe_key=key) as c:
            load(c, rows)
            spy.clear()
            a, b, cc, d = (col(rows, x) for x in "abcd")
            qs = ["SELECT SUM(a*b) FROM t", "SELECT SUM((a+2*b)*(c-d)) FROM t",
                  "SELECT SUM(a)*SUM(b) FROM t", "SELECT (SUM(a)+SUM(b))*(SUM(c)-1) FROM t",
                  "SELECT 2*SUM(a*b)-SUM(c*d)/4+7 FROM t", "SELECT AVG(a*b) FROM t"]
            for q in qs:
                c.execute(q)
            plain = set()
            for xs in (a, b, cc, d):
                plain |= set(xs)
            for i in range(n):
                plain |= {a[i] * b[i], (a[i] + 2 * b[i]) * (cc[i] - d[i]), cc[i] * d[i]}
            plain |= {sum(a), sum(b), sum(cc), sum(d), sum(x * y for x, y in zip(a, b)),
                      sum(a) * sum(b), (sum(a) + sum(b)) * (sum(cc) - 1)}
            plain = {p for p in plain if abs(p) >= 100}
            names = {"t", "id", "g", "a", "b", "c", "d"}
            assert spy.methods().count("fhe_mul") == 7
            ro = {"fhe_mul", "plain_cells", "matching_rowids", "schema", "tables"}
            assert audit(spy.log, spy.out, names=names, allowed_methods=ro, secrets_=secret_forms(key),
                         plaintexts=plain, n_rows=n) == []
            # nothing but the read-only methods reached the server during the queries
            assert set(spy.methods()) <= ro
    finally:
        s.stop()


def test_the_audit_has_teeth():
    """Break the system on purpose; the audit must notice every time."""
    key = key_for("pyecc")
    names = {"t", "a", "b"}
    ro = {"fhe_mul"}
    clean = [("fhe_mul", ["t", "sum", [0, 1], None, [["a", 2]], 3, [["b", 1]], 0, "pyecc"])]
    blob = [("fhe_mul", base64.b64encode(bytes(1 + 4 * 384)).decode())]
    kw = dict(names=names, allowed_methods=ro, secrets_=secret_forms(key), plaintexts={4321, -987654}, n_rows=2)
    assert audit(clean, blob, **kw) == []
    leaks = {
        "the secret key as a constant": ["t", "sum", [0], None, [["a", 1]], key._s, [["b", 1]], 0],
        "the second secret": ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], fhe.derive_s2(key._s)],
        "a plaintext as a constant": ["t", "sum", [0], None, [["a", 1]], 4321, [["b", 1]], 0],
        "a decrypted product as a constant": ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], -987654],
        "a re-encrypted intermediate (a ciphertext as an argument)":
            ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0, base64.b64encode(key.encrypt(5)).decode()],
        "a ciphertext as raw text": ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0, key.encrypt(5).hex()],
        "bytes": ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0, key.encrypt(5)],
        "a float": ["t", "sum", [0], None, [["a", 1]], 0, [["b", 1]], 0.5],
        "a coefficient above the bound": ["t", "sum", [0], None, [["a", (1 << 40) + 1]], 0, [["b", 1]], 0],
        "an unexpected column": ["t", "sum", [0], None, [["zz", 1]], 0, [["b", 1]], 0],
    }
    for why, args in leaks.items():
        assert audit([("fhe_mul", args)], blob, **kw), why
    assert audit([("update_cell", ["t", 0, "a", {}])], blob, **kw), "a write"
    assert audit(clean, [("fhe_mul", base64.b64encode(bytes(64)).decode())], **kw), "a wrong-size reply"


def test_a_sabotaged_owner_is_caught_by_the_audit(backend, monkeypatch):
    """The real client, broken so that it ships the secret key (or a decrypted partial result) to the
    server, must trip the audit. This is the 'owner decrypts the intermediate' failure mode the design
    forbids: any such path puts owner-derived data on the wire."""
    from torusdb_core import fhe_expr
    key = key_for(backend)
    rows = [(1, 1, 411, 523, 311, 612), (2, 1, -402, 333, 701, -415)]
    s = Running()
    spy = Spy(s)
    try:
        with s.connect(fhe_key=key) as c:
            load(c, rows)
            real = fhe_expr.FheExprRunner._operand

            def leaky(self, lin):
                terms, const = real(self, lin)
                partial = sum(r[2] * r[3] for r in rows)            # a decrypted intermediate
                return terms, partial % (1 << 40)
            monkeypatch.setattr(fhe_expr.FheExprRunner, "_operand", leaky)
            spy.clear()
            try:
                c.execute("SELECT SUM(a*b) FROM t")
            except Exception:                                       # noqa: BLE001  (the result is now garbage)
                pass
            plain = {411 * 523 + 402 * -333}
            bad = audit(spy.log, spy.out, names={"t", "id", "g", "a", "b", "c", "d"},
                        allowed_methods={"fhe_mul", "plain_cells", "matching_rowids", "schema", "tables"},
                        secrets_=secret_forms(key), plaintexts={p % (1 << 40) for p in plain}, n_rows=2)
            assert bad and "plaintext" in bad[0]
    finally:
        s.stop()


# ── the primitive: bilinearity, constants, independence, no value oracle ─────────────────────────────
def test_mul_cells_matches_plaintext_arithmetic_on_both_backends(backend):
    key = key_for(backend, 10 ** 5)
    r = random.Random(3)
    n = 4
    xs = [[r.randint(-9, 9) for _ in range(n)] for _ in range(3)]
    cells = [[key.encrypt(v) for v in col_] for col_ in xs]
    L = [(2, cells[0]), (-1, cells[1])]
    R = [(3, cells[2]), (1, cells[0])]
    want = sum((2 * xs[0][i] - xs[1][i] + 4) * (3 * xs[2][i] + xs[0][i] - 6) for i in range(n))
    assert key.decrypt_dot(fhe.mul_cells(L, 4, R, -6, "sum", backend)) == want
    sa = lambda j: sum(xs[j])                                                       # noqa: E731
    want = (2 * sa(0) - sa(1) + 7) * (3 * sa(2) + sa(0))
    assert key.decrypt_dot(fhe.mul_cells(L, 7, R, 0, "agg", backend)) == want
    # chunks multiply (bilinearity): the owner may split a request into pieces
    p1 = fhe.mul_cells([(k, c[:2]) for k, c in L], 4, [(k, c[:2]) for k, c in R], -6, "sum", backend)
    p2 = fhe.mul_cells([(k, c[2:]) for k, c in L], 4, [(k, c[2:]) for k, c in R], -6, "sum", backend)
    assert key.decrypt_dot(fhe.mul_dots(p1, p2)) == sum(
        (2 * xs[0][i] - xs[1][i] + 4) * (3 * xs[2][i] + xs[0][i] - 6) for i in range(n))
    # a constant-only side: 0 * anything and the empty product
    assert key.decrypt_dot(fhe.mul_cells([(1, cells[0])], 0, [], 5, "sum", backend)) == 5 * sum(xs[0])
    assert key.decrypt_dot(fhe.mul_cells([], 0, [], 0, "sum", backend)) == 0
    for bad in ([(0, cells[0])], [(1 << 41, cells[0])], [(True, cells[0])], [(1.0, cells[0])]):
        with pytest.raises(FheError):
            fhe.mul_cells(bad, 0, [(1, cells[1])], 0, "sum", backend)
    with pytest.raises(FheError):
        fhe.mul_cells([(1, cells[0])], 1 << 41, [(1, cells[1])], 0, "sum", backend)
    with pytest.raises(FheError):
        fhe.mul_cells([(1, cells[0][:2])], 0, [(1, cells[1])], 0, "sum", backend)       # unaligned rows
    with pytest.raises(FheError):
        fhe.mul_cells([(1, [b"short"])], 0, [(1, cells[1][:1])], 0, "sum", backend)


def test_linear_combinations_open_no_value_oracle():
    """The operands the server forms (public integer combinations of cells, plus constants) are
    ciphertexts like any other: none of the pairing identities between them and the PUBLIC keys
    tests a guessed plaintext. Positive control: with the weak key Q2 = s*G2 the test works."""
    from py_ecc.optimized_bn128 import G1, G2, add, multiply, neg, pairing
    be = fhe._fb.get("pyecc")
    key = fhe.FheKey(key_for("pyecc", 10 ** 5)._s, 10 ** 5, backend="pyecc")
    cells = [key.encrypt(v) for v in (17, -5, 40)]
    ks, const = (2, -3, 1), 9
    value = sum(k * v for k, v in zip(ks, (17, -5, 40))) + const
    g2 = fhe._lin_halves([(k, [c]) for k, c in zip(ks, cells)], const, None, be, "g2")[0]
    g1 = fhe._lin_halves([(k, [c]) for k, c in zip(ks, cells)], const, None, be, "g1")[0]
    (d1, d2), (c1, c2) = g2, g1
    Q, Q2 = key.Q, key.Q2

    from py_ecc.optimized_bn128 import curve_order as _n

    def identities(v):
        v = v % _n
        a1 = pairing(G2, add(c2, neg(multiply(G1, v))))
        a2 = pairing(add(d2, neg(multiply(G2, v))), G1)
        return [a1 == pairing(Q2, c1), a1 == pairing(d1, Q), a2 == pairing(d1, Q), a2 == pairing(Q2, c1)]
    for guess in (value, value + 1, 0, 1, -value):
        assert not any(identities(guess)), guess
    weak = multiply(G2, key._s)
    assert pairing(G2, add(c2, neg(multiply(G1, value)))) == pairing(weak, c1)           # the control fires
    # the two halves of a combination keep INDEPENDENT randomness: D1 and C1 are unrelated points,
    # and neither is a multiple of the generator the combination could expose
    assert pairing(d1, G1) != pairing(G2, c1)
    # a combination that cancels completely is the PUBLIC constant (identity randomness), which is
    # exactly what anyone can build from nothing -- it reveals nothing about the cancelled cells
    z = fhe._lin_halves([(1, [cells[0]]), (-1, [cells[0]])], 0, None, be, "g2")[0]
    assert be.g1_is_zero(z[0]) and be.g1_is_zero(z[1])


def test_randomness_of_the_two_halves_is_independent_in_every_cell(backend):
    key = key_for(backend, 10 ** 5)
    be = key.be
    seen = set()
    for _ in range(6):
        c1, c2, d1, d2 = fhe.parse_cell(key.encrypt(7), be)
        # e(P, D1) == e(C1, G2) would mean r1 == r2 (shared randomness)
        assert be.gt_key(be.final(be.miller(d1, be.G1))) != be.gt_key(be.final(be.miller(be.G2, c1)))
        seen.add(be.g1_key(c1))
    assert len(seen) == 6


# ── threshold keys ──────────────────────────────────────────────────────────────────────────────────
from test_fhe_threshold import keyset, keyset2, tkey  # noqa: E402,F401  (module-scoped fixtures)


@pytest.mark.parametrize("auth", [False, True])
def test_threshold_key_products_equal_the_plain_key(tkey, auth):
    rows = [(1, 1, 4, -3, 2, 5), (2, 1, -6, 7, 0, 1), (3, 2, 9, 2, -4, 3)]
    a, b, cc, d = (col(rows, x) for x in "abcd")
    s = Running()
    try:
        with s.connect(fhe_key=tkey, authenticated=auth) as c:
            load(c, rows)
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(x * y for x, y in zip(a, b))]]
            assert c.execute("SELECT SUM(a)*SUM(b)+3 FROM t").rows == [[sum(a) * sum(b) + 3]]
            if not auth:
                assert c.execute("SELECT SUM((a+b)*(c-d)) FROM t").rows == [
                    [sum((x + y) * (z - w) for x, y, z, w in zip(a, b, cc, d))]]
    finally:
        s.stop()


# ── anchored mode: the row set and freshness still hold for the local recomputation ─────────────────
def test_anchored_connection_verifies_the_local_recomputation(tmp_path):
    key = key_for("pyecc", 10 ** 4)
    s = Running()
    try:
        with s.connect(fhe_key=key, authenticated=True, integrity_anchor=str(tmp_path / "anchor.json")) as c:
            load(c, ROWS_SMALL)
            a, b = col(ROWS_SMALL, "a"), col(ROWS_SMALL, "b")
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[sum(x * y for x, y in zip(a, b))]]
            assert c.execute("SELECT SUM(a)*SUM(b) FROM t").rows == [[sum(a) * sum(b)]]
            # replay of an older complete version of a cell (value, tag, nonce) is refused
            store = s.srv.engine.srv._rows["t"]
            old = {k: store.row(0)[k] for k in ("a", "__fmac__a", "__fnonce__a")}
            c.execute("UPDATE t SET a = 100 WHERE id = 1")
            assert c.execute("SELECT SUM(a*b) FROM t").rows == [[100 * b[0] + a[1] * b[1] + a[2] * b[2]]]
            for k, v in old.items():
                store.set_cell(0, k, v)
            with pytest.raises(torussql.IntegrityError):
                c.execute("SELECT SUM(a*b) FROM t")
    finally:
        s.stop()


def test_bare_sum_of_two_columns_stays_a_dot(monkeypatch):
    """Pinned by the v0.5/v0.6 conformance suite: `SUM(x*y)` of two bare FHE columns is rejected (spell it DOT)."""
    from torussql_parser import fhe_expr
    monkeypatch.setattr(fhe_expr, "REJECT_BARE_COLUMN_PRODUCT", True)
    s = Running()
    try:
        with s.connect(fhe_key=key_for("pyecc")) as c:
            c.execute("CREATE TABLE t (id INT PLAIN, a INT FHE, b INT FHE)")
            c.execute("INSERT INTO t (id, a, b) VALUES (1, 3, 4)")
            with pytest.raises(torussql.ProgrammingError, match="FHE"):
                c.execute("SELECT SUM(a*b) FROM t")
            assert c.execute("SELECT DOT(a, b) FROM t").rows == [[12]]
            assert c.execute("SELECT SUM(a*b)*1 FROM t").rows == [[12]]          # any other spelling is fine
    finally:
        s.stop()
