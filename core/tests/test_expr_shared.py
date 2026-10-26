# SPDX-License-Identifier: Apache-2.0
"""Shared-wire evaluation of expressions (expr_mode="shared", the default): the paper's Π_C with
every wire a two-party additive sharing over Z/nZ -- the server keeps its share of every
intermediate, the owner its own; nothing is fetched, unmasked or computed in plaintext.

Engine-level tests against the in-process server (the wire / real-server variants are in
``tests/test_expr_shared_e2e.py``). Sections: correctness (differential, random deep circuits),
cost accounting, "the owner never fetches an operand", the abort oracle, the server-side wire
store (caps, TTL, errors), the wire AUDIT (what the server receives is uniform; the audit has
teeth), and integrity (authenticated mode) plus the pinned unauthenticated limitations.
"""
from __future__ import annotations

import random
import secrets
from fractions import Fraction

import pytest

from torusdb_core import expr_shared
from torusdb_core.errors import (DepthLimitExceeded, DivisionByZero, ExecError, IntegrityError,
                                 PlanError)
from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer
from torusdb_core.protocol import N, OutOfBudget, encode
from torusdb_core.wires import WireError, WireLimits, WireStore, _OPS

import test_expr_v06 as v06
from test_crypto_audit import CHI2_LIMIT, Recording, _expr_secrets, chi2_uniform, expr_workload

F = Fraction
ROWS, R, one, per_row = v06.ROWS, v06.R, v06.one, v06.per_row


@pytest.fixture(params=[False, True], ids=["plain", "authenticated"])
def cli(request):
    return v06.make(request.param)[1]


# ── correctness: deep circuits, division, fractions, negatives, budget ──────
@pytest.mark.parametrize("depth", [2, 3, 5, 8])
def test_product_chains_up_to_the_default_cap_are_exact(cli, depth):
    expr = "*".join((["a", "b", "c", "d"] * 3)[:depth + 1])
    want = []
    for i in range(len(ROWS)):
        x = R(i)
        v = 1
        for name in expr.split("*"):
            v *= x[name]
        want.append(v)
    assert per_row(cli, expr) == want
    assert cli.last_expr_cost["mode"] == "shared"
    assert cli.last_expr_cost["mult_rounds"] == depth == cli.last_expr_cost["depth"]


def test_mixed_expression_all_four_operators_and_fractions(cli):
    got = per_row(cli, "((a+b)*(c-d) - a*b/c) / (r*r + 1) + s/3")
    want = []
    for i in range(len(ROWS)):
        x = R(i)
        want.append(((x["a"] + x["b"]) * (x["c"] - x["d"]) - F(x["a"] * x["b"], x["c"]))
                    / (x["r"] ** 2 + 1) + F(x["s"]) / 3)
    assert got == want


def test_division_by_an_encrypted_value_never_decrypts_it(cli):
    got = per_row(cli, "a/b")
    assert got == [F(R(i)["a"], R(i)["b"]) for i in range(len(ROWS))]
    # one product level for rho*y, one for x*(1/y)
    assert cli.last_expr_cost["mult_rounds"] == 2 and cli.last_expr_cost["inversions"] == len(ROWS)
    assert one(cli, "SELECT SUM(a*b)/SUM(c) FROM t")[0] == F(sum(R(i)["a"] * R(i)["b"] for i in range(5)),
                                                             sum(R(i)["c"] for i in range(5)))


def test_negative_zero_and_out_of_budget(cli):
    assert per_row(cli, "(0-a)*(0-b)*c") == [R(i)["a"] * R(i)["b"] * R(i)["c"] for i in range(5)]
    assert per_row(cli, "a*b*c*0") == [0] * 5
    cli.execute("INSERT INTO t (id, dept, q, a, b, c, d, r, s, e) VALUES "
                f"(9, 9, 1, {2 ** 70}, {2 ** 70}, 1, 1, 1, 1, 1)")
    with pytest.raises(OutOfBudget):
        cli.execute("SELECT a*b*c FROM t WHERE id = 9")
    assert one(cli, "SELECT a*b*c/(a*b) FROM t WHERE id = 9")[0] == [1]      # intermediate overflow cancels


@pytest.mark.parametrize("auth", [False, True])
def test_random_deep_circuits_match_fraction_arithmetic_or_fail_loudly(auth):
    """Random circuits that favour products (height up to 6, so many levels), against exact
    Fraction arithmetic; a zero denominator must be a DivisionByZero, an overflow an OutOfBudget."""
    from torusdb_core.protocol import _BOUND, _RANGE
    _, cli = v06.make(auth)
    rng = random.Random(777 + auth)
    leaves = ["a", "b", "c", "d", "r", "q"]

    def gen(depth):
        if depth == 0 or rng.random() < 0.15:
            return ("col", rng.choice(leaves)) if rng.random() < 0.8 else ("lit", rng.choice([F(2), F(-3), F(1, 3)]))
        return (rng.choice("**+-/"), gen(depth - 1), gen(depth - 1))
    ran = zero = budget = 0
    deepest = 0
    for _ in range(120):
        tree = gen(rng.randint(2, 6))
        if tree[0] in ("col", "lit"):
            continue
        sql = f"SELECT {v06._sql(tree)} FROM t"
        exp, zerodiv = [], False
        for i in range(len(ROWS)):
            try:
                exp.append(v06._py(tree, R(i)))
            except ZeroDivisionError:
                zerodiv = True
        try:
            got = cli.execute(sql).rows[0][0]
        except PlanError:
            continue
        except DivisionByZero:
            assert zerodiv, sql
            zero += 1
            continue
        except OutOfBudget:
            assert any(abs(v.numerator) > _BOUND or v.denominator > _BOUND
                       or abs(v.numerator) * v.denominator >= _RANGE for v in exp), sql
            budget += 1
            continue
        assert not zerodiv, sql
        assert got == exp, sql
        ran += 1
        deepest = max(deepest, (cli.last_expr_cost or {}).get("depth", 0))
    assert ran > 50 and deepest >= 4, (ran, zero, budget, deepest)


def test_every_planned_depth_is_checked_before_any_request_including_divisions():
    class Spy(NoKeyServer):
        def __init__(self):
            super().__init__()
            self.log = []

        def wire_exec(self, ops):
            self.log.append("wire_exec")
            return super().wire_exec(ops)
    srv = Spy()
    _, cli = v06.make(server=srv)
    srv.log.clear()
    cli.max_mult_depth = 3
    assert per_row(cli, "a/b")                                   # 2 levels: ok
    with pytest.raises(DepthLimitExceeded, match="max_mult_depth"):
        cli.execute("SELECT a/b/c/d FROM t")                    # 4 levels in shared mode (1 per division)
    srv.log.clear()
    with pytest.raises(DepthLimitExceeded):
        cli.execute("SELECT a*b*c*d*a FROM t")
    assert srv.log == []
    cli.max_mult_depth = 0
    assert per_row(cli, "a/3+s")                                 # public division: no level


def test_scalar_and_row_mixing_nulls_and_empty_inputs(cli):
    assert one(cli, "SELECT SUM(a)*SUM(b) + COUNT(*) FROM t")[0] == \
        sum(R(j)["a"] for j in range(5)) * sum(R(j)["b"] for j in range(5)) + 5
    assert one(cli, "SELECT a*b*c FROM t WHERE id > 100")[0] == []
    assert one(cli, "SELECT SUM(a*b*c) FROM t WHERE id > 100")[0] == 0
    assert one(cli, "SELECT AVG(a*b) FROM t WHERE id > 100")[0] is None
    assert one(cli, "SELECT a*b*c FROM t WHERE id = 1")[0] == [2 * 3 * 4]
    assert one(cli, "SELECT q*a*b FROM t")[0] == [R(i)["q"] * R(i)["a"] * R(i)["b"] for i in range(5)]


def test_large_widths_are_chunked_into_spans_and_several_requests():
    srv = NoKeyServer()
    srv._wl = WireLimits(max_request_elements=90, max_ops=5)       # forces spans of 10 rows
    cli = NoKeyClient(srv, authenticated=True)
    cli.execute("CREATE TABLE t (a INT PAIRED, b INT PAIRED, c INT PAIRED, q INT PLAIN)")
    rows = [(i - 20, 2 * i + 1, 7 - i, i % 3 + 1) for i in range(45)]
    for a, b, c, q in rows:
        cli.execute(f"INSERT INTO t (a, b, c, q) VALUES ({a}, {b}, {c}, {q})")
    got = cli.execute("SELECT (a*b*c + q)/q - a/b FROM t").rows[0][0]
    assert got == [F(a * b * c + q, q) - F(a, b) for a, b, c, q in rows]
    assert cli.last_expr_cost["requests"] > 6
    assert cli.execute("SELECT SUM(a*b*c) FROM t").rows[0][0] == sum(a * b * c for a, b, c, _ in rows)
    assert srv._wire_store().stats() == {"wires": 0, "elements": 0}


# ── cost accounting ──────────────────────────────────────────────────────────
def test_cost_accounting_rounds_equal_depth_and_openings_are_counted():
    _, cli = v06.make()
    per_row(cli, "a*b*c")
    c = cli.last_expr_cost
    assert (c["mult_rounds"], c["depth"], c["products"], c["openings"]) == (2, 2, 2 * 5, 4 * 5)
    assert c["reveals"] == 1 and c["requests"] == 3 and c["wires"] >= 5       # depth + 1 exchanges
    per_row(cli, "a*b + c*d + a*d")                               # one level, three products
    c = cli.last_expr_cost
    assert (c["mult_rounds"], c["products"], c["requests"]) == (1, 15, 2)
    one(cli, "SELECT SUM(a+2*b) FROM t")                          # linear: a single exchange
    c = cli.last_expr_cost
    assert (c["mult_rounds"], c["requests"], c["products"], c["linear_sums"]) == (0, 1, 0, 2)


def test_dividing_by_an_encrypted_value_costs_exactly_one_extra_level():
    _, cli = v06.make()
    per_row(cli, "a*b*c")
    base = cli.last_expr_cost["mult_rounds"]
    per_row(cli, "a*b/c")                                         # inv(c): level 1, product: level 2
    assert cli.last_expr_cost["mult_rounds"] == 2 == base
    per_row(cli, "a*b*c/d")                                       # 2 levels for a*b*c, then x*(1/d)
    assert cli.last_expr_cost["mult_rounds"] == 3
    per_row(cli, "(a*b)/(c*d)")                                   # c*d: 1, rho*(c*d): 2, x*inv: 3
    assert cli.last_expr_cost["mult_rounds"] == 3


# ── nothing is fetched, unmasked or computed in plaintext at the owner ───────
class CallSpy(NoKeyServer):
    def __init__(self):
        super().__init__()
        self.calls = []

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if callable(attr) and not name.startswith("_") and name != "calls":
            calls = super().__getattribute__("calls")

            def spy(*a, **k):
                calls.append(name)
                return attr(*a, **k)
            return spy
        return attr


@pytest.mark.parametrize("auth", [False, True])
def test_the_owner_fetches_no_operand_and_decodes_only_the_result(auth, monkeypatch):
    srv = CallSpy()
    _, cli = v06.make(auth, server=srv)
    srv.calls.clear()
    decoded = []
    real = expr_shared.decode
    monkeypatch.setattr(expr_shared, "decode", lambda v, **k: decoded.append(v) or real(v, **k))

    def boom(*a, **k):                                           # the v0.6 path: fetch + unmask cells
        raise AssertionError("the owner read an operand cell")
    monkeypatch.setattr(NoKeyClient, "_read_verified_scalars", boom)
    queries = ["SELECT a*b*c*d FROM t", "SELECT SUM(a*b*c) FROM t", "SELECT a/b FROM t",
               "SELECT (a+b)*(c-d)/(a*b+1) FROM t", "SELECT SUM(a+b-s/2) FROM t",
               "SELECT SUM(a*b)/SUM(c) FROM t"]
    expected_decodes = 0
    for q in queries:
        rows = cli.execute(q).rows
        expected_decodes += len(rows[0][0]) if isinstance(rows[0][0], list) else 1
    assert set(srv.calls) <= {"wire_exec", "wire_free", "matching_rowids", "plain_cells", "limits"}, \
        set(srv.calls)
    assert len(decoded) == expected_decodes, "something besides the results was decoded"
    assert srv._wire_store().stats() == {"wires": 0, "elements": 0}       # every wire freed


# ── the abort oracle: a zero denominator does not change what the server sees ─
def _shape(ops):
    """Everything a server sees EXCEPT the (uniform) ring values: op names, wire ids (renamed by
    first use), spans and vector lengths."""
    ids = {}
    out = []
    for op in ops:
        row = [op[0]]
        for x in op[1:]:
            if isinstance(x, str) and "." in x and x.count(".") == 1:
                row.append(ids.setdefault(x, len(ids)))
            elif isinstance(x, list):
                row.append(("L", len(x)))
            elif isinstance(x, dict):
                row.append({k: len(v) for k, v in sorted(x.items())})
            elif isinstance(x, bool) or x is None:
                row.append(x)
            elif isinstance(x, int) and x < 10 ** 6:
                row.append(x)
            else:
                row.append("R")
        out.append(row)
    return out


class OpTrace(NoKeyServer):
    def __init__(self):
        super().__init__()
        self.requests = []

    def wire_exec(self, ops):
        self.requests.append(_shape(ops))
        return super().wire_exec(ops)


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
@pytest.mark.parametrize("sql", ["SELECT a/b FROM t", "SELECT c*d/(a-a+b)*a FROM t",
                                 "SELECT SUM(a/b*c) FROM t", "SELECT 1/(a*b-c*d) FROM t"])
def test_a_zero_denominator_does_not_change_the_request_sequence(auth, sql):
    srv = OpTrace()
    _, cli = v06.make(auth, server=srv)

    def trace(zero):
        srv.requests.clear()
        if zero:
            with pytest.raises(DivisionByZero):
                cli.execute(sql)
        else:
            cli.execute(sql)
        return [list(r) for r in srv.requests]
    clean = trace(False)
    cli.execute("UPDATE t SET b = 0 WHERE id IN (2, 4)")
    cli.execute("UPDATE t SET c = 6, d = 1 WHERE id = 1")           # a*b = c*d for 1/(a*b-c*d)
    zero = trace(True)
    assert zero == clean, f"the request sequence depends on a zero denominator for {sql}"
    assert len(clean) >= 3 and any(op[0] == "mul" for r in clean for op in r)


def test_the_opened_t_is_uniform_nonzero_and_zero_is_replaced_by_a_dummy():
    """What the server learns from the division: t^-1 (as a public multiplier). It must look the
    same for y != 0 and y == 0 (a fresh uniform non-zero dummy)."""
    class Grab(NoKeyServer):
        def __init__(self):
            super().__init__()
            self.tinv = []

        def wire_exec(self, ops):
            for op in ops:
                if op[0] == "mulv":
                    self.tinv += op[3]
            return super().wire_exec(ops)
    samples = {}
    for label, yval in (("nonzero", 123456789), ("zero", 0)):
        srv = Grab()
        cli = NoKeyClient(srv)
        cli.execute("CREATE TABLE z (a INT PAIRED, b INT PAIRED)")
        for _ in range(2500):
            cli.execute(f"INSERT INTO z (a, b) VALUES (5, {yval})")
        if yval:
            cli.execute("SELECT a/b FROM z")
        else:
            with pytest.raises(DivisionByZero):
                cli.execute("SELECT a/b FROM z")
        samples[label] = srv.tinv
    for label, vals in samples.items():
        assert len(vals) == 2500 and 0 not in vals, label
        assert chi2_uniform(vals) < CHI2_LIMIT, label
        assert len(set(vals)) == len(vals), label
    ca, cb = [0] * 16, [0] * 16
    for v in samples["nonzero"]:
        ca[v * 16 // N] += 1
    for v in samples["zero"]:
        cb[v * 16 // N] += 1
    assert sum((x - y) ** 2 / max(1, x + y) for x, y in zip(ca, cb)) < CHI2_LIMIT


# ── the server-side wire store ────────────────────────────────────────────────
def _store(**kw):
    clock = [0.0]
    st = WireStore(WireLimits(**kw), clock=lambda: clock[0])
    return st, clock


def _cells(table, col, rows):
    return [0 if r is None else 1000 + r for r in rows]


def test_wire_caps_are_enforced_with_clear_errors():
    st, _ = _store(max_wires=3, max_elements=20, max_request_elements=10, max_ops=4)
    st.exec([["load", "a", "t", "x", [0, 1, 2, 3], False]], _cells)
    st.exec([["load", "b", "t", "x", [0, 1, 2, 3], True]], _cells)             # 4 + 8 elements
    with pytest.raises(WireError, match="memory cap"):
        st.exec([["load", "c", "t", "x", list(range(9)), False]], _cells)             # 12 + 9 > 20
    st.exec([["add", "c", "a", "a"]], _cells)
    with pytest.raises(WireError, match="too many live wires"):
        st.exec([["neg", "d", "a"]], _cells)
    st.free()
    with pytest.raises(WireError, match="request too large"):
        st.exec([["load", "e", "t", "x", list(range(11)), False]], _cells)
    with pytest.raises(WireError, match="at most 4 operations"):
        st.exec([["free", []]] * 5, _cells)
    assert st.stats() == {"wires": 0, "elements": 0}


def test_server_wide_budget_is_shared_between_sessions():
    from torusdb_core.wires import WireBudget
    b = WireBudget(10)
    s1, s2 = WireStore(WireLimits(), b), WireStore(WireLimits(), b)
    s1.exec([["load", "a", "t", "x", [0] * 6, False]], _cells)
    with pytest.raises(WireError, match="server-wide"):
        s2.exec([["load", "a", "t", "x", [0] * 6, False]], _cells)
    s1.free()
    s2.exec([["load", "a", "t", "x", [0] * 6, False]], _cells)
    assert b.used == 6


def test_idle_wires_expire_after_the_ttl():
    st, clock = _store(ttl=30)
    st.exec([["load", "a", "t", "x", [0, 1], False]], _cells)
    clock[0] = 20
    st.exec([["neg", "b", "a"]], _cells)                                   # touching keeps `a` alive
    clock[0] = 45
    assert st.exec([["reveal", "a", 0, 2]], _cells)[0][0] == [1000, 1001]   # a was touched at t=20
    clock[0] = 100
    with pytest.raises(WireError, match="unknown wire .* expired"):
        st.exec([["reveal", "a", 0, 2]], _cells)
    assert st.stats() == {"wires": 0, "elements": 0}
    st.exec([["load", "a", "t", "x", [0], False]], _cells)
    clock[0] = 1000
    assert st.expire() == 1


@pytest.mark.parametrize("bad,msg", [
    ([["bogus"]], "unknown wire operation"),
    ([["neg", "z", "missing"]], "unknown wire"),
    ([["load", "a", "t", "x", "notalist", False]], "list of row ids"),
    ([["load", "a", "t", "x", [-1], False]], "non-negative"),
    ([["mulc", "a", "b", -1]], "not a ring element"),
    ([["mulc", "a", "b", True]], "not a ring element"),
    ([["mulc", "a", "b", str(N)]], "not a ring element"),
    ([["mulc", "a", "b", "1e3"]], "not a ring element"),
    ([["neg"]], "bad arguments"),
    ("notalist", "at most"),
    ([[]], "must be a list starting with its name"),
    ([["load", "", "t", "x", [], False]], "wire id"),
])
def test_malformed_requests_are_rejected_not_executed(bad, msg):
    st, _ = _store()
    st.exec([["load", "b", "t", "x", [0], False]], _cells)
    with pytest.raises(WireError, match=msg):
        st.exec(bad, _cells)


def test_gate_level_invariants_untagged_and_tagged_operands_cannot_mix():
    st, _ = _store()
    st.exec([["load", "a", "t", "x", [0, 1], False], ["load", "b", "t", "x", [0, 1], True],
             ["load", "c", "t", "x", [0], False]], lambda t, c, r: [0 if x is None else 7 for x in r])
    for op in (["add", "o", "a", "b"], ["add", "o", "a", "c"], ["bc", "o", "a", 3]):
        with pytest.raises(WireError):
            st.exec([op], _cells)
    with pytest.raises(WireError, match="exactly"):
        st.exec([["mul", "o", "a", "a", {"u": [1, 2]}, 0, 2]], _cells)
    with pytest.raises(WireError, match="still being filled"):
        st.exec([["put", "p", [1], None, 0, 2], ["neg", "o", "p"]], _cells)
    with pytest.raises(WireError, match="in order"):
        st.exec([["put", "p", [1, 2], None, 1, 2]], _cells)             # would overflow the wire


def test_a_store_holds_no_key_mask_or_plaintext_field():
    """Structural: a wire is only (vals, macs, width, filled, touched); the store has no slot for
    a key, a mask, a MAC key or a decoder."""
    from torusdb_core.wires import _Wire
    assert set(_Wire.__slots__) == {"vals", "macs", "width", "filled", "touched"}
    st, _ = _store()
    assert not {"key", "alpha", "mask", "masks", "decode", "secret"} & set(dir(st))


def test_ring_values_hold_the_beaver_identity_for_arbitrary_rings_elements():
    """Protocol level: for random shared X, Y and random dealt triples the two shares add up to
    X*Y -- including negative and fractional encodings."""
    from torusdb_core.protocol import decode
    rng = random.Random(5)
    for _ in range(200):
        x, y = F(rng.randint(-10 ** 9, 10 ** 9), rng.randint(1, 50)), F(rng.randint(-10 ** 9, 10 ** 9), rng.randint(1, 50))
        X, Y = encode(x), encode(y)
        XS, YS = secrets.randbelow(N), secrets.randbelow(N)
        XO, YO = (X - XS) % N, (Y - YS) % N
        st, _ = _store()
        st.exec([["put", "x", [XS], None, 0, 1], ["put", "y", [YS], None, 0, 1]], _cells)
        S, O = expr_shared.SharedExprRunner._deal(type("D", (), {"auth": False, "alpha": 0})(), 1)
        eo, go = [(XO - O["u"][0]) % N], [(YO - O["v"][0]) % N]
        eS, gS, _, _ = st.exec([["mul", "z", "x", "y", dict(S, eo=eo, go=go), 0, 1]], _cells)[0]
        e, g = (eS[0] + eo[0]) % N, (gS[0] + go[0]) % N
        ZO = (O["w"][0] + e * O["v"][0] + g * O["u"][0]) % N
        ZS = st.exec([["reveal", "z", 0, 1]], _cells)[0][0][0]
        assert decode((ZS + ZO) % N) == x * y


# ── the wire audit: everything the server receives ───────────────────────────
AUDITED_OPS = {                                  # every wire operation, and the audit that covers it
    "load": "rows only: no ring element is sent",
    "loadsum": "rows only: no ring element is sent",
    "put": "uniform + unique (rho shares)",
    "neg": "no ring element", "add": "no ring element", "sub": "no ring element",
    "bc": "no ring element", "sum": "no ring element", "free": "no ring element",
    "mulc": "public constants of the query (never a secret-derived value)",
    "addc": "public constants of the query",
    "mulv": "uniform t^-1 / public 0-1 selectors / public plain values",
    "addv": "public plain values",
    "mul": "triple shares + owner opening shares: uniform + unique",
    "reveal": "no ring element is sent (server -> owner only)",
}


def test_every_wire_operation_and_rpc_has_an_audit_entry():
    assert set(AUDITED_OPS) == set(_OPS), "a wire operation was added/removed without an audit entry"
    from torusdb_core.nokey_engine import NoKeyServer as S
    rpcs = {n for n in dir(S) if n.startswith("wire_")}
    assert rpcs == {"wire_exec", "wire_free"}, rpcs
    try:
        import nokey_server
    except ImportError:                                # pragma: no cover - server not on the path
        return
    assert nokey_server.WIRE_RPCS == rpcs and rpcs <= nokey_server.READ_RPCS


class WireRecorder(Recording):
    """Records every ring element the server is handed, by class."""

    def __init__(self):
        super().__init__()
        self.requests = []

    def wire_exec(self, ops):
        self.requests.append(ops)
        return super().wire_exec(ops)


def audit(requests) -> list[str]:
    """Violations in what a server received. Empty = every secret-bearing field is uniform and no
    value is ever repeated."""
    bad = []
    levels: list[dict] = []
    puts = []
    for ops in requests:
        for op in ops:
            if op[0] == "mul":
                t = op[4]
                levels.append(t)
            elif op[0] == "put":
                puts += op[2] + (op[3] or [])
    pooled: dict[str, list] = {}
    for t in levels:
        for k, v in t.items():
            pooled.setdefault(k, []).extend(v)
    for k, vals in sorted(pooled.items()):
        if len(vals) >= 1000 and chi2_uniform(vals) >= CHI2_LIMIT:
            bad.append(f"mul.{k}: not uniform")
        if len(set(vals)) != len(vals):
            bad.append(f"mul.{k}: a value repeated (triple/mask reuse)")
    if puts:
        if len(set(puts)) != len(puts):
            bad.append("put: a value repeated")
        if len(puts) >= 1000 and chi2_uniform(puts) >= CHI2_LIMIT:
            bad.append("put: not uniform")
    return bad


def _identical_rows_db(srv, rows=1200, auth=False):
    cli = NoKeyClient(srv, authenticated=auth)
    cli.execute("CREATE TABLE z (a INT PAIRED, b INT PAIRED, c INT PAIRED, d INT PAIRED)")
    for _ in range(rows):
        cli.execute("INSERT INTO z (a, b, c, d) VALUES (7, 7, 7, 7)")      # identical plaintexts on purpose
    return cli


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_audit_server_view_is_uniform_at_every_level_for_identical_plaintexts(auth):
    srv = WireRecorder()
    cli = _identical_rows_db(srv, auth=auth)
    srv.requests.clear()
    cli.execute("SELECT a*b*c*d FROM z")                                   # 3 levels
    cli.execute("SELECT a/b FROM z")                                       # division
    assert audit(srv.requests) == []
    muls = [op for r in srv.requests for op in r if op[0] == "mul"]
    assert len(muls) == 3 + 2
    assert all(len(op[4]["eo"]) == 1200 for op in muls)


@pytest.mark.parametrize("auth", [False, True], ids=["plain", "authenticated"])
def test_audit_nothing_secret_derived_reaches_the_server_in_expressions(auth):
    srv = WireRecorder()
    cli = NoKeyClient(srv, authenticated=auth)
    expr_workload(cli)
    masks = set(cli._masks.values())
    assert masks and not (masks & srv.seen), "a mask reached the server"
    leaked = _expr_secrets() & srv.seen
    assert not leaked, f"{len(leaked)} plaintext/intermediate/inverse encodings reached the server"
    if auth:
        assert cli._alpha not in srv.seen
    assert audit(srv.requests) == []


def test_audit_two_plaintexts_give_indistinguishable_opening_shares():
    srv = WireRecorder()
    cli = NoKeyClient(srv)
    cli.execute("CREATE TABLE z (k INT PLAIN, a INT PAIRED, b INT PAIRED, c INT PAIRED)")
    for _ in range(1500):
        cli.execute("INSERT INTO z (k, a, b, c) VALUES (0, 0, 0, 0)")
        cli.execute("INSERT INTO z (k, a, b, c) VALUES (1, 10000000000000, -4, 123456789)")
    srv.requests.clear()
    cli.execute("SELECT a*b*c FROM z")
    lvl2 = [op for r in srv.requests for op in r if op[0] == "mul"][1][4]["eo"]   # operand = an intermediate
    ca, cb = [0] * 16, [0] * 16
    for i, v in enumerate(lvl2):
        (ca if i % 2 == 0 else cb)[v * 16 // N] += 1
    assert sum((x - y) ** 2 / max(1, x + y) for x, y in zip(ca, cb)) < CHI2_LIMIT


# — teeth: the audit must FAIL when masking is deliberately broken —
def test_audit_has_teeth_a_dealer_that_does_not_mask_its_share_is_caught(monkeypatch):
    """A dealer whose owner-side triple shares are all 0 leaves the SERVER holding every product
    in the clear; from level 2 on the owner's opening shares (eo, go) are then constants. The audit
    must report it."""
    real = expr_shared.SharedExprRunner._deal

    def broken(self, k):
        S, O = real(self, k)
        for name in O:
            O[name] = [0] * k
        S["w"] = [u * v % N for u, v in zip(S["u"], S["v"])]      # keeps (u, v, w) a valid triple
        return S, O
    srv = WireRecorder()
    cli = _identical_rows_db(srv, rows=1200)
    srv.requests.clear()
    cli.execute("SELECT a*b*c*d FROM z")
    assert audit(srv.requests) == []                              # the honest dealer passes ...
    monkeypatch.setattr(expr_shared.SharedExprRunner, "_deal", broken)
    srv.requests.clear()
    assert cli.execute("SELECT a*b*c*d FROM z").rows[0][0] == [7 ** 4] * 1200   # ... still computes correctly
    violations = audit(srv.requests)
    assert any("eo" in v or "go" in v for v in violations), violations


def test_audit_has_teeth_a_reused_triple_is_caught(monkeypatch):
    real = expr_shared.SharedExprRunner._deal
    cache = {}

    def reuse(self, k):
        if k not in cache:
            cache[k] = real(self, k)
        S, O = cache[k]
        return {n: list(v) for n, v in S.items()}, {n: list(v) for n, v in O.items()}
    monkeypatch.setattr(expr_shared.SharedExprRunner, "_deal", reuse)
    srv = WireRecorder()
    cli = _identical_rows_db(srv, rows=1200)
    srv.requests.clear()
    cli.execute("SELECT a*b*c FROM z")
    assert any("repeated" in v for v in audit(srv.requests))


def cell_audit(srv, plaintext_encodings) -> list[str]:
    """Violations in the stored database: a cell equal to an encoded plaintext."""
    cells = {int(v["v"]) for rows in srv.to_body()["rows"].values() for row in rows
             for v in row.values() if isinstance(v, dict) and v.get("t") == "i"}
    return ["a stored cell equals an encoded plaintext"] if cells & plaintext_encodings else []


def test_audit_has_teeth_unmasked_cells_are_caught(monkeypatch):
    """If the owner stored cells without a pad the plaintext would sit at the server; the stored-cell
    audit must flag exactly that, and pass for the real blinding."""
    from torusdb_core.protocol import Owner
    secrets_ = {encode(123456789), encode(987654321)}

    def fill():
        srv = NoKeyServer()
        cli = NoKeyClient(srv)
        cli.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
        for i, v in enumerate((123456789, 987654321)):
            cli.execute(f"INSERT INTO t (id, v) VALUES ({i + 10 ** 7}, {v})")
        return srv
    assert cell_audit(fill(), secrets_) == []
    monkeypatch.setattr(Owner, "blind", lambda self, s: (s % N, 0))
    assert cell_audit(fill(), secrets_)


# ── integrity (authenticated mode) and the pinned unauthenticated limits ─────
class Tamper(NoKeyServer):
    """A malicious server: mutates its own shares / replies according to ``rule``."""

    def __init__(self, rule=None):
        super().__init__()
        self.rule = rule
        self.n = 0

    def wire_exec(self, ops):
        res = super().wire_exec(ops)
        if self.rule:
            self.n += 1
            self.rule(self, ops, res)
        return res


def test_tampered_reveal_share_is_detected_in_authenticated_mode():
    def rule(self, ops, res):
        for op, r in zip(ops, res):
            if op[0] == "reveal" and op[1]:
                r[0][0] = (r[0][0] + 1) % N
    _, cli = v06.make(True, server=Tamper(rule))
    with pytest.raises(IntegrityError, match="MAC check failed"):
        cli.execute("SELECT a*b*c FROM t")


def test_tampered_opening_share_is_detected():
    seen = {"n": 0}

    def rule(self, ops, res):
        for op, r in zip(ops, res):
            if op[0] == "mul":
                seen["n"] += 1
                r[0][2] = (r[0][2] + 3) % N                       # e_S is a lie, its tag share is honest
    _, cli = v06.make(True, server=Tamper(rule))
    with pytest.raises(IntegrityError, match="MAC check failed on a multiplication opening"):
        cli.execute("SELECT a*b*c FROM t")
    assert seen["n"]


def test_a_server_that_uses_a_different_opening_than_it_reports_is_caught_at_the_end():
    """It reports honest (e_S, tag) but computes its product share from e + delta: the opening
    check passes, the final MAC check does not."""
    class Sneaky(NoKeyServer):
        def wire_exec(self, ops):
            ops = [list(o) for o in ops]
            for op in ops:
                if op[0] == "mul":
                    t = dict(op[4])
                    t["eo"] = [(x + 1) % N for x in t["eo"]]      # server uses e' = e + 1
                    op[4] = t
            res = super().wire_exec(ops)
            return res
    _, cli = v06.make(True, server=Sneaky())
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a*b*c FROM t")


@pytest.mark.parametrize("sql", ["SELECT a*b*c*d FROM t", "SELECT a/b FROM t", "SELECT SUM(a+b) FROM t",
                                 "SELECT SUM(a*b)/SUM(c) FROM t"])
def test_tampered_stored_cell_is_detected_whatever_the_expression(sql):
    srv, cli = v06.make(True)
    srv._rows["t"][1]["b"] = (srv._rows["t"][1]["b"] + 5) % N
    with pytest.raises(IntegrityError):
        cli.execute(sql)
    srv._rows["t"][1]["b"] = (srv._rows["t"][1]["b"] - 5) % N
    cli.execute(sql)


def test_swapped_and_replayed_cells_are_detected_in_expressions():
    srv, cli = v06.make(True)
    r = srv._rows["t"]
    r[1]["a"], r[2]["a"] = r[2]["a"], r[1]["a"]
    r[1]["__mac__a"], r[2]["__mac__a"] = r[2]["__mac__a"], r[1]["__mac__a"]
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a*b*c FROM t")
    r[1]["a"], r[2]["a"] = r[2]["a"], r[1]["a"]
    r[1]["__mac__a"], r[2]["__mac__a"] = r[2]["__mac__a"], r[1]["__mac__a"]
    old = dict(r[2])
    cli.execute("UPDATE t SET a = 999 WHERE id = 3")
    r[2]["a"], r[2]["__mac__a"] = old["a"], old["__mac__a"]               # a consistent stale pair
    with pytest.raises(IntegrityError):
        cli.execute("SELECT SUM(a*b)/SUM(c) FROM t")


def test_tampering_only_the_mac_cell_is_detected_in_expressions():
    srv, cli = v06.make(True)
    srv._rows["t"][4]["__mac__b"] = (srv._rows["t"][4]["__mac__b"] + 1) % N
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a*b*c FROM t")


@pytest.mark.parametrize("target", ["put", "mulv", "mul_tag", "mul_value"])
def test_tampering_with_any_wire_share_in_flight_is_detected(target):
    """The malicious server perturbs its own share of: a dealt rho (put), the t^-1 multiplier it was
    sent (mulv), the tag share, or the value share, of a product -- all end in IntegrityError."""
    class Evil(NoKeyServer):
        def wire_exec(self, ops):
            ops = [list(o) for o in ops]
            for op in ops:                                   # deviations BEFORE the server computes
                if op[0] == "put" and target == "put":
                    op[2] = [(op[2][0] + 1) % N] + op[2][1:]
                if op[0] == "mulv" and target == "mulv":
                    op[3] = [(op[3][0] + 1) % N] + op[3][1:]
            res = super().wire_exec(ops)
            for op, rr in zip(ops, res):                     # ... and AFTER
                if op[0] == "mul" and target == "mul_tag" and rr[2]:
                    rr[2][0] = (rr[2][0] + 1) % N
                if op[0] == "mul" and target == "mul_value":
                    st = self._wire_store().wires[op[1]]
                    st.vals[0] = (st.vals[0] + 1) % N
            return res
    _, cli = v06.make(True, server=Evil())
    sql = "SELECT a*b*c FROM t" if target.startswith("mul_") else "SELECT a/b FROM t"
    with pytest.raises(IntegrityError):
        cli.execute(sql)


@pytest.mark.parametrize("zero_row", [False, True])
def test_tampering_with_the_denominator_is_integrity_not_a_zero_oracle(zero_row):
    """Authenticated: shifting a denominator's share is caught by the MAC check on the opened t
    BEFORE any zero test, so the error is an IntegrityError whether or not y was the guess."""
    def rule(self, ops, res):
        if any(o[0] == "mul" for o in ops):                  # the request that opens t = rho*y
            for op, r in zip(ops, res):
                if op[0] == "reveal":
                    r[0][3] = (r[0][3] + 12345) % N
    rows = list(ROWS)
    if zero_row:
        rows[3] = rows[3][:4] + (0,) + rows[3][5:]            # b = 0 in row 3
    _, cli = v06.make(True, rows=rows, server=Tamper(rule))
    with pytest.raises(IntegrityError):
        cli.execute("SELECT a/b FROM t")


def test_without_authentication_a_lying_server_is_not_detected_pinned_limitation():
    """expr_mode="shared" without authenticated=True is secure against a SEMI-HONEST server only.
    A server that adds delta to its share of any wire shifts the result by a delta of its choosing
    (for a linear result, exactly delta), and nothing notices. Pinned here so the claim in the docs
    never silently grows."""
    def rule(self, ops, res):
        if self.n == 1:
            return
        for op, r in zip(ops, res):
            if op[0] == "reveal":
                r[0][0] = (r[0][0] + 17) % N
    srv, cli = v06.make(False, server=Tamper(rule))
    honest = [R(i)["a"] * R(i)["b"] for i in range(5)]
    got = per_row(cli, "a*b+0")
    assert got[0] == honest[0] + 17 and got[1:] == honest[1:]        # silently wrong, by exactly 17
    # and a tampered stored cell changes the answer without any error
    srv._rows["t"][2]["a"] = (srv._rows["t"][2]["a"] + 1) % N
    cli.server.rule = None
    assert per_row(cli, "a*b+0")[2] == (R(2)["a"] + 1) * R(2)["b"]


def test_unauthenticated_active_attacker_gets_a_zero_oracle_authenticated_does_not():
    """Pinned limitation: without MACs a malicious server can shift the share of a denominator by
    -c and watch whether the owner reports a division by zero (iff y == c); with MACs the same
    attack ends in IntegrityError whatever y is."""
    class ShiftY(NoKeyServer):
        """Shifts the server's stored share of column b (the denominator) by -c in every load."""

        def __init__(self, c):
            super().__init__()
            self.c = c

        def _wire_cells(self, table, col, rows):
            cells = super()._wire_cells(table, col, rows)
            return [(x - self.c) % N if col == "b" else x for x in cells]
    rows = ROWS
    yvals = [r[4] for r in rows]
    for auth in (False, True):
        outcomes = []
        for guess in (yvals[2], yvals[2] + 100):                     # right guess, wrong guess
            srv = ShiftY(guess)
            _, cli = v06.make(auth, rows=[rows[2]], server=srv)       # a single row, y = yvals[2]
            try:
                cli.execute("SELECT a/b FROM t")
                outcomes.append("ok")
            except DivisionByZero:
                outcomes.append("zero")
            except IntegrityError:
                outcomes.append("integrity")
        if auth:
            assert outcomes == ["integrity", "integrity"]
        else:
            assert outcomes == ["zero", "ok"]                        # the oracle works: documented


# ── modes ────────────────────────────────────────────────────────────────────
def test_owner_mode_is_still_available_and_agrees():
    _, shared = v06.make(False)
    _, owner = v06.make(False, expr_mode="owner")
    for sql in ["SELECT a*b*c*d FROM t", "SELECT a/b + s FROM t", "SELECT SUM(a*b)/SUM(c) FROM t"]:
        assert shared.execute(sql).rows == owner.execute(sql).rows
    assert owner.last_expr_cost.get("mode") is None and "requests" not in owner.last_expr_cost


def test_a_server_without_the_wire_rpcs_gives_a_clear_error():
    class Old:
        """A proxy of a server that predates wire protocol 2.1."""

        def __init__(self, inner):
            self._i = inner

        def __getattr__(self, name):
            if name.startswith("wire_"):
                raise AttributeError(name)
            return getattr(self._i, name)
    inner = NoKeyServer()
    cli = NoKeyClient(Old(inner))
    cli.execute("CREATE TABLE t (a INT PAIRED, b INT PAIRED)")
    cli.execute("INSERT INTO t (a, b) VALUES (2, 3)")
    with pytest.raises(ExecError, match="expr_mode='owner'"):
        cli.execute("SELECT a*b*a FROM t")
    cli.expr_mode = "owner"
    assert cli.execute("SELECT a*b*a FROM t").rows == [[[12]]]
    cli.expr_mode = "bogus"
    with pytest.raises(PlanError, match="expr_mode"):
        cli.execute("SELECT a*b*a FROM t")
