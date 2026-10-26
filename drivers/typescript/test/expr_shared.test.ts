// SPDX-License-Identifier: Apache-2.0
// Shared-wire expressions (expressionMode "shared", the default) against a REAL keyless server: the
// cross-language vectors (value, error class, cost, and the SHAPE of every wire request must equal the
// Python reference), a live Python peer against the same server, the abort-oracle trace, integrity
// (tampering / swap / replay in authenticated mode), caps / TTL / old-server errors, wire cleanup on every
// exit path, and an audit of everything the server is sent (with controls proving the audit can fail).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import {
  Client, TorusError, eq, gt, isIn, N, Column, ExprValue, Decoded, encodeInt, encodeRational,
} from "../src/torusdb";
import { fake, base, recorder, rawRpc, Recorder } from "./fake";
import { startProxy } from "./anchor_proxy";
import { skipReason, startServer, RunningServer, tmpdir, runExprPeer } from "./helpers";
import {
  vec, cellValue, show, showAll, loadTables, runCase, costOf, wireTrace, traceDigest, collectInts, audit, chi2,
  CHI2_LIMIT, rng, genTree,
} from "./exprCommon";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const R = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);
const kind = (k: string) => (e: unknown) => e instanceof TorusError && e.kind === k;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── the shared vectors: value, error, cost AND the shape of every wire request ──────────────────
for (const auth of [false, true]) {
  R(`vectors: ${vec.exec.cases.length} expressions give the Python reference's result, error, cost and wire trace (shared, ${auth ? "authenticated" : "plain"})`, async () => {
    const s = await startServer();
    try {
      const rec = await recorder(s);
      const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth, timeoutMs: 60_000 });
      assert.equal(db.expressionMode, "shared");
      await loadTables(db);
      let ok = 0, bad = 0, divisions = 0;
      for (const c of vec.exec.cases) {
        const want = c.shared;
        const where = `${c.table ?? "join"}: ${c.expr}${c.where ? " WHERE " + JSON.stringify(c.where) : ""}${c.max_depth !== undefined ? ` [max ${c.max_depth}]` : ""}`;
        const n0 = rec.log.length;
        if (want.error) {
          await assert.rejects(runCase(db, c), kind(want.error), where);
          assert.equal(db.lastExprCost, null, where);
          bad++;
        } else {
          const got = await runCase(db, c);
          assert.deepEqual(showAll(got), want.value, where);
          const cost = db.lastExprCost!;
          assert.equal(cost.mode, "shared", where);
          assert.deepEqual(costOf(cost, true), want.cost, where);
          if (want.cost.inversions > 0) divisions++;
          ok++;
        }
        const trace = traceDigest(wireTrace(rec.log, n0));
        assert.equal(trace, auth ? c.shared_auth_trace : want.trace, `wire trace: ${where}`);
      }
      assert.ok(ok > 300 && bad > 50 && divisions > 50, `${ok} ok / ${bad} errors / ${divisions} with a division`);
      db.close(); rec.close();
    } finally { await s.stop(); }
  });
}

R("the owner transport is still there: the same vectors, the old costs, no wire request", async () => {
  const s = await startServer();
  try {
    const rec = await recorder(s);
    const db = await Client.connect("127.0.0.1", rec.port, { expressionMode: "owner", timeoutMs: 60_000 });
    assert.equal(db.expressionMode, "owner");
    await loadTables(db);
    for (const c of vec.exec.cases.slice(0, 120)) {
      if (c.error) { await assert.rejects(runCase(db, c), kind(c.error)); continue; }
      assert.deepEqual(showAll(await runCase(db, c)), c.value, c.expr);
      assert.equal(db.lastExprCost!.mode, undefined);
      assert.equal(db.lastExprCost!.requests, undefined);
    }
    assert.ok(!rec.log.some((e) => e.m.startsWith("wire_")));
    db.close(); rec.close();
  } finally { await s.stop(); }
});

R("expressionMode is validated at connect time and on assignment", async () => {
  await assert.rejects(Client.connect(srv.host, srv.port, { expressionMode: "bogus" as any }), kind("InterfaceError"));
  const db = await Client.connect(srv.host, srv.port);
  assert.throws(() => { db.expressionMode = "nope" as any; }, kind("InterfaceError"));
  db.expressionMode = "owner";
  assert.equal(db.expressionMode, "owner");
  db.close();
});

// ── a live Python peer (shared mode) against the same server ────────────────────────────────────
const FIXED = ["a*b*c", "a*b*c*d", "(a+b)*(c-d)*a+s/2", "SUM(a*b*c)/COUNT(*)", "a/b", "r/c*a", "SUM(a)/SUM(c)", "100/c",
  "AVG(a*b)", "a*b/(c*d)", "SUM(a+2*b-s/4)", "a/0", "a*name", "SUM(id*2)", "s*a*b", "a*(b-b)", "1/(a-a)",
  "a/b/c/d", "a/b/c/d/a", "(a*b)/(c*d)", "SUM(a/b*c)", "AVG(a/b)", "SUM(a)/(SUM(b)-SUM(b))"];

for (const auth of [false, true]) {
  R(`Python (shared mode) and this driver agree on ${auth ? "authenticated" : "plain"} expressions: values, errors, costs, wire traces (one server)`, async () => {
    const seed = Number(process.env.TORUSDB_PEER_SEED ?? 20260626) + (auth ? 1 : 0);
    const r = rng(seed);
    const exprs = [...FIXED];
    while (exprs.length < 190) {
      const t = genTree(r, 1 + Math.floor(r() * 4), ["a", "b", "c", "d", "r", "q"]);
      if (/^[a-z]+$/.test(t)) continue;
      exprs.push(t);
    }
    const tdef = vec.exec.tables.find((x: any) => x.name === "t");
    const cols = tdef.columns as Array<[string, string, string]>;
    const pyT = auth ? "py_t_auth" : "py_t", tsT = auth ? "ts_t_auth" : "ts_t";
    const queries = exprs.map((expr) => ({ table: pyT, expr }));
    const peer = runExprPeer(srv.host, srv.port, {
      auth, mode: "shared", tables: [{ name: pyT, columns: cols, rows: tdef.rows }], queries,
    });
    assert.equal(peer.length, exprs.length);

    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth, timeoutMs: 120_000 });
    const schema: Column[] = cols.map(([name, type, policy]) => ({ name, type, policy } as Column));
    await db.createTable(tsT, schema);
    await db.insertMany(tsT, tdef.rows.map((row: Array<string | null>) => Object.fromEntries(schema.map((c, k) => [c.name, cellValue(row[k])]))));
    let ok = 0, errs = 0, divs = 0;
    for (let i = 0; i < exprs.length; i++) {
      const want = peer[i];
      const n0 = rec.log.length;
      let got: any;
      try {
        const v: ExprValue = await db.expr(tsT, exprs[i]);
        got = { value: showAll(v), cost: costOf(db.lastExprCost!, true) };
        ok++;
        if (got.cost.inversions > 0) divs++;
      } catch (e) {
        if (!(e instanceof TorusError)) throw e;
        got = { error: e.kind };
        errs++;
      }
      got.trace = traceDigest(wireTrace(rec.log, n0));
      assert.deepEqual(got, want, `${exprs[i]}`);
    }
    assert.ok(ok > 60 && errs > 10 && divs > 10, `${ok} ok / ${errs} errors / ${divs} divisions`);
    db.close(); rec.close();
  });
}

// ── a small fixed table for the behavioural tests ───────────────────────────────────────────────
const SCHEMA: Column[] = [
  { name: "id", type: "int", policy: "plain" }, { name: "dept", type: "int", policy: "plain" },
  { name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" },
  { name: "c", type: "int", policy: "paired" }, { name: "d", type: "int", policy: "paired" },
  { name: "r", type: "rational", policy: "paired" }, { name: "s", type: "rational", policy: "encrypted" },
];
const ROWS = [
  { id: 1, dept: 5, a: 1_000_003n, b: 2_000_011n, c: 3_000_017n, d: 5n, r: { num: 5_000_011n, den: 7n }, s: { num: 9_000_001n, den: 3n } },
  { id: 2, dept: 5, a: 1_000_033n, b: -2_000_029n, c: 3_000_041n, d: -1n, r: { num: -5_000_021n, den: 11n }, s: { num: 7_000_003n, den: 5n } },
  { id: 3, dept: 9, a: -1_000_037n, b: 2_000_039n, c: -3_000_043n, d: 8n, r: { num: 5_000_047n, den: 13n }, s: { num: -6_000_001n, den: 7n } },
  { id: 4, dept: 9, a: 1_000_051n, b: 2_000_057n, c: 3_000_059n, d: 2n, r: { num: 5_000_063n, den: 17n }, s: { num: 8_000_009n, den: 9n } },
];
async function seed(db: Client, t: string, rows = ROWS): Promise<void> {
  await db.createTable(t, SCHEMA);
  await db.insertMany(t, rows);
}
let seq = 0;
const tname = (b: string) => `${b}_${process.pid}_${++seq}`;

// exact rationals for the expected values
type Fr = { n: bigint; d: bigint };
const gcd = (a: bigint, b: bigint): bigint => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
const fr = (n: bigint, d = 1n): Fr => { if (d < 0n) { n = -n; d = -d; } const g = gcd(n, d) || 1n; return { n: n / g, d: d / g }; };
const fadd = (x: Fr, y: Fr) => fr(x.n * y.d + y.n * x.d, x.d * y.d);
const fsub = (x: Fr, y: Fr) => fr(x.n * y.d - y.n * x.d, x.d * y.d);
const fmul = (x: Fr, y: Fr) => fr(x.n * y.n, x.d * y.d);
const fdiv = (x: Fr, y: Fr) => fr(x.n * y.d, x.d * y.n);
const fshow = (x: Fr) => (x.d === 1n ? x.n.toString() : `${x.n}/${x.d}`);
const col = (name: "a" | "b" | "c" | "d") => ROWS.map((r) => fr(r[name]));
const rat = (name: "r" | "s") => ROWS.map((r) => fr(r[name].num, r[name].den));
const prodOf = (...names: Array<"a" | "b" | "c" | "d">) =>
  ROWS.map((_, i) => names.reduce((p, n) => fmul(p, col(n)[i]), fr(1n)));
const strs = (v: ExprValue) => showAll(v) as Array<string | null>;

const reqs = (rec: Recorder, n0: number, m: string) => rec.log.slice(n0).filter((e) => e.m === m);
const wireIds = (rec: Recorder, n0: number): string[] => {
  const ids = new Set<string>();
  for (const e of reqs(rec, n0, "wire_exec")) {
    for (const op of e.a[0] as any[]) for (const x of op.slice(1, 4)) if (typeof x === "string" && /^[0-9a-f]{12}\.\d+$/.test(x)) ids.add(x);
  }
  return [...ids];
};
/** True when the server still knows the wire (a `reveal` of 0 elements succeeds only on a live wire). */
async function wireAlive(db: Client, id: string): Promise<boolean> {
  try { await (db as any).call("wire_exec", [[["reveal", id, 0, 0]]], 4096); return true; } catch (e) {
    if (e instanceof TorusError && e.kind === "WireError" && /unknown wire/.test(e.message)) return false;
    throw e;
  }
}

// ── results over the wire ───────────────────────────────────────────────────────────────────────
for (const auth of [false, true]) {
  R(`depth 2 / 3 / 5 products, mixed operators and sums are exact; one request per level (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth });
    const t = tname("sh");
    await seed(db, t);
    for (const [names, depth] of [[["a", "b", "c"], 2], [["a", "b", "c", "d"], 3], [["a", "b", "c", "d", "a", "b"], 5]] as Array<[Array<"a" | "b" | "c" | "d">, number]>) {
      const n0 = rec.log.length;
      assert.deepEqual(strs(await db.expr(t, names.join("*"))), prodOf(...names).map(fshow));
      const c = db.lastExprCost!;
      assert.equal(c.mode, "shared");
      assert.equal(c.multRounds, depth);
      assert.equal(c.depth, depth);
      assert.equal(c.requests, depth + 1);
      assert.equal(reqs(rec, n0, "wire_exec").length, depth + 1);
      assert.equal(reqs(rec, n0, "mult_combine_batch").length, 0);
      assert.equal(reqs(rec, n0, "blinded_cells").length, 0, "the owner must not fetch operand cells");
    }
    const [a, b, c, d, s] = [col("a"), col("b"), col("c"), col("d"), rat("s")];
    const want = ROWS.map((_, i) => fadd(fsub(fmul(fmul(fadd(a[i], b[i]), fsub(c[i], d[i])), a[i]), fdiv(fmul(b[i], c[i]), d[i])), fdiv(s[i], fr(2n))));
    assert.deepEqual(strs(await db.expr(t, "(a+b)*(c-d)*a - b*c/d + s/2", ne2(1))), want.filter((_, i) => i !== 1).map(fshow));
    assert.equal(await db.expr(t, "SUM(a*b*c*d)"), prodOf("a", "b", "c", "d").reduce((p, q) => fadd(p, q), fr(0n)).n);
    const sab = prodOf("a", "b").reduce((p, q) => fadd(p, q), fr(0n)).n, sc = col("c").reduce((p, q) => fadd(p, q), fr(0n)).n;
    assert.equal(await db.expr(t, "SUM(a*b)*SUM(c)"), sab * sc);
    const g = await db.expr(t, "SUM(a*b*c)/COUNT(*)", isIn("dept", [5])) as Decoded;
    assert.equal(show(g), fshow(fr(prodOf("a", "b", "c").slice(0, 2).reduce((p, q) => fadd(p, q), fr(0n)).n, 2n)));
    db.close(); rec.close();
  });
}
function ne2(i: number) { return isIn("id", ROWS.map((r) => r.id).filter((x) => x !== ROWS[i].id)); }

for (const auth of [false, true]) {
  R(`division by an encrypted value: never decrypted, one extra level, exact (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth });
    const t = tname("shd");
    await seed(db, t);
    const [a, b, c, r] = [col("a"), col("b"), col("c"), rat("r")];
    assert.deepEqual(strs(await db.expr(t, "a/b")), a.map((x, i) => fshow(fdiv(x, b[i]))));
    assert.equal(db.lastExprCost!.multRounds, 2);                          // rho*y, then x*(1/y)
    assert.equal(db.lastExprCost!.inversions, ROWS.length);
    assert.equal(db.lastExprCost!.reveals, 2);                             // t, and the result
    assert.deepEqual(strs(await db.expr(t, "r/c")), r.map((x, i) => fshow(fdiv(x, c[i]))));
    assert.deepEqual(strs(await db.expr(t, "12/c")), c.map((x) => fshow(fdiv(fr(12n), x))));
    assert.deepEqual(strs(await db.expr(t, "a/(b*c)*r")), a.map((x, i) => fshow(fmul(fdiv(x, fmul(b[i], c[i])), r[i]))));
    const sab = prodOf("a", "b").reduce((p, q) => fadd(p, q), fr(0n)), sc = c.reduce((p, q) => fadd(p, q), fr(0n));
    assert.equal(show(await db.expr(t, "SUM(a*b)/SUM(c)") as Decoded), fshow(fdiv(sab, sc)));
    assert.equal(db.lastExprCost!.inversions, 1);
    await assert.rejects(db.expr(t, "a/(d-d)"), (e: unknown) => e instanceof TorusError && e.kind === "DivisionByZero" && /division by zero/.test(e.message));
    assert.equal(db.lastExprCost, null);
    // the server never saw an inverse-bearing request other than the (uniform) multiplier t^-1
    for (const e of rec.log.filter((x) => x.m === "wire_exec")) {
      for (const op of e.a[0] as any[]) assert.ok(["load", "loadsum", "put", "neg", "mulc", "addc", "mulv", "addv", "add", "sub", "bc", "sum", "mul", "reveal", "free"].includes(op[0]), op[0]);
    }
    db.close(); rec.close();
  });
}

R("cost accounting: rounds equal depth, openings / wires / requests / reveals are counted, one extra level per division", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = tname("cost");
  await seed(db, t);
  const n = ROWS.length;
  await db.expr(t, "a*b*c");
  let c = db.lastExprCost!;
  assert.deepEqual([c.multRounds, c.depth, c.products, c.openings], [2, 2, 2 * n, 4 * n]);
  assert.ok(c.reveals === 1 && c.requests === 3 && c.wires! >= 5, JSON.stringify(c));
  await db.expr(t, "a*b + c*d + a*d");
  c = db.lastExprCost!;
  assert.deepEqual([c.multRounds, c.products, c.requests], [1, 3 * n, 2]);
  await db.expr(t, "SUM(a+2*b)");                                          // linear: a single exchange
  c = db.lastExprCost!;
  assert.deepEqual([c.multRounds, c.requests, c.products, c.linearSums], [0, 1, 0, 2]);
  await db.expr(t, "a*b*c");
  const base0 = db.lastExprCost!.multRounds;
  await db.expr(t, "a*b/c");                                               // inv(c): level 1, product: level 2
  assert.equal(db.lastExprCost!.multRounds, 2); assert.equal(base0, 2);
  await db.expr(t, "a*b*c/d");
  assert.equal(db.lastExprCost!.multRounds, 3);
  await db.expr(t, "(a*b)/(c*d)");                                         // c*d: 1, rho*(c*d): 2, x*inv: 3
  assert.equal(db.lastExprCost!.multRounds, 3);
  db.close();
});

R("the depth cap counts the extra level of a division and is enforced before ANY request", async () => {
  const rec = await recorder(srv);
  const db = await Client.connect("127.0.0.1", rec.port, { maxMultDepth: 3 });
  const t = tname("capd");
  await seed(db, t);
  assert.ok(await db.expr(t, "a/b"));                                      // 2 levels: ok
  const n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a/b/c/d"), (e: unknown) => e instanceof TorusError && e.kind === "DepthLimitExceeded" && /maxMultDepth/.test(e.message) && /extra level/.test(e.message));
  await assert.rejects(db.expr(t, "a*b*c*d*a"), kind("DepthLimitExceeded"));
  assert.equal(rec.log.length, n0, "a request was sent before the depth check");
  assert.equal(db.analyzeExpr(t, "a/b").depth, 1, "analyzeExpr reports the dialect depth (owner rounds), not the shared one");
  db.maxMultDepth = 0;
  assert.ok(await db.expr(t, "a/3+s"));                                    // public division: no level
  await assert.rejects(db.expr(t, "a/b"), kind("DepthLimitExceeded"));
  db.close(); rec.close();
});

R("NULL operands, empty selections and the empty aggregate", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = tname("nul");
  await db.createTable(t, [{ name: "id", type: "int", policy: "plain" }, { name: "w", type: "int", policy: "plain" },
    { name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
  await db.insertMany(t, [{ id: 1, w: 2, a: 3, b: 4 }, { id: 2, w: null, a: 5, b: 6 }, { id: 3, w: 3, a: 7, b: 8 }]);
  assert.deepEqual(await db.expr(t, "a*b*w"), [24n, null, 168n]);
  assert.equal(await db.expr(t, "SUM(a*b*w)"), 192n);
  assert.equal(show(await db.expr(t, "AVG(a*b*w)") as Decoded), "96");
  assert.deepEqual(await db.expr(t, "a*b", gt("id", 99)), []);
  assert.equal(await db.expr(t, "SUM(a*b)", gt("id", 99)), 0n);
  assert.equal(await db.expr(t, "AVG(a*b)", gt("id", 99)), null);
  assert.equal(await db.expr(t, "COUNT(*)", gt("id", 99)), 0n);
  assert.deepEqual(await db.expr(t, "a/b*w"), [{ num: 3n, den: 2n }, null, { num: 21n, den: 8n }]);
  await assert.rejects(db.expr(t, "SUM(a)/COUNT(*)", gt("id", 99)), kind("DivisionByZero"));
  db.close();
});

// ── the abort oracle: a zero denominator does not change what the server sees ───────────────────
for (const auth of [false, true]) {
  R(`a zero denominator does not change the request sequence (shape of every wire request) (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth });
    const t = tname("zero");
    await seed(db, t);
    const exprs = ["a/b", "c*d/(a-a+b)*a", "SUM(a/b*c)", "a*c/(b+d-d)", "1/(a*b-c*d)", "100/(b-b+b)", "a/b/c"];
    for (const x of exprs) {
      const trace = async (expectErr: boolean) => {
        const n0 = rec.log.length;
        if (expectErr) await assert.rejects(db.expr(t, x), kind("DivisionByZero"), x);
        else await db.expr(t, x);
        return JSON.stringify(wireTrace(rec.log, n0));
      };
      const clean = await trace(false);
      const orig = ROWS.map((r) => ({ b: r.b, c: r.c, d: r.d }));
      await db.update(t, { b: 0n }, isIn("id", [2, 4]));
      if (x === "1/(a*b-c*d)") { await db.update(t, { a: 1n, b: 6n, c: 6n, d: 1n }, eq("id", 1)); }
      const zero = await trace(true);
      await db.update(t, { b: orig[0].b, a: ROWS[0].a, c: orig[0].c, d: orig[0].d }, eq("id", 1));
      await db.update(t, { b: orig[1].b }, eq("id", 2));
      await db.update(t, { b: orig[3].b }, eq("id", 4));
      assert.equal(zero, clean, `the request sequence depends on a zero denominator for ${x}`);
      assert.ok(JSON.parse(clean).length >= 2 && clean.includes('"mul"'), x);
    }
    db.close(); rec.close();
  });
}

// ── lifecycle: wires are freed on every exit path ───────────────────────────────────────────────
R("wires are freed after every query, success or error: the last request frees them, an abort uses wire_free", async () => {
  const rec = await recorder(srv);
  const db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
  const t = tname("free");
  await seed(db, t);
  const check = async (n0: number, expectFreeCall: boolean, label: string) => {
    const ids = wireIds(rec, n0);
    assert.ok(ids.length >= 3, label);
    for (const id of ids) assert.equal(await wireAlive(db, id), false, `${label}: wire ${id} survived`);
    assert.equal(reqs(rec, n0, "wire_free").length > 0, expectFreeCall, label);
  };
  let n0 = rec.log.length;
  await db.expr(t, "a*b*c*d");
  await check(n0, false, "success");
  await db.update(t, { b: 0n }, eq("id", 2));
  n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a/b"), kind("DivisionByZero"));      // runs to the end, then raises
  await check(n0, false, "division by zero");
  await db.insert(t, { id: 9, dept: 9, a: 2n ** 70n, b: 2n ** 70n, c: 1n, d: 1n, r: 1n, s: 1n });
  n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a*b*c", eq("id", 9)), kind("OutOfBudget"));
  await check(n0, false, "out of budget");
  // an abort in mid-protocol (the MAC check on an opening fails at the first level): explicit wire_free
  await rawRpc(srv.port, "update_cell", [t, 0, "b", { t: "i", v: "123456789" }]);
  n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a*b*c*d"), kind("IntegrityError"));
  await check(n0, true, "integrity abort");
  db.close(); rec.close();
});

R("a lost connection mid-protocol is a ConnectionError and the server drops the dead session's wires", async () => {
  const s2 = await startServer(["--wire-max-total-elements", "40"]);
  try {
    const px = await startProxy(s2);
    const db = await Client.connect("127.0.0.1", px.port, { timeoutMs: 5000 });
    const t = tname("lost");
    await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }, { name: "c", type: "int", policy: "paired" }]);
    await db.insertMany(t, [{ a: 1n, b: 2n, c: 3n }, { a: 4n, b: 5n, c: 6n }]);
    let nth = 0;
    px.hooks.resp = (r) => (r.m === "wire_exec" && ++nth === 2 ? "drop" : undefined);
    await assert.rejects(db.expr(t, "a*b*c"), kind("ConnectionError"));
    // the budget is server-wide: if the dead session still held its wires this load would not fit
    const other = await Client.connect(s2.host, s2.port);
    const t2 = tname("lost2");
    await other.createTable(t2, [{ name: "a", type: "int", policy: "paired" }]);
    await other.insertMany(t2, Array.from({ length: 18 }, (_, i) => ({ a: BigInt(i) })));
    let ok = false;
    for (let k = 0; k < 50 && !ok; k++) {
      try { await other.expr(t2, "-a"); ok = true; } catch (e) { if (!(e instanceof TorusError) || e.kind !== "WireError") throw e; await sleep(100); }
    }
    assert.ok(ok, "the dead session's wires were never released");
    other.close(); px.close();
  } finally { await s2.stop(); }
});

R("a transaction end frees the session's wires, a disconnect too; wires are private to their session", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = tname("txw");
  await seed(db, t);
  const load = (c: Client, wid: string) => (c as any).call("wire_exec", [[["load", wid, t, "a", [0, 1, 2], false]]], 4096);
  await db.begin();
  await load(db, "w1");
  assert.equal(await wireAlive(db, "w1"), true);
  await db.rollback();
  assert.equal(await wireAlive(db, "w1"), false);
  await db.begin();
  await load(db, "w1");
  await db.commit();
  assert.equal(await wireAlive(db, "w1"), false);
  await load(db, "w2");
  const other = await Client.connect(srv.host, srv.port);
  assert.equal(await wireAlive(other, "w2"), false, "another session sees this session's wire");
  assert.equal(await (other as any).call("wire_free", [["w2"]], 4096), 0, "freed another session's wire");
  assert.equal(await wireAlive(db, "w2"), true);
  await (db as any).call("wire_free", [["w2"]], 4096);
  assert.equal(await wireAlive(db, "w2"), false);
  db.close(); other.close();
});

R("expressions see the open transaction, rollback restores, a vault reload keeps working", async () => {
  const db = await Client.connect(srv.host, srv.port, { authenticated: true });
  const t = tname("tx");
  await seed(db, t);
  const before = await db.expr(t, "SUM(a*b*c)") as bigint;
  await db.begin();
  await db.insert(t, { id: 6, dept: 5, a: 10n, b: 10n, c: 10n, d: 1n, r: 1n, s: 1n });
  await db.update(t, { b: 0n }, eq("id", 1));
  assert.equal(await db.expr(t, "SUM(a*b*c)"), before + 1000n - ROWS[0].a * ROWS[0].b * ROWS[0].c);
  await assert.rejects(db.expr(t, "a/b"), kind("DivisionByZero"));
  await db.rollback();
  assert.equal(await db.expr(t, "SUM(a*b*c)"), before);
  assert.equal(show((await db.expr(t, "a/b") as Decoded[])[0]), "1000003/2000011");
  const vf = path.join(tmpdir(), "v.json");
  db.saveVault(vf);
  db.close();
  const db2 = await Client.connect(srv.host, srv.port, { authenticated: true, vaultPath: vf });
  assert.deepEqual(await db2.expr(t, "a*b*c", eq("id", 1)), [ROWS[0].a * ROWS[0].b * ROWS[0].c]);
  db2.close();
});

// ── server caps, TTL, old servers, roles ────────────────────────────────────────────────────────
R("caps are clear WireErrors and leave nothing behind (session memory, wire count, server-wide)", async () => {
  for (const [flags, expr, msg] of [
    [["--wire-max-elements", "14"], "a*b*c*d", /memory cap/],
    [["--wire-max-wires", "3"], "a*b*c*d + a*b - c*d", /too many live wires/],
    [["--wire-max-total-elements", "12"], "a*b*c*d", /server-wide/],
  ] as Array<[string[], string, RegExp]>) {
    const s2 = await startServer(flags);
    try {
      const rec = await recorder(s2);
      const db = await Client.connect("127.0.0.1", rec.port);
      const t = tname("cap");
      await seed(db, t);
      if (flags[0] === "--wire-max-elements") assert.ok(await db.expr(t, "SUM(a+b)"));      // a few width-1 wires: fine
      const n0 = rec.log.length;
      await assert.rejects(db.expr(t, expr), (e: unknown) => e instanceof TorusError && e.kind === "WireError" && msg.test(e.message), flags[0]);
      assert.equal(db.lastExprCost, null);
      for (const id of wireIds(rec, n0)) assert.equal(await wireAlive(db, id), false, `${flags[0]}: ${id}`);
      db.close(); rec.close();
    } finally { await s2.stop(); }
  }
});

R("unused wires expire after the TTL: a clear error naming it", async () => {
  const s2 = await startServer(["--wire-ttl", "0.3"]);
  try {
    const db = await Client.connect(s2.host, s2.port);
    const t = tname("ttl");
    await seed(db, t);
    await (db as any).call("wire_exec", [[["load", "w1", t, "a", [0, 1, 2], false]]], 4096);
    await sleep(700);
    await assert.rejects((db as any).call("wire_exec", [[["reveal", "w1", 0, 3]]], 4096),
      (e: unknown) => e instanceof TorusError && e.kind === "WireError" && /expired/.test(e.message));
    assert.deepEqual((await db.expr(t, "a*b") as bigint[]).length, ROWS.length);             // normal queries are unaffected
    db.close();
  } finally { await s2.stop(); }
});

R("a server without the wire RPCs gets a clear error before any wire request; owner mode still works", async () => {
  const rec = await recorder(srv, (m, _a, reply) => {
    if (m === "hello" && reply.ok) {
      const lim = { ...(reply.ok.limits ?? {}) }; delete lim.wires;
      return { ok: { ...reply.ok, limits: lim } };
    }
    return reply;
  });
  const db = await Client.connect("127.0.0.1", rec.port);
  assert.equal(db.serverInfo.limits?.wires, undefined);
  const t = tname("old");
  await seed(db, t);
  const n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a*b*c"), (e: unknown) => e instanceof TorusError && e.kind === "ExecError" && /expressionMode: 'owner'/.test(e.message) && /expr_mode='owner'/.test(e.message));
  assert.equal(db.lastExprCost, null);
  assert.ok(!rec.log.slice(n0).some((e) => e.m.startsWith("wire_")), "a wire RPC was sent to a server that does not offer it");
  db.expressionMode = "owner";
  assert.deepEqual(strs(await db.expr(t, "a*b*c")), prodOf("a", "b", "c").map(fshow));
  db.close(); rec.close();
});

R("the read-only role may run shared expressions (the wire RPCs are reads) and still cannot write", async () => {
  const f = path.join(tmpdir(), "tokens");
  fs.writeFileSync(f, `admin:admin-token-0123456789\nrw:rw-token-0123456789abc\nro:ro-token-0123456789abc\n`, { mode: 0o600 });
  const s2 = await startServer(["--token-file", f]);
  try {
    const vf = path.join(tmpdir(), "vault.json");
    const rw = await Client.connect(s2.host, s2.port, { token: "rw-token-0123456789abc", vaultPath: vf });
    const t = tname("ro");
    await seed(rw, t);
    rw.saveVault(vf);
    const ro = await Client.connect(s2.host, s2.port, { token: "ro-token-0123456789abc", vaultPath: vf });
    assert.deepEqual(strs(await ro.expr(t, "a*b*c")), prodOf("a", "b", "c").map(fshow));
    await assert.rejects(ro.update(t, { a: 1n }, eq("id", 1)), kind("Forbidden"));
    rw.close(); ro.close();
    const reply = await rawRpc(s2.port, "wire_exec", [[]]);                                  // no token
    assert.match(String(reply.err), /^Unauthenticated/);
  } finally { await s2.stop(); }
});

R("a server limit on the request size splits every level into several requests, within the advertised caps", async () => {
  const rec = await recorder(srv, (m, _a, reply) => {
    if (m === "hello" && reply.ok) {
      return { ok: { ...reply.ok, limits: { ...reply.ok.limits, wires: { ...reply.ok.limits.wires, max_request_elements: 90, max_ops: 5 } } } };
    }
    return reply;
  });
  const db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
  const t = tname("chunk");
  await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" },
    { name: "c", type: "int", policy: "paired" }, { name: "q", type: "int", policy: "plain" }]);
  const rows = Array.from({ length: 45 }, (_, i) => ({ a: BigInt(i - 20), b: BigInt(2 * i + 1), c: BigInt(7 - i), q: i % 3 + 1 }));
  await db.insertMany(t, rows);
  const n0 = rec.log.length;
  const got = strs(await db.expr(t, "(a*b*c + q)/q - a/b"));
  assert.deepEqual(got, rows.map((r) => fshow(fsub(fdiv(fr(r.a * r.b * r.c + BigInt(r.q)), fr(BigInt(r.q))), fr(r.a, r.b)))));
  assert.ok(db.lastExprCost!.requests! > 6);
  for (const e of reqs(rec, n0, "wire_exec")) {
    const ops = e.a[0] as any[];
    assert.ok(ops.length <= 5, `${ops.length} ops in one request`);
    let n = 0;
    for (const op of ops) {
      if (op[0] === "load" || op[0] === "loadsum") n += op[4].length;
      else if (op[0] === "mulv" || op[0] === "addv") n += op[3].length;
      else if (op[0] === "put") n += op[2].length * (op[3] ? 2 : 1);
      else if (op[0] === "mul") n += Object.values(op[4] as Record<string, unknown[]>).reduce((s, v) => s + v.length, 0);
      else if (op[0] === "reveal") n += op[3] * 2;
    }
    assert.ok(n <= 90, `${n} elements in one request`);
  }
  assert.equal(await db.expr(t, "SUM(a*b*c)"), rows.reduce((s, r) => s + r.a * r.b * r.c, 0n));
  db.close(); rec.close();
});

// ── a malicious server (reply level): integrity in authenticated mode, typed errors always ──────
const wireTamper = (fn: (ops: any[], res: any[], nth: number) => void) => (m: string, a: any[], reply: any, nth: number) => {
  if (m === "wire_exec" && reply.ok) {
    const copy = JSON.parse(JSON.stringify(reply));          // a NEW object: the recorder forwards only replaced replies
    fn(a[0], copy.ok, nth);
    return copy;
  }
  return reply;
};
const plus = (x: string, d: bigint) => ((BigInt(x) + d) % N).toString();

R("authenticated: a tampered reveal / opening share / reply is detected (IntegrityError), unauthenticated is pinned as undetected", async () => {
  // the final reveal
  let rec = await recorder(srv, wireTamper((ops, res) => ops.forEach((op, i) => { if (op[0] === "reveal" && op[1]) res[i][0][0] = plus(res[i][0][0], 1n); })));
  let db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
  let t = tname("tr");
  await seed(db, t);
  await assert.rejects(db.expr(t, "a*b*c"), (e: unknown) => e instanceof TorusError && e.kind === "IntegrityError" && /MAC check failed/.test(e.message));
  db.close(); rec.close();
  // an opening share e_S (its tag share stays honest)
  rec = await recorder(srv, wireTamper((ops, res) => ops.forEach((op, i) => { if (op[0] === "mul") res[i][0][2] = plus(res[i][0][2], 3n); })));
  db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
  t = tname("tr");
  await seed(db, t);
  await assert.rejects(db.expr(t, "a*b*c"), (e: unknown) => e instanceof TorusError && e.kind === "IntegrityError" && /MAC check failed on a multiplication opening/.test(e.message));
  // the tag share of the opening
  db.close(); rec.close();
  rec = await recorder(srv, wireTamper((ops, res) => ops.forEach((op, i) => { if (op[0] === "mul") res[i][2][1] = plus(res[i][2][1], 1n); })));
  db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
  t = tname("tr");
  await seed(db, t);
  await assert.rejects(db.expr(t, "a*b*c"), kind("IntegrityError"));
  assert.equal(db.lastExprCost, null);
  db.close(); rec.close();
  // WITHOUT authentication a lying server shifts the result by a delta of its choosing and nothing notices
  rec = await recorder(srv, wireTamper((ops, res, nth) => {
    if (nth > 1) ops.forEach((op, i) => { if (op[0] === "reveal") res[i][0][0] = plus(res[i][0][0], 17n); });
  }));
  db = await Client.connect("127.0.0.1", rec.port);
  t = tname("tr");
  await seed(db, t);
  const got = await db.expr(t, "a*b+0") as bigint[];
  const honest = ROWS.map((r) => r.a * r.b);
  assert.equal(got[0], honest[0] + 17n);
  assert.deepEqual(got.slice(1), honest.slice(1));
  db.close(); rec.close();
});

R("authenticated: a server that computes with other shares than it reports is caught (put / mulv / product value / opening)", async () => {
  for (const [target, sql] of [["put", "a/b"], ["mulv", "a/b"], ["mul_w", "a*b*c"], ["mul_eo", "a*b*c"]] as Array<[string, string]>) {
    const px = await startProxy(srv);
    px.hooks.req = (r) => {
      if (r.m !== "wire_exec") return undefined;
      for (const op of r.a[0] as any[]) {
        if (op[0] === "put" && target === "put") op[2][0] = plus(op[2][0], 1n);
        if (op[0] === "mulv" && target === "mulv") op[3][0] = plus(op[3][0], 1n);
        if (op[0] === "mul" && target === "mul_w") op[4].w[0] = plus(op[4].w[0], 1n);       // its product share is shifted
        if (op[0] === "mul" && target === "mul_eo") op[4].eo = op[4].eo.map((x: string) => plus(x, 1n));   // it uses e' = e + 1
      }
      return undefined;
    };
    const db = await Client.connect("127.0.0.1", px.port, { authenticated: true });
    const t = tname("tw");
    await seed(db, t);
    await assert.rejects(db.expr(t, sql), kind("IntegrityError"), target);
    db.close(); px.close();
  }
});

for (const zeroRow of [false, true]) {
  R(`authenticated: tampering with the denominator is an IntegrityError, never a zero oracle (${zeroRow ? "zero denominator" : "non-zero denominators"})`, async () => {
    const rec = await recorder(srv, wireTamper((ops, res) => {
      if (ops.some((o) => o[0] === "mul")) ops.forEach((op, i) => { if (op[0] === "reveal") res[i][0][3] = plus(res[i][0][3], 12345n); });
    }));
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: true });
    const t = tname("td");
    await seed(db, t, zeroRow ? ROWS.map((r, i) => (i === 3 ? { ...r, b: 0n } : r)) : ROWS);
    await assert.rejects(db.expr(t, "a/b"), kind("IntegrityError"));
    db.close(); rec.close();
  });
}

R("malformed wire replies are typed errors, never a wrong number (unauthenticated too)", async () => {
  const cases: Array<[string, (ops: any[], res: any[]) => any, string]> = [
    ["too few results", (_o, res) => res.slice(1), "IntegrityError"],
    ["not a list", () => null, "IntegrityError"],
    ["a non-numeric element", (ops, res) => { ops.forEach((op, i) => { if (op[0] === "mul") res[i][0][0] = "x"; }); return res; }, "ProtocolError"],
    ["an element >= n", (ops, res) => { ops.forEach((op, i) => { if (op[0] === "mul") res[i][1][0] = N.toString(); }); return res; }, "IntegrityError"],
    ["a short vector", (ops, res) => { ops.forEach((op, i) => { if (op[0] === "mul") res[i][0] = res[i][0].slice(1); }); return res; }, "IntegrityError"],
    ["a malformed reveal", (ops, res) => { ops.forEach((op, i) => { if (op[0] === "reveal") res[i] = [res[i][0]]; }); return res; }, "IntegrityError"],
  ];
  for (const [label, fn, want] of cases) {
    const rec = await recorder(srv, (m, a, reply) => {
      if (m === "wire_exec" && reply.ok) return { ok: fn(a[0], JSON.parse(JSON.stringify(reply.ok))) };
      return reply;
    });
    const db = await Client.connect("127.0.0.1", rec.port);
    const t = tname("mal");
    await seed(db, t);
    await assert.rejects(db.expr(t, "a*b*c"), kind(want), label);
    assert.equal(db.lastExprCost, null);
    db.close(); rec.close();
  }
});

// ── stored cells tampered, swapped, replayed (authenticated) ────────────────────────────────────
const cellOf = async (t: string, c: string, ids: number[]) => (await rawRpc(srv.port, "blinded_cells", [t, c, ids])).ok as Array<{ t: string; v: string }>;

R("authenticated: a tampered stored cell is detected whatever the expression, in shared mode as well", async () => {
  for (const sql of ["a*b*c*d", "a/b", "SUM(a+b)", "SUM(a*b)/SUM(c)", "b*2+a"]) {
    const db = await Client.connect(srv.host, srv.port, { authenticated: true });
    const t = tname("tc");
    await seed(db, t);
    const [cell] = await cellOf(t, "b", [1]);
    await rawRpc(srv.port, "update_cell", [t, 1, "b", { t: "i", v: plus(cell.v, 5n) }]);
    await assert.rejects(db.expr(t, sql), kind("IntegrityError"), sql);
    await rawRpc(srv.port, "update_cell", [t, 1, "b", cell]);
    assert.ok(await db.expr(t, sql), `${sql} after restoring the cell`);
    db.close();
  }
});

R("authenticated: swapped cells, replayed stale cells and a tampered MAC cell are detected", async () => {
  const db = await Client.connect(srv.host, srv.port, { authenticated: true });
  const t = tname("sw");
  await seed(db, t);
  const [a1, a2] = await cellOf(t, "a", [1, 2]);
  const [m1, m2] = await cellOf(t, "__mac__a", [1, 2]);
  for (const [r, v, m] of [[1, a2, m2], [2, a1, m1]] as Array<[number, any, any]>) {
    await rawRpc(srv.port, "update_cell", [t, r, "a", v]);
    await rawRpc(srv.port, "update_cell", [t, r, "__mac__a", m]);
  }
  await assert.rejects(db.expr(t, "a*b*c"), kind("IntegrityError"));
  for (const [r, v, m] of [[1, a1, m1], [2, a2, m2]] as Array<[number, any, any]>) {
    await rawRpc(srv.port, "update_cell", [t, r, "a", v]);
    await rawRpc(srv.port, "update_cell", [t, r, "__mac__a", m]);
  }
  assert.ok(await db.expr(t, "a*b*c"));
  // replay: a consistent stale (cell, tag) pair from before an UPDATE
  const [old] = await cellOf(t, "a", [2]);
  const [oldm] = await cellOf(t, "__mac__a", [2]);
  await db.update(t, { a: 999n }, eq("id", 3));
  await rawRpc(srv.port, "update_cell", [t, 2, "a", old]);
  await rawRpc(srv.port, "update_cell", [t, 2, "__mac__a", oldm]);
  await assert.rejects(db.expr(t, "SUM(a*b)/SUM(c)"), kind("IntegrityError"));
  // only the MAC cell
  const t2 = tname("sw2");
  await seed(db, t2);
  const [mb] = await cellOf(t2, "__mac__b", [3]);
  await rawRpc(srv.port, "update_cell", [t2, 3, "__mac__b", { t: "i", v: plus(mb.v, 1n) }]);
  await assert.rejects(db.expr(t2, "a*b*c"), kind("IntegrityError"));
  db.close();
});

R("pinned limitation: unauthenticated shared wires leak a zero oracle to an ACTIVE server; authenticated ones do not", async () => {
  for (const auth of [false, true]) {
    const outcomes: string[] = [];
    for (const guess of [7n, 107n]) {                                // y = 7: right guess, wrong guess
      const db = await Client.connect(srv.host, srv.port, { authenticated: auth });
      const t = tname("zo");
      await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
      await db.insertMany(t, [{ a: 3n, b: 7n }]);
      const [cell] = await cellOf(t, "b", [0]);                      // the active server shifts the stored share of y by -guess
      await rawRpc(srv.port, "update_cell", [t, 0, "b", { t: "i", v: plus(cell.v, N - guess) }]);
      try { await db.expr(t, "a/b"); outcomes.push("ok"); } catch (e) {
        outcomes.push(e instanceof TorusError && e.kind === "DivisionByZero" ? "zero" : e instanceof TorusError && e.kind === "IntegrityError" ? "integrity" : "other");
      }
      db.close();
    }
    assert.deepEqual(outcomes, auth ? ["integrity", "integrity"] : ["zero", "ok"], `auth=${auth}`);
  }
});

// ── the wire audit: what the server is sent ─────────────────────────────────────────────────────
const ALLOWED = ["wire_exec", "wire_free", "matching_rowids", "plain_cells", "schema", "tables"];

/** The banned values (decimal strings) that appear anywhere in the requests of `log`. */
function leaked(log: Recorder["log"], banned: Iterable<string>): string[] {
  const seen = new Set<string>();
  for (const e of log) collectInts(e.a, seen);
  return [...banned].filter((b) => seen.has(b));
}

async function identicalRows(rec: Recorder, auth: boolean, rows = 1200) {
  const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth, timeoutMs: 120_000 });
  const t = tname("same");
  await db.createTable(t, ["a", "b", "c", "d"].map((name) => ({ name, type: "int", policy: "paired" } as Column)));
  await db.insertMany(t, Array.from({ length: rows }, () => ({ a: 7n, b: 7n, c: 7n, d: 7n })));
  return { db, t };
}

for (const auth of [false, true]) {
  R(`wire audit: identical plaintexts give uniform shares at every level, no value is ever reused (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const { db, t } = await identicalRows(rec, auth);
    const n0 = rec.log.length;
    assert.deepEqual(await db.expr(t, "a*b*c*d"), new Array(1200).fill(7n ** 4n));        // 3 levels
    await db.expr(t, "a/b");                                                              // a division
    const sent = rec.log.slice(n0);
    assert.deepEqual(audit(sent), []);
    const muls = sent.filter((e) => e.m === "wire_exec").flatMap((e) => (e.a[0] as any[]).filter((op) => op[0] === "mul"));
    assert.equal(muls.length, 3 + 2);
    assert.ok(muls.every((op) => op[4].eo.length === 1200 && op[4].go.length === 1200));
    // the control: the same audit flags a log in which the dealer did not mask its share
    const bad = JSON.parse(JSON.stringify(sent));
    for (const e of bad) if (e.m === "wire_exec") for (const op of e.a[0]) if (op[0] === "mul") { op[4].eo = op[4].eo.map(() => "123"); op[4].go = op[4].go.map(() => "456"); }
    const v = audit(bad);
    assert.ok(v.some((x) => x.includes("eo")) && v.some((x) => x.includes("go")), JSON.stringify(v));
    db.close(); rec.close();
  });
}

for (const auth of [false, true]) {
  R(`wire audit: nothing derived from keys, masks, plaintexts, intermediates or inverses reaches the server (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { authenticated: auth });
    const t = tname("aud");
    await seed(db, t);
    await db.update(t, { b: 2_000_099n }, eq("id", 2));
    const rows = ROWS.map((r) => ({ ...r }));
    rows[1].b = 2_000_099n;
    const queries = ["a*b*c*d", "SUM(a*b*c*a)", "a/b", "r/c*a", "SUM(a*b)/COUNT(*)", "s/4+a*b*c", "SUM(a+b-s/2)",
      "(a+b)*(c-a)*b+s/3", "a/(b*c)*r", "100/b", "SUM(a)/SUM(b)", "a/b/c"];
    const n0 = rec.log.length;
    for (const q of queries) await db.expr(t, q);
    const sent = rec.log.slice(n0);
    const vf = path.join(tmpdir(), "audit-vault.json");
    db.saveVault(vf);
    const vault = JSON.parse(fs.readFileSync(vf, "utf8"));
    const masks = new Set<string>((vault.masks as unknown[][]).map((m) => String(m[3])));
    assert.ok(masks.size > 20);
    const methods = new Set(sent.map((e) => e.m));
    for (const m of methods) assert.ok(ALLOWED.includes(m), `unexpected RPC ${m}`);
    assert.ok(methods.has("wire_exec") && !methods.has("blinded_cells") && !methods.has("mult_combine_batch"));
    assert.deepEqual(leaked(sent, masks), [], "a mask value reached the server");
    if (auth) { assert.ok(vault.alpha); assert.deepEqual(leaked(sent, [String(vault.alpha)]), [], "the MAC key reached the server"); }
    const inv = (x: bigint) => { let r = 1n, b = ((x % N) + N) % N, e = N - 2n; while (e) { if (e & 1n) r = r * b % N; b = b * b % N; e >>= 1n; } return r; };
    const fr_ = (n: bigint, d: bigint) => encodeRational(n, d);
    const secrets = new Set<string>();
    for (const r of rows) {
      const { a, b, c, d } = r, rn = r.r, sn = r.s;
      const vals: bigint[] = [a, b, c, d, a * b, a * b * c, a * b * c * d, a * b * c * a, a + b, c - a, (a + b) * (c - a), (a + b) * (c - a) * b].map((v) => encodeInt(v));
      vals.push(fr_(rn.num, rn.den), fr_(sn.num, sn.den), fr_(sn.num, sn.den * 4n), fr_(sn.num, sn.den * 3n),
        fr_(a, b), fr_(1n, b), fr_(1n, b * c), fr_(a, b * c), fr_(a * rn.num, b * c * rn.den), fr_(rn.den, rn.num),
        fr_(rn.num, rn.den * c), fr_(rn.num * a, rn.den * c), fr_(100n, b), fr_(a, b * c), fr_(1n, c), fr_(a * c, b * c * c));
      vals.push(inv(encodeInt(b)), inv(encodeInt(c)), inv(encodeInt(b * c)), inv(encodeInt(d)), inv(fr_(rn.num, rn.den)));
      for (const v of vals) if (v >= 1000n && v < N - 1000n) secrets.add(v.toString());     // tiny values collide with row ids
    }
    secrets.delete(encodeRational(1n, 4n).toString()); secrets.delete(encodeRational(1n, 3n).toString());   // public constants of the queries
    secrets.delete(encodeRational(-1n, 4n).toString()); secrets.delete(encodeRational(-1n, 3n).toString());
    secrets.delete(encodeRational(1n, 2n).toString()); secrets.delete(encodeRational(-1n, 2n).toString());
    assert.deepEqual(leaked(sent, secrets), [], "a plaintext / intermediate / inverse encoding reached the server");
    assert.deepEqual(audit(sent), []);
    // the check has teeth: a mask, the MAC key or an encoded plaintext slipped into ANY request is found
    const doctored = JSON.parse(JSON.stringify(sent));
    const target = doctored.find((e: any) => e.m === "wire_exec");
    target.a[0].push(["free", [[...masks][0]]]);
    assert.deepEqual(leaked(doctored, masks), [[...masks][0]]);
    target.a[0].push(["mulc", "x.1", "x.2", [...secrets][0]]);
    assert.deepEqual(leaked(doctored, secrets), [[...secrets][0]]);
    // every triple / opening share is a huge uniform-looking residue
    const shares: bigint[] = [];
    for (const e of sent) if (e.m === "wire_exec") for (const op of e.a[0] as any[]) if (op[0] === "mul") for (const k of ["u", "v", "w", "eo", "go"]) for (const x of op[4][k]) shares.push(BigInt(x));
    assert.ok(shares.length > 100 && shares.filter((x) => x > N / 100n).length > 0.95 * shares.length);
    assert.equal(new Set(shares).size, shares.length);
    db.close(); rec.close();
  });
}

R("wire audit: two different plaintexts give indistinguishable opening shares (even at a level fed by an intermediate)", async () => {
  const rec = await recorder(srv);
  const db = await Client.connect("127.0.0.1", rec.port, { timeoutMs: 120_000 });
  const t = tname("two");
  await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }, { name: "c", type: "int", policy: "paired" }]);
  const rows: Array<Record<string, bigint>> = [];
  for (let i = 0; i < 1500; i++) { rows.push({ a: 0n, b: 0n, c: 0n }); rows.push({ a: 10_000_000_000_000n, b: -4n, c: 123_456_789n }); }
  await db.insertMany(t, rows);
  const n0 = rec.log.length;
  await db.expr(t, "a*b*c");
  const muls = rec.log.slice(n0).filter((e) => e.m === "wire_exec").flatMap((e) => (e.a[0] as any[]).filter((op) => op[0] === "mul"));
  const eo = (muls[1][4].eo as string[]).map(BigInt);                      // level 2: the operand is an intermediate
  const ca = new Array(16).fill(0), cb = new Array(16).fill(0);
  eo.forEach((v, i) => { (i % 2 === 0 ? ca : cb)[Number(v * 16n / N)]++; });
  const stat = ca.reduce((s, x, k) => s + (x - cb[k]) ** 2 / Math.max(1, x + cb[k]), 0);
  assert.ok(stat < CHI2_LIMIT, `two-sample chi2 ${stat}`);
  assert.ok(chi2(eo) < CHI2_LIMIT);
  db.close(); rec.close();
});

R("wire audit controls: a reused triple and a leaked value are caught by the audit helpers", async () => {
  const rec = await recorder(srv);
  const { db, t } = await identicalRows(rec, false, 1200);
  const n0 = rec.log.length;
  await db.expr(t, "a*b*c");
  const sent: Recorder["log"] = JSON.parse(JSON.stringify(rec.log.slice(n0)));
  assert.deepEqual(audit(sent), []);
  const muls = sent.filter((e) => e.m === "wire_exec").flatMap((e) => (e.a[0] as any[]).filter((op) => op[0] === "mul"));
  muls[1][4].u = [...muls[0][4].u];                                         // the second level reuses the first level's triple
  assert.ok(audit(sent).some((x) => x.includes("repeated")));
  db.close(); rec.close();
});

// ── a hostile fake server: the evaluator cleans up after itself ─────────────────────────────────
test("a malformed wire_exec reply aborts the query with a typed error, then wire_free names every wire the query created", async () => {
  const wires = { max_wires: 4096, max_elements: 4000000, ttl: 120, max_ops: 20000, max_request_elements: 150000 };
  const f = await fake(base({
    hello: { ok: { protocol: 2, server: "fake", auth_required: false, max_frame: 33554432, persistent: false, limits: { max_items: 200000, wires } } },
    insert_many: { ok: [0, 1] },
    matching_rowids: { ok: [0, 1] },
    wire_exec: { ok: [] },                                            // wrong number of results
    wire_free: { ok: 0 },
  }));
  const db = await Client.connect("127.0.0.1", f.port);
  await db.createTable("t", [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
  await db.insertMany("t", [{ a: 1, b: 2 }, { a: 3, b: 4 }]);
  await assert.rejects(db.expr("t", "a*b"), (e: unknown) => e instanceof TorusError && e.kind === "IntegrityError");
  assert.equal(db.lastExprCost, null);
  const execs = f.bodies.map((b) => JSON.parse(b)).filter((r) => r.m === "wire_exec");
  const frees = f.bodies.map((b) => JSON.parse(b)).filter((r) => r.m === "wire_free");
  assert.equal(execs.length, 1);
  assert.equal(frees.length, 1);
  const created = new Set<string>();
  for (const op of execs[0].a[0]) for (const x of op.slice(1, 4)) if (typeof x === "string" && /^[0-9a-f]{12}\.\d+$/.test(x)) created.add(x);
  assert.ok(created.size >= 3);
  assert.deepEqual(new Set(frees[0].a[0]), created);
  db.close(); f.close();
});

R("the multiplier t^-1 a division sends is uniform, non-zero and never repeated, whether or not y was zero (a zero is replaced by a dummy)", async () => {
  const samples: Record<string, bigint[]> = {};
  for (const [label, yval] of [["nonzero", 123_456_789n], ["zero", 0n]] as Array<[string, bigint]>) {
    const rec = await recorder(srv);
    const db = await Client.connect("127.0.0.1", rec.port, { timeoutMs: 120_000 });
    const t = tname("tinv");
    await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
    await db.insertMany(t, Array.from({ length: 2500 }, () => ({ a: 5n, b: yval })));
    const n0 = rec.log.length;
    if (yval !== 0n) await db.expr(t, "a/b"); else await assert.rejects(db.expr(t, "a/b"), kind("DivisionByZero"));
    const tinv: bigint[] = [];
    for (const e of rec.log.slice(n0)) if (e.m === "wire_exec") for (const op of e.a[0] as any[]) if (op[0] === "mulv") for (const x of op[3]) tinv.push(BigInt(x));
    samples[label] = tinv;
    db.close(); rec.close();
  }
  for (const [label, vals] of Object.entries(samples)) {
    assert.equal(vals.length, 2500, label);
    assert.ok(!vals.includes(0n), `${label}: a zero multiplier reached the server`);
    assert.ok(chi2(vals) < CHI2_LIMIT, `${label}: not uniform`);
    assert.equal(new Set(vals).size, vals.length, label);
  }
  const ca = new Array(16).fill(0), cb = new Array(16).fill(0);
  for (const v of samples.nonzero) ca[Number(v * 16n / N)]++;
  for (const v of samples.zero) cb[Number(v * 16n / N)]++;
  assert.ok(ca.reduce((s, x, k) => s + (x - cb[k]) ** 2 / Math.max(1, x + cb[k]), 0) < CHI2_LIMIT);
});
