// SPDX-License-Identifier: Apache-2.0
// Dialect v0.6 expressions against a REAL keyless server (Python): the shared vectors (every result,
// error and cost must equal the Python reference), rounds == depth, the depth cap, the abort-oracle
// protection, integrity (authenticated mode) and an audit of everything the server is sent.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import {
  Client, TorusError, eq, ne, gt, isIn, N, Column, JoinResult, ExprValue, encodeInt, encodeRational, Decoded,
} from "../src/torusdb";
import { fake, base, recorder, rawRpc, Recorder } from "./fake";
import { skipReason, startServer, RunningServer, tmpdir, EXPR_VECTORS, ownerConnect } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const R = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);
const kind = (k: string) => (e: unknown) => e instanceof TorusError && e.kind === k;
const vec = JSON.parse(fs.readFileSync(EXPR_VECTORS, "utf8"));

// ── helpers ──────────────────────────────────────────────────────────────────
type Cell = string | null;
function cellValue(s: Cell): bigint | { num: bigint; den: bigint } | null {
  if (s === null) return null;
  if (s.includes("/")) { const [n, d] = s.split("/").map(BigInt); return { num: n, den: d }; }
  return BigInt(s);
}
function show(v: Decoded | null): string | null {
  if (v === null) return null;
  return typeof v === "bigint" ? v.toString() : `${v.num}/${v.den}`;
}
function showAll(v: ExprValue): string | null | Array<string | null> {
  return Array.isArray(v) ? v.map(show) : show(v);
}

async function loadTables(db: Client, prefix = ""): Promise<void> {
  for (const t of vec.exec.tables as Array<{ name: string; columns: Array<[string, string, string]>; rows: Cell[][] }>) {
    const cols: Column[] = t.columns.map(([name, type, policy]) => ({ name, type, policy } as Column));
    await db.createTable(prefix + t.name, cols);
    if (t.rows.length) {
      await db.insertMany(prefix + t.name, t.rows.map((r) => Object.fromEntries(cols.map((c, k) => [c.name, cellValue(r[k])]))));
    }
  }
}

function wherePred(w: { col: string; op: string; val: any }) {
  switch (w.op) {
    case "=": return eq(w.col, w.val);
    case "<>": return ne(w.col, w.val);
    case ">": return gt(w.col, w.val);
    case "IN": return isIn(w.col, w.val);
    default: throw new Error("where op " + w.op);
  }
}

async function runCase(db: Client, c: any): Promise<ExprValue> {
  db.maxMultDepth = c.max_depth ?? 8;
  if (c.join) {
    const j = c.join;
    const joined: JoinResult = await db.join(j.left[0], j.steps.map((s: any) => ({
      table: s.table, alias: s.alias, leftAlias: s.left_alias, leftCol: s.left_col, rightCol: s.right_col, kind: s.kind,
    })), { alias: j.left[1] });
    return db.joinExpr(joined, c.expr);
  }
  return db.expr(c.table, c.expr, c.where ? wherePred(c.where) : null);
}

// ── the shared vectors ───────────────────────────────────────────────────────
for (const auth of [false, true]) {
  R(`vectors: ${vec.exec.cases.length} expressions give the Python reference's result, error and cost (${auth ? "authenticated" : "plain"})`, async () => {
    const s = await startServer();
    try {
      const db = await ownerConnect(s.host, s.port, { authenticated: auth, timeoutMs: 60_000 });
      await loadTables(db);
      let ok = 0, bad = 0;
      for (const c of vec.exec.cases) {
        const where = `${c.table ?? "join"}: ${c.expr}${c.where ? " WHERE " + JSON.stringify(c.where) : ""}${c.max_depth !== undefined ? ` [max ${c.max_depth}]` : ""}`;
        if (c.error) {
          await assert.rejects(runCase(db, c), kind(c.error), where);
          assert.equal(db.lastExprCost, null, where);
          bad++;
        } else {
          const got = await runCase(db, c);
          assert.deepEqual(showAll(got), c.value, where);
          const cost = db.lastExprCost!;
          assert.deepEqual({ depth: cost.depth, mult_rounds: cost.multRounds, products: cost.products,
                             inversions: cost.inversions, linear_sums: cost.linearSums }, c.cost, where);
          assert.equal(cost.multRounds, cost.depth, where);
          ok++;
        }
      }
      assert.ok(ok > 300 && bad > 50, `${ok} ok / ${bad} errors`);
      db.close();
    } finally { await s.stop(); }
  });
}

// ── small fixed table used by the behavioural tests ──────────────────────────
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

R("rounds follow the multiplicative depth, one mult_combine_batch per level (checked on the wire)", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("rd");
  await seed(db, t);
  const cases: Array<[string, number]> = [["a*b", 1], ["a*b*c", 2], ["a*b*c*d", 3], ["(a*b)*(c*d)", 2],
    ["a*b + c*d + a*d", 1], ["2*a*b*3", 1], ["a/b", 1], ["100/c", 0], ["s/4+a*3", 0], ["a*b*c*d*a*b", 5],
    ["SUM(a*b*c)", 2], ["SUM(a)/SUM(c)", 1], ["a/b/c", 2]];
  for (const [x, depth] of cases) {
    const n0 = rec.log.length;
    await db.expr(t, x);
    const mults = rec.log.slice(n0).filter((e) => e.m === "mult_combine_batch");
    assert.equal(mults.length, depth, x);
    assert.equal(db.lastExprCost!.depth, depth, x);
    assert.equal(db.lastExprCost!.multRounds, depth, x);
  }
  db.close(); rec.close();
});

R("the depth cap is enforced before ANY request, per connection and per assignment", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port, { maxMultDepth: 2 });
  const t = tname("cap");
  await seed(db, t);
  assert.equal(db.maxMultDepth, 2);
  assert.ok(await db.expr(t, "a*b*c"));                                      // depth 2: allowed
  const n0 = rec.log.length;
  await assert.rejects(db.expr(t, "a*b*c*d"), (e: unknown) => e instanceof TorusError && e.kind === "DepthLimitExceeded" && /maxMultDepth/.test(e.message));
  assert.equal(rec.log.length, n0, "a request was sent before the depth check");
  db.maxMultDepth = 3;
  assert.ok(await db.expr(t, "a*b*c*d"));
  db.maxMultDepth = 0;
  await assert.rejects(db.expr(t, "a*b+0"), kind("DepthLimitExceeded"));
  assert.ok(await db.expr(t, "s/2+a*3"));                                    // depth 0 is always fine
  for (const bad of [-1, 1.5, NaN, "3" as any]) assert.throws(() => { db.maxMultDepth = bad; }, kind("InterfaceError"));
  await assert.rejects(ownerConnect("127.0.0.1", rec.port, { maxMultDepth: -2 }), kind("InterfaceError"));
  db.close(); rec.close();
  // the default is 8
  const d2 = await ownerConnect(srv.host, srv.port);
  assert.equal(d2.maxMultDepth, 8);
  const t2 = tname("cap8");
  await d2.createTable(t2, [{ name: "a", type: "int", policy: "paired" }]);
  await d2.insertMany(t2, [{ a: 1n }, { a: -1n }]);
  assert.ok(await d2.expr(t2, ["a", ...Array(8).fill("a")].join("*")));     // 8 products = depth 8
  await assert.rejects(d2.expr(t2, ["a", ...Array(9).fill("a")].join("*")), kind("DepthLimitExceeded"));
  d2.close();
});

R("a zero denominator does not change the request sequence the server sees", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("zero");
  await seed(db, t);
  const exprs = ["a/b", "c*d/(a-a+b)*a", "SUM(a/b*c)", "a*c/(b+d-d)", "100/(b-b+b)"];
  for (const x of exprs) {
    const trace = async (expectErr: boolean) => {
      const n0 = rec.log.length;
      if (expectErr) await assert.rejects(db.expr(t, x), kind("DivisionByZero"), x);
      else await db.expr(t, x);
      // method names and the number of items of every list argument
      return rec.log.slice(n0).map((e) => [e.m, e.a.map((v) => (Array.isArray(v) ? v.length : 0))]);
    };
    const clean = await trace(false);
    await db.update(t, { b: 0n }, isIn("id", [2, 4]));
    const zero = await trace(true);
    await db.update(t, { b: 2_000_011n }, isIn("id", [2, 4]));
    assert.deepEqual(zero, clean, `the request sequence depends on a zero denominator for ${x}`);
    if (!x.startsWith("100/")) assert.ok(zero.some(([m]) => m === "mult_combine_batch"), x);   // depth 0: no round at all
  }
  db.close(); rec.close();
});

R("division by zero: rows removed by WHERE do not count; an empty aggregate divides by zero; no cost is recorded", async () => {
  const db = await ownerConnect(srv.host, srv.port);
  const t = tname("dz");
  await seed(db, t);
  await db.update(t, { b: 0n }, eq("id", 2));
  await assert.rejects(db.expr(t, "a/b"), (e: unknown) => e instanceof TorusError && e.kind === "DivisionByZero" && /division by zero/.test(e.message));
  assert.equal(db.lastExprCost, null);
  assert.deepEqual(showAll(await db.expr(t, "a/b", ne("id", 2))),
    ["1000003/2000011", "-1000037/2000039", "1000051/2000057"]);
  await assert.rejects(db.expr(t, "SUM(a)/COUNT(*)", gt("id", 99)), kind("DivisionByZero"));
  await assert.rejects(db.expr(t, "a/(b-b)"), kind("DivisionByZero"));
  await assert.rejects(db.expr(t, "a/0"), kind("PlanError"));
  db.close();
});

R("authenticated mode: tampered operands are detected through deep products, divisions and linear sums", async () => {
  const db = await ownerConnect(srv.host, srv.port, { authenticated: true });
  const t = tname("tamper");
  await seed(db, t);
  const forged = { t: "i", v: "123456789" };
  await rawRpc(srv.port, "update_cell", [t, 1, "b", forged]);
  for (const x of ["a*b*c*d", "a/b", "SUM(a*b)/COUNT(*)", "SUM(a+b)", "b*2+a"]) {
    await assert.rejects(db.expr(t, x), kind("IntegrityError"), x);
  }
  assert.ok(await db.expr(t, "a*c*d"));                                      // untouched columns still work
  db.close();
});

R("authenticated mode: a forged product term at ANY level is detected; unauthenticated mode does not (documented)", async () => {
  for (const level of [1, 2, 3]) {
    const rec = await recorder(srv, (m, _a, reply, nth) => {
      if (m === "mult_combine_batch" && nth === level && reply.ok) {
        return { ok: reply.ok.map((x: string) => ((BigInt(x) + 1n) % N).toString()) };
      }
      return reply;
    });
    const db = await ownerConnect("127.0.0.1", rec.port, { authenticated: true });
    const t = tname("forge");
    await seed(db, t);
    await assert.rejects(db.expr(t, "a*b*c*d"), (e: unknown) => e instanceof TorusError && e.kind === "IntegrityError" && /forged product/.test(e.message), `level ${level}`);
    db.close(); rec.close();
  }
  // a reply with the wrong number of terms is an integrity failure too
  const rec = await recorder(srv, (m, _a, reply) => (m === "mult_combine_batch" && reply.ok ? { ok: reply.ok.slice(1) } : reply));
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("forge2");
  await seed(db, t);
  await assert.rejects(db.expr(t, "a*b"), kind("IntegrityError"));
  db.close(); rec.close();
  // without authenticated mode nothing checks e*g (as for dot): the answer is silently wrong
  const rec2 = await recorder(srv, (m, _a, reply) => (m === "mult_combine_batch" && reply.ok
    ? { ok: reply.ok.map((x: string) => ((BigInt(x) + 1n) % N).toString()) } : reply));
  const d2 = await ownerConnect("127.0.0.1", rec2.port);
  const t2 = tname("forge3");
  await seed(d2, t2);
  const got = await d2.expr(t2, "a*b*c") as Decoded[];
  assert.notDeepEqual(got.map(show), ROWS.map((r) => (r.a * r.b * r.c).toString()));
  d2.close(); rec2.close();
});

R("expressions see uncommitted changes, rollback restores, a vault reload keeps working", async () => {
  const db = await ownerConnect(srv.host, srv.port, { authenticated: true });
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
  await db.transaction(async () => {
    await db.update(t, { a: 100n }, eq("id", 1));
    assert.deepEqual(await db.expr(t, "a*b*c", eq("id", 1)), [100n * ROWS[0].b * ROWS[0].c]);
  });
  const vf = path.join(tmpdir(), "v.json");
  db.saveVault(vf);
  db.close();
  const db2 = await ownerConnect(srv.host, srv.port, { authenticated: true, vaultPath: vf });
  assert.deepEqual(await db2.expr(t, "a*b*c", eq("id", 1)), [100n * ROWS[0].b * ROWS[0].c]);
  db2.close();
});

R("analyzeExpr reports kind/depth/cost without a request; FHE columns are rejected naming FHE; STR/ENC rules", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("an");
  await db.createTable(t, [
    { name: "id", type: "int", policy: "plain" }, { name: "nm", type: "str", policy: "plain" },
    { name: "e", type: "rational", policy: "encrypted" }, { name: "p", type: "int", policy: "paired" },
    { name: "q", type: "int", policy: "paired" }, { name: "f", type: "int", policy: "fhe" },
  ]);
  const n0 = rec.log.length;
  assert.deepEqual(db.analyzeExpr(t, "p*q*p"), { kind: "row", enc: true, depth: 2, ctMuls: 2, inversions: 0, text: "p*q*p" });
  assert.equal(db.analyzeExpr(t, "SUM(p*q)/SUM(p)").depth, 2);
  for (const x of ["x*y*x", "f/2", "f+1", "SUM(f)/COUNT(*)", "SUM(f*f)", "p*f*p", "f*2+p"]) {
    const y = x.replace(/x/g, "f").replace(/y/g, "f");
    assert.throws(() => db.analyzeExpr(t, y), (e: unknown) => e instanceof TorusError && e.kind === "PlanError" && /FHE column 'f' cannot be used inside an arithmetic expression/.test(e.message), y);
  }
  assert.throws(() => db.analyzeExpr(t, "nm*2+p"), /STR column 'nm'/);
  assert.throws(() => db.analyzeExpr(t, "e*p"), /requires PAIRED columns \(column 'e' is ENC\)/);
  assert.throws(() => db.analyzeExpr(t, "p/e"), /PAIRED/);
  assert.equal(rec.log.length, n0, "analysis must not send anything");
  db.close(); rec.close();
});

R("tables learned only from the server are refused for expressions (a lying server could relabel a column)", async () => {
  const owner = await ownerConnect(srv.host, srv.port);
  const t = tname("untrusted");
  await seed(owner, t);
  const other = await ownerConnect(srv.host, srv.port);            // syncSchema: learns the table, untrusted
  await assert.rejects(other.expr(t, "a*b*c"), kind("UntrustedSchema"));
  other.trustTable(t);
  await assert.rejects(other.expr(t, "a*b*c"), /no mask/);           // trusted now, but it has no masks: loud, not wrong
  owner.close(); other.close();
});

R("an expression 98 levels high runs (maximum parser height), exactly", async () => {
  const db = await ownerConnect(srv.host, srv.port, { maxMultDepth: 120, timeoutMs: 120_000 });
  const t = tname("tall");
  await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }]);
  await db.insertMany(t, [{ a: 1n }, { a: -1n }]);
  assert.deepEqual(await db.expr(t, "a" + "*a".repeat(98)), [1n, -1n]);
  assert.equal(db.lastExprCost!.multRounds, 98);
  assert.deepEqual(await db.expr(t, "a" + "+a".repeat(98)), [99n, -99n]);
  assert.equal(db.lastExprCost!.multRounds, 0);
  db.close();
});

R("a linear SUM is a Pi_lin aggregate (blinded_sum), not a row download; coefficients may exceed the budget while the result does not", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("lin");
  await seed(db, t);
  const n0 = rec.log.length;
  const expected = ROWS.reduce((s, r) => s + r.a + 2n * r.b, 0n);
  assert.equal(await db.expr(t, "SUM(a+2*b)"), expected);
  const seen = rec.log.slice(n0).map((e) => e.m);
  assert.ok(!seen.includes("blinded_cells"), "a linear SUM must use server-side sums");
  assert.equal(seen.filter((m) => m === "blinded_sum").length, 2);
  assert.deepEqual({ ...db.lastExprCost! }, { depth: 0, multRounds: 0, products: 0, inversions: 0, linearSums: 2 });
  const big = 2n ** 100n;
  const t2 = tname("lin2");
  await db.createTable(t2, [{ name: "a", type: "int", policy: "paired" }]);
  await db.insertMany(t2, [{ a: 0n }, { a: 0n }]);
  assert.equal(await db.expr(t2, `SUM(a*${big}*${big})`), 0n);
  assert.deepEqual(await db.expr(t2, `a*${big}*${big}`), [0n, 0n]);
  db.close(); rec.close();
});

R("a server limit on max_items chunks each level into several requests, still one logical round per level", async () => {
  const rec = await recorder(srv, (m, _a, reply) => {
    if (m === "hello" && reply.ok) return { ok: { ...reply.ok, limits: { ...(reply.ok.limits ?? {}), max_items: 7 } } };
    return reply;
  });
  const db = await ownerConnect("127.0.0.1", rec.port);
  assert.equal(db.serverInfo.limits?.maxItems, 7);
  const t = tname("chunk");
  await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }, { name: "c", type: "int", policy: "paired" }]);
  const rows = Array.from({ length: 20 }, (_, i) => ({ a: BigInt(i + 1), b: BigInt(2 * i - 5), c: BigInt(i % 4 + 1) }));
  await db.insertMany(t, rows);
  const n0 = rec.log.length;
  assert.deepEqual(await db.expr(t, "a*b*c"), rows.map((r) => r.a * r.b * r.c));
  const mults = rec.log.slice(n0).filter((e) => e.m === "mult_combine_batch");
  assert.equal(mults.length, 6);                                           // 2 levels x ceil(20 / 7)
  assert.ok(mults.every((e) => e.a[0].length <= 7));
  assert.equal(db.lastExprCost!.multRounds, 2);
  db.close(); rec.close();
});

R("the empty selection and NULL operands", async () => {
  const db = await ownerConnect(srv.host, srv.port);
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
  db.close();
});

// ── the server never receives a key, a mask, a MAC key or a plaintext-derived value ──────────────
function collectInts(x: unknown, out: Set<string>): void {
  if (typeof x === "boolean") return;
  if (typeof x === "number") { out.add(String(x)); return; }
  if (typeof x === "string") { if (/^-?[0-9]+$/.test(x)) out.add(x); return; }
  if (Array.isArray(x)) { x.forEach((v) => collectInts(v, out)); return; }
  if (x && typeof x === "object") Object.values(x).forEach((v) => collectInts(v, out));
}
const encR = (num: bigint, den: bigint) => encodeRational(num, den);

for (const auth of [false, true]) {
  R(`wire audit: nothing derived from keys, masks or plaintexts reaches the server (${auth ? "authenticated" : "plain"})`, async () => {
    const rec = await recorder(srv);
    const db = await ownerConnect("127.0.0.1", rec.port, { authenticated: auth });
    const t = tname("aud");
    await seed(db, t);
    await db.update(t, { b: 2_000_099n }, eq("id", 2));
    const rows = ROWS.map((r) => ({ ...r }));
    rows[1].b = 2_000_099n;
    const queries = ["a*b*c*d", "SUM(a*b*c*a)", "a/b", "r/c*a", "SUM(a*b)/COUNT(*)", "s/4+a*b*c", "SUM(a+b-s/2)",
      "(a+b)*(c-a)*b+s/3", "a/(b*c)*r", "100/b", "SUM(a)/SUM(b)"];
    const n0 = rec.log.length;
    for (const q of queries) await db.expr(t, q);
    const sent = rec.log.slice(n0);
    // the secrets the owner holds: masks and the MAC key are in the vault file
    const vf = path.join(tmpdir(), "audit-vault.json");
    db.saveVault(vf);
    const vault = JSON.parse(fs.readFileSync(vf, "utf8"));
    const masks = new Set<string>((vault.masks as unknown[][]).map((m) => String(m[3])));
    assert.ok(masks.size > 20);
    const methods = new Set(sent.map((e) => e.m));
    for (const m of methods) {
      assert.ok(["blinded_cells", "blinded_sum", "blinded_scaled_sum", "mult_combine_batch", "matching_rowids", "plain_cells",
        "schema", "tables"].includes(m), `unexpected RPC ${m}`);
    }
    assert.ok(methods.has("mult_combine_batch"));
    const seen = new Set<string>();
    for (const e of sent) collectInts(e.a, seen);
    for (const m of masks) assert.ok(!seen.has(m), "a mask value reached the server");
    if (auth) { assert.ok(vault.alpha); assert.ok(!seen.has(String(vault.alpha)), "the MAC key reached the server"); }
    // encoded plaintexts, intermediates, inverses and results
    const fr = (n: bigint, d: bigint) => encR(n, d);
    const inv = (x: bigint) => { let r = 1n, b = x % N, e = N - 2n; if (b < 0n) b += N; while (e) { if (e & 1n) r = r * b % N; b = b * b % N; e >>= 1n; } return r; };
    const secrets = new Set<bigint>();
    for (const r of rows) {
      const { a, b, c, d } = r;
      const rn = r.r, sn = r.s;
      const vals: bigint[] = [a, b, c, d, a * b, a * b * c, a * b * c * d, a * b * c * a, a + b, c - a, (a + b) * (c - a), (a + b) * (c - a) * b]
        .map((v) => encodeInt(v));
      vals.push(fr(rn.num, rn.den), fr(sn.num, sn.den), fr(sn.num, sn.den * 4n), fr(sn.num, sn.den * 3n),
        fr(a, b), fr(1n, b), fr(1n, b * c), fr(a, b * c), fr(a * rn.num, b * c * rn.den), fr(rn.den, rn.num),
        fr(rn.num, rn.den * c), fr(rn.num * a, rn.den * c), fr(100n, b));
      vals.push(inv(encodeInt(b)), inv(encodeInt(c)), inv(encodeInt(b * c)), inv(fr(rn.num, rn.den)));
      for (const v of vals) if (v >= 1000n && v < N - 1000n) secrets.add(v);   // tiny values would collide with row ids
    }
    const leaked = [...secrets].filter((v) => seen.has(v.toString()));
    assert.equal(leaked.length, 0, `${leaked.length} plaintext/intermediate/inverse encodings reached the server`);
    // the check has teeth: a value the owner did send is found, and so would a leaked secret be
    const tainted = new Set(seen); tainted.add([...secrets][0].toString());
    assert.ok([...secrets].some((v) => tainted.has(v.toString())));
    assert.ok(seen.has("0"), "row ids are expected on the wire");
    // the openings that did reach it are uniform-looking residues, never reused
    const opened: bigint[] = [];
    for (const e of sent) if (e.m === "mult_combine_batch") for (const pair of e.a[0]) for (const x of pair) opened.push(BigInt(x));
    assert.ok(opened.length > 100);
    assert.equal(new Set(opened).size, opened.length, "an opening value repeated: a triple was reused");
    assert.ok(opened.filter((x) => x > N / 100n).length > 0.95 * opened.length);
    db.close(); rec.close();
  });
}

R("wire audit: identical plaintexts give uniform openings at every level", async () => {
  const rec = await recorder(srv);
  const db = await ownerConnect("127.0.0.1", rec.port);
  const t = tname("uni");
  await db.createTable(t, [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" },
    { name: "c", type: "int", policy: "paired" }, { name: "d", type: "int", policy: "paired" }]);
  await db.insertMany(t, Array.from({ length: 1200 }, () => ({ a: 7n, b: 7n, c: 7n, d: 7n })));
  const n0 = rec.log.length;
  await db.expr(t, "a*b*c*d");
  const rounds = rec.log.slice(n0).filter((e) => e.m === "mult_combine_batch");
  assert.equal(rounds.length, 3);
  const all: bigint[] = [];
  for (const r of rounds) {
    assert.equal(r.a[0].length, 1200);
    const es = r.a[0].map((p: string[]) => BigInt(p[0]));
    const bins = new Array(8).fill(0);
    for (const e of es) bins[Number(e * 8n / N)]++;
    const chi = bins.reduce((s: number, o: number) => s + (o - 150) ** 2 / 150, 0);
    assert.ok(chi < 40, `chi2 ${chi}`);                                // df = 7: P(>40) ~ 1e-6
    for (const p of r.a[0]) all.push(BigInt(p[0]), BigInt(p[1]));
  }
  assert.equal(new Set(all).size, all.length);
  db.close(); rec.close();
});

// ── unit-level (hostile fake server): wrong-length / malformed product replies are typed errors ──
test("a malformed mult_combine_batch reply is a typed error, never a wrong number", async () => {
  for (const reply of [{ ok: null }, { ok: [1] }, { ok: ["x", "y"] }, { ok: [{}] }, { ok: ["1", "2", "3"] }]) {
    const f = await fake(base({
      insert_many: { ok: [0, 1] },
      matching_rowids: { ok: [0, 1] },
      blinded_cells: { ok: [{ t: "i", v: "5" }, { t: "i", v: "6" }] },
      mult_combine_batch: reply as any,
    }));
    const db = await ownerConnect("127.0.0.1", f.port);
    await db.createTable("t", [{ name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
    await db.insertMany("t", [{ a: 1, b: 2 }, { a: 3, b: 4 }]);
    await assert.rejects(db.expr("t", "a*b"), (e: unknown) => e instanceof TorusError, JSON.stringify(reply));
    assert.equal(db.lastExprCost, null);
    db.close(); f.close();
  }
});

test("a server that relabels encrypted columns as plain gets no expression request", async () => {
  // the lie: `v` is announced as PLAIN although the owner never created this table; an expression over it
  // would use a blinded value as a public operand. It is refused before anything is sent.
  const f = await fake(base({
    tables: { ok: ["t"] },
    schema: { ok: [["id", "int", "plain"], ["v", "int", "plain"], ["w", "int", "paired"]] },
  }));
  const db = await ownerConnect("127.0.0.1", f.port);
  const n0 = f.seen.length;
  for (const x of ["v*w+0", "w*v*w", "SUM(w+v)"]) await assert.rejects(db.expr("t", x), kind("UntrustedSchema"), x);
  assert.equal(f.seen.length, n0, "an expression request reached the server");
  db.close(); f.close();
});
