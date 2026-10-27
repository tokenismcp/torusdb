// SPDX-License-Identifier: Apache-2.0
// v0.6.1 expressions over FHE columns (docs/fhe-columns.md "Expressions over FHE columns";
// proto/fhe-wire.md `fhe_mul`): static accept/reject matrix (no server) and end-to-end evaluation
// against the REAL Python server, cross-checked against the Python engine itself via
// drivers/expr_peer.py (a separate owner holding the same FHE key, its own copy of the tables).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  Client, FheKey, TorusError, eq, Column, FheExprCost,
} from "../src/torusdb";
import { scopeResolver, ExprColumn, parseExpression } from "../src/expr";
import { analyzeFheExpr, referencesFheColumn } from "../src/fheExpr";
import { FHE_DOT_BYTES } from "../src/fhe";
import { skipReason, startServer, RunningServer, uniq, runExprPeer } from "./helpers";

const kind = (k: string) => (e: unknown) => e instanceof TorusError && e.kind === k;

// ── static analysis (no server): mirrors parser/torussql_parser/fhe_expr.py's accept/reject matrix ──
const SCOPE: ExprColumn[] = [
  { name: "a", type: "int", policy: "fhe" },
  { name: "b", type: "int", policy: "fhe" },
  { name: "c", type: "int", policy: "fhe" },
  { name: "d", type: "int", policy: "fhe" },
  { name: "p", type: "int", policy: "plain" },
  { name: "q", type: "int", policy: "paired" },
];
const resolve = scopeResolver([["t", SCOPE]]);
const col = (n: string) => resolve(n).col;

function plan(expr: string) {
  const tree = parseExpression(expr);
  if (!referencesFheColumn(tree, col)) throw new Error(`${expr}: no FHE column reference (test setup error)`);
  return analyzeFheExpr(tree, col);
}

test("FHE expr static: accepted shapes (docs/fhe-columns.md)", () => {
  const ok = [
    "SUM((a+b)*c)",                // per-row product of two linear forms, aggregated
    "SUM((a+2*b)*(c-d))",
    "SUM(a)*SUM(b)",                // product of two aggregates
    "(SUM(a)+2*SUM(b))*(SUM(c)-1)",
    "2*SUM(a*c)-SUM(b*d)/4+7",      // public scale/add/divide after decryption
    "AVG(a*c)",
    "SUM(2*a*c)",                   // a coefficient defeats the bare-column-product special case
    "SUM((a+0)*c)",
    "SUM(a*c)*1",
    "SUM((a+0)*(a+0))",             // the same column on both sides, spelled so it is not the bare x*y shape
  ];
  for (const e of ok) assert.doesNotThrow(() => plan(e), e);
});

test("FHE expr static: SUM(x*y) of two BARE distinct FHE columns is now accepted (v0.6.2, same as DOT(x,y))", () => {
  // REJECT_BARE_COLUMN_PRODUCT flipped to false: a bare SUM(a*b) goes through the same fhe_mul path
  // as every other product shape, giving the exact product-of-sums result (checked end to end,
  // numerically identical to DOT(a,b), by the "stays numerically equal to DOT" server test below).
  assert.doesNotThrow(() => plan("SUM(a*b)"));
  assert.doesNotThrow(() => plan("SUM(b*a)"));
  assert.equal(plan("SUM(a*b)").level, "agg");
});

test("FHE expr static: rejected shapes with a precise message", () => {
  assert.throws(() => plan("SUM(a*b)*SUM(c)"), kind("PlanError"));          // product of a product (depth 2)
  assert.throws(() => plan("SUM((a+b)*c*d)"), kind("PlanError"));            // triple product: depth > 1
  assert.throws(() => plan("SUM(a)/COUNT(*)"), kind("PlanError"));           // AVG spelled by hand: COUNT(*) is not FHE
  assert.throws(() => plan("a+1"), kind("PlanError"));                       // per-row, non-aggregated
  assert.throws(() => plan("SUM(a)+p"), kind("PlanError"));                  // FHE mixed with PLAIN
  assert.throws(() => plan("SUM(a/2*c)"), kind("PlanError"));                // non-integer operand coefficient
  assert.throws(() => plan("SUM(a)"), kind("PlanError"));                    // no product anywhere: old "FHE column" message
  assert.throws(() => plan("AVG(a)*AVG(b)"), kind("PlanError"));             // AVG as a factor is not an integer-linear form
});

test("FHE expr static: FHE mixed with PAIRED is rejected, not silently accepted", () => {
  assert.throws(() => plan("SUM(a*c)+q"), kind("PlanError"));
});

// ── v0.6.2: per-row (non-aggregated) FHE products, as a projection (SELECT a*b FROM t) ───────────────
test("FHE expr static: a per-row product is accepted only when the caller opts in (allowRow=true)", () => {
  const rowOk = ["a*b", "(a+1)*(b+1)", "(a+2*b)*(c-d)", "2*(a*b)-1", "a*b+c"];
  for (const e of rowOk) {
    const tree = parseExpression(e);
    // every existing caller leaves allowRow at its default (false) and keeps rejecting this shape
    assert.throws(() => analyzeFheExpr(tree, col), kind("PlanError"), `${e} (default allowRow)`);
    const p = analyzeFheExpr(tree, col, true);
    assert.equal(p.level, "row", e);
    assert.ok(p.products >= 1, e);
  }
});

test("FHE expr static: a per-row FHE value with no product is rejected even with allowRow=true", () => {
  assert.throws(() => analyzeFheExpr(parseExpression("a+1"), col, true), kind("PlanError"));
  assert.throws(() => analyzeFheExpr(parseExpression("a"), col, true), kind("PlanError"));
});

test("FHE expr static: a per-row depth-2 product stays rejected even with allowRow=true", () => {
  assert.throws(() => analyzeFheExpr(parseExpression("(a*b)*c"), col, true), kind("PlanError"));
});

// ── end to end against the real server ───────────────────────────────────────
const skip = skipReason();
const EMP: Column[] = [
  { name: "id", type: "int", policy: "plain" },
  { name: "dept", type: "int", policy: "plain" },
  { name: "rate", type: "int", policy: "fhe" },
  { name: "hours", type: "int", policy: "fhe" },
  { name: "bonus", type: "int", policy: "fhe" },
];
const ROWS = [[1, 5, 40, 160, 3], [2, 5, 55, 150, 1], [3, 7, 30, 120, 0], [4, 5, 20, 100, 2]];
const SECRET = "7f".padStart(64, "0");      // any valid 32-byte secret in [1, n): a plain hex literal is fine here
const RANGE = 10_000_000;
const OPTS = { timeoutMs: 240_000 };
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

async function seed(db: Client, t: string): Promise<number[]> {
  await db.createTable(t, EMP);
  const ids: number[] = [];
  for (const [id, dept, rate, hours, bonus] of ROWS) ids.push(await db.insert(t, { id, dept, rate, hours, bonus }));
  return ids;
}

let mem: RunningServer;
before(async () => { if (!skip) mem = await startServer(); });
after(async () => { if (!skip) await mem?.stop(); });

// expected plaintext values, computed independently in JS from ROWS (not from the driver under test)
function expected(fn: (row: { rate: number; hours: number; bonus: number; dept: number }) => number): number {
  return ROWS.reduce((acc, [, dept, rate, hours, bonus]) => acc + fn({ dept, rate, hours, bonus }), 0);
}

T("FHE expr: SUM(L*R), SUM(A)*SUM(B), and a public affine combination (delegated mode)", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("emp");
    await seed(db, t);
    const sumProd = expected((r) => (r.rate + r.bonus) * r.hours);
    assert.equal(await db.expr(t, "SUM((rate+bonus)*hours)"), BigInt(sumProd));
    assert.equal(db.lastFheExprCost!.products, 1);
    assert.ok(db.lastFheExprCost!.pairings > 0);
    assert.ok(db.lastFheExprCost!.gtResults >= 1);

    const sumRate = expected((r) => r.rate), sumHours = expected((r) => r.hours);
    assert.equal(await db.expr(t, "SUM(rate)*SUM(hours)"), BigInt(sumRate * sumHours));

    const affine = 2 * sumProd - expected((r) => r.bonus * r.hours) + 7;
    assert.equal(await db.expr(t, "2*SUM((rate+bonus)*hours)-SUM(bonus*hours)/4*4+7"), BigInt(affine));

    // AVG(a*c): SUM/n in exact (reduced) rational arithmetic
    const n = ROWS.length;
    const avgVal = await db.expr(t, "AVG(rate*hours)");
    const sumRH = expected((r) => r.rate * r.hours);
    const g = (x: bigint, y: bigint): bigint => (y === 0n ? x : g(y, x % y));
    const gg = g(BigInt(sumRH), BigInt(n));
    if (gg === BigInt(n)) assert.equal(avgVal, BigInt(sumRH) / BigInt(n));
    else assert.deepEqual(avgVal, { num: BigInt(sumRH) / gg, den: BigInt(n) / gg });

    // WHERE restricts the row set the server/owner sees
    const d5sum = expected((r) => (r.rate + r.bonus) * r.hours);     // all rows are dept 5 or 7; filter below
    const filtered = ROWS.filter(([, dept]) => dept === 5).reduce((acc, [, , rate, hours, bonus]) => acc + (rate + bonus) * hours, 0);
    assert.equal(await db.expr(t, "SUM((rate+bonus)*hours)", eq("dept", 5)), BigInt(filtered));
    assert.notEqual(filtered, d5sum); // sanity: the filter actually changed something given dept 7 exists
  } finally { db.close(); }
});

T("FHE expr: SUM(x*y) of two bare FHE columns (v0.6.2) equals DOT(x,y) exactly", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("emp");
    await seed(db, t);
    const sumProd = expected((r) => r.rate * r.hours);
    const viaExpr = await db.expr(t, "SUM(rate*hours)");
    const viaDot = await db.dot(t, "rate", "hours");
    assert.equal(viaExpr, BigInt(sumProd));
    assert.equal(viaDot, BigInt(sumProd));
    assert.equal(viaExpr, viaDot);
    assert.equal(db.lastFheExprCost!.products, 1);
  } finally { db.close(); }
});

T("FHE expr: local mode (authenticated) matches delegated mode", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  // both connections authenticated (rows need integrity tags for local mode to read them); `delegated`
  // explicitly opts out of local verification for the FHE-product terms via fheDotMode.
  const local = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: true, ...OPTS });
  const delegated = await Client.connect(mem.host, mem.port,
    { fheKey: FheKey.fromHex(SECRET, RANGE), authenticated: true, fheDotMode: "delegated", ...OPTS });
  try {
    const t = uniq("emp");
    await seed(local, t);
    await delegated.syncSchema(); delegated.trustTable(t);
    const expr = "SUM((rate+2*bonus)*(hours-8))";
    const want = expected((r) => (r.rate + 2 * r.bonus) * (r.hours - 8));
    assert.equal(await delegated.expr(t, expr), BigInt(want));
    assert.equal(await local.expr(t, expr), BigInt(want));
    assert.equal(delegated.lastFheExprCost!.decryptedCells, 0);           // delegated: the server multiplies
    assert.ok(local.lastFheExprCost!.decryptedCells > 0);                 // local: the owner reads and verifies cells
    assert.equal(local.lastFheExprCost!.serverProducts, 0);
  } finally { delegated.close(); local.close(); }
});

// ── v0.6.2: row-level (non-aggregated) FHE products - SELECT L*R FROM t, one ciphertext per row ──────
T("FHE expr row-level: a*b and (a+2*b)*(c-d) per row, local and delegated modes agree", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const local = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: true, ...OPTS });
  const delegated = await Client.connect(mem.host, mem.port,
    { fheKey: FheKey.fromHex(SECRET, RANGE), authenticated: true, fheDotMode: "delegated", ...OPTS });
  try {
    const t = uniq("emp");
    await seed(local, t);
    await delegated.syncSchema(); delegated.trustTable(t);

    const wantAB = ROWS.map(([, , rate, hours]) => BigInt(rate * hours));
    const gotLocalAB = await local.expr(t, "rate*hours");
    const gotDelegatedAB = await delegated.expr(t, "rate*hours");
    assert.deepEqual(gotLocalAB, wantAB);
    assert.deepEqual(gotDelegatedAB, wantAB);
    assert.equal(local.lastFheExprCost!.serverProducts, 0);           // local: the owner multiplies
    assert.equal(delegated.lastFheExprCost!.decryptedCells, 0);       // delegated: the server multiplies

    const wantAffine = ROWS.map(([, , rate, hours, bonus]) => BigInt((rate + 2 * bonus) * (hours - 8)));
    const gotLocalAffine = await local.expr(t, "(rate+2*bonus)*(hours-8)");
    const gotDelegatedAffine = await delegated.expr(t, "(rate+2*bonus)*(hours-8)");
    assert.deepEqual(gotLocalAffine, wantAffine);
    assert.deepEqual(gotDelegatedAffine, wantAffine);

    const gotScaled = await local.expr(t, "2*(rate*hours)-1");
    assert.deepEqual(gotScaled, ROWS.map(([, , rate, hours]) => BigInt(2 * rate * hours - 1)));

    // WHERE narrows the row set BEFORE the per-row product is computed
    const gotFiltered = await local.expr(t, "rate*hours", eq("dept", 5));
    const wantFiltered = ROWS.filter(([, dept]) => dept === 5).map(([, , rate, hours]) => BigInt(rate * hours));
    assert.deepEqual(gotFiltered, wantFiltered);
  } finally { delegated.close(); local.close(); }
});

T("FHE expr row-level: authenticated default is local (the server never multiplies)", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: true, ...OPTS });
  const methods: string[] = [];
  const origCall = (db as unknown as { call: (m: string, a: unknown[], n: number) => Promise<unknown> }).call.bind(db);
  (db as unknown as { call: typeof origCall }).call = async (m: string, a: unknown[], n: number) => {
    methods.push(m);
    return origCall(m, a, n);
  };
  try {
    const t = uniq("emp");
    await seed(db, t);
    const want = ROWS.map(([, , rate, hours]) => BigInt(rate * hours));
    const got = await db.expr(t, "rate*hours");
    assert.deepEqual(got, want);
    assert.ok(!methods.includes("fhe_mul"));
  } finally { db.close(); }
});

T("FHE expr row-level: an explicit delegated opt-in on an authenticated connection has no integrity " +
  "(negative control, same gap as DOT / the aggregate product)", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port,
    { fheKey: key, authenticated: true, fheDotMode: "delegated", ...OPTS });
  const origCall = (db as unknown as { call: (m: string, a: unknown[], n: number) => Promise<unknown> }).call.bind(db);
  let sabotage = false;
  (db as unknown as { call: typeof origCall }).call = async (m: string, a: unknown[], n: number) => {
    if (sabotage && m === "fhe_mul") {
      const args = a.slice();
      const ids = args[2] as number[];
      args[2] = ids.slice().reverse();          // same (distinct) ids, reordered: rows silently swapped
      return origCall(m, args, n);
    }
    return origCall(m, a, n);
  };
  try {
    const t = uniq("emp");
    await seed(db, t);
    const want = ROWS.map(([, , rate, hours]) => BigInt(rate * hours));
    assert.deepEqual(await db.expr(t, "rate*hours"), want);
    sabotage = true;
    const got = await db.expr(t, "rate*hours");
    assert.notDeepEqual(got, want);                 // wrong, and silently accepted: no integrity check exists
  } finally { db.close(); }
});

T("FHE expr: rejected at the connection exactly like the static analyzer (PlanError, no RPC sent)", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("emp");
    await seed(db, t);
    await assert.rejects(db.expr(t, "SUM(rate*hours)*SUM(bonus)"), kind("PlanError")); // product of a product
    await assert.rejects(db.expr(t, "rate+1"), kind("PlanError"));                    // per-row, no product anywhere
    await assert.rejects(db.expr(t, "SUM(rate)+id"), kind("PlanError"));              // FHE + PLAIN
    assert.equal(db.lastFheExprCost, null);
  } finally { db.close(); }
});

T("FHE expr: cross-checked against the Python engine (drivers/expr_peer.py), same key, same rows", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const tsT = uniq("ts_emp"), pyT = uniq("py_emp");
    await seed(db, tsT);
    const exprsToCheck = [
      "SUM((rate+bonus)*hours)",
      "SUM(rate)*SUM(hours)",
      "2*SUM(rate*hours)-SUM(bonus*hours)/4+7",
      "AVG(rate*hours)",
      "SUM(rate*hours)",              // v0.6.2: bare product, same shape as DOT(rate, hours)
      "rate*hours",                   // v0.6.2: row-level projection
      "(rate+2*bonus)*(hours-8)",     // v0.6.2: row-level, linear forms on both sides
    ];
    const tsValues: Array<string | Array<string | null>> = [];
    for (const e of exprsToCheck) {
      const v = await db.expr(tsT, e);
      if (typeof v === "bigint") tsValues.push(v.toString());
      else if (v === null) tsValues.push("null");
      else if (Array.isArray(v)) {
        tsValues.push(v.map((x) => (x === null ? null : typeof x === "bigint" ? x.toString() : `${x.num}/${x.den}`)));
      } else tsValues.push(`${v.num}/${v.den}`);
    }
    const peerCols = EMP.map((c) => [c.name, c.type, c.policy] as [string, string, string]);
    const peerRows = ROWS.map((r) => r.map((x) => String(x)));
    const peerOut = runExprPeer(mem.host, mem.port, {
      fhe_key: { secret: SECRET, range: RANGE },
      tables: [{ name: pyT, columns: peerCols, rows: peerRows }],
      queries: exprsToCheck.map((e) => ({ table: pyT, expr: e })),
    });
    for (let i = 0; i < exprsToCheck.length; i++) {
      assert.deepEqual(tsValues[i], peerOut[i].value, exprsToCheck[i]);
      assert.ok(!("error" in peerOut[i]), `${exprsToCheck[i]}: python peer error ${JSON.stringify(peerOut[i])}`);
    }
  } finally { db.close(); }
});

T("FHE expr: wire audit — fhe_mul carries only table/column names, row ids, small integers and a back-end " +
  "hint, in both aggregate and row ('row') modes, and every reply is standard-size base64 blob(s)", async () => {
  const key = FheKey.fromHex(SECRET, RANGE);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  const seen: unknown[][] = [];
  const replies: unknown[] = [];
  const origCall = (db as unknown as { call: (m: string, a: unknown[], n: number) => Promise<unknown> }).call.bind(db);
  (db as unknown as { call: typeof origCall }).call = async (m: string, a: unknown[], n: number) => {
    const r = await origCall(m, a, n);
    if (m === "fhe_mul") { seen.push(a); replies.push(r); }
    return r;
  };
  try {
    const t = uniq("emp");
    await seed(db, t);
    await db.expr(t, "SUM((rate+2*bonus)*(hours-8))");
    await db.expr(t, "(rate+2*bonus)*(hours-8)");              // v0.6.2: mode "row"
    assert.ok(seen.length > 0);
    for (const args of seen) {
      const json = JSON.stringify(args);
      assert.doesNotMatch(json, /secret|s2|alpha|gamma/i);
      // every integer literal in the request is small (coefficients/constants, row ids) - never a 384-byte blob
      assert.doesNotMatch(json, /"[0-9a-f]{100,}"/);
    }
    assert.ok(replies.length > 0);
    for (const reply of replies) {
      // mode "sum": a single base64 blob; mode "row": a list of blobs, one per row - either way, every
      // blob is exactly FHE_DOT_BYTES raw bytes, never anything else (a key, a plaintext, a mismatched size)
      const blobs = Array.isArray(reply) ? reply : [reply];
      assert.ok(blobs.length > 0);
      for (const b of blobs) {
        assert.equal(typeof b, "string");
        const raw = Buffer.from(b as string, "base64");
        assert.equal(raw.length, FHE_DOT_BYTES);
      }
    }
  } finally { db.close(); }
});
