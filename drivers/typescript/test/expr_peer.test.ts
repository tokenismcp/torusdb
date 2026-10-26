// SPDX-License-Identifier: Apache-2.0
// Cross-implementation check: the SAME expressions run through the Python engine (a peer process) and this
// driver against ONE real server; values, error classes and costs must be identical. Random expressions
// (seed in TORUSDB_PEER_SEED) exercise precedence, division, zero denominators, NULLs and the budget.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import { Client, Column, Decoded, ExprValue, TorusError } from "../src/torusdb";
import { skipReason, startServer, RunningServer, runExprPeer, EXPR_VECTORS, ownerConnect } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const vec = JSON.parse(fs.readFileSync(EXPR_VECTORS, "utf8"));

function rng(seed: number) {
  let s = seed >>> 0;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
}
function genTree(r: () => number, depth: number, leaves: string[]): string {
  if (depth === 0 || r() < 0.25) {
    if (r() < 0.7) return leaves[Math.floor(r() * leaves.length)];
    const lits = ["2", "3", "(-4)", "7", "1", "FRAC(1,3)", "FRAC(-5,2)"];
    return lits[Math.floor(r() * lits.length)];
  }
  if (r() < 0.1) return `(-${genTree(r, depth - 1, leaves)})`;
  const op = "+-*/"[Math.floor(r() * 4)];
  return `(${genTree(r, depth - 1, leaves)}${op}${genTree(r, depth - 1, leaves)})`;
}

const FIXED = ["a*b*c", "a*b*c*d", "(a+b)*(c-d)*a+s/2", "SUM(a*b*c)/COUNT(*)", "a/b", "r/c*a", "SUM(a)/SUM(c)", "100/c",
  "AVG(a*b)", "a*b/(c*d)", "SUM(a+2*b-s/4)", "a/0", "a*name", "SUM(id*2)", "s*a*b", "a*(b-b)", "1/(a-a)"];

for (const auth of [false, true]) {
  test(`Python engine and this driver agree on ${auth ? "authenticated" : "plain"} expressions (one server)`, { skip }, async () => {
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
      auth, tables: [{ name: pyT, columns: cols, rows: tdef.rows }], queries,
    });
    assert.equal(peer.length, exprs.length);

    const db = await ownerConnect(srv.host, srv.port, { authenticated: auth, timeoutMs: 120_000 });
    const schema: Column[] = cols.map(([name, type, policy]) => ({ name, type, policy } as Column));
    await db.createTable(tsT, schema);
    const val = (s: string | null) => (s === null ? null : s.includes("/") ? { num: BigInt(s.split("/")[0]), den: BigInt(s.split("/")[1]) } : BigInt(s));
    await db.insertMany(tsT, tdef.rows.map((row: Array<string | null>) => Object.fromEntries(schema.map((c, k) => [c.name, val(row[k])]))));
    const show = (v: Decoded | null) => (v === null ? null : typeof v === "bigint" ? v.toString() : `${v.num}/${v.den}`);
    let ok = 0, errs = 0;
    for (let i = 0; i < exprs.length; i++) {
      const want = peer[i];
      let got: any;
      try {
        const v: ExprValue = await db.expr(tsT, exprs[i]);
        const c = db.lastExprCost!;
        got = { value: Array.isArray(v) ? v.map(show) : show(v),
                cost: { depth: c.depth, mult_rounds: c.multRounds, products: c.products, inversions: c.inversions, linear_sums: c.linearSums } };
        ok++;
      } catch (e) {
        if (!(e instanceof TorusError)) throw e;
        got = { error: e.kind };
        errs++;
      }
      assert.deepEqual(got, want, `${exprs[i]}`);
    }
    assert.ok(ok > 60 && errs > 10, `${ok} ok / ${errs} errors`);
    db.close();
  });
}
