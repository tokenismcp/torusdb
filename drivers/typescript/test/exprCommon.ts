// SPDX-License-Identifier: Apache-2.0
// Shared helpers of the shared-wire (expressionMode "shared") tests: the cross-language vectors, the
// language-neutral wire "shape" (drivers/wire_shape.py) and a request-level view of a Recorder log.
import { createHash } from "crypto";
import * as fs from "fs";
import {
  Client, eq, ne, gt, isIn, Column, JoinResult, ExprValue, Decoded, N,
} from "../src/torusdb";
import { Recorder } from "./fake";
import { EXPR_VECTORS } from "./helpers";

export const vec = JSON.parse(fs.readFileSync(EXPR_VECTORS, "utf8"));

export type Cell = string | null;
export function cellValue(s: Cell): bigint | { num: bigint; den: bigint } | null {
  if (s === null) return null;
  if (s.includes("/")) { const [n, d] = s.split("/").map(BigInt); return { num: n, den: d }; }
  return BigInt(s);
}
export function show(v: Decoded | null): string | null {
  if (v === null) return null;
  return typeof v === "bigint" ? v.toString() : `${v.num}/${v.den}`;
}
export function showAll(v: ExprValue): string | null | Array<string | null> {
  return Array.isArray(v) ? v.map(show) : show(v);
}

export async function loadTables(db: Client, prefix = ""): Promise<void> {
  for (const t of vec.exec.tables as Array<{ name: string; columns: Array<[string, string, string]>; rows: Cell[][] }>) {
    const cols: Column[] = t.columns.map(([name, type, policy]) => ({ name, type, policy } as Column));
    await db.createTable(prefix + t.name, cols);
    if (t.rows.length) {
      await db.insertMany(prefix + t.name, t.rows.map((r) => Object.fromEntries(cols.map((c, k) => [c.name, cellValue(r[k])]))));
    }
  }
}

export function wherePred(w: { col: string; op: string; val: any }) {
  switch (w.op) {
    case "=": return eq(w.col, w.val);
    case "<>": return ne(w.col, w.val);
    case ">": return gt(w.col, w.val);
    case "IN": return isIn(w.col, w.val);
    default: throw new Error("where op " + w.op);
  }
}

export async function runCase(db: Client, c: any): Promise<ExprValue> {
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

/** The cost fields the Python reference reports, from a driver's `lastExprCost`. */
export function costOf(c: any, shared: boolean): Record<string, number> {
  const o: Record<string, number> = { depth: c.depth, mult_rounds: c.multRounds, products: c.products,
    inversions: c.inversions, linear_sums: c.linearSums };
  if (shared) Object.assign(o, { openings: c.openings, wires: c.wires, requests: c.requests, reveals: c.reveals });
  return o;
}

// ── the language-neutral shape of the wire requests (drivers/wire_shape.py) ─────────────────────
const ID = /^[0-9a-f]{12}\.[0-9]+$/;
export function opShape(op: any[], ids: Map<string, number>): unknown[] {
  const row: unknown[] = [op[0]];
  op.slice(1).forEach((x, k0) => {
    const k = k0 + 1;
    if ((op[0] === "mulc" || op[0] === "addc") && k === 3) row.push("R");
    else if (x === null || typeof x === "boolean" || typeof x === "number") row.push(x);
    else if (typeof x === "string") {
      if (ID.test(x)) { if (!ids.has(x)) ids.set(x, ids.size); row.push(`#${ids.get(x)}`); } else row.push("R");
    } else if (Array.isArray(x)) row.push(["L", x.length]);
    else if (typeof x === "object") row.push(["D", Object.keys(x).sort().map((key) => [key, (x as any)[key].length])]);
    else row.push("?");
  });
  return row;
}

/** One entry per wire_exec / wire_free request in `log[from..]`. */
export function wireTrace(log: Recorder["log"], from = 0): unknown[] {
  const out: unknown[] = [];
  for (const e of log.slice(from)) {
    if (e.m === "wire_exec") { const ids = new Map<string, number>(); out.push(["exec", (e.a[0] as any[]).map((o) => opShape(o, ids))]); }
    else if (e.m === "wire_free") out.push(["free", e.a[0] === null ? null : (e.a[0] as unknown[]).length]);
  }
  return out;
}
export const traceDigest = (t: unknown[]): string => createHash("sha256").update(JSON.stringify(t)).digest("hex");

// ── the server's view, as numbers ───────────────────────────────────────────────────────────────
/** Every ring element (decimal string or integer) anywhere in a value. */
export function collectInts(x: unknown, out: Set<string>): void {
  if (typeof x === "boolean") return;
  if (typeof x === "number") { out.add(String(x)); return; }
  if (typeof x === "string") { if (/^-?[0-9]+$/.test(x)) out.add(x); return; }
  if (Array.isArray(x)) { x.forEach((v) => collectInts(v, out)); return; }
  if (x && typeof x === "object") Object.values(x).forEach((v) => collectInts(v, out));
}

/** Chi-square of `vals` (uniform in [0, N)) over 8 bins; df = 7, P(> 40) ~ 1e-6. */
export function chi2(vals: bigint[], bins = 16): number {
  const cnt = new Array(bins).fill(0);
  for (const v of vals) cnt[Number(v * BigInt(bins) / N)]++;
  const exp = vals.length / bins;
  return cnt.reduce((s: number, o: number) => s + (o - exp) ** 2 / exp, 0);
}
export const CHI2_LIMIT = 50;                // df = 15: P(> 50) ~ 1e-5

/** Violations in what a server received (the ring elements of `mul` triples / openings and `put`s must be
 *  uniform and never repeat). Empty = clean. Mirrors core/tests/test_expr_shared.py `audit`. */
export function audit(log: Recorder["log"]): string[] {
  const bad: string[] = [];
  const pooled = new Map<string, bigint[]>();
  const puts: bigint[] = [];
  for (const e of log) {
    if (e.m !== "wire_exec") continue;
    for (const op of e.a[0] as any[]) {
      if (op[0] === "mul") {
        for (const [k, v] of Object.entries(op[4] as Record<string, string[]>)) {
          if (!pooled.has(k)) pooled.set(k, []);
          for (const x of v) pooled.get(k)!.push(BigInt(x));
        }
      } else if (op[0] === "put") {
        for (const x of op[2] as string[]) puts.push(BigInt(x));
        if (op[3]) for (const x of op[3] as string[]) puts.push(BigInt(x));
      }
    }
  }
  for (const [k, vals] of [...pooled].sort()) {
    if (vals.length >= 1000 && chi2(vals) >= CHI2_LIMIT) bad.push(`mul.${k}: not uniform`);
    if (new Set(vals).size !== vals.length) bad.push(`mul.${k}: a value repeated (triple/mask reuse)`);
  }
  if (puts.length) {
    if (new Set(puts).size !== puts.length) bad.push("put: a value repeated");
    if (puts.length >= 1000 && chi2(puts) >= CHI2_LIMIT) bad.push("put: not uniform");
  }
  return bad;
}

// ── random expressions (the same generator as expr_peer.test.ts) ────────────────────────────────
export function rng(seed: number) {
  let s = seed >>> 0;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
}
export function genTree(r: () => number, depth: number, leaves: string[]): string {
  if (depth === 0 || r() < 0.25) {
    if (r() < 0.7) return leaves[Math.floor(r() * leaves.length)];
    const lits = ["2", "3", "(-4)", "7", "1", "FRAC(1,3)", "FRAC(-5,2)"];
    return lits[Math.floor(r() * lits.length)];
  }
  if (r() < 0.1) return `(-${genTree(r, depth - 1, leaves)})`;
  const op = "+-*/"[Math.floor(r() * 4)];
  return `(${genTree(r, depth - 1, leaves)}${op}${genTree(r, depth - 1, leaves)})`;
}
