// SPDX-License-Identifier: Apache-2.0
// Owner-computed evaluation of TorusSQL v0.6 arithmetic expressions (`expressionMode: "owner"`): the
// no-key paper's circuit composition Pi_C over the blinded database. Port of
// `core/torusdb_core/expr_eval.py` (the reference); read its header for the full "who computes what"
// account. The DEFAULT transport is the shared-wire one in exprShared.ts (every wire a two-party
// additive sharing, nothing unmasked at the owner, products computed by both parties). This file also
// holds the expression compiler and the public-value evaluator that both modes share. In short:
//
//  * the SERVER holds blinded scalars s~ = s + r and plaintext columns, no key, no mask. It only
//    (i) sums stored blinded cells for LINEAR SUM(...) arguments (Pi_lin) and (ii) multiplies the
//    two openings e*g of each Beaver product (Pi_mult), both on values uniform and independent of
//    the data;
//  * the OWNER (this process) unmasks the cells it reads, applies every linear gate, every public
//    multiplication and division locally, draws a fresh triple per ciphertext product, reconstructs
//    the product, and inverts encrypted denominators. Products and quotients are therefore NOT
//    offloaded: the owner already holds both operands of every product (review packet 3.3, F-3);
//  * one batched `mult_combine_batch` exchange per multiplicative LEVEL: rounds == depth;
//  * an intermediate (a product, a quotient) exists only here. It reaches the server only inside
//    the next level's opening e = x - u with a fresh uniform u (the Pi_boot re-mask);
//  * a zero denominator does NOT abort: the protocol runs to its last round with a dummy inverse
//    and only then raises DivisionByZero, so the request sequence does not reveal the zero;
//  * all arithmetic is exact in Z/nZ; only the final decode can fail, and it raises OutOfBudget.

import { TorusError } from "./errors";
import { Expr, Frac, frac, fMul, fDiv, ExprInfo } from "./expr";

/** The ring Z/nZ and the exact encoding, injected by the client (keeps this file import-free of it). */
export interface Ring {
  readonly N: bigint;
  mod(a: bigint): bigint;
  rand(): bigint;
  /** Frac -> Z/nZ; throws OutOfBudget outside the exactness contract. */
  encode(v: Frac): bigint;
  /** Z/nZ -> bigint | {num, den}; strict (throws OutOfBudget). */
  decode(s: bigint): bigint | { num: bigint; den: bigint };
  inv(a: bigint): bigint;                 // a != 0 (mod N)
}

/** The server's shared-wire caps, as published in `hello.limits.wires` (wire protocol 2.1). */
export interface WireLimits {
  maxWires?: number;
  maxElements?: number;
  ttl?: number;
  maxOps?: number;
  maxRequestElements?: number;
}

/** What the shared evaluator needs from the connection besides {@link ExprHost}. */
export interface SharedHost {
  /** the owner's MAC key (0n when the connection is not authenticated) */
  alpha(): bigint;
  /** `hello.limits.wires` (undefined: the server does not offer the wire RPCs) */
  wireLimits(): WireLimits | undefined;
  /** the mask r of the stored cell table[id].col (throws when this vault does not hold it) */
  mask(table: string, id: number, col: string): bigint;
  /** one RPC (`wire_exec` / `wire_free`) */
  rpc(method: string, args: unknown[], maxReply: number): Promise<unknown>;
}

export interface ENode {
  op: string;
  args: number[];
  level: number;
  enc: boolean;
  shape: "scalar" | "row";
  data?: unknown;
}

/** What the evaluator needs from the connection. */
export interface ExprHost {
  authenticated: boolean;
  /** Most openings per `mult_combine_batch` request. */
  maxItems(): number;
  /** PLAIN column values for the (possibly null, possibly repeated) row ids, one request per call. */
  plainColumn(table: string, col: string, ids: Array<number | null>): Promise<unknown[]>;
  /** The unmasked, MAC-verified (authenticated) scalars of an ENC/PAIRED column for distinct sorted ids. */
  encScalars(table: string, col: string, ids: number[]): Promise<bigint[]>;
  /** The unmasked, MAC-verified, UNDECODED sum of an ENC/PAIRED column over `ids` (Pi_lin). */
  linSum(table: string, col: string, ids: number[]): Promise<bigint>;
  /** One `mult_combine_batch` request: the server's e*g for each (e, g). */
  multCombine(openings: Array<[bigint, bigint]>): Promise<bigint[]>;
  /** Is the column PLAIN? */
  isPlain(table: string, col: string): boolean;
  /** The shared-wire transport (`expressionMode: "shared"`); absent when the host only does owner mode. */
  shared?: SharedHost;
}

export interface ExprCost {
  depth: number;
  multRounds: number;
  products: number;
  inversions: number;
  linearSums: number;
  /** `"shared"` when the shared-wire transport ran (absent in owner mode, like the Python driver). */
  mode?: "shared";
  /** ring elements opened (e and g of every product, the t = rho*y of every division) - shared mode */
  openings?: number;
  /** wires created on the server - shared mode */
  wires?: number;
  /** `wire_exec` requests sent (one per multiplicative level plus one, more if a cap splits a level) - shared mode */
  requests?: number;
  /** result wires revealed (the result, and one t = rho*y per division level) - shared mode */
  reveals?: number;
}

export type Vec = Array<bigint | null>;

type Lin = { coef: Map<string, Frac>; konst: Frac };

/** If `e` is a linear form over ENCRYPTED columns only (no product of two columns, no division by a
 *  column, no PLAIN column), its coefficients; else null. Such a SUM is a Pi_lin aggregate. */
function linear(e: Expr, isEncCol: (name: string) => boolean): Lin | null {
  switch (e.t) {
    case "lit": return { coef: new Map(), konst: e.v };
    case "col": return isEncCol(e.name) ? { coef: new Map([[e.name, frac(1n)]]), konst: frac(0n) } : null;
    case "neg": {
      const r = linear(e.e, isEncCol);
      if (!r) return null;
      const coef = new Map<string, Frac>();
      for (const [k, v] of r.coef) coef.set(k, frac(-v.num, v.den));
      return { coef, konst: frac(-r.konst.num, r.konst.den) };
    }
    case "bin": {
      const l = linear(e.l, isEncCol);
      const r = linear(e.r, isEncCol);
      if (!l || !r) return null;
      if (e.op === "+" || e.op === "-") {
        const sg = e.op === "+" ? 1n : -1n;
        const coef = new Map(l.coef);
        for (const [k, v] of r.coef) {
          const cur = coef.get(k) ?? frac(0n);
          const add = frac(sg * v.num, v.den);
          coef.set(k, frac(cur.num * add.den + add.num * cur.den, cur.den * add.den));
        }
        const rk = frac(sg * r.konst.num, r.konst.den);
        return { coef, konst: frac(l.konst.num * rk.den + rk.num * l.konst.den, l.konst.den * rk.den) };
      }
      if (e.op === "*") {
        if (l.coef.size === 0) {
          return { coef: new Map([...r.coef].map(([k, v]) => [k, fMul(l.konst, v)])), konst: fMul(l.konst, r.konst) };
        }
        if (r.coef.size === 0) {
          return { coef: new Map([...l.coef].map(([k, v]) => [k, fMul(r.konst, v)])), konst: fMul(l.konst, r.konst) };
        }
        return null;
      }
      if (e.op === "/" && r.coef.size === 0 && r.konst.num !== 0n) {
        return { coef: new Map([...l.coef].map(([k, v]) => [k, fDiv(v, r.konst)])), konst: fDiv(l.konst, r.konst) };
      }
      return null;
    }
    default: return null;
  }
}

export class ExprRunner {
  /** extra product levels a division by an ENCRYPTED value costs (0: owner-computed; 1: shared wires) */
  protected readonly invLevels: number = 0;
  protected nodes: ENode[] = [];
  private colcache = new Map<string, Vec>();
  protected readonly pos = new Map<string, number>();
  protected readonly R: number;
  readonly cost: ExprCost = { depth: 0, multRounds: 0, products: 0, inversions: 0, linearSums: 0 };
  protected zero: string | null = null;      // set when a denominator was 0 (raised after the last round)

  /**
   * @param inst   alias -> table, in tuple order
   * @param loc    resolves a column reference of `expr` to its (alias, column)
   * @param tuples one row id (or null: NULL side of a LEFT JOIN) per alias, per row
   */
  constructor(protected readonly host: ExprHost, protected readonly ring: Ring, protected readonly expr: Expr,
              protected readonly info: ExprInfo, protected readonly inst: ReadonlyMap<string, string>,
              protected readonly loc: (name: string) => { alias: string; col: string },
              protected readonly tuples: Array<Array<number | null>>) {
    [...inst.keys()].forEach((a, k) => this.pos.set(a, k));
    this.R = tuples.length;
  }

  // ── compile the tree into a DAG with multiplicative levels ──
  protected add(n: ENode): number { this.nodes.push(n); return this.nodes.length - 1; }

  protected isEncCol(name: string): boolean {
    const { alias, col } = this.loc(name);
    return !this.host.isPlain(this.inst.get(alias)!, col);
  }

  protected compile(e: Expr): number {
    switch (e.t) {
      case "lit": return this.add({ op: "lit", args: [], level: 0, enc: false, shape: "scalar", data: e.v });
      case "col": return this.add({ op: "col", args: [], level: 0, enc: this.isEncCol(e.name), shape: "row", data: e.name });
      case "neg": {
        const a = this.compile(e.e);
        const n = this.nodes[a];
        return this.add({ op: "neg", args: [a], level: n.level, enc: n.enc, shape: n.shape });
      }
      case "agg": {
        if (e.fn === "COUNT") return this.add({ op: "count", args: [], level: 0, enc: false, shape: "scalar" });
        const lin = linear(e.arg!, (n) => this.isEncCol(n));
        if (lin !== null && lin.coef.size > 0) {
          return this.add({ op: "linsum", args: [], level: 0, enc: true, shape: "scalar", data: { fn: e.fn, lin } });
        }
        const a = this.compile(e.arg!);
        const n = this.nodes[a];
        return this.add({ op: e.fn === "SUM" ? "sum" : "avg", args: [a], level: n.level, enc: n.enc, shape: "scalar" });
      }
      case "bin": {
        const a = this.compile(e.l);
        let b = this.compile(e.r);
        let op: string = e.op;
        if (e.op === "/" && e.r.t === "lit") {
          // x / k, k public: multiply by k^-1 mod n (= encode(1/k)); no inversion step
          const f = fDiv(frac(1n), e.r.v);
          this.nodes.pop();                                       // drop the literal's own node
          b = this.add({ op: "lit", args: [], level: 0, enc: false, shape: "scalar", data: f });
          op = "*";
        } else if (e.op === "/") {
          const nb = this.nodes[b];
          b = this.add({ op: "inv", args: [b], level: nb.level + (nb.enc ? this.invLevels : 0), enc: nb.enc, shape: nb.shape });
          op = "*";
        }
        const na = this.nodes[a], nb = this.nodes[b];
        const shape = na.shape === "row" || nb.shape === "row" ? "row" : "scalar";
        const enc = na.enc || nb.enc;
        if (op === "*") {
          if (na.enc && nb.enc) return this.add({ op: "cmul", args: [a, b], level: Math.max(na.level, nb.level) + 1, enc: true, shape });
          return this.add({ op: "smul", args: [a, b], level: Math.max(na.level, nb.level), enc, shape });
        }
        return this.add({ op: op === "+" ? "add" : "sub", args: [a, b], level: Math.max(na.level, nb.level), enc, shape });
      }
    }
  }

  // ── leaves ──
  private async colVector(name: string): Promise<Vec> {
    const { alias, col } = this.loc(name);
    const key = `${alias}\u0000${col}`;                      // `a` and `t.a` are one column
    const got = this.colcache.get(key);
    if (got) return got;
    const table = this.inst.get(alias)!;
    const p = this.pos.get(alias)!;
    const ids = this.tuples.map((t) => t[p]);
    let out: Vec;
    if (this.host.isPlain(table, col)) {
      const cells = await this.host.plainColumn(table, col, ids);
      out = cells.map((v) => (v === null || v === undefined ? null : this.ring.encode(numeric(v, name))));
    } else {
      const uniq = [...new Set(ids.filter((i): i is number => i !== null))].sort((a, b) => a - b);
      const ss = uniq.length ? await this.host.encScalars(table, col, uniq) : [];
      const byId = new Map<number, bigint>();
      uniq.forEach((id, k) => byId.set(id, ss[k]));
      out = ids.map((i) => (i === null ? null : byId.get(i)!));
    }
    this.colcache.set(key, out);
    return out;
  }

  protected validTuples(names: string[]): Array<Array<number | null>> {
    const aliases = [...new Set(names.map((n) => this.loc(n).alias))].sort();
    return this.tuples.filter((t) => aliases.every((a) => t[this.pos.get(a)!] !== null));
  }

  protected ringOf(k: Frac): bigint {
    // a folded public coefficient as a ring element WITHOUT the representability check of encode():
    // the coefficient of a linear form may be a product of literals that is not representable on
    // its own (only the final result has to be)
    const N = this.ring.N;
    return this.ring.mod(k.num) * this.ring.inv(this.ring.mod(k.den)) % N;
  }

  private async linsum(node: ENode): Promise<Vec> {
    const { fn, lin } = node.data as { fn: string; lin: Lin };
    const names = [...lin.coef.keys()];
    const valid = this.validTuples(names);
    const N = this.ring.N;
    let total = lin.konst.num !== 0n ? this.ringOf(lin.konst) * BigInt(valid.length) % N : 0n;
    for (const [name, k] of lin.coef) {
      if (k.num === 0n) continue;
      const { alias, col } = this.loc(name);
      const p = this.pos.get(alias)!;
      const ids = valid.map((t) => t[p] as number);
      const s = ids.length ? await this.host.linSum(this.inst.get(alias)!, col, ids) : 0n;
      total = (total + this.ringOf(k) * s) % N;
      this.cost.linearSums += 1;
    }
    if (fn === "AVG") {
      if (valid.length === 0) return [null];
      return [total * this.ring.inv(BigInt(valid.length)) % N];
    }
    return [total];
  }

  protected bc(v: Vec, n: number): Vec {
    if (v.length === n) return v;
    const out: Vec = [];
    for (let i = 0; i < n; i++) out.push(...v);                    // Python `v * n`
    return out;
  }

  protected async local(node: ENode, vals: Map<number, Vec>): Promise<Vec> {
    const N = this.ring.N;
    switch (node.op) {
      case "lit": return [this.ring.encode(node.data as Frac)];
      case "col": return this.colVector(node.data as string);
      case "count": return [BigInt(this.tuples.length)];
      case "linsum": return this.linsum(node);
    }
    const a = vals.get(node.args[0])!;
    switch (node.op) {
      case "neg": return a.map((x) => (x === null ? null : this.ring.mod(-x)));
      case "sum": {
        let s = 0n;
        for (const x of a) if (x !== null) s += x;
        return [s % N];
      }
      case "avg": {
        const live = a.filter((x): x is bigint => x !== null);
        if (live.length === 0) return [null];
        return [live.reduce((p, q) => p + q, 0n) % N * this.ring.inv(BigInt(live.length)) % N];
      }
      case "inv": {
        const out: Vec = [];
        for (let k = 0; k < a.length; k++) {
          const x = a[k];
          if (x === null) { out.push(null); continue; }
          if (this.ring.mod(x) === 0n) {
            // Do NOT stop here: aborting would show the server (as a missing request) that a
            // denominator was zero. Carry on with a dummy 0 so the request sequence is independent
            // of the data, and raise at the end.
            if (this.zero === null) this.zero = node.shape === "row" ? ` (result row ${k})` : "";
            out.push(0n);
            continue;
          }
          out.push(this.ring.inv(x));
          this.cost.inversions += 1;
        }
        return out;
      }
    }
    const b = vals.get(node.args[1])!;
    const w = Math.max(a.length, b.length);
    const aa = this.bc(a, w), bb = this.bc(b, w);
    const n = Math.min(aa.length, bb.length);
    const out: Vec = [];
    for (let k = 0; k < n; k++) {
      const x = aa[k], y = bb[k];
      if (x === null || y === null) { out.push(null); continue; }
      switch (node.op) {
        case "add": out.push((x + y) % N); break;
        case "sub": out.push(this.ring.mod(x - y)); break;
        case "smul": out.push(x * y % N); break;     // public scalar x value: NOT a ciphertext product
        default: throw new TorusError("ExecError", `internal: unknown operator ${node.op}`);
      }
    }
    return out;
  }

  /** ONE owner round for every ciphertext x ciphertext product of a level (Pi_mult, batched). */
  private async multRound(levelNodes: number[], vals: Map<number, Vec>): Promise<void> {
    const ring = this.ring, N = ring.N;
    const ops: Array<[number, number]> = [];
    const triples: Array<{ u: bigint; v: bigint; w: bigint }> = [];
    const openings: Array<[bigint, bigint]> = [];
    const shapes = new Map<number, number>();
    for (const i of levelNodes) {
      const node = this.nodes[i];
      const a0 = vals.get(node.args[0])!, b0 = vals.get(node.args[1])!;
      const w = Math.max(a0.length, b0.length);
      const a = this.bc(a0, w), b = this.bc(b0, w);
      shapes.set(i, w);
      const n = Math.min(a.length, b.length);
      for (let k = 0; k < n; k++) {
        const x = a[k], y = b[k];
        if (x === null || y === null) continue;
        const u = ring.rand(), v = ring.rand();            // a fresh triple per product, never reused
        triples.push({ u, v, w: u * v % N });
        openings.push([ring.mod(x - u), ring.mod(y - v)]);
        ops.push([i, k]);
      }
    }
    const egs: bigint[] = [];
    const step = Math.max(1, Math.min(100_000, this.host.maxItems()));
    for (let s = 0; s < openings.length; s += step) {
      for (const x of await this.host.multCombine(openings.slice(s, s + step))) egs.push(x);
    }
    if (egs.length !== openings.length) {
      throw new TorusError("IntegrityError", "server returned the wrong number of product terms");
    }
    for (const i of levelNodes) vals.set(i, new Array<bigint | null>(shapes.get(i)!).fill(null));
    for (let j = 0; j < ops.length; j++) {
      const [i, k] = ops[j];
      const [e, g] = openings[j];
      const { u, v, w } = triples[j];
      if (this.host.authenticated && ring.mod(egs[j]) !== e * g % N) {
        throw new TorusError("IntegrityError", "server returned a forged product term in an expression (e*g mismatch)");
      }
      vals.get(i)![k] = ring.mod(w + e * v + g * u + egs[j]);
    }
    this.cost.multRounds += 1;
    this.cost.products += openings.length;
  }

  /** Evaluate. Returns the decoded value (agg) or one decoded value (or null) per row (row). */
  async run(): Promise<unknown> {
    const root = this.compile(this.expr);
    const depth = this.nodes.reduce((m, n) => Math.max(m, n.level), 0);
    if (depth !== this.info.depth) {                            // planner/engine disagree: never guess
      throw new TorusError("ExecError", `internal: planned multiplicative depth ${this.info.depth} != compiled depth ${depth}`);
    }
    const vals = new Map<number, Vec>();
    for (let lvl = 0; lvl <= depth; lvl++) {
      if (lvl > 0) {
        const muls = this.nodes.flatMap((n, i) => (n.op === "cmul" && n.level === lvl ? [i] : []));
        if (muls.length) await this.multRound(muls, vals);
      }
      for (let i = 0; i < this.nodes.length; i++) {
        const n = this.nodes[i];
        if (n.level === lvl && n.op !== "cmul") vals.set(i, await this.local(n, vals));
      }
    }
    if (this.zero !== null) {
      throw new TorusError("DivisionByZero", `division by zero: a denominator is 0${this.zero}`);
    }
    this.cost.depth = depth;
    const out = vals.get(root)!;
    if (this.info.kind === "row") {
      const rows = this.R ? this.bc(out, this.R) : [];
      return rows.map((v) => (v === null ? null : this.ring.decode(v)));
    }
    const v = out[0];
    return v === null ? null : this.ring.decode(v);
  }
}

function numeric(v: unknown, name: string): Frac {
  if (typeof v === "bigint") return frac(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return frac(BigInt(v));
  if (typeof v === "object" && v !== null && typeof (v as Frac).num === "bigint" && typeof (v as Frac).den === "bigint") {
    return frac((v as Frac).num, (v as Frac).den);
  }
  throw new TorusError("ExecError", `column '${name}' holds a non-numeric value in an expression`);
}
