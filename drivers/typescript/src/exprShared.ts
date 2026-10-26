// SPDX-License-Identifier: Apache-2.0
// Shared-wire evaluation of TorusSQL v0.6 arithmetic expressions (`expressionMode: "shared"`, the
// default): the paper's circuit composition Pi_C (Lee, "No-Key Delegation of EC-FHE", Construction 20)
// with every wire held as a TWO-PARTY ADDITIVE SHARING over Z/nZ - the owner's half of the protocol.
// Port of `core/torusdb_core/expr_shared.py` (the reference; the server half is `wires.py`). Read the
// header of that file for the full account; in short:
//
// Every wire X (a column, a literal-scaled sum, a product, a quotient...) is X = X_S + X_O (mod n). A
// stored cell is x~ = x + r, so a LOADED wire has X_S = x~ (the server's own stored value) and
// X_O = -r (the mask the owner already holds). Nothing else is ever sent about a loaded column.
//
//  * the SERVER (a session-scoped wire store) applies every linear gate to ITS share, computes ITS share
//    of every Beaver product and keeps the result as a NEW server-resident wire. It never receives a
//    key, a mask, a MAC key or anything derived from a plaintext except uniform shares and openings; it
//    never decodes; it never learns a product, quotient or the result (it only SENDS its share of the
//    result wire(s) to the owner).
//  * the OWNER (this file) applies the same linear gates to ITS shares (local arithmetic), deals one
//    Beaver triple (u, v, w = uv) per product ELEMENT - the server gets only its additive SHARES of it -
//    computes ITS share of each product and finally adds the server's share of the result wire to its
//    own and decodes (strict: OutOfBudget). It fetches no operand cell and unmasks no operand or
//    intermediate. (This O(rows) owner work is inherent to unconditionally secure two-party
//    computation; the owner is also the DEALER, so a curious owner process could derive the operands
//    from its own openings - that is a property of this code, not a cryptographic guarantee; see
//    docs/crypto-review-packet.md 3.3.)
//  * one request/response per multiplicative level (batched over all products and rows of the level);
//    a division by an ENCRYPTED y deals a fresh uniform non-zero rho, forms [t] = [rho]*[y] by a Beaver
//    product, OPENS t = rho*y (MAC-checked in authenticated mode, BEFORE the zero test), and sets
//    [1/y] = t^-1 * [rho] (a public-scalar multiplication). A zero t is replaced by a fresh random
//    non-zero dummy before anything goes back, the protocol runs to its last request, and only then
//    DivisionByZero is raised: the request sequence is the same whether or not a denominator was zero.
//  * authenticated mode: every wire carries a share of its SPDZ tag alpha*X (alpha known only to the
//    owner); every opening and the revealed result are MAC-checked by the owner.
//  * every wire the query created is dropped with `wire_free` on EVERY exit path (success needs none:
//    the last request frees everything after the reveal).

import { randomBytes } from "crypto";
import { TorusError } from "./errors";
import { ENode, ExprHost, ExprRunner, Ring, SharedHost, Vec } from "./exprEval";
import type { Expr, ExprInfo } from "./expr";
export type { SharedHost, WireLimits } from "./exprEval";

const MAX_RING_DIGITS = 80;
const DEC = /^[0-9]+$/;
const integrity = (m: string) => new TorusError("IntegrityError", m);
const proto = (m: string) => new TorusError("ProtocolError", m);

/** A shared (or public) value of one node. Public: `wid` undefined and `pub` holds the ring elements
 *  (null = dead). Shared: `wid` is the server wire, `own` the owner's value shares, `ownm` its tag
 *  shares (authenticated mode) and `live` the positions that exist (null = all). */
interface V {
  w: number;
  pub?: Vec;
  wid?: string;
  own?: bigint[];
  ownm?: bigint[] | null;
  live?: boolean[] | null;
}
const isShared = (v: V): boolean => v.wid !== undefined;

type Op = unknown[];
interface Pending { op: Op; cost: number; handler: ((r: unknown) => void) | null }
interface Triple { u: bigint[]; v: bigint[]; w: bigint[]; mu?: bigint[]; mv?: bigint[]; mw?: bigint[] }
const KEEP = Symbol("keep");

// ── the JSON encoding of requests and replies (core/torusdb_core/wires.py: ops_to_wire / results_from_wire)
const strs = (v: bigint[]): string[] => v.map((x) => x.toString());

/** Operations as they travel: ring elements are decimal strings, row ids / widths / spans are numbers. */
export function opsToWire(ops: Op[]): unknown[] {
  return ops.map((op) => {
    const name = op[0] as string;
    switch (name) {
      case "mulc": case "addc": return [name, op[1], op[2], (op[3] as bigint).toString()];
      case "put": return [name, op[1], strs(op[2] as bigint[]), op[3] === null ? null : strs(op[3] as bigint[]), op[4], op[5]];
      case "mulv": case "addv": return [name, op[1], op[2], strs(op[3] as bigint[]), op[4], op[5]];
      case "mul": {
        const t = op[4] as Record<string, bigint[]>;
        const o: Record<string, string[]> = {};
        for (const k of Object.keys(t)) o[k] = strs(t[k]);
        return [name, op[1], op[2], op[3], o, op[5], op[6]];
      }
      default: return op;
    }
  });
}

function ringStr(x: unknown, what: string): bigint {
  if (typeof x !== "string" || x.length === 0 || x.length > MAX_RING_DIGITS || !DEC.test(x)) {
    throw proto(`bad ring element in ${what}`);
  }
  return BigInt(x);
}
function vecOrNull(x: unknown, what: string): bigint[] | null {
  if (x === null || x === undefined) return null;
  if (!Array.isArray(x)) throw proto(`${what}: expected a list`);
  return x.map((e) => ringStr(e, what));
}

/** Replies decoded: a product answers `[e_S, g_S, tag(e)_S, tag(g)_S]`, a reveal `[share, tag share]`. */
export function resultsFromWire(ops: Op[], res: unknown): unknown[] {
  if (!Array.isArray(res) || res.length !== ops.length) {
    throw integrity("server answered the wrong number of wire operations");
  }
  return ops.map((op, i) => {
    const r = res[i];
    if (op[0] === "mul") {
      if (!Array.isArray(r) || r.length !== 4) throw integrity("server returned a malformed product reply");
      return r.map((x) => vecOrNull(x, "mul"));
    }
    if (op[0] === "reveal") {
      if (!Array.isArray(r) || r.length !== 2) throw integrity("server returned a malformed reveal reply");
      return r.map((x) => vecOrNull(x, "reveal"));
    }
    return r;
  });
}

/** An upper bound for the size of the reply to `ops`, in ring elements. */
function replyElements(ops: Op[]): number {
  let n = 0;
  for (const op of ops) {
    if (op[0] === "mul") n += 4 * (op[4] as Triple).u.length;
    else if (op[0] === "reveal") n += 2 * (op[3] as number);
  }
  return n;
}

const mod = (a: bigint, N: bigint): bigint => { const r = a % N; return r < 0n ? r + N : r; };

export class SharedExprRunner extends ExprRunner {
  protected override readonly invLevels: number = 1;     // dividing by an encrypted value costs one extra level

  private readonly sh: SharedHost;
  private readonly auth: boolean;
  private readonly alpha: bigint;
  private readonly NN: bigint;
  private readonly qid = randomBytes(6).toString("hex");
  private seq = 0;
  private pending: Pending[] = [];
  private post: Array<() => void> = [];          // callbacks run after the pending ops were answered
  private tofree: string[] = [];                 // wires to drop at the end of the next flush
  private liveIds = new Set<string>();
  private maskCache = new Map<string, bigint>();
  private inv = new Map<number, { rho: V; tinv: bigint[]; live: boolean[] | null }>();
  private budget = 100_000;
  private maxOps = 10_000;
  private chunk = 11_111;
  private readonly ccost = { openings: 0, wires: 0, requests: 0, reveals: 0 };

  constructor(host: ExprHost, ring: Ring, expr: Expr, info: ExprInfo, inst: ReadonlyMap<string, string>,
              loc: (name: string) => { alias: string; col: string }, tuples: Array<Array<number | null>>) {
    super(host, ring, expr, info, inst, loc, tuples);
    if (!host.shared) throw new TorusError("InterfaceError", "internal: the shared evaluator needs a SharedHost");
    this.sh = host.shared;
    this.auth = host.authenticated;
    this.alpha = this.auth ? this.sh.alpha() : 0n;
    this.NN = ring.N;
  }

  // ── plumbing ─────────────────────────────────────────────────────────────
  /** The number of sequential product levels the expression needs in this mode (no request is sent). */
  sharedDepth(): number {
    this.nodes = [];
    this.compile(this.expr);
    return this.nodes.reduce((m, n) => Math.max(m, n.level), 0);
  }

  private setupLimits(): void {
    const lim = this.sh.wireLimits();
    if (lim === undefined) {
      throw new TorusError("ExecError",
        "this server does not offer the shared-wire RPCs (wire_exec); connect with " +
        "expressionMode: 'owner' (expr_mode='owner' in the Python driver) to evaluate expressions the v0.6 " +
        "way (the owner unmasks the operand cells), or upgrade the server");
    }
    this.budget = lim.maxRequestElements ?? this.budget;
    this.maxOps = lim.maxOps ?? this.maxOps;
    this.chunk = Math.max(1, Math.floor(this.budget / 9));
  }

  private newWire(): string {
    this.seq += 1;
    const wid = `${this.qid}.${this.seq}`;
    this.liveIds.add(wid);
    this.ccost.wires += 1;
    return wid;
  }

  private emit(op: Op, cost = 0, handler: ((r: unknown) => void) | null = null): void {
    this.pending.push({ op, cost, handler });
  }

  private freeAfter(wid: string | undefined): void {
    if (wid !== undefined) this.tofree.push(wid);
  }

  private async flush(): Promise<void> {
    const pend = this.pending;
    this.pending = [];
    let freed: string[] = [];
    if (this.tofree.length) {
      freed = this.tofree;
      this.tofree = [];
      for (let k = 0; k < freed.length; k += 2000) pend.push({ op: ["free", freed.slice(k, k + 2000)], cost: 0, handler: null });
    }
    const groups: Pending[][] = [];
    let cur: Pending[] = [], used = 0;
    for (const ent of pend) {
      if (cur.length && (used + ent.cost > this.budget || cur.length >= this.maxOps)) {
        groups.push(cur);
        cur = []; used = 0;
      }
      cur.push(ent);
      used += ent.cost;
    }
    if (cur.length) groups.push(cur);
    for (const grp of groups) {
      const ops = grp.map((e) => e.op);
      const reply = await this.sh.rpc("wire_exec", [opsToWire(ops)], replyElements(ops) * (MAX_RING_DIGITS + 8) + ops.length * 16 + 4096);
      this.ccost.requests += 1;
      const res = resultsFromWire(ops, reply);
      grp.forEach((ent, k) => { if (ent.handler) ent.handler(res[k]); });
    }
    for (const w of freed) this.liveIds.delete(w);       // only now: a failed flush must still free them
    const post = this.post;
    this.post = [];
    for (const fn of post) fn();
  }

  /** Drop whatever this query still holds on the server (best effort, never throws). */
  private async cleanup(): Promise<void> {
    this.pending = [];
    this.post = [];
    const ids = [...new Set([...this.liveIds, ...this.tofree])];
    this.liveIds.clear();
    this.tofree = [];
    for (let k = 0; k < ids.length; k += 2000) {
      try {
        await this.sh.rpc("wire_free", [ids.slice(k, k + 2000)], 4096);
      } catch { return; }
    }
  }

  private vecOk(x: bigint[] | null, k: number, what = "reply"): bigint[] {
    if (x === null || x.length !== k || x.some((v) => v >= this.NN)) throw integrity(`server returned a malformed ${what}`);
    return x;
  }

  private m(a: bigint): bigint { return mod(a, this.NN); }

  // ── public-value helpers ─────────────────────────────────────────────────
  private spanOps(name: string, out: string, a: string, vec: bigint[], w: number): void {
    if (vec.length === 0) { this.emit([name, out, a, [], 0, w]); return; }
    for (let lo = 0; lo < vec.length; lo += this.chunk) {
      const part = vec.slice(lo, lo + this.chunk);
      this.emit([name, out, a, part, lo, w], part.length);
    }
  }

  private bcast(v: V, w: number): V {
    if (v.w === w) return v;
    if (v.w !== 1) throw new TorusError("ExecError", "internal: operand widths are neither equal nor scalar");
    if (!isShared(v)) return { w, pub: rep(v.pub!, w) };
    const out = this.newWire();
    this.emit(["bc", out, v.wid, w]);
    this.freeAfter(out);
    return { w, wid: out, own: rep(v.own!, w), ownm: v.ownm == null ? null : rep(v.ownm, w), live: v.live == null ? null : rep(v.live, w) };
  }

  private wd(a: V, b: V): number { return a.w === 0 || b.w === 0 ? 0 : Math.max(a.w, b.w); }

  // ── gates on shared values (owner shares + server ops) ───────────────────
  private gNeg(a: V): V {
    const out = this.newWire();
    this.emit(["neg", out, a.wid]);
    return { w: a.w, wid: out, own: a.own!.map((x) => this.m(-x)), ownm: a.ownm == null ? null : a.ownm.map((x) => this.m(-x)), live: a.live };
  }

  private gMulc(a: V, k: bigint, live: boolean[] | null | typeof KEEP = KEEP): V {
    const out = this.newWire();
    k = this.m(k);
    this.emit(["mulc", out, a.wid, k]);
    const N = this.NN;
    return { w: a.w, wid: out, own: a.own!.map((x) => x * k % N), ownm: a.ownm == null ? null : a.ownm.map((x) => x * k % N),
             live: live === KEEP ? a.live : live };
  }

  private gMulv(a: V, vec: bigint[], live: boolean[] | null): V {
    const out = this.newWire();
    this.spanOps("mulv", out, a.wid!, vec, a.w);
    const N = this.NN;
    return { w: a.w, wid: out, own: a.own!.map((x, j) => x * vec[j] % N),
             ownm: a.ownm == null ? null : a.ownm.map((x, j) => x * vec[j] % N), live };
  }

  private gAddc(a: V, c: bigint, live: boolean[] | null): V {
    const out = this.newWire();
    c = this.m(c);
    this.emit(["addc", out, a.wid, c]);
    const ownm = a.ownm == null ? null : a.ownm.map((x) => (x + this.alpha * c) % this.NN);
    return { w: a.w, wid: out, own: [...a.own!], ownm, live };
  }

  private gAddv(a: V, vec: bigint[], live: boolean[] | null): V {
    const out = this.newWire();
    this.spanOps("addv", out, a.wid!, vec, a.w);
    const ownm = a.ownm == null ? null : a.ownm.map((x, j) => (x + this.alpha * vec[j]) % this.NN);
    return { w: a.w, wid: out, own: [...a.own!], ownm, live };
  }

  private gAddSub(op: "add" | "sub", a: V, b: V): V {
    const w = this.wd(a, b);
    a = this.bcast(a, w); b = this.bcast(b, w);
    const out = this.newWire();
    this.emit([op, out, a.wid, b.wid]);
    const f = op === "add" ? (x: bigint, y: bigint) => (x + y) % this.NN : (x: bigint, y: bigint) => this.m(x - y);
    return { w, wid: out, own: a.own!.map((x, j) => f(x, b.own![j])),
             ownm: a.ownm == null ? null : a.ownm.map((x, j) => f(x, b.ownm![j])),
             live: andLive(a.live, b.live, w) };
  }

  /** (scalar or null, vector or null, live) of a public operand; dead -> 0. */
  private pubParts(p: V): { sc: bigint | null; vec: bigint[] | null; live: boolean[] | null } {
    if (p.w === 1) {
      const x = p.pub![0];
      return { sc: x === null ? 0n : x, vec: null, live: x === null ? [false] : null };
    }
    const vals = p.pub!.map((x) => (x === null ? 0n : x));
    const alive = p.pub!.map((x) => x !== null);
    return { sc: null, vec: vals, live: alive.every((x) => x) ? null : alive };
  }

  /** Shared `s` with public `p`: op in add / sub / smul (`flip`: p - s). */
  private gPub(op: string, s: V, p: V, flip = false): V {
    const parts = this.pubParts(p);
    let { sc } = parts;
    let { vec } = parts;
    if (vec !== null && s.w !== p.w) s = this.bcast(s, p.w);
    let live = s.live ?? null;
    if (parts.live !== null) {
      if (vec === null) live = new Array<boolean>(s.w).fill(false);   // a dead scalar kills every position
      else live = live === null ? parts.live : parts.live.map((x, j) => x && live![j]);
    }
    if (op === "smul") return vec === null ? this.gMulc(s, sc!, live) : this.gMulv(s, vec, live);
    if (flip) {
      s = this.gNeg(s);                                               // p - s = (-s) + p
      this.freeAfter(s.wid);
    } else if (op === "sub") {
      sc = sc === null ? null : this.m(-sc);
      vec = vec === null ? null : vec.map((x) => this.m(-x));
    }
    return vec === null ? this.gAddc(s, sc!, live) : this.gAddv(s, vec, live);
  }

  private gSum(a: V): V {
    if (a.live != null && !a.live.every((x) => x)) {                  // dead positions must not contribute
      a = this.gMulv(a, a.live.map((x) => (x ? 1n : 0n)), null);
      this.freeAfter(a.wid);
    }
    const out = this.newWire();
    this.emit(["sum", out, a.wid]);
    const N = this.NN;
    const sum = (xs: bigint[]) => xs.reduce((p, q) => p + q, 0n) % N;
    return { w: 1, wid: out, own: [sum(a.own!)], ownm: a.ownm == null ? null : [sum(a.ownm)], live: null };
  }

  // ── leaves ───────────────────────────────────────────────────────────────
  private maskOf(table: string, id: number, col: string): bigint {
    const key = `${table}\u0000${id}\u0000${col}`;
    let m = this.maskCache.get(key);
    if (m === undefined) { m = this.sh.mask(table, id, col); this.maskCache.set(key, m); }
    return m;
  }

  private load(name: string): V {
    const { alias, col } = this.loc(name);
    const table = this.inst.get(alias)!;
    const p = this.pos.get(alias)!;
    const ids = this.tuples.map((t) => t[p]);
    const own = ids.map((i) => (i === null ? 0n : this.m(-this.maskOf(table, i, col))));
    const ownm = this.auth ? ids.map((i) => (i === null ? 0n : this.m(-this.maskOf(table, i, "__mac__" + col)))) : null;
    const out = this.newWire();
    if (ids.length === 0) this.emit(["load", out, table, col, [], this.auth, 0, 0]);
    for (let lo = 0; lo < ids.length; lo += this.chunk) {
      const part = ids.slice(lo, lo + this.chunk);
      this.emit(["load", out, table, col, part, this.auth, lo, ids.length], part.length);
    }
    const live = ids.every((i) => i !== null) ? null : ids.map((i) => i !== null);
    return { w: ids.length, wid: out, own, ownm, live };
  }

  private linsumShared(node: ENode): V {
    const { fn, lin } = node.data as { fn: string; lin: { coef: Map<string, { num: bigint; den: bigint }>; konst: { num: bigint; den: bigint } } };
    const names = [...lin.coef.keys()];
    const valid = this.validTuples(names);
    const cnt = valid.length;
    const N = this.NN;
    let acc: V | null = null;
    for (const [name, k] of lin.coef) {
      if (k.num === 0n) continue;
      const { alias, col } = this.loc(name);
      const table = this.inst.get(alias)!;
      const p = this.pos.get(alias)!;
      const ids = valid.map((t) => t[p] as number);
      this.cost.linearSums += 1;
      if (ids.length === 0) continue;
      const out = this.newWire();
      for (let lo = 0; lo < ids.length; lo += this.chunk) {
        const part = ids.slice(lo, lo + this.chunk);
        this.emit(["loadsum", out, table, col, part, this.auth, lo > 0], part.length);
      }
      let sm = 0n, smm = 0n;
      for (const i of ids) {
        sm += this.maskOf(table, i, col);
        if (this.auth) smm += this.maskOf(table, i, "__mac__" + col);
      }
      let v: V = { w: 1, wid: out, own: [this.m(-sm)], ownm: this.auth ? [this.m(-smm)] : null };
      v = this.gMulc(v, this.ringOf(k));
      this.freeAfter(out);
      if (acc === null) {
        acc = v;
      } else {
        const nw = this.gAddSub("add", acc, v);
        this.freeAfter(acc.wid);
        this.freeAfter(v.wid);
        acc = nw;
      }
    }
    const c0 = lin.konst.num !== 0n ? this.ringOf(lin.konst) * BigInt(cnt) % N : 0n;
    let total: V;
    if (acc === null) {
      total = { w: 1, pub: [c0] };
    } else if (c0 !== 0n) {
      total = this.gAddc(acc, c0, null);
      this.freeAfter(acc.wid);
    } else {
      total = acc;
    }
    if (fn === "AVG") {
      if (valid.length === 0) return { w: 1, pub: [null] };
      const inv = this.ring.inv(BigInt(cnt));
      if (!isShared(total)) return { w: 1, pub: [total.pub![0]! * inv % N] };
      const out = this.gMulc(total, inv);
      this.freeAfter(total.wid);
      return out;
    }
    return total;
  }

  // ── the pass over the DAG ────────────────────────────────────────────────
  private async computeNode(i: number, vals: Map<number, V | undefined>): Promise<void> {
    const node = this.nodes[i];
    const op = node.op;
    if (this.inv.has(i)) {                                  // an inversion started one level earlier
      vals.set(i, this.invFinish(i));
      return;
    }
    const args = node.args.map((a) => vals.get(a)!);
    if (!node.enc || (args.length > 0 && !args.some(isShared))) {
      // public subtree: plain list arithmetic at the owner (both parties know it)
      const pubvals = new Map<number, Vec>();
      for (const a of node.args) pubvals.set(a, vals.get(a)!.pub!);
      const lst = await this.local(node, pubvals);
      vals.set(i, { w: lst.length, pub: lst });
      return;
    }
    switch (op) {
      case "col": vals.set(i, this.load(node.data as string)); return;
      case "linsum": vals.set(i, this.linsumShared(node)); return;
      case "neg": vals.set(i, this.gNeg(args[0])); return;
      case "sum": vals.set(i, this.gSum(args[0])); return;
      case "avg": {
        const a = args[0];
        const live = a.live == null ? a.w : a.live.filter((x) => x).length;
        if (live === 0) { vals.set(i, { w: 1, pub: [null] }); return; }
        const s = this.gSum(a);
        vals.set(i, this.gMulc(s, this.ring.inv(BigInt(live))));
        this.freeAfter(s.wid);
        return;
      }
      case "add": case "sub": case "smul": {
        const [a, b] = args;
        if (isShared(a) && isShared(b)) {
          if (op === "smul") throw new TorusError("ExecError", "internal: a product of two shared wires must be a Beaver gate");
          vals.set(i, this.gAddSub(op, a, b));
        } else if (isShared(a)) {
          vals.set(i, this.gPub(op, a, b));
        } else {
          vals.set(i, this.gPub(op, b, a, op === "sub"));
        }
        return;
      }
      default: throw new TorusError("ExecError", `internal: unknown operator ${op}`);
    }
  }

  // — Beaver gate: Z = X*Y ---------------------------------------------------
  /** k fresh triples, additively shared: server shares and owner shares. */
  private deal(k: number): { S: Triple; O: Triple } {
    const N = this.NN, al = this.alpha, rb = () => this.ring.rand();
    const S: Triple = { u: [], v: [], w: [] };
    const O: Triple = { u: [], v: [], w: [] };
    if (this.auth) { S.mu = []; S.mv = []; S.mw = []; O.mu = []; O.mv = []; O.mw = []; }
    for (let j = 0; j < k; j++) {
      const uS = rb(), uO = rb(), vS = rb(), vO = rb(), wS = rb();
      const u = (uS + uO) % N, v = (vS + vO) % N, w = u * v % N;
      S.u.push(uS); O.u.push(uO);
      S.v.push(vS); O.v.push(vO);
      S.w.push(wS); O.w.push(this.m(w - wS));
      if (this.auth) {
        const muS = rb(), mvS = rb(), mwS = rb();
        S.mu!.push(muS); O.mu!.push(this.m(al * u - muS));
        S.mv!.push(mvS); O.mv!.push(this.m(al * v - mvS));
        S.mw!.push(mwS); O.mw!.push(this.m(al * w - mwS));
      }
    }
    return { S, O };
  }

  private emitMul(a: V, b: V): V {
    const w = this.wd(a, b);
    a = this.bcast(a, w); b = this.bcast(b, w);
    const out = this.newWire();
    const res: V = { w, wid: out, own: new Array<bigint>(w).fill(0n), ownm: this.auth ? new Array<bigint>(w).fill(0n) : null,
                     live: andLive(a.live, b.live, w) };
    const per = this.auth ? 8 : 5;
    const av = a, bv = b;
    for (let lo = 0; lo < Math.max(w, 1); lo += this.chunk) {
      const k = Math.min(this.chunk, w - lo);
      const { S, O } = this.deal(k);
      const eo = av.own!.slice(lo, lo + k).map((x, j) => this.m(x - O.u[j]));
      const go = bv.own!.slice(lo, lo + k).map((y, j) => this.m(y - O.v[j]));
      const tri = { ...S, eo, go };
      this.emit(["mul", out, av.wid, bv.wid, tri, lo, w], k * per,
                (r) => this.onMul(r, av, bv, res, lo, k, eo, go, O));
    }
    this.cost.products += w;
    return res;
  }

  private onMul(r: unknown, a: V, b: V, res: V, lo: number, k: number, eo: bigint[], go: bigint[], O: Triple): void {
    if (!Array.isArray(r) || r.length !== 4) throw integrity("server returned a malformed product reply");
    const eS = this.vecOk(r[0], k), gS = this.vecOk(r[1], k);
    const al = this.alpha, N = this.NN;
    let meS: bigint[] = [], mgS: bigint[] = [];
    if (this.auth) { meS = this.vecOk(r[2], k); mgS = this.vecOk(r[3], k); }
    for (let j = 0; j < k; j++) {
      const e = (eS[j] + eo[j]) % N, g = (gS[j] + go[j]) % N;
      if (this.auth) {
        // MAC-check both openings: the server's reported tag share of e (resp. g) plus the owner's
        // must equal alpha*e (resp. alpha*g)
        if (this.m((meS[j] + a.ownm![lo + j] - O.mu![j]) - al * e) !== 0n ||
            this.m((mgS[j] + b.ownm![lo + j] - O.mv![j]) - al * g) !== 0n) {
          throw integrity("MAC check failed on a multiplication opening -- the server tampered with a wire share");
        }
      }
      res.own![lo + j] = (O.w[j] + e * O.v[j] + g * O.u[j]) % N;
      if (this.auth) {
        res.ownm![lo + j] = (O.mw![j] + e * O.mv![j] + g * O.mu![j] + al * e % N * g) % N;
      }
    }
    this.ccost.openings += 2 * k;
  }

  private publicMul(a: V, b: V): V {
    if (!isShared(a) && !isShared(b)) {
      const w = this.wd(a, b);
      a = this.bcast(a, w); b = this.bcast(b, w);
      return { w, pub: a.pub!.map((x, j) => (x === null || b.pub![j] === null ? null : x * b.pub![j]! % this.NN)) };
    }
    return isShared(a) ? this.gPub("smul", a, b) : this.gPub("smul", b, a);
  }

  // — reveal (the only thing the server ever sends back about a result) —
  private emitReveal(v: V, sink: { z: bigint[]; m: bigint[] }): void {
    sink.z = new Array<bigint>(v.w).fill(0n);
    sink.m = new Array<bigint>(v.w).fill(0n);
    for (let lo = 0; lo < v.w; lo += this.chunk) {
      const k = Math.min(this.chunk, v.w - lo);
      this.emit(["reveal", v.wid, lo, k], k * (this.auth ? 2 : 1), (r) => this.onReveal(r, sink, lo, k));
    }
    this.ccost.reveals += 1;
  }

  private onReveal(r: unknown, sink: { z: bigint[]; m: bigint[] }, lo: number, k: number): void {
    if (!Array.isArray(r) || r.length !== 2) throw integrity("server returned a malformed reveal reply");
    const z = this.vecOk(r[0], k);
    for (let j = 0; j < k; j++) sink.z[lo + j] = z[j];
    if (this.auth) {
      const m = this.vecOk(r[1], k);
      for (let j = 0; j < k; j++) sink.m[lo + j] = m[j];
    }
  }

  /** z = server share + owner share per position, MAC-checked on live positions. */
  private openWire(v: V, sink: { z: bigint[]; m: bigint[] }): bigint[] {
    const out: bigint[] = [];
    for (let j = 0; j < v.w; j++) {
      const z = (sink.z[j] + v.own![j]) % this.NN;
      if (this.auth && (v.live == null || v.live[j])) {
        if (this.m(sink.m[j] + v.ownm![j] - this.alpha * z) !== 0n) {
          throw integrity("MAC check failed on the revealed result -- the server returned a forged or inconsistent share");
        }
      }
      out.push(z);
    }
    return out;
  }

  // — division by an encrypted y: [t] = [rho]*[y], open t, [1/y] = t^-1 [rho] —
  private invStart(i: number, y: V): void {
    const N = this.NN, rb = () => this.ring.rand();
    const nz = () => 1n + this.ring.rand() % (N - 1n);              // uniform NON-ZERO
    const w = y.w;
    const rho: bigint[] = [], rS: bigint[] = [], rO: bigint[] = [];
    for (let j = 0; j < w; j++) { rho.push(nz()); rS.push(rb()); rO.push(this.m(rho[j] - rS[j])); }
    let mS: bigint[] | null = null, mO: bigint[] | null = null;
    if (this.auth) {
      mS = rho.map(() => rb());
      mO = rho.map((r, j) => this.m(this.alpha * r - mS![j]));
    }
    const wid = this.newWire();
    const step = this.chunk;
    if (w === 0) this.emit(["put", wid, [], this.auth ? [] : null, 0, 0]);
    for (let lo = 0; lo < w; lo += step) {
      const part = rS.slice(lo, lo + step);
      this.emit(["put", wid, part, mS === null ? null : mS.slice(lo, lo + step), lo, w], part.length * (this.auth ? 2 : 1));
    }
    const rhoV: V = { w, wid, own: rO, ownm: mO };
    const prod = this.emitMul(rhoV, y);
    const sink = { z: [] as bigint[], m: [] as bigint[] };
    this.emitReveal(prod, sink);
    this.freeAfter(prod.wid);
    this.post.push(() => {
      const ts = this.openWire(prod, sink);                          // t = rho*y, MAC-checked
      const tinv: bigint[] = [];
      ts.forEach((t, j) => {
        if (t === 0n) {
          if (y.live == null || y.live[j]) {
            if (this.zero === null) this.zero = this.nodes[i].shape === "row" ? ` (result row ${j})` : "";
          }
          t = nz();                                                  // dummy: the server must not learn it
        } else {
          this.cost.inversions += 1;
        }
        tinv.push(this.ring.inv(t));
      });
      this.ccost.openings += ts.length;
      this.inv.set(i, { rho: rhoV, tinv, live: y.live ?? null });
    });
  }

  private invFinish(i: number): V {
    const { rho, tinv, live } = this.inv.get(i)!;
    this.inv.delete(i);
    const out = this.newWire();
    this.spanOps("mulv", out, rho.wid!, tinv, rho.w);
    this.freeAfter(rho.wid);
    const N = this.NN;
    return { w: rho.w, wid: out, own: rho.own!.map((x, j) => x * tinv[j] % N),
             ownm: rho.ownm == null ? null : rho.ownm.map((x, j) => x * tinv[j] % N), live };
  }

  // ── run ──────────────────────────────────────────────────────────────────
  /** Evaluate. Returns the decoded value (agg) or one decoded value (or null) per row (row). */
  override async run(): Promise<unknown> {
    const root = this.compile(this.expr);
    const depth = this.nodes.reduce((m, n) => Math.max(m, n.level), 0);
    this.setupLimits();
    const refs = new Array<number>(this.nodes.length).fill(0);
    for (const n of this.nodes) for (const a of n.args) refs[a] += 1;
    refs[root] += 1;
    const vals = new Map<number, V | undefined>();
    // the node `i` was used once more; drop its wire after the last use
    const consume = (i: number): void => {
      for (const a of this.nodes[i].args) {
        refs[a] -= 1;
        const va = vals.get(a);
        if (refs[a] === 0 && va !== undefined && isShared(va)) {
          this.freeAfter(va.wid);
          vals.set(a, undefined);                                    // the owner's share is dead too
        }
      }
    };
    try {
      let sink = { z: [] as bigint[], m: [] as bigint[] };
      for (let lvl = 0; lvl <= depth; lvl++) {
        for (let i = 0; i < this.nodes.length; i++) {
          const n = this.nodes[i];
          if (n.level === lvl && n.op !== "cmul") {
            const started = this.inv.has(i);
            await this.computeNode(i, vals);
            if (!started) consume(i);                                // an inversion consumed its argument at its start
          }
        }
        let muls = 0;
        for (let i = 0; i < this.nodes.length; i++) {
          const n = this.nodes[i];
          if (n.level !== lvl + 1) continue;
          if (n.op === "cmul") {
            const a = vals.get(n.args[0])!, b = vals.get(n.args[1])!;
            if (isShared(a) && isShared(b)) {
              vals.set(i, this.emitMul(a, b));
              muls += 1;
            } else {                                                 // an operand turned out public (empty AVG)
              vals.set(i, this.publicMul(a, b));
            }
            consume(i);
          } else if (n.op === "inv" && n.enc && isShared(vals.get(n.args[0])!)) {
            this.invStart(i, vals.get(n.args[0])!);
            consume(i);
            muls += 1;
          }
        }
        if (muls) this.cost.multRounds += 1;
        if (lvl === depth) {
          const rootv = vals.get(root)!;
          sink = { z: [], m: [] };
          if (isShared(rootv)) this.emitReveal(rootv, sink);
          // the last request also drops everything the query still holds (after the reveal)
          this.tofree = [...new Set([...this.tofree, ...this.liveIds])];
        }
        await this.flush();
      }
      const rootv = vals.get(root)!;
      let outv: Vec;
      if (isShared(rootv)) {
        const zs = this.openWire(rootv, sink);
        outv = zs.map((z, j) => (rootv.live == null || rootv.live[j] ? z : null));
      } else {
        outv = rootv.pub!;
      }
      if (this.zero !== null) throw new TorusError("DivisionByZero", `division by zero: a denominator is 0${this.zero}`);
      this.cost.depth = depth;
      this.cost.mode = "shared";
      Object.assign(this.cost, this.ccost);
      if (this.info.kind === "row") {
        const rows = this.R ? this.bc(outv, this.R) : [];
        return rows.map((v) => (v === null ? null : this.ring.decode(v)));
      }
      const v = outv[0];
      return v === null ? null : this.ring.decode(v);
    } finally {
      await this.cleanup();
    }
  }
}

function rep<T>(xs: T[], n: number): T[] {
  const out: T[] = [];
  for (let i = 0; i < n; i++) out.push(...xs);
  return out;
}

/** Liveness of a binary result at width `w` (a position is live iff it is live in both operands). */
function andLive(a: boolean[] | null | undefined, b: boolean[] | null | undefined, w: number): boolean[] | null {
  if (a == null && b == null) return null;
  const x = a == null ? new Array<boolean>(w).fill(true) : a.length === w ? a : rep(a, w);
  const y = b == null ? new Array<boolean>(w).fill(true) : b.length === w ? b : rep(b, w);
  return x.map((v, j) => v && y[j]);
}
