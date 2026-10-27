// SPDX-License-Identifier: Apache-2.0
// Static analysis of v0.6.1 / v0.6.2 expressions over FHE columns (EC-FHE, BN254), ported line-for-line
// from `parser/torussql_parser/fhe_expr.py` (the single source of truth, shared there by the open
// validator, the planner and the evaluator) onto the TorusSQL v0.6 expression AST of `expr.ts`.
//
// FHE columns are EC-FHE ciphertexts. The keyless server can add ciphertexts (G1 side) and pair the
// G2 half of one ciphertext with the G1 half of another (GT side); a GT element cannot be paired
// again. So exactly ONE ciphertext x ciphertext product level exists, and nothing is ever decrypted
// or re-encrypted at the server or in between. What this module accepts is the set of shapes for
// which that is enough:
//
//     expression  ::=  public affine combination of TERMS
//     TERM        ::=  SUM(P)                 P a per-row product  L * R
//                   |  AL * AR                AL, AR aggregate linear forms (products of SUMs)
//                   |  SUM(L) / AVG(...)      a plain linear sum (needs at least one product elsewhere)
//     L, R        ::=  integer-linear forms   k1*col1 + k2*col2 + ... + c   over FHE columns
//     AL, AR      ::=  k1*SUM(col1) + ... + c    (SUM(L) is the aggregate of a linear form)
//     public      ::=  literals, + - between terms, * and / by a literal, unary minus, AVG's 1/n
//
// v0.6.2 additionally accepts the SAME product shapes UN-AGGREGATED, as a per-row projection
// (`SELECT L*R FROM t`, including the bare `SELECT a*b FROM t`) when the caller opts in
// (`analyzeFheExpr(tree, resolve, /* allowRow */ true)`): `FheExprPlan.level` is `"row"` (one value
// per row) instead of `"agg"`. `Client.exprPlan` (torusdb.ts) is the only caller and always opts in,
// exactly mirroring the single Python caller (`torussql_parser.expr.analyze_expr`, `allow_row=True`).
//
// Rejected, with a precise message (never evaluated): a product of a product (depth > 1), a division
// by anything that is not a literal, FHE mixed with PLAIN/ENC/PAIRED columns, a per-row (non-aggregated)
// FHE value with NO product anywhere, non-integer operand coefficients, operands wider than the bounds
// below. This file does NOT reinvent the matrix: `drivers/expr_vectors.json`'s FHE cases are the source
// of truth for the expected accept/reject verdicts, exercised by `test/expr_peer.test.ts` / `test/fheExpr.test.ts`.
//
// The result of analysis, `FheExprPlan`, is also what the evaluator (`torusdb.ts`'s `runFheExpr*`) runs,
// so the validator and the evaluator agree by construction - exactly the Python design.

import { TorusError } from "./errors";
import {
  Expr, Frac, frac, fAdd, fSub, fMul, fDiv, fNeg, fIsZero, checkConst, ExprColumn, ResolveColumn,
} from "./expr";

const planErr = (m: string) => new TorusError("PlanError", m);

/** `SUM(x * y)` over two bare FHE columns IS `DOT(x, y)` numerically, and (v0.6.2) is now accepted
 *  through the same `fhe_mul` path as every other product shape (`DOT` keeps working unchanged).
 *  Set to `true` to go back to rejecting it with the pre-v0.6.1 text (one line; also update
 *  `test/fheExpr.test.ts` and `drivers/expr_vectors.json`). */
export const REJECT_BARE_COLUMN_PRODUCT = false;
/** `|k|` of an operand coefficient / `|c|` of its constant (= the dlog bound). */
export const MAX_COEF = 1n << 40n;
/** Distinct columns in one operand. */
export const MAX_COLS = 16;
/** Product terms in one expression. */
export const MAX_PRODUCTS = 16;

function oldMessage(name: string): string {
  return `FHE column '${name}' cannot be used inside an arithmetic expression ` +
    `(FHE columns support SUM, AVG, k*SUM and DOT only)`;
}

function fail(msg: string): never {
  throw planErr(`FHE expression: ${msg}`);
}

const MIX = "per-row columns and aggregates cannot be mixed; wrap the columns in SUM(...)";
const DEPTH = "a product of products (or of a product and anything else) is not available: the server pairs " +
  "two ciphertexts once, a pairing result cannot be paired again, and no intermediate is ever " +
  "decrypted or re-encrypted. Use products of integer-linear forms: SUM(a*b), " +
  "SUM((a+2*b)*(c-d)), SUM(a)*SUM(b)";

// ── polynomials in n (the number of rows); exponents restricted to {-1, 0, 1} ────────────────────
export type Poly = Map<number, Frac>;

function pclean(p: Poly): Poly {
  const out: Poly = new Map();
  for (const [e, v] of p) if (!fIsZero(v)) out.set(e, v);
  return out;
}
function polyAdd(a: Poly, b: Poly, sg: bigint = 1n): Poly {
  const out = new Map(a);
  for (const [e, v] of b) {
    const cur = out.get(e) ?? frac(0n);
    out.set(e, sg === 1n ? fAdd(cur, v) : fSub(cur, v));
  }
  return pclean(out);
}
function polyScale(a: Poly, f: Frac): Poly {
  const out: Poly = new Map();
  for (const [e, v] of a) out.set(e, fMul(v, f));
  return pclean(out);
}
function polyShift(a: Poly, d: number): Poly {
  const out: Poly = new Map();
  for (const [e, v] of a) out.set(e + d, v);
  return out;
}
/** The value of a polynomial at `n` rows; `null` when it has an n^-1 term and n === 0. */
export function pevalPoly(a: Poly, n: number): Frac | null {
  let tot = frac(0n);
  for (const [e, v] of a) {
    if (e < 0 && n === 0) return null;
    const p = e === 0 ? frac(1n) : e === 1 ? frac(BigInt(n)) : frac(1n, BigInt(n) ** BigInt(-e));
    tot = fAdd(tot, fMul(v, p));
  }
  return tot;
}

// ── Lin: Σ coefs[col]·col + c over FHE columns ──────────────────────────────────────────────────
export type Level = "row" | "agg";
export interface Lin { readonly tag: "lin"; readonly level: Level; readonly coefs: Map<string, Frac>; readonly c: Poly }

function mkLin(level: Level, coefs: Map<string, Frac>, c: Poly): Lin {
  const co = new Map<string, Frac>();
  for (const [k, v] of coefs) if (!fIsZero(v)) co.set(k, v);
  return { tag: "lin", level, coefs: co, c };
}
function linAdd(x: Lin, y: Lin, sg: bigint): Lin {
  if (x.level !== y.level) fail(MIX);
  const co = new Map(x.coefs);
  for (const [k, v] of y.coefs) {
    const cur = co.get(k) ?? frac(0n);
    co.set(k, sg === 1n ? fAdd(cur, v) : fSub(cur, v));
  }
  return mkLin(x.level, co, polyAdd(x.c, y.c, sg));
}
function linScale(x: Lin, f: Frac): Lin {
  const co = new Map<string, Frac>();
  for (const [k, v] of x.coefs) co.set(k, fMul(v, f));
  return mkLin(x.level, co, polyScale(x.c, f));
}

// ── Term / Res: a public affine combination of terms ────────────────────────────────────────────
export type Term =
  | readonly ["lin", Lin]
  | readonly ["prod", Lin, Lin]
  | readonly ["sumprod", Lin, Lin]
  | readonly ["aggprod", Lin, Lin]
  | readonly ["sum", string];

export interface Res { readonly tag: "res"; readonly level: Level; readonly terms: Array<readonly [Poly, Term]>; readonly const: Poly }

function linToRes(x: Lin): Res {
  if (x.level === "row") return { tag: "res", level: "row", terms: [[new Map([[0, frac(1n)]]), ["lin", x]]], const: new Map() };
  const terms: Array<readonly [Poly, Term]> = [];
  for (const [k, v] of x.coefs) terms.push([new Map([[0, v]]), ["sum", k]]);
  return { tag: "res", level: "agg", terms, const: new Map(x.c) };
}
function resAdd(x: Res, y: Res, sg: bigint): Res {
  if (x.level !== y.level) fail(MIX);
  return { tag: "res", level: x.level,
    terms: [...x.terms, ...y.terms.map(([c, t]) => [polyScale(c, frac(sg)), t] as const)],
    const: polyAdd(x.const, y.const, sg) };
}
function resScale(x: Res, f: Frac): Res {
  return { tag: "res", level: x.level, terms: x.terms.map(([c, t]) => [polyScale(c, f), t] as const), const: polyScale(x.const, f) };
}

type FVal = Frac | Lin | Res;
const isFrac = (x: FVal): x is Frac => (x as Lin | Res).tag === undefined;
const isLin = (x: FVal): x is Lin => (x as Lin).tag === "lin";

function checkOperand(x: Lin, which: string): void {
  if (x.coefs.size === 0) {
    fail(`the ${which} operand of a product has no FHE column (a constant factor is a scalar: write k * ...)`);
  }
  if (x.coefs.size > MAX_COLS) fail(`an operand of a product combines at most ${MAX_COLS} columns`);
  for (const [k, v] of x.coefs) {
    if (v.den !== 1n) {
      fail(`the coefficient of '${k}' in the ${which} operand of a product is not an integer; ` +
        `a ciphertext cannot be divided: scale outside, e.g. (a+b)*c/2 instead of ((a+b)/2)*c`);
    }
    if ((v.num < 0n ? -v.num : v.num) > MAX_COEF) fail(`the coefficient of '${k}' exceeds 2^40 in absolute value`);
  }
  for (const [e, v] of x.c) {
    if (e < 0 || v.den !== 1n || (v.num < 0n ? -v.num : v.num) > MAX_COEF) {
      fail(`the constant of the ${which} operand of a product must be an integer of magnitude ` +
        `<= 2^40 (and not depend on AVG)`);
    }
  }
}

function mulVal(x0: FVal, y0: FVal): FVal {
  let x = x0, y = y0;
  if (isFrac(x) && isFrac(y)) return fMul(x, y);
  if (isFrac(x)) { [x, y] = [y, x]; }
  if (isFrac(y)) return isLin(x) ? linScale(x, y) : resScale(x as Res, y);
  if (isLin(x) && isLin(y)) {
    if (x.level !== y.level) fail(MIX);
    checkOperand(x, "left");
    checkOperand(y, "right");
    if (x.level === "row") return { tag: "res", level: "row", terms: [[new Map([[0, frac(1n)]]), ["prod", x, y]]], const: new Map() };
    return { tag: "res", level: "agg", terms: [[new Map([[0, frac(1n)]]), ["aggprod", x, y]]], const: new Map() };
  }
  const deep = [x, y].some((r) => !isFrac(r) && !isLin(r) &&
    (r as Res).terms.some(([, t]) => t[0] === "prod" || t[0] === "sumprod" || t[0] === "aggprod"));
  if (deep) fail(DEPTH);
  fail("a factor of a product must be an integer-linear form of FHE columns (or of their SUMs); " +
    "AVG(...) and sums of terms are not");
}

function addConst(x: Lin | Res, c: Frac): Lin | Res {
  if (isLin(x)) return mkLin(x.level, new Map(x.coefs), polyAdd(x.c, fIsZero(c) ? new Map() : new Map([[0, c]])));
  return { tag: "res", level: x.level, terms: x.terms, const: polyAdd(x.const, fIsZero(c) ? new Map() : new Map([[0, c]])) };
}
function negVal(x: FVal): FVal {
  if (isFrac(x)) return fNeg(x);
  return isLin(x) ? linScale(x, frac(-1n)) : resScale(x as Res, frac(-1n));
}
function addVal(x: FVal, y: FVal, sg: bigint): FVal {
  if (isFrac(x) && isFrac(y)) return sg === 1n ? fAdd(x, y) : fSub(x, y);
  if (isFrac(x)) return addConst(sg === 1n ? (y as Lin | Res) : (negVal(y) as Lin | Res), x);
  if (isFrac(y)) return addConst(x as Lin | Res, sg === 1n ? y : fNeg(y));
  if (isLin(x) && isLin(y)) return linAdd(x, y, sg);
  const xr = isLin(x) ? linToRes(x) : (x as Res);
  const yr = isLin(y) ? linToRes(y) : (y as Res);
  return resAdd(xr, yr, sg);
}

function sumVal(x: FVal): FVal {
  if (isFrac(x) || x.level !== "row") fail("SUM(...) needs an argument that contains an FHE column and no aggregate");
  if (isLin(x)) return mkLin("agg", new Map(x.coefs), polyShift(x.c, 1));
  const r = x as Res;
  const terms: Array<readonly [Poly, Term]> = [];
  let cst = polyShift(r.const, 1);
  for (const [c, t] of r.terms) {
    if (t[0] === "prod") {
      terms.push([c, ["sumprod", t[1], t[2]]]);
    } else {
      const lin = t[1] as Lin;
      for (const [col, k] of lin.coefs) terms.push([polyScale(c, k), ["sum", col]]);
      const k0 = lin.c.get(0) ?? frac(0n);
      cst = polyAdd(cst, polyShift(polyScale(c, k0), 1));
    }
  }
  return { tag: "res", level: "agg", terms, const: cst };
}
function avgVal(x: FVal): FVal {
  let s = sumVal(x);
  if (isLin(s)) s = linToRes(s);
  const r = s as Res;
  return { tag: "res", level: r.level, terms: r.terms.map(([c, t]) => [polyShift(c, -1), t] as const), const: polyShift(r.const, -1) };
}

/** A validated FHE expression: a public-affine combination with >= 1 product term, either aggregated
 *  (`level: "agg"`: `SUM(L*R)` / `AL*AR`) or, when the caller opts in (`allowRow`), per row
 *  (`level: "row"`: one value per row, `L*R` un-aggregated, as a projection - e.g. `SELECT a*b FROM t`,
 *  `SELECT (a+2*b)*(c-d) FROM t`). `tree` is the constant-folded AST (mirrors the Python analyzer's
 *  `(FheExpr, folded_tree)` pair; used for the expression's canonical text). */
export interface FheExprPlan {
  readonly terms: Array<readonly [Poly, Term]>;
  readonly const: Poly;
  readonly products: number;
  readonly level: Level;
  readonly tree: Expr;
}

/** Constant-fold `e` (`Lit op Lit` -> `Lit`, `Neg(Lit)` -> `Lit`), exactly `parser/torussql_parser/expr.py`'s
 *  `_fold`: a literal division by zero is rejected right here (even deep inside a non-literal tree), and
 *  every folded constant is bounds-checked (`checkConst`) exactly as the plain expression path does. */
function foldFhe(e: Expr): Expr {
  switch (e.t) {
    case "lit":
    case "col":
      return e;
    case "neg": {
      const o = foldFhe(e.e);
      if (o.t === "lit") {
        const v = fNeg(o.v);
        checkConst(v);
        return { t: "lit", v };
      }
      return { t: "neg", e: o };
    }
    case "agg":
      return e.arg ? { t: "agg", fn: e.fn, arg: foldFhe(e.arg) } : e;
    case "bin": {
      const l = foldFhe(e.l), r = foldFhe(e.r);
      if (e.op === "/" && r.t === "lit" && fIsZero(r.v)) throw planErr("division by zero");
      if (l.t === "lit" && r.t === "lit") {
        const v = e.op === "+" ? fAdd(l.v, r.v) : e.op === "-" ? fSub(l.v, r.v)
          : e.op === "*" ? fMul(l.v, r.v) : fDiv(l.v, r.v);
        checkConst(v);
        return { t: "lit", v };
      }
      return { t: "bin", op: e.op, l, r };
    }
  }
}

function collectColumns(e: Expr): string[] {
  const out: string[] = [];
  const walk = (n: Expr): void => {
    if (n.t === "col") { if (!out.includes(n.name)) out.push(n.name); }
    else if (n.t === "neg") walk(n.e);
    else if (n.t === "bin") { walk(n.l); walk(n.r); }
    else if (n.t === "agg" && n.arg) walk(n.arg);
  };
  walk(e);
  return out;
}

/** Does `tree` reference at least one FHE column? Used to dispatch between the plain-expression
 *  analyzer (`analyzeExpression`) and this one before either runs. */
export function referencesFheColumn(tree: Expr, resolve: ResolveColumn): boolean {
  return collectColumns(tree).some((n) => resolve(n).policy === "fhe");
}

/** Validate `rawTree` against the v0.6.1 / v0.6.2 FHE shapes. Throws `TorusError` kind "PlanError"
 *  exactly where the Python analyzer (`torussql_parser.fhe_expr.analyze`) does. `resolve` maps a
 *  (possibly qualified) column reference to its policy/name/type. `allowRow` (default `false`,
 *  matching every Python caller other than `analyze_expr`'s single `allow_row=True`) additionally
 *  accepts a per-row product of two integer-linear forms, un-aggregated (one ciphertext per row,
 *  opened by the owner into one value per row - never summed into one GT element); with it left
 *  `false`, a bare per-row product keeps being rejected exactly as before v0.6.2. */
export function analyzeFheExpr(rawTree: Expr, resolve: ResolveColumn, allowRow = false): FheExprPlan {
  const tree = foldFhe(rawTree);
  const seen: string[] = [];

  if (REJECT_BARE_COLUMN_PRODUCT && tree.t === "agg" && tree.fn === "SUM" && tree.arg &&
      tree.arg.t === "bin" && tree.arg.op === "*" && tree.arg.l.t === "col" && tree.arg.r.t === "col") {
    const c = resolve(tree.arg.l.name);
    if (c.policy === "fhe") throw planErr(oldMessage(c.name));
  }

  const ev = (e: Expr): FVal => {
    switch (e.t) {
      case "lit":
        return e.v;
      case "col": {
        const c = resolve(e.name);
        if (c.policy !== "fhe") throw planErr(oldMessage(seen[0] ?? c.name));
        return mkLin("row", new Map([[c.name, frac(1n)]]), new Map());
      }
      case "neg":
        return negVal(ev(e.e));
      case "agg": {
        if (e.fn === "COUNT") throw planErr(oldMessage(seen[0]));
        const a = ev(e.arg!);
        if (isFrac(a)) fail(`${e.fn}(...) needs an argument that contains an FHE column`);
        return e.fn === "SUM" ? sumVal(a) : avgVal(a);
      }
      case "bin": {
        const a = ev(e.l), b = ev(e.r);
        if (e.op === "+") return addVal(a, b, 1n);
        if (e.op === "-") return addVal(a, b, -1n);
        if (e.op === "*") return mulVal(a, b);
        // "/"
        if (!isFrac(b)) throw planErr(oldMessage(seen[0]));
        if (fIsZero(b)) throw planErr("division by zero");
        return mulVal(a, fDiv(frac(1n), b));
      }
    }
  };

  const cols = collectColumns(tree);
  for (const name of cols) { const c = resolve(name); if (c.policy === "fhe") seen.push(c.name); }
  if (seen.length === 0) throw new Error("analyzeFheExpr is for expressions with at least one FHE column reference");
  for (const name of cols) { const c = resolve(name); if (c.policy !== "fhe") throw planErr(oldMessage(seen[0])); }

  let v = ev(tree);
  if (isFrac(v)) throw planErr("expression contains no column or aggregate (a constant is not a result)");
  if (isLin(v)) {
    if (v.level === "row") throw planErr(oldMessage(seen[0]));
    v = linToRes(v);
  }
  const r = v as Res;
  if (r.level === "row") {
    const prods = r.terms.filter(([, t]) => t[0] === "prod");
    if (prods.length === 0) throw planErr(oldMessage(seen[0]));
    if (!allowRow) {
      fail("a per-row product of FHE columns is not supported here; aggregate it: SUM(a*b) " +
        "(a bare projection such as SELECT a*b FROM t is accepted — see fhe-columns.md)");
    }
    if (prods.length > MAX_PRODUCTS) fail(`at most ${MAX_PRODUCTS} products per expression`);
    return { terms: r.terms, const: r.const, products: prods.length, level: "row", tree };
  }
  const prods = r.terms.filter(([, t]) => t[0] === "sumprod" || t[0] === "aggprod");
  if (prods.length === 0) throw planErr(oldMessage(seen[0]));
  if (prods.length > MAX_PRODUCTS) fail(`at most ${MAX_PRODUCTS} products per expression`);
  return { terms: r.terms, const: r.const, products: prods.length, level: "agg", tree };
}

/** `([(column, int k)], int constant)` of a validated operand: the constant of an aggregate operand
 *  may depend on the number of rows (`c0 + c1*n`), evaluated here at the actual row count. */
export function operandAt(lin: Lin, n: number): { terms: Array<readonly [string, bigint]>; constant: bigint } {
  const c = pevalPoly(lin.c, n);
  if (c === null || c.den !== 1n || (c.num < 0n ? -c.num : c.num) > MAX_COEF) {
    throw planErr("an operand constant of an FHE product exceeds 2^40 for this many rows");
  }
  const terms: Array<readonly [string, bigint]> = [];
  for (const [col, k] of lin.coefs) terms.push([col, k.num]); // checked integer in checkOperand
  return { terms, constant: c.num };
}

export type { ExprColumn, ResolveColumn };
