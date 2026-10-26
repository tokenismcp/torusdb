// SPDX-License-Identifier: Apache-2.0
// TorusSQL dialect v0.6 arithmetic expressions: grammar, static analysis, canonical text.
//
// This file is a port of `parser/torussql_parser/expr.py` plus the expression part of
// `parser/torussql_parser/parser.py` (the reference). It accepts and rejects exactly the same
// expressions: same grammar and precedence, same exact constant folding, same policy rules, same
// depth/cost accounting. It is pure (no I/O); the owner-side evaluation is `exprEval.ts`.
//
//   expr    ::= term { ('+' | '-') term }
//   term    ::= unary { ('*' | '/') unary }
//   unary   ::= '-' unary | primary
//   primary ::= int | FRAC(int, int) | colref | '(' expr ')'
//             | SUM(expr) | AVG(expr) | COUNT(*)
//
// Errors: syntax -> TorusError kind "ParseError"; policy/type/scope violations -> kind "PlanError"
// (the engine's class for what the open validator calls ValidationError).

import { TorusError } from "./errors";

/** Tree height limit (the parser, validator and engine all recurse over the tree). */
export const MAX_EXPR_HEIGHT = 100;
/** |numerator| / denominator bound of a constant (2^126). */
export const MAX_SCALAR = 1n << 126n;
const MAX_INT_DIGITS = 4300;       // Python's default int<->str conversion limit (ParseError beyond)

const parseErr = (m: string) => new TorusError("ParseError", m);
const planErr = (m: string) => new TorusError("PlanError", m);

// ── exact rationals ──────────────────────────────────────────────────────────
/** An exact rational in lowest terms with `den >= 1` (`den === 1n` is an integer). */
export interface Frac { readonly num: bigint; readonly den: bigint }

function gcd(a: bigint, b: bigint): bigint {
  if (a < 0n) a = -a;
  if (b < 0n) b = -b;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}
export function frac(num: bigint, den: bigint = 1n): Frac {
  if (den === 0n) throw new TorusError("ValueError", "zero denominator");
  if (den < 0n) { num = -num; den = -den; }
  const g = gcd(num, den);
  return g > 1n ? { num: num / g, den: den / g } : { num, den };
}
export const fAdd = (a: Frac, b: Frac) => frac(a.num * b.den + b.num * a.den, a.den * b.den);
export const fSub = (a: Frac, b: Frac) => frac(a.num * b.den - b.num * a.den, a.den * b.den);
export const fMul = (a: Frac, b: Frac) => frac(a.num * b.num, a.den * b.den);
export const fDiv = (a: Frac, b: Frac) => frac(a.num * b.den, a.den * b.num);
export const fNeg = (a: Frac): Frac => ({ num: -a.num, den: a.den });
export const fIsZero = (a: Frac) => a.num === 0n;
/** Python `str(Fraction)` / `str(int)`. */
export const fStr = (a: Frac) => (a.den === 1n ? a.num.toString() : `${a.num}/${a.den}`);

// ── AST ──────────────────────────────────────────────────────────────────────
export type Expr =
  | { readonly t: "lit"; readonly v: Frac }
  | { readonly t: "col"; readonly name: string }
  | { readonly t: "neg"; readonly e: Expr }
  | { readonly t: "bin"; readonly op: "+" | "-" | "*" | "/"; readonly l: Expr; readonly r: Expr }
  | { readonly t: "agg"; readonly fn: "SUM" | "AVG" | "COUNT"; readonly arg: Expr | null };

const lit = (v: Frac): Expr => ({ t: "lit", v });
const col = (name: string): Expr => ({ t: "col", name });
const neg = (e: Expr): Expr => ({ t: "neg", e });
const bin = (op: "+" | "-" | "*" | "/", l: Expr, r: Expr): Expr => ({ t: "bin", op, l, r });
const agg = (fn: "SUM" | "AVG" | "COUNT", arg: Expr | null): Expr => ({ t: "agg", fn, arg });

// ── tokeniser (the Python regex, hand-written) ───────────────────────────────
interface Tok { kind: "num" | "str" | "id" | "sym"; text: string; num: bigint; pos: number }

// Python's `\s` for str patterns (note: not JavaScript's: no U+FEFF, but U+001C..U+001F and U+0085)
const WS = new Set([..." \t\n\v\f\r\u001c\u001d\u001e\u001f\u0085      　",
  ...Array.from({ length: 11 }, (_, k) => String.fromCharCode(0x2000 + k))]);
const isDigit = (c: string | undefined) => c !== undefined && c >= "0" && c <= "9";
const isIdStart = (c: string) => (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "_";
const isIdPart = (c: string) => isIdStart(c) || isDigit(c);
const SYM1 = new Set(["(", ")", ",", "*", "=", "<", ">", "?", ".", ";", "+", "-", "/"]);
const SYM2 = new Set(["==", "!=", "<>", "<=", ">="]);

function tokenise(sql: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (WS.has(c)) { i++; continue; }
    if (c === "-" && sql[i + 1] === "-") {                    // -- comment to end of line
      const j = sql.indexOf("\n", i);
      i = j < 0 ? sql.length : j;
      continue;
    }
    if (c === "/" && sql[i + 1] === "*") {                    // /* comment */ (unterminated: a plain '/')
      const j = sql.indexOf("*/", i + 2);
      if (j >= 0) { i = j + 2; continue; }
    }
    if (isDigit(c) || (c === "-" && isDigit(sql[i + 1]))) {   // -?[0-9]+  (a '-' glued to digits is one token)
      let j = i + (c === "-" ? 1 : 0);
      const start = j;
      while (isDigit(sql[j])) j++;
      if (j - start > MAX_INT_DIGITS) throw parseErr(`integer literal at ${i} is too long`);
      toks.push({ kind: "num", text: sql.slice(i, j), num: BigInt(sql.slice(i, j)), pos: i });
      i = j;
      continue;
    }
    if (c === "'") {
      // a string token can never be part of an expression: reject at once (any outcome is a ParseError)
      throw parseErr(`unexpected string literal at ${i} in an arithmetic expression`);
    }
    if (isIdStart(c)) {
      let j = i + 1;
      while (j < sql.length && isIdPart(sql[j])) j++;
      toks.push({ kind: "id", text: sql.slice(i, j), num: 0n, pos: i });
      i = j;
      continue;
    }
    const two = sql.slice(i, i + 2);
    if (SYM2.has(two)) { toks.push({ kind: "sym", text: two, num: 0n, pos: i }); i += 2; continue; }
    if (SYM1.has(c)) { toks.push({ kind: "sym", text: c, num: 0n, pos: i }); i++; continue; }
    throw parseErr(`unexpected char at ${i}: ${JSON.stringify(sql.slice(i, i + 10))}`);
  }
  return toks;
}

// ── parser ───────────────────────────────────────────────────────────────────
const CLAUSE_WORDS = new Set(["FROM", "AS", "WHERE", "GROUP", "HAVING", "LIMIT", "OFFSET",
  "JOIN", "ON", "AND", "OR", "SELECT"]);

const tooDeep = () => parseErr(`expression is nested too deeply (tree height limit ${MAX_EXPR_HEIGHT})`);

class Parser {
  i = 0;
  nest = 0;                       // open parentheses / unary minus signs (bounds recursion)
  constructor(readonly toks: Tok[]) {}

  describe(t: Tok | undefined): string { return t ? `${t.kind}:${t.kind === "num" ? t.num : t.text}@${t.pos}` : "end of input"; }
  peek(): Tok | undefined { return this.toks[this.i]; }
  isSym(v: string): boolean { const t = this.peek(); return t !== undefined && t.kind === "sym" && t.text === v; }
  isOp(...ops: string[]): boolean { const t = this.peek(); return t !== undefined && t.kind === "sym" && ops.includes(t.text); }
  eatSym(v: string): Tok {
    const t = this.peek();
    if (!t || t.kind !== "sym" || t.text !== v) throw parseErr(`expected '${v}' got ${this.describe(t)}`);
    this.i++;
    return t;
  }
  eatId(): Tok {
    const t = this.peek();
    if (!t || t.kind !== "id") throw parseErr(`expected an identifier got ${this.describe(t)}`);
    this.i++;
    return t;
  }
  /** In operator position the tokeniser's negative literal (`a-1` lexes as `a`, `-1`) is really a
   *  binary minus: split it into `-` and `1`. */
  splitNeg(): void {
    const t = this.toks[this.i];
    if (t !== undefined && t.kind === "num" && t.num < 0n) {
      this.toks.splice(this.i, 1,
        { kind: "sym", text: "-", num: 0n, pos: t.pos },
        { kind: "num", text: String(-t.num), num: -t.num, pos: t.pos });
    }
  }
  enter(): void { if (++this.nest > MAX_EXPR_HEIGHT) throw tooDeep(); }
}

type Node = [Expr, number];       // [tree, height]

function parseExpr(p: Parser): Node {
  let [left, h] = parseTerm(p);
  for (;;) {
    p.splitNeg();
    if (!p.isOp("+", "-")) return [left, h];
    const op = p.toks[p.i++].text as "+" | "-";
    const [right, h2] = parseTerm(p);
    h = Math.max(h, h2) + 1;
    if (h > MAX_EXPR_HEIGHT) throw tooDeep();
    left = bin(op, left, right);
  }
}

function parseTerm(p: Parser): Node {
  let [left, h] = parseUnary(p);
  while (p.isOp("*", "/")) {
    const op = p.toks[p.i++].text as "*" | "/";
    const [right, h2] = parseUnary(p);
    h = Math.max(h, h2) + 1;
    if (h > MAX_EXPR_HEIGHT) throw tooDeep();
    left = bin(op, left, right);
  }
  return [left, h];
}

function parseUnary(p: Parser): Node {
  if (p.isOp("-")) {
    p.i++;
    p.enter();
    const [operand, h] = parseUnary(p);
    p.nest--;
    if (operand.t === "lit") return [lit(fNeg(operand.v)), h];
    if (h + 1 > MAX_EXPR_HEIGHT) throw tooDeep();
    return [neg(operand), h + 1];
  }
  return parsePrimary(p);
}

function containsAgg(e: Expr): boolean {
  switch (e.t) {
    case "agg": return true;
    case "bin": return containsAgg(e.l) || containsAgg(e.r);
    case "neg": return containsAgg(e.e);
    default: return false;
  }
}

function parseColRef(p: Parser): string {
  const name = p.eatId().text;
  if (p.isSym(".")) {
    p.i++;
    return `${name}.${p.eatId().text}`;
  }
  return name;
}

function parsePrimary(p: Parser): Node {
  const t0 = p.peek();
  if (t0 && t0.kind === "num") { p.i++; return [lit(frac(t0.num)), 0]; }
  if (p.isOp("(")) {
    p.i++;
    p.enter();
    const [e, h] = parseExpr(p);
    p.eatSym(")");
    p.nest--;
    return [e, h];
  }
  if (!t0 || t0.kind !== "id") throw parseErr(`could not parse an expression at token ${p.describe(t0)}`);
  const nxt = p.toks[p.i + 1];
  const isCall = nxt !== undefined && nxt.kind === "sym" && nxt.text === "(";
  const kw = t0.text.toUpperCase();
  if (kw === "FRAC" && isCall) {
    p.i++; p.eatSym("(");
    const nt = p.peek();
    if (!nt || nt.kind !== "num") throw parseErr(`FRAC numerator must be integer, got ${p.describe(nt)}`);
    p.i++;
    p.eatSym(",");
    const dt = p.peek();
    if (!dt || dt.kind !== "num") throw parseErr(`FRAC denominator must be integer, got ${p.describe(dt)}`);
    p.i++;
    p.eatSym(")");
    if (dt.num === 0n) throw parseErr("FRAC denominator must be nonzero");
    return [lit(frac(nt.num, dt.num)), 0];
  }
  if (isCall) {
    if (kw === "COUNT") {
      p.i++; p.eatSym("("); p.eatSym("*"); p.eatSym(")");
      return [agg("COUNT", null), 0];
    }
    if (kw === "SUM" || kw === "AVG") {
      p.i++; p.eatSym("(");
      p.enter();
      const [arg, h] = parseExpr(p);
      p.nest--;
      p.eatSym(")");
      if (containsAgg(arg)) throw parseErr(`${kw}(...) cannot contain another aggregate`);
      if (h + 1 > MAX_EXPR_HEIGHT) throw tooDeep();
      return [agg(kw, arg), h + 1];
    }
    if (kw === "MIN" || kw === "MAX" || kw === "DOT") {
      throw parseErr(`${kw}(...) cannot be used inside an arithmetic expression ` +
        `(MIN, MAX and DOT are whole projections; this driver offers dot() / joinDot() for DOT)`);
    }
    throw parseErr(`unknown function ${JSON.stringify(t0.text)}`);
  }
  if (CLAUSE_WORDS.has(kw)) throw parseErr(`expected an expression, got keyword ${kw}`);
  return [col(parseColRef(p)), 0];
}

/** Parse ONE arithmetic expression (the text of a SELECT-list item, without `AS`). Throws
 *  `TorusError` kind "ParseError". Nothing may follow the expression. */
export function parseExpression(text: string): Expr {
  if (typeof text !== "string") throw new TorusError("InterfaceError", "the expression must be a string");
  const p = new Parser(tokenise(text));
  const t = p.peek();
  if (t && t.kind === "id" && p.toks[p.i + 1]?.kind === "sym" && p.toks[p.i + 1].text === "(") {
    const kw = t.text.toUpperCase();
    if (kw === "MIN" || kw === "MAX" || kw === "DOT") {
      throw parseErr(`${kw}(...) cannot be used inside an arithmetic expression ` +
        `(MIN, MAX and DOT are whole projections; this driver offers dot() / joinDot() for DOT)`);
    }
  }
  const [e] = parseExpr(p);
  const rest = p.peek();
  if (rest !== undefined) throw parseErr(`unexpected token after the expression: ${p.describe(rest)}`);
  return e;
}

// ── static analysis (`analyze_expr`) ─────────────────────────────────────────
/** What analysis needs to know about a column. */
export interface ExprColumn { readonly name: string; readonly type: string; readonly policy: string }

export interface ExprInfo {
  /** "row": one value per selected row; "agg": one value per query. */
  kind: "row" | "agg";
  /** depends on at least one ENC/PAIRED column */
  enc: boolean;
  /** ciphertext x ciphertext product levels = owner rounds */
  depth: number;
  /** ciphertext x ciphertext products per row (Beaver triples) */
  ctMuls: number;
  /** owner-assisted inversions (non-constant denominators) */
  inversions: number;
  /** canonical text of the constant-folded expression (the default output name) */
  text: string;
}

interface Sum { kind: "const" | "row" | "agg"; cols: ExprColumn[]; depth: number; muls: number; invs: number }
const CONST: Sum = { kind: "const", cols: [], depth: 0, muls: 0, invs: 0 };

function checkConst(v: Frac): void {
  const n = v.num < 0n ? -v.num : v.num;
  if (n > MAX_SCALAR || v.den > MAX_SCALAR) {
    throw planErr(`constant ${fStr(v)} is out of range (|numerator|, denominator <= 2^126): a larger ` +
      `constant could wrap around the modulus and return a wrong value`);
  }
}

const polName = (c: ExprColumn) => (c.policy === "encrypted" ? "ENC" : c.policy.toUpperCase());

function requirePaired(cols: ExprColumn[], why: string): void {
  for (const c of cols) {
    if (c.policy !== "paired") {
      throw planErr(`${why} requires PAIRED columns (column '${c.name}' is ${polName(c)}); ` +
        `an ENC column is additive-only`);
    }
  }
}

function mergeKind(a: Sum["kind"], b: Sum["kind"]): Sum["kind"] {
  if (a === "const") return b;
  if (b === "const" || a === b) return a;
  throw planErr("an expression cannot mix per-row columns and aggregates; wrap the columns " +
    "in SUM(...) / AVG(...) or select the aggregate on its own");
}

/** `resolve(name)` maps a (possibly qualified) column reference to its column, throwing the
 *  caller's own PlanError for an unknown or ambiguous one. */
export type ResolveColumn = (name: string) => ExprColumn;

function an(e: Expr, resolve: ResolveColumn): [Expr, Sum] {
  switch (e.t) {
    case "lit":
      checkConst(e.v);
      return [e, CONST];
    case "col": {
      const c = resolve(e.name);
      if (c.type === "str") throw planErr(`STR column '${c.name}' cannot be used in an arithmetic expression`);
      if (c.policy === "fhe") {
        throw planErr(`FHE column '${c.name}' cannot be used inside an arithmetic expression ` +
          `(FHE columns support SUM, AVG, k*SUM and DOT only)`);
      }
      return [e, { kind: "row", cols: c.policy === "plain" ? [] : [c], depth: 0, muls: 0, invs: 0 }];
    }
    case "neg": {
      const [o, s] = an(e.e, resolve);
      if (o.t === "lit") {
        const v = fNeg(o.v);
        checkConst(v);
        return [lit(v), CONST];
      }
      return [neg(o), s];
    }
    case "agg": {
      if (e.fn === "COUNT") return [e, { kind: "agg", cols: [], depth: 0, muls: 0, invs: 0 }];
      const [arg, s] = an(e.arg!, resolve);
      if (s.kind !== "row") {
        throw planErr(`${e.fn}(...) needs an argument that contains a column ` +
          `(not a constant or another aggregate)`);
      }
      if (e.fn === "SUM" && s.cols.length === 0) {
        throw planErr("SUM requires an encrypted expression (an ENC/PAIRED column); " +
          "the argument depends only on PLAIN columns");
      }
      return [agg(e.fn, arg), { kind: "agg", cols: s.cols, depth: s.depth, muls: s.muls, invs: s.invs }];
    }
    case "bin": {
      const [l, ls] = an(e.l, resolve);
      const [r, rs] = an(e.r, resolve);
      const kind = mergeKind(ls.kind, rs.kind);
      const encL = ls.cols.length > 0, encR = rs.cols.length > 0;
      const cols = [...ls.cols, ...rs.cols];
      let depth = Math.max(ls.depth, rs.depth);
      let muls = ls.muls + rs.muls;
      let invs = ls.invs + rs.invs;
      if (e.op === "*") {
        if (encL && encR) {
          requirePaired(cols, "a ciphertext x ciphertext product");
          depth += 1;
          muls += 1;
        }
      } else if (e.op === "/") {
        if (r.t === "lit") {
          if (fIsZero(r.v)) throw planErr("division by zero");
        } else {
          invs += 1;
          if (encR) {
            requirePaired([...rs.cols, ...(encL ? ls.cols : [])], "division by an encrypted denominator");
            if (encL) {
              depth = Math.max(ls.depth, rs.depth) + 1;
              muls += 1;
            } else {
              depth = rs.depth;
            }
          }
        }
      }
      if (l.t === "lit" && r.t === "lit") {                       // exact constant folding
        const v = e.op === "+" ? fAdd(l.v, r.v) : e.op === "-" ? fSub(l.v, r.v)
          : e.op === "*" ? fMul(l.v, r.v) : fDiv(l.v, r.v);
        checkConst(v);
        return [lit(v), CONST];
      }
      return [bin(e.op, l, r), { kind, cols, depth, muls, invs }];
    }
  }
}

const PREC: Record<string, number> = { "+": 1, "-": 1, "*": 2, "/": 2 };

/** Canonical, minimally parenthesised text of an expression (the default output name). */
export function renderExpr(e: Expr, parent = 0, right = false): string {
  switch (e.t) {
    case "lit": {
      const s = e.v.den === 1n ? e.v.num.toString() : `FRAC(${e.v.num},${e.v.den})`;
      return e.v.den === 1n && e.v.num < 0n && parent ? `(${s})` : s;
    }
    case "col": return e.name;
    case "neg": {
      const inner = `-${renderExpr(e.e, 3)}`;
      return parent ? `(${inner})` : inner;                       // never emit `--` (a comment)
    }
    case "agg": return e.fn === "COUNT" ? "count(*)" : `${e.fn.toLowerCase()}(${renderExpr(e.arg!)})`;
    case "bin": {
      const p = PREC[e.op];
      const s = `${renderExpr(e.l, p)}${e.op}${renderExpr(e.r, p, true)}`;
      return p < parent || (p === parent && right) ? `(${s})` : s;
    }
  }
}

/** Check `expr` against the column policies `resolve` reports and return the constant-folded tree
 *  plus its kind, depth and cost. Throws `TorusError` kind "PlanError" for every rule violation
 *  (exactly the rules of the Python open validator and engine; spec v0.6 section 5.3). */
export function analyzeExpression(expr: Expr, resolve: ResolveColumn): { expr: Expr; info: ExprInfo } {
  const [node, s] = an(expr, resolve);
  if (s.kind === "const") {
    throw planErr("expression contains no column or aggregate (a constant is not a result)");
  }
  if (s.kind === "row" && s.cols.length === 0) {
    throw planErr("a per-row expression needs at least one ENC/PAIRED column; an expression " +
      "over PLAIN columns only is not supported (select the columns and compute " +
      "it client-side)");
  }
  return {
    expr: node,
    info: { kind: s.kind, enc: s.cols.length > 0, depth: s.depth, ctMuls: s.muls, inversions: s.invs,
            text: renderExpr(node) },
  };
}

/** Table instances visible to an expression (alias or table name -> its columns), resolving column
 *  references like the engine's planner: `inst.col` or a bare, unambiguous `col`. */
export function scopeResolver(instances: Array<[string, ReadonlyArray<ExprColumn>]>): (ref: string) => { inst: string; col: ExprColumn } {
  const specs = new Map<string, ReadonlyArray<ExprColumn>>();
  for (const [name, cols] of instances) {
    if (specs.has(name)) {
      throw planErr(`duplicate table name '${name}' in FROM/JOIN — give each occurrence a distinct alias`);
    }
    specs.set(name, cols);
  }
  return (ref: string) => {
    const dot = ref.indexOf(".");
    if (dot >= 0) {
      const inst = ref.slice(0, dot), cname = ref.slice(dot + 1);
      const cols = specs.get(inst);
      if (!cols) throw planErr(`unknown table '${inst}' in column ref '${ref}'`);
      const c = cols.find((x) => x.name === cname);
      if (!c) throw planErr(`no such column: '${cname}' in table '${inst}'`);
      return { inst, col: c };
    }
    const owners = [...specs].filter(([, cols]) => cols.some((x) => x.name === ref));
    if (owners.length === 1) return { inst: owners[0][0], col: owners[0][1].find((x) => x.name === ref)! };
    if (owners.length > 1) throw planErr(`column '${ref}' is ambiguous in join — qualify as table.col`);
    throw planErr(`no such column: '${ref}'`);
  };
}
