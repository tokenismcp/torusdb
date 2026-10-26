// SPDX-License-Identifier: Apache-2.0
//! TorusSQL dialect v0.6 arithmetic expressions: grammar, static analysis, canonical text.
//!
//! A port of `parser/torussql_parser/expr.py` plus the expression part of
//! `parser/torussql_parser/parser.py` (the reference): the same grammar and precedence, the same exact
//! constant folding, the same policy rules, the same depth and cost accounting - it accepts and rejects
//! exactly the same expressions. Pure (no I/O); the owner-side evaluation is `expr_eval.rs`.
//!
//! ```text
//! expr    ::= term { ('+' | '-') term }
//! term    ::= unary { ('*' | '/') unary }
//! unary   ::= '-' unary | primary
//! primary ::= int | FRAC(int, int) | colref | '(' expr ')'
//!           | SUM(expr) | AVG(expr) | COUNT(*)
//! ```
//!
//! Errors: syntax -> `Kind::Parse`; policy/type/scope violations -> `Kind::PlanError` (the engine's class for
//! what the open validator calls `ValidationError`).

use crate::error::{Error, Kind};
use crate::Column;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

type Result<T> = std::result::Result<T, Error>;

/// Tree height limit (the parser, validator and engine all recurse over the tree).
pub const MAX_EXPR_HEIGHT: usize = 100;
const MAX_INT_DIGITS: usize = 4300; // Python's default int<->str conversion limit (ParseError beyond)

fn parse_err(m: impl Into<String>) -> Error {
    Error::new(Kind::Parse, m)
}
fn plan_err(m: impl Into<String>) -> Error {
    Error::new(Kind::PlanError, m)
}

fn max_scalar() -> BigInt {
    BigInt::one() << 126
}

// ── exact rationals ──────────────────────────────────────────────────────────
/// An exact rational in lowest terms with `den >= 1` (`den == 1` is an integer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frac {
    pub num: BigInt,
    pub den: BigInt,
}

impl Frac {
    pub fn new(num: BigInt, den: BigInt) -> Frac {
        assert!(!den.is_zero(), "zero denominator");
        let (mut n, mut d) = if den.is_negative() { (-num, -den) } else { (num, den) };
        let g = n.gcd(&d);
        if g > BigInt::one() {
            n /= &g;
            d /= &g;
        }
        Frac { num: n, den: d }
    }
    pub fn int(v: i64) -> Frac {
        Frac { num: BigInt::from(v), den: BigInt::one() }
    }
    pub fn add(&self, o: &Frac) -> Frac {
        Frac::new(&self.num * &o.den + &o.num * &self.den, &self.den * &o.den)
    }
    pub fn sub(&self, o: &Frac) -> Frac {
        Frac::new(&self.num * &o.den - &o.num * &self.den, &self.den * &o.den)
    }
    pub fn mul(&self, o: &Frac) -> Frac {
        Frac::new(&self.num * &o.num, &self.den * &o.den)
    }
    /// `o` must be non-zero.
    pub fn div(&self, o: &Frac) -> Frac {
        Frac::new(&self.num * &o.den, &self.den * &o.num)
    }
    pub fn neg(&self) -> Frac {
        Frac { num: -&self.num, den: self.den.clone() }
    }
    pub fn is_zero(&self) -> bool {
        self.num.is_zero()
    }
    pub fn is_int(&self) -> bool {
        self.den.is_one()
    }
}

impl std::fmt::Display for Frac {
    /// Python `str(Fraction)` / `str(int)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.den.is_one() {
            write!(f, "{}", self.num)
        } else {
            write!(f, "{}/{}", self.num, self.den)
        }
    }
}

// ── AST ──────────────────────────────────────────────────────────────────────
/// An arithmetic expression tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Lit(Frac),
    /// a (possibly `inst.`-qualified) column reference
    Col(String),
    Neg(Box<Expr>),
    Bin(char, Box<Expr>, Box<Expr>),
    /// `SUM(expr)`, `AVG(expr)` (fn = "SUM" / "AVG") or `COUNT(*)` (fn = "COUNT", no argument)
    Agg(&'static str, Option<Box<Expr>>),
}

fn bin(op: char, l: Expr, r: Expr) -> Expr {
    Expr::Bin(op, Box::new(l), Box::new(r))
}

// ── tokeniser (the Python regex, hand-written) ───────────────────────────────
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TK {
    Num,
    Id,
    Sym,
}
#[derive(Clone, Debug)]
struct Tok {
    kind: TK,
    text: String,
    num: BigInt,
    pos: usize,
}

/// Python's `\s` for str patterns (not Rust's `char::is_whitespace`: U+001C..U+001F are spaces here).
fn is_py_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1c}'..='\u{1f}' | '\u{85}' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}
fn is_id_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn tokenise(sql: &str) -> Result<Vec<Tok>> {
    let cs: Vec<char> = sql.chars().collect();
    let mut toks = vec![];
    let mut i = 0;
    let at = |k: usize| cs.get(k).copied();
    while i < cs.len() {
        let c = cs[i];
        if is_py_space(c) {
            i += 1;
            continue;
        }
        if c == '-' && at(i + 1) == Some('-') {
            // -- comment to end of line
            while i < cs.len() && cs[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && at(i + 1) == Some('*') {
            // /* comment */ (unterminated: a plain '/')
            let mut j = i + 2;
            let mut found = None;
            while j + 1 < cs.len() {
                if cs[j] == '*' && cs[j + 1] == '/' {
                    found = Some(j + 2);
                    break;
                }
                j += 1;
            }
            if let Some(e) = found {
                i = e;
                continue;
            }
        }
        if c.is_ascii_digit() || (c == '-' && at(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let mut j = i + if c == '-' { 1 } else { 0 };
            let start = j;
            while j < cs.len() && cs[j].is_ascii_digit() {
                j += 1;
            }
            if j - start > MAX_INT_DIGITS {
                return Err(parse_err(format!("integer literal at {} is too long", i)));
            }
            let text: String = cs[i..j].iter().collect();
            let num: BigInt = text.parse().unwrap();
            toks.push(Tok { kind: TK::Num, text, num, pos: i });
            i = j;
            continue;
        }
        if c == '\'' {
            // a string token can never be part of an expression: reject at once (any outcome is a ParseError)
            return Err(parse_err(format!("unexpected string literal at {} in an arithmetic expression", i)));
        }
        if is_id_start(c) {
            let mut j = i + 1;
            while j < cs.len() && (is_id_start(cs[j]) || cs[j].is_ascii_digit()) {
                j += 1;
            }
            toks.push(Tok { kind: TK::Id, text: cs[i..j].iter().collect(), num: BigInt::zero(), pos: i });
            i = j;
            continue;
        }
        if let Some(n) = at(i + 1) {
            let two: String = [c, n].iter().collect();
            if matches!(two.as_str(), "==" | "!=" | "<>" | "<=" | ">=") {
                toks.push(Tok { kind: TK::Sym, text: two, num: BigInt::zero(), pos: i });
                i += 2;
                continue;
            }
        }
        if "(),*=<>?.;+-/".contains(c) {
            toks.push(Tok { kind: TK::Sym, text: c.to_string(), num: BigInt::zero(), pos: i });
            i += 1;
            continue;
        }
        let rest: String = cs[i..(i + 10).min(cs.len())].iter().collect();
        return Err(parse_err(format!("unexpected char at {}: {:?}", i, rest)));
    }
    Ok(toks)
}

// ── parser ───────────────────────────────────────────────────────────────────
const CLAUSE_WORDS: [&str; 12] =
    ["FROM", "AS", "WHERE", "GROUP", "HAVING", "LIMIT", "OFFSET", "JOIN", "ON", "AND", "OR", "SELECT"];

fn too_deep() -> Error {
    parse_err(format!("expression is nested too deeply (tree height limit {})", MAX_EXPR_HEIGHT))
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
    nest: usize, // open parentheses / unary minus signs (bounds recursion)
}

impl Parser {
    fn describe(&self, t: Option<&Tok>) -> String {
        match t {
            Some(t) => format!("{:?}:{}@{}", t.kind, if t.kind == TK::Num { t.num.to_string() } else { t.text.clone() }, t.pos),
            None => "end of input".into(),
        }
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }
    fn is_sym(&self, v: &str) -> bool {
        self.peek().is_some_and(|t| t.kind == TK::Sym && t.text == v)
    }
    fn is_op(&self, ops: &[&str]) -> bool {
        self.peek().is_some_and(|t| t.kind == TK::Sym && ops.contains(&t.text.as_str()))
    }
    fn eat_sym(&mut self, v: &str) -> Result<()> {
        if self.is_sym(v) {
            self.i += 1;
            Ok(())
        } else {
            Err(parse_err(format!("expected '{}' got {}", v, self.describe(self.peek()))))
        }
    }
    fn eat_id(&mut self) -> Result<String> {
        match self.peek() {
            Some(t) if t.kind == TK::Id => {
                let s = t.text.clone();
                self.i += 1;
                Ok(s)
            }
            other => Err(parse_err(format!("expected an identifier got {}", self.describe(other)))),
        }
    }
    /// In operator position the tokeniser's negative literal (`a-1` lexes as `a`, `-1`) is really a
    /// binary minus: split it into `-` and `1`.
    fn split_neg(&mut self) {
        if let Some(t) = self.toks.get(self.i) {
            if t.kind == TK::Num && t.num.is_negative() {
                let pos = t.pos;
                let pos_num = -t.num.clone();
                self.toks.splice(
                    self.i..self.i + 1,
                    [
                        Tok { kind: TK::Sym, text: "-".into(), num: BigInt::zero(), pos },
                        Tok { kind: TK::Num, text: pos_num.to_string(), num: pos_num, pos },
                    ],
                );
            }
        }
    }
    fn enter(&mut self) -> Result<()> {
        self.nest += 1;
        if self.nest > MAX_EXPR_HEIGHT {
            return Err(too_deep());
        }
        Ok(())
    }
}

type Node = (Expr, usize); // (tree, height)

fn parse_expr(p: &mut Parser) -> Result<Node> {
    let (mut left, mut h) = parse_term(p)?;
    loop {
        p.split_neg();
        if !p.is_op(&["+", "-"]) {
            return Ok((left, h));
        }
        let op = p.toks[p.i].text.chars().next().unwrap();
        p.i += 1;
        let (right, h2) = parse_term(p)?;
        h = h.max(h2) + 1;
        if h > MAX_EXPR_HEIGHT {
            return Err(too_deep());
        }
        left = bin(op, left, right);
    }
}

fn parse_term(p: &mut Parser) -> Result<Node> {
    let (mut left, mut h) = parse_unary(p)?;
    while p.is_op(&["*", "/"]) {
        let op = p.toks[p.i].text.chars().next().unwrap();
        p.i += 1;
        let (right, h2) = parse_unary(p)?;
        h = h.max(h2) + 1;
        if h > MAX_EXPR_HEIGHT {
            return Err(too_deep());
        }
        left = bin(op, left, right);
    }
    Ok((left, h))
}

fn parse_unary(p: &mut Parser) -> Result<Node> {
    if p.is_op(&["-"]) {
        p.i += 1;
        p.enter()?;
        let (operand, h) = parse_unary(p)?;
        p.nest -= 1;
        if let Expr::Lit(v) = &operand {
            return Ok((Expr::Lit(v.neg()), h));
        }
        if h + 1 > MAX_EXPR_HEIGHT {
            return Err(too_deep());
        }
        return Ok((Expr::Neg(Box::new(operand)), h + 1));
    }
    parse_primary(p)
}

fn contains_agg(e: &Expr) -> bool {
    match e {
        Expr::Agg(..) => true,
        Expr::Bin(_, l, r) => contains_agg(l) || contains_agg(r),
        Expr::Neg(o) => contains_agg(o),
        _ => false,
    }
}

fn parse_col_ref(p: &mut Parser) -> Result<String> {
    let name = p.eat_id()?;
    if p.is_sym(".") {
        p.i += 1;
        return Ok(format!("{}.{}", name, p.eat_id()?));
    }
    Ok(name)
}

fn whole_projection(kw: &str) -> Error {
    parse_err(format!(
        "{}(...) cannot be used inside an arithmetic expression (MIN, MAX and DOT are whole projections; \
         this driver offers dot() / join_dot() for DOT)",
        kw
    ))
}

fn parse_primary(p: &mut Parser) -> Result<Node> {
    if let Some(t) = p.peek() {
        if t.kind == TK::Num {
            let v = Frac::new(t.num.clone(), BigInt::one());
            p.i += 1;
            return Ok((Expr::Lit(v), 0));
        }
    }
    if p.is_op(&["("]) {
        p.i += 1;
        p.enter()?;
        let (e, h) = parse_expr(p)?;
        p.eat_sym(")")?;
        p.nest -= 1;
        return Ok((e, h));
    }
    let t0 = match p.peek() {
        Some(t) if t.kind == TK::Id => t.clone(),
        other => return Err(parse_err(format!("could not parse an expression at token {}", p.describe(other)))),
    };
    let is_call = p.toks.get(p.i + 1).is_some_and(|n| n.kind == TK::Sym && n.text == "(");
    let kw = t0.text.to_ascii_uppercase();
    if kw == "FRAC" && is_call {
        p.i += 1;
        p.eat_sym("(")?;
        let nt = match p.peek() {
            Some(t) if t.kind == TK::Num => t.num.clone(),
            other => return Err(parse_err(format!("FRAC numerator must be integer, got {}", p.describe(other)))),
        };
        p.i += 1;
        p.eat_sym(",")?;
        let dt = match p.peek() {
            Some(t) if t.kind == TK::Num => t.num.clone(),
            other => return Err(parse_err(format!("FRAC denominator must be integer, got {}", p.describe(other)))),
        };
        p.i += 1;
        p.eat_sym(")")?;
        if dt.is_zero() {
            return Err(parse_err("FRAC denominator must be nonzero"));
        }
        return Ok((Expr::Lit(Frac::new(nt, dt)), 0));
    }
    if is_call {
        match kw.as_str() {
            "COUNT" => {
                p.i += 1;
                p.eat_sym("(")?;
                p.eat_sym("*")?;
                p.eat_sym(")")?;
                return Ok((Expr::Agg("COUNT", None), 0));
            }
            "SUM" | "AVG" => {
                let f: &'static str = if kw == "SUM" { "SUM" } else { "AVG" };
                p.i += 1;
                p.eat_sym("(")?;
                p.enter()?;
                let (arg, h) = parse_expr(p)?;
                p.nest -= 1;
                p.eat_sym(")")?;
                if contains_agg(&arg) {
                    return Err(parse_err(format!("{}(...) cannot contain another aggregate", kw)));
                }
                if h + 1 > MAX_EXPR_HEIGHT {
                    return Err(too_deep());
                }
                return Ok((Expr::Agg(f, Some(Box::new(arg))), h + 1));
            }
            "MIN" | "MAX" | "DOT" => return Err(whole_projection(&kw)),
            _ => return Err(parse_err(format!("unknown function {:?}", t0.text))),
        }
    }
    if CLAUSE_WORDS.contains(&kw.as_str()) {
        return Err(parse_err(format!("expected an expression, got keyword {}", kw)));
    }
    Ok((Expr::Col(parse_col_ref(p)?), 0))
}

/// Parse ONE arithmetic expression (the text of a SELECT-list item, without `AS`). Errors have
/// `Kind::Parse`. Nothing may follow the expression.
pub fn parse_expression(text: &str) -> Result<Expr> {
    let mut p = Parser { toks: tokenise(text)?, i: 0, nest: 0 };
    if let Some(t) = p.peek() {
        if t.kind == TK::Id && p.toks.get(1).is_some_and(|n| n.kind == TK::Sym && n.text == "(") {
            let kw = t.text.to_ascii_uppercase();
            if matches!(kw.as_str(), "MIN" | "MAX" | "DOT") {
                return Err(whole_projection(&kw));
            }
        }
    }
    let (e, _) = parse_expr(&mut p)?;
    if let Some(t) = p.peek() {
        return Err(parse_err(format!("unexpected token after the expression: {}", p.describe(Some(t)))));
    }
    Ok(e)
}

// ── static analysis (`analyze_expr`) ─────────────────────────────────────────
/// What analysis found out about an expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprInfo {
    /// "row" (one value per selected row) or "agg" (one value per query)
    pub kind: &'static str,
    /// depends on at least one ENC/PAIRED column
    pub enc: bool,
    /// ciphertext x ciphertext product levels = owner rounds
    pub depth: usize,
    /// ciphertext x ciphertext products per row (Beaver triples)
    pub ct_muls: usize,
    /// owner-assisted inversions (non-constant denominators)
    pub inversions: usize,
    /// canonical text of the constant-folded expression (the default output name)
    pub text: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Const,
    Row,
    Agg,
}
struct Sum {
    kind: K,
    cols: Vec<Column>,
    depth: usize,
    muls: usize,
    invs: usize,
}
fn konst() -> Sum {
    Sum { kind: K::Const, cols: vec![], depth: 0, muls: 0, invs: 0 }
}

fn check_const(v: &Frac) -> Result<()> {
    let m = max_scalar();
    if v.num.abs() > m || v.den > m {
        return Err(plan_err(format!(
            "constant {} is out of range (|numerator|, denominator <= 2^126): a larger \
             constant could wrap around the modulus and return a wrong value",
            v
        )));
    }
    Ok(())
}

fn pol_name(c: &Column) -> String {
    if c.policy == "encrypted" {
        "ENC".into()
    } else {
        c.policy.to_uppercase()
    }
}

fn require_paired(cols: &[Column], why: &str) -> Result<()> {
    for c in cols {
        if c.policy != "paired" {
            return Err(plan_err(format!(
                "{} requires PAIRED columns (column '{}' is {}); an ENC column is additive-only",
                why,
                c.name,
                pol_name(c)
            )));
        }
    }
    Ok(())
}

fn merge_kind(a: K, b: K) -> Result<K> {
    if a == K::Const {
        return Ok(b);
    }
    if b == K::Const || a == b {
        return Ok(a);
    }
    Err(plan_err(
        "an expression cannot mix per-row columns and aggregates; wrap the columns \
         in SUM(...) / AVG(...) or select the aggregate on its own",
    ))
}

type Resolve<'a> = &'a dyn Fn(&str) -> Result<Column>;

fn an(e: &Expr, resolve: Resolve) -> Result<(Expr, Sum)> {
    match e {
        Expr::Lit(v) => {
            check_const(v)?;
            Ok((e.clone(), konst()))
        }
        Expr::Col(name) => {
            let c = resolve(name)?;
            if c.ty == "str" {
                return Err(plan_err(format!("STR column '{}' cannot be used in an arithmetic expression", c.name)));
            }
            if c.policy == "fhe" {
                return Err(plan_err(format!(
                    "FHE column '{}' cannot be used inside an arithmetic expression \
                     (FHE columns support SUM, AVG, k*SUM and DOT only)",
                    c.name
                )));
            }
            let cols = if c.policy == "plain" { vec![] } else { vec![c] };
            Ok((e.clone(), Sum { kind: K::Row, cols, depth: 0, muls: 0, invs: 0 }))
        }
        Expr::Neg(inner) => {
            let (o, s) = an(inner, resolve)?;
            if let Expr::Lit(v) = &o {
                let nv = v.neg();
                check_const(&nv)?;
                return Ok((Expr::Lit(nv), konst()));
            }
            Ok((Expr::Neg(Box::new(o)), s))
        }
        Expr::Agg(f, arg) => {
            if *f == "COUNT" {
                return Ok((e.clone(), Sum { kind: K::Agg, cols: vec![], depth: 0, muls: 0, invs: 0 }));
            }
            let (a, s) = an(arg.as_ref().unwrap(), resolve)?;
            if s.kind != K::Row {
                return Err(plan_err(format!(
                    "{}(...) needs an argument that contains a column (not a constant or another aggregate)",
                    f
                )));
            }
            if *f == "SUM" && s.cols.is_empty() {
                return Err(plan_err(
                    "SUM requires an encrypted expression (an ENC/PAIRED column); \
                     the argument depends only on PLAIN columns",
                ));
            }
            Ok((Expr::Agg(f, Some(Box::new(a))), Sum { kind: K::Agg, cols: s.cols, depth: s.depth, muls: s.muls, invs: s.invs }))
        }
        Expr::Bin(op, le, re) => {
            let (l, ls) = an(le, resolve)?;
            let (r, rs) = an(re, resolve)?;
            let kind = merge_kind(ls.kind, rs.kind)?;
            let (enc_l, enc_r) = (!ls.cols.is_empty(), !rs.cols.is_empty());
            let mut cols = ls.cols.clone();
            cols.extend(rs.cols.iter().cloned());
            let mut depth = ls.depth.max(rs.depth);
            let mut muls = ls.muls + rs.muls;
            let mut invs = ls.invs + rs.invs;
            if *op == '*' {
                if enc_l && enc_r {
                    require_paired(&cols, "a ciphertext x ciphertext product")?;
                    depth += 1;
                    muls += 1;
                }
            } else if *op == '/' {
                if let Expr::Lit(v) = &r {
                    if v.is_zero() {
                        return Err(plan_err("division by zero"));
                    }
                } else {
                    invs += 1;
                    if enc_r {
                        let mut need = rs.cols.clone();
                        if enc_l {
                            need.extend(ls.cols.iter().cloned());
                        }
                        require_paired(&need, "division by an encrypted denominator")?;
                        if enc_l {
                            depth = ls.depth.max(rs.depth) + 1;
                            muls += 1;
                        } else {
                            depth = rs.depth;
                        }
                    }
                }
            }
            if let (Expr::Lit(a), Expr::Lit(b)) = (&l, &r) {
                // exact constant folding
                let v = match op {
                    '+' => a.add(b),
                    '-' => a.sub(b),
                    '*' => a.mul(b),
                    _ => a.div(b),
                };
                check_const(&v)?;
                return Ok((Expr::Lit(v), konst()));
            }
            Ok((bin(*op, l, r), Sum { kind, cols, depth, muls, invs }))
        }
    }
}

fn prec(op: char) -> u8 {
    if op == '+' || op == '-' {
        1
    } else {
        2
    }
}

/// Canonical, minimally parenthesised text of an expression (the default output name).
pub fn render_expr(e: &Expr) -> String {
    render(e, 0, false)
}

fn render(e: &Expr, parent: u8, right: bool) -> String {
    match e {
        Expr::Lit(v) => {
            let s = if v.is_int() { v.num.to_string() } else { format!("FRAC({},{})", v.num, v.den) };
            if v.is_int() && v.num.is_negative() && parent > 0 {
                format!("({})", s)
            } else {
                s
            }
        }
        Expr::Col(n) => n.clone(),
        Expr::Neg(o) => {
            let inner = format!("-{}", render(o, 3, false));
            if parent > 0 {
                format!("({})", inner) // never emit `--` (a comment)
            } else {
                inner
            }
        }
        Expr::Agg(f, a) => match a {
            None => "count(*)".into(),
            Some(a) => format!("{}({})", f.to_lowercase(), render(a, 0, false)),
        },
        Expr::Bin(op, l, r) => {
            let p = prec(*op);
            let s = format!("{}{}{}", render(l, p, false), op, render(r, p, true));
            if p < parent || (p == parent && right) {
                format!("({})", s)
            } else {
                s
            }
        }
    }
}

/// Check `expr` against the column policies `resolve` reports and return the constant-folded tree plus
/// its kind, depth and cost. Errors have `Kind::PlanError` for every rule violation (exactly the rules of
/// the Python open validator and engine; spec v0.6 section 5.3).
pub fn analyze_expression(expr: &Expr, resolve: Resolve) -> Result<(Expr, ExprInfo)> {
    let (node, s) = an(expr, resolve)?;
    if s.kind == K::Const {
        return Err(plan_err("expression contains no column or aggregate (a constant is not a result)"));
    }
    if s.kind == K::Row && s.cols.is_empty() {
        return Err(plan_err(
            "a per-row expression needs at least one ENC/PAIRED column; an expression \
             over PLAIN columns only is not supported (select the columns and compute \
             it client-side)",
        ));
    }
    let info = ExprInfo {
        kind: if s.kind == K::Row { "row" } else { "agg" },
        enc: !s.cols.is_empty(),
        depth: s.depth,
        ct_muls: s.muls,
        inversions: s.invs,
        text: render_expr(&node),
    };
    Ok((node, info))
}

/// Table instances visible to an expression (alias or table name -> its columns), resolving column
/// references like the engine's planner: `inst.col` or a bare, unambiguous `col`.
pub struct Scope {
    specs: Vec<(String, Vec<Column>)>,
}

impl Scope {
    pub fn new(instances: Vec<(String, Vec<Column>)>) -> Result<Scope> {
        let mut specs: Vec<(String, Vec<Column>)> = vec![];
        for (name, cols) in instances {
            if specs.iter().any(|(n, _)| *n == name) {
                return Err(plan_err(format!(
                    "duplicate table name '{}' in FROM/JOIN — give each occurrence a distinct alias",
                    name
                )));
            }
            specs.push((name, cols));
        }
        Ok(Scope { specs })
    }

    /// -> (instance, column)
    pub fn resolve(&self, r: &str) -> Result<(String, Column)> {
        if let Some((inst, cname)) = r.split_once('.') {
            let Some((_, cols)) = self.specs.iter().find(|(n, _)| n == inst) else {
                return Err(plan_err(format!("unknown table '{}' in column ref '{}'", inst, r)));
            };
            return match cols.iter().find(|c| c.name == cname) {
                Some(c) => Ok((inst.to_string(), c.clone())),
                None => Err(plan_err(format!("no such column: '{}' in table '{}'", cname, inst))),
            };
        }
        let owners: Vec<&(String, Vec<Column>)> = self.specs.iter().filter(|(_, cols)| cols.iter().any(|c| c.name == r)).collect();
        match owners.len() {
            1 => Ok((owners[0].0.clone(), owners[0].1.iter().find(|c| c.name == r).unwrap().clone())),
            0 => Err(plan_err(format!("no such column: '{}'", r))),
            _ => Err(plan_err(format!("column '{}' is ambiguous in join — qualify as table.col", r))),
        }
    }
}

/// Every column reference of an expression, in first-use order.
pub fn columns_of(e: &Expr) -> Vec<String> {
    fn walk(e: &Expr, out: &mut Vec<String>) {
        match e {
            Expr::Col(n) => {
                if !out.contains(n) {
                    out.push(n.clone());
                }
            }
            Expr::Neg(o) => walk(o, out),
            Expr::Bin(_, l, r) => {
                walk(l, out);
                walk(r, out);
            }
            Expr::Agg(_, Some(a)) => walk(a, out),
            _ => {}
        }
    }
    let mut v = vec![];
    walk(e, &mut v);
    v
}
