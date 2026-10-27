// SPDX-License-Identifier: Apache-2.0
//! Static analysis of v0.6.1/v0.6.2 expressions over FHE columns (EC-FHE, BN254). A port of
//! `parser/torussql_parser/fhe_expr.py` (the single source of truth, shared there by the open
//! validator, the planner and the evaluator) and of its TypeScript sibling
//! `drivers/typescript/src/fheExpr.ts`, onto the TorusSQL v0.6 expression AST of `expr.rs`.
//!
//! FHE columns are EC-FHE ciphertexts. The keyless server can add ciphertexts (G1 side) and pair the
//! G2 half of one ciphertext with the G1 half of another (GT side); a GT element cannot be paired
//! again. So exactly ONE ciphertext x ciphertext product level exists, and nothing is ever decrypted
//! or re-encrypted at the server or in between. What this module accepts is the set of shapes for
//! which that is enough:
//!
//! ```text
//! expression  ::=  public affine combination of TERMS
//! TERM        ::=  SUM(P)                 P a per-row product  L * R
//!               |  AL * AR                AL, AR aggregate linear forms (products of SUMs)
//!               |  SUM(L) / AVG(...)      a plain linear sum (needs at least one product elsewhere)
//! L, R        ::=  integer-linear forms   k1*col1 + k2*col2 + ... + c   over FHE columns
//! AL, AR      ::=  k1*SUM(col1) + ... + c    (SUM(L) is the aggregate of a linear form)
//! public      ::=  literals, + - between terms, * and / by a literal, unary minus, AVG's 1/n
//! ```
//!
//! Rejected, with a precise message (never evaluated): a product of a product (depth > 1), a division
//! by anything that is not a literal, FHE mixed with PLAIN/ENC/PAIRED columns, a per-row
//! (non-aggregated) FHE value, non-integer operand coefficients, operands wider than the bounds below.
//!
//! **Deviation from the TypeScript port, follow-current-code note**: `drivers/typescript/src/fheExpr.ts`
//! still special-cases `SUM(x*y)` of two *bare* FHE columns as rejected
//! (`REJECT_BARE_COLUMN_PRODUCT = true`, the pre-v0.6.1 text, in favour of `DOT(x, y)`). The core engine's
//! analyzer it was ported from (`parser/torussql_parser/fhe_expr.py`) has since moved to
//! `REJECT_BARE_COLUMN_PRODUCT = False` (v0.6.2: that spelling is accepted through the same `fhe_mul`
//! path as every other product shape; `DOT` keeps working unchanged). Per this task's instruction to
//! follow the current engine code over a stale description, this Rust port matches the CURRENT Python
//! analyzer (`REJECT_BARE_COLUMN_PRODUCT = false` below) rather than the stale TypeScript one; the
//! constant is kept (and the dead branch it guards, for the structural port) so turning it back on is a
//! one-line change, exactly mirroring both references' comments. See the top-level task report for this
//! one-flag divergence.
//!
//! This Rust port also does not implement the engine's `allow_row` per-row *projection* variant (v0.6.2,
//! e.g. `SELECT a*b FROM t`, `fhe_mul` mode `"row"`): that is a different entry point than
//! `Client::expr`/`expr_as`/`join_expr` (which only ever evaluate an AGGREGATE expression), and the
//! TypeScript port does not expose it either, so it is out of scope for this port too.

use crate::error::{Error, Kind};
use crate::expr::{columns_of, Expr, Frac};
use crate::Column;
use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, Error>;

fn plan_err(m: impl Into<String>) -> Error {
    Error::new(Kind::PlanError, m)
}
fn fail(msg: impl std::fmt::Display) -> Error {
    plan_err(format!("FHE expression: {}", msg))
}

/// `SUM(x * y)` over two bare FHE columns IS `DOT(x, y)` (use `DOT`). See the module doc comment:
/// the current `parser/torussql_parser/fhe_expr.py` has this `False` (v0.6.2 accepts the spelling);
/// kept `false` here to match, with the special-case branch retained as dead code for parity.
pub const REJECT_BARE_COLUMN_PRODUCT: bool = false;
/// Distinct columns in one operand of a product.
pub const MAX_COLS: usize = 16;
/// Product terms in one expression.
pub const MAX_PRODUCTS: usize = 16;

fn max_coef() -> BigInt {
    BigInt::one() << 40
}

fn old_message(name: &str) -> String {
    format!(
        "FHE column '{}' cannot be used inside an arithmetic expression \
         (FHE columns support SUM, AVG, k*SUM and DOT only)",
        name
    )
}

const MIX: &str = "per-row columns and aggregates cannot be mixed; wrap the columns in SUM(...)";
const DEPTH: &str = "a product of products (or of a product and anything else) is not available: the server pairs \
two ciphertexts once, a pairing result cannot be paired again, and no intermediate is ever \
decrypted or re-encrypted. Use products of integer-linear forms: SUM(a*b), \
SUM((a+2*b)*(c-d)), SUM(a)*SUM(b)";

// ── polynomials in n (the number of rows); exponents restricted to {-1, 0, 1} ────────────────────
/// A polynomial in `n` (the row count): exponent -> coefficient, exponents in `{-1, 0, 1}`.
pub type Poly = BTreeMap<i32, Frac>;

fn pclean(mut p: Poly) -> Poly {
    p.retain(|_, v| !v.is_zero());
    p
}
fn poly_add(a: &Poly, b: &Poly, sg: i64) -> Poly {
    let mut out = a.clone();
    for (e, v) in b {
        let cur = out.get(e).cloned().unwrap_or_else(|| Frac::int(0));
        out.insert(*e, if sg == 1 { cur.add(v) } else { cur.sub(v) });
    }
    pclean(out)
}
fn poly_scale(a: &Poly, f: &Frac) -> Poly {
    let mut out = Poly::new();
    for (e, v) in a {
        out.insert(*e, v.mul(f));
    }
    pclean(out)
}
fn poly_shift(a: &Poly, d: i32) -> Poly {
    a.iter().map(|(e, v)| (e + d, v.clone())).collect()
}
fn poly_const(c: Frac) -> Poly {
    let mut p = Poly::new();
    if !c.is_zero() {
        p.insert(0, c);
    }
    p
}
fn poly1() -> Poly {
    let mut p = Poly::new();
    p.insert(0, Frac::int(1));
    p
}
/// The value of a polynomial at `n` rows; `None` when it has an `n^-1` term and `n == 0`.
pub fn peval_poly(a: &Poly, n: i64) -> Option<Frac> {
    let mut tot = Frac::int(0);
    for (&e, v) in a {
        if e < 0 && n == 0 {
            return None;
        }
        let p = match e {
            0 => Frac::int(1),
            1 => Frac::new(BigInt::from(n), BigInt::one()),
            -1 => Frac::new(BigInt::one(), BigInt::from(n)),
            other => unreachable!("FHE expression polynomials only use exponents -1, 0, 1 (got {})", other),
        };
        tot = tot.add(&v.mul(&p));
    }
    Some(tot)
}

// ── Lin: Σ coefs[col]·col + c over FHE columns ──────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Row,
    Agg,
}

/// `Σ coefs[col]·col + c` over FHE columns. `level` `Row`: a value per row (`c` a constant
/// polynomial); `Agg`: `col` stands for `SUM(col)` and `c` is a polynomial in `n` (`SUM(a+1) = SUM(a) + n`).
#[derive(Clone, Debug)]
pub struct Lin {
    pub level: Level,
    /// insertion order (also the order `fhe_mul`'s wire terms are sent in); never a zero coefficient.
    pub coefs: Vec<(String, Frac)>,
    pub c: Poly,
}

fn coef_get(coefs: &[(String, Frac)], k: &str) -> Frac {
    coefs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_else(|| Frac::int(0))
}
fn coef_set(coefs: &mut Vec<(String, Frac)>, k: &str, v: Frac) {
    match coefs.iter_mut().find(|(n, _)| n == k) {
        Some(e) => e.1 = v,
        None => coefs.push((k.to_string(), v)),
    }
}
fn mk_lin(level: Level, coefs: Vec<(String, Frac)>, c: Poly) -> Lin {
    Lin { level, coefs: coefs.into_iter().filter(|(_, v)| !v.is_zero()).collect(), c }
}
fn lin_add(x: &Lin, y: &Lin, sg: i64) -> Result<Lin> {
    if x.level != y.level {
        return Err(fail(MIX));
    }
    let mut co = x.coefs.clone();
    for (k, v) in &y.coefs {
        let cur = coef_get(&co, k);
        coef_set(&mut co, k, if sg == 1 { cur.add(v) } else { cur.sub(v) });
    }
    Ok(mk_lin(x.level, co, poly_add(&x.c, &y.c, sg)))
}
fn lin_scale(x: &Lin, f: &Frac) -> Lin {
    let co = x.coefs.iter().map(|(k, v)| (k.clone(), v.mul(f))).collect();
    mk_lin(x.level, co, poly_scale(&x.c, f))
}

// ── Term / Res: a public affine combination of terms ────────────────────────────────────────────
#[derive(Clone, Debug)]
pub enum Term {
    Lin(Lin),
    Prod(Lin, Lin),
    SumProd(Lin, Lin),
    AggProd(Lin, Lin),
    Sum(String),
}

#[derive(Clone, Debug)]
pub struct Res {
    pub level: Level,
    pub terms: Vec<(Poly, Term)>,
    pub const_: Poly,
}

fn lin_to_res(x: Lin) -> Res {
    match x.level {
        Level::Row => Res { level: Level::Row, terms: vec![(poly1(), Term::Lin(x))], const_: Poly::new() },
        Level::Agg => {
            let terms = x
                .coefs
                .iter()
                .map(|(k, v)| {
                    let mut p = Poly::new();
                    p.insert(0, v.clone());
                    (p, Term::Sum(k.clone()))
                })
                .collect();
            Res { level: Level::Agg, terms, const_: x.c.clone() }
        }
    }
}
fn res_add(x: Res, y: Res, sg: i64) -> Result<Res> {
    if x.level != y.level {
        return Err(fail(MIX));
    }
    let mut terms = x.terms;
    for (c, t) in y.terms {
        terms.push((poly_scale(&c, &Frac::int(sg)), t));
    }
    Ok(Res { level: x.level, terms, const_: poly_add(&x.const_, &y.const_, sg) })
}
fn res_scale(x: Res, f: &Frac) -> Res {
    let terms = x.terms.into_iter().map(|(c, t)| (poly_scale(&c, f), t)).collect();
    Res { level: x.level, terms, const_: poly_scale(&x.const_, f) }
}

enum FVal {
    Frac(Frac),
    Lin(Lin),
    Res(Res),
}
enum LinOrRes {
    L(Lin),
    R(Res),
}
fn to_lor(v: FVal) -> LinOrRes {
    match v {
        FVal::Lin(l) => LinOrRes::L(l),
        FVal::Res(r) => LinOrRes::R(r),
        FVal::Frac(_) => unreachable!("to_lor: caller must handle the constant case first"),
    }
}
fn from_lor(v: LinOrRes) -> FVal {
    match v {
        LinOrRes::L(l) => FVal::Lin(l),
        LinOrRes::R(r) => FVal::Res(r),
    }
}
fn to_res(v: FVal) -> Res {
    match v {
        FVal::Lin(l) => lin_to_res(l),
        FVal::Res(r) => r,
        FVal::Frac(_) => unreachable!("to_res: caller must handle the constant case first"),
    }
}

fn check_operand(x: &Lin, which: &str) -> Result<()> {
    if x.coefs.is_empty() {
        return Err(fail(format!(
            "the {} operand of a product has no FHE column (a constant factor is a scalar: write k * ...)",
            which
        )));
    }
    if x.coefs.len() > MAX_COLS {
        return Err(fail(format!("an operand of a product combines at most {} columns", MAX_COLS)));
    }
    let mc = max_coef();
    for (k, v) in &x.coefs {
        if !v.is_int() {
            return Err(fail(format!(
                "the coefficient of '{}' in the {} operand of a product is not an integer; \
                 a ciphertext cannot be divided: scale outside, e.g. (a+b)*c/2 instead of ((a+b)/2)*c",
                k, which
            )));
        }
        if v.num.abs() > mc {
            return Err(fail(format!("the coefficient of '{}' exceeds 2^40 in absolute value", k)));
        }
    }
    for (e, v) in &x.c {
        if *e < 0 || !v.is_int() || v.num.abs() > mc {
            return Err(fail(format!(
                "the constant of the {} operand of a product must be an integer of magnitude \
                 <= 2^40 (and not depend on AVG)",
                which
            )));
        }
    }
    Ok(())
}

fn mul_val(x: FVal, y: FVal) -> Result<FVal> {
    match (x, y) {
        (FVal::Frac(a), FVal::Frac(b)) => Ok(FVal::Frac(a.mul(&b))),
        (FVal::Frac(a), FVal::Lin(l)) | (FVal::Lin(l), FVal::Frac(a)) => Ok(FVal::Lin(lin_scale(&l, &a))),
        (FVal::Frac(a), FVal::Res(r)) | (FVal::Res(r), FVal::Frac(a)) => Ok(FVal::Res(res_scale(r, &a))),
        (FVal::Lin(x), FVal::Lin(y)) => {
            if x.level != y.level {
                return Err(fail(MIX));
            }
            check_operand(&x, "left")?;
            check_operand(&y, "right")?;
            Ok(match x.level {
                Level::Row => FVal::Res(Res { level: Level::Row, terms: vec![(poly1(), Term::Prod(x, y))], const_: Poly::new() }),
                Level::Agg => {
                    FVal::Res(Res { level: Level::Agg, terms: vec![(poly1(), Term::AggProd(x, y))], const_: Poly::new() })
                }
            })
        }
        (x, y) => {
            fn deep(v: &FVal) -> bool {
                matches!(v, FVal::Res(r) if r.terms.iter().any(|(_, t)| matches!(t, Term::Prod(..) | Term::SumProd(..) | Term::AggProd(..))))
            }
            if deep(&x) || deep(&y) {
                Err(fail(DEPTH))
            } else {
                Err(fail(
                    "a factor of a product must be an integer-linear form of FHE columns (or of their SUMs); \
                     AVG(...) and sums of terms are not",
                ))
            }
        }
    }
}

fn add_const(x: LinOrRes, c: Frac) -> LinOrRes {
    let cp = poly_const(c);
    match x {
        LinOrRes::L(l) => LinOrRes::L(Lin { level: l.level, coefs: l.coefs, c: poly_add(&l.c, &cp, 1) }),
        LinOrRes::R(r) => LinOrRes::R(Res { level: r.level, terms: r.terms, const_: poly_add(&r.const_, &cp, 1) }),
    }
}
fn neg_val(x: FVal) -> FVal {
    match x {
        FVal::Frac(a) => FVal::Frac(a.neg()),
        FVal::Lin(l) => FVal::Lin(lin_scale(&l, &Frac::int(-1))),
        FVal::Res(r) => FVal::Res(res_scale(r, &Frac::int(-1))),
    }
}
fn add_val(x: FVal, y: FVal, sg: i64) -> Result<FVal> {
    match (x, y) {
        (FVal::Frac(a), FVal::Frac(b)) => Ok(FVal::Frac(if sg == 1 { a.add(&b) } else { a.sub(&b) })),
        (FVal::Frac(a), y) => {
            let yr = if sg == 1 { y } else { neg_val(y) };
            Ok(from_lor(add_const(to_lor(yr), a)))
        }
        (x, FVal::Frac(b)) => {
            let b = if sg == 1 { b } else { b.neg() };
            Ok(from_lor(add_const(to_lor(x), b)))
        }
        (FVal::Lin(x), FVal::Lin(y)) => Ok(FVal::Lin(lin_add(&x, &y, sg)?)),
        (x, y) => Ok(FVal::Res(res_add(to_res(x), to_res(y), sg)?)),
    }
}

fn sum_val(x: FVal) -> Result<FVal> {
    let row_ok = match &x {
        FVal::Lin(l) => l.level == Level::Row,
        FVal::Res(r) => r.level == Level::Row,
        FVal::Frac(_) => false,
    };
    if !row_ok {
        return Err(fail("SUM(...) needs an argument that contains an FHE column and no aggregate"));
    }
    match x {
        FVal::Lin(l) => Ok(FVal::Lin(Lin { level: Level::Agg, coefs: l.coefs, c: poly_shift(&l.c, 1) })),
        FVal::Res(r) => {
            let mut terms = vec![];
            let mut cst = poly_shift(&r.const_, 1);
            for (c, t) in r.terms {
                match t {
                    Term::Prod(l, rr) => terms.push((c, Term::SumProd(l, rr))),
                    Term::Lin(lin) => {
                        for (col, k) in &lin.coefs {
                            terms.push((poly_scale(&c, k), Term::Sum(col.clone())));
                        }
                        let k0 = lin.c.get(&0).cloned().unwrap_or_else(|| Frac::int(0));
                        cst = poly_add(&cst, &poly_shift(&poly_scale(&c, &k0), 1), 1);
                    }
                    _ => unreachable!("a row-level Res only ever holds Prod/Lin terms"),
                }
            }
            Ok(FVal::Res(Res { level: Level::Agg, terms, const_: cst }))
        }
        FVal::Frac(_) => unreachable!(),
    }
}
fn avg_val(x: FVal) -> Result<FVal> {
    let s = sum_val(x)?;
    let r = to_res(s);
    let terms = r.terms.into_iter().map(|(c, t)| (poly_shift(&c, -1), t)).collect();
    Ok(FVal::Res(Res { level: r.level, terms, const_: poly_shift(&r.const_, -1) }))
}

/// A validated FHE expression: an aggregate public-affine combination with >= 1 product term.
#[derive(Debug)]
pub struct FheExprPlan {
    pub terms: Vec<(Poly, Term)>,
    pub const_: Poly,
    pub products: usize,
}

/// `(instance-bare-name) -> Column` resolver, matching the single-table scope an FHE expression runs in.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<Column>;

/// Does `tree` reference at least one FHE column? Used to dispatch between the plain-expression
/// analyzer (`analyze_expression`) and this one before either runs.
pub fn references_fhe_column(tree: &Expr, resolve: Resolve) -> Result<bool> {
    for name in columns_of(tree) {
        if resolve(&name)?.policy == "fhe" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Validate `tree` against the v0.6.1/v0.6.2 FHE shapes. Errors have `Kind::PlanError` exactly where
/// the Python analyzer (`torussql_parser.fhe_expr.analyze`) raises them. `resolve` maps a (possibly
/// qualified) column reference to its policy/name/type.
pub fn analyze_fhe_expr(tree: &Expr, resolve: Resolve) -> Result<FheExprPlan> {
    // v0.6.1's pinned rejection of a bare `SUM(col*col)`; OFF by default (see the module doc comment).
    // Kept so flipping `REJECT_BARE_COLUMN_PRODUCT` back to `true` is a one-line change.
    if REJECT_BARE_COLUMN_PRODUCT {
        if let Expr::Agg("SUM", Some(arg)) = tree {
            if let Expr::Bin('*', l, r) = &**arg {
                if let (Expr::Col(ln), Expr::Col(_)) = (&**l, &**r) {
                    let c = resolve(ln)?;
                    if c.policy == "fhe" {
                        return Err(plan_err(old_message(&c.name)));
                    }
                }
            }
        }
    }

    let cols = columns_of(tree);
    let mut seen: Vec<String> = vec![];
    for name in &cols {
        let c = resolve(name)?;
        if c.policy == "fhe" {
            seen.push(c.name.clone());
        }
    }
    if seen.is_empty() {
        return Err(Error::interface("analyze_fhe_expr is for expressions with at least one FHE column reference"));
    }
    for name in &cols {
        let c = resolve(name)?;
        if c.policy != "fhe" {
            return Err(plan_err(old_message(&seen[0])));
        }
    }

    fn ev(e: &Expr, resolve: Resolve, seen: &[String]) -> Result<FVal> {
        match e {
            Expr::Lit(v) => Ok(FVal::Frac(v.clone())),
            Expr::Col(name) => {
                let c = resolve(name)?;
                if c.policy != "fhe" {
                    return Err(plan_err(old_message(seen.first().map(|s| s.as_str()).unwrap_or(&c.name))));
                }
                Ok(FVal::Lin(mk_lin(Level::Row, vec![(c.name.clone(), Frac::int(1))], Poly::new())))
            }
            Expr::Neg(inner) => Ok(neg_val(ev(inner, resolve, seen)?)),
            Expr::Agg(f, arg) => {
                if *f == "COUNT" {
                    return Err(plan_err(old_message(&seen[0])));
                }
                let a = ev(arg.as_ref().unwrap(), resolve, seen)?;
                if matches!(a, FVal::Frac(_)) {
                    return Err(fail(format!("{}(...) needs an argument that contains an FHE column", f)));
                }
                if *f == "SUM" {
                    sum_val(a)
                } else {
                    avg_val(a)
                }
            }
            Expr::Bin(op, l, r) => {
                let a = ev(l, resolve, seen)?;
                let b = ev(r, resolve, seen)?;
                match op {
                    '+' => add_val(a, b, 1),
                    '-' => add_val(a, b, -1),
                    '*' => mul_val(a, b),
                    _ => match b {
                        FVal::Frac(bv) => {
                            if bv.is_zero() {
                                return Err(plan_err("division by zero"));
                            }
                            mul_val(a, FVal::Frac(Frac::int(1).div(&bv)))
                        }
                        _ => Err(plan_err(old_message(&seen[0]))),
                    },
                }
            }
        }
    }

    let v = ev(tree, resolve, &seen)?;
    let r = match v {
        FVal::Frac(_) => return Err(plan_err("expression contains no column or aggregate (a constant is not a result)")),
        FVal::Lin(l) => {
            if l.level == Level::Row {
                return Err(plan_err(old_message(&seen[0])));
            }
            lin_to_res(l)
        }
        FVal::Res(r) => r,
    };
    if r.level == Level::Row {
        if r.terms.iter().any(|(_, t)| matches!(t, Term::Prod(..))) {
            return Err(fail("a per-row product of FHE columns is not supported; aggregate it: SUM(a*b)"));
        }
        return Err(plan_err(old_message(&seen[0])));
    }
    let products = r.terms.iter().filter(|(_, t)| matches!(t, Term::SumProd(..) | Term::AggProd(..))).count();
    if products == 0 {
        return Err(plan_err(old_message(&seen[0])));
    }
    if products > MAX_PRODUCTS {
        return Err(fail(format!("at most {} products per expression", MAX_PRODUCTS)));
    }
    Ok(FheExprPlan { terms: r.terms, const_: r.const_, products })
}

/// `([(column, int k)], int constant)` of a validated operand at `n` rows: the constant of an
/// aggregate operand may depend on the number of rows (`c0 + c1*n`), evaluated here at the actual
/// row count.
pub fn operand_at(lin: &Lin, n: i64) -> Result<(Vec<(String, i64)>, i64)> {
    let c = peval_poly(&lin.c, n)
        .ok_or_else(|| plan_err("an operand constant of an FHE product exceeds 2^40 for this many rows"))?;
    if !c.is_int() || c.num.abs() > max_coef() {
        return Err(plan_err("an operand constant of an FHE product exceeds 2^40 for this many rows"));
    }
    let mut terms = Vec::with_capacity(lin.coefs.len());
    for (k, v) in &lin.coefs {
        let n = v.num.to_i64().ok_or_else(|| plan_err("an operand coefficient does not fit in 64 bits"))?;
        terms.push((k.clone(), n));
    }
    let constant = c.num.to_i64().ok_or_else(|| plan_err("an operand constant does not fit in 64 bits"))?;
    Ok((terms, constant))
}
