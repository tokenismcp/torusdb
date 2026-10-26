// SPDX-License-Identifier: Apache-2.0
//! Owner-side evaluation of TorusSQL v0.6 arithmetic expressions: the no-key paper's circuit composition
//! Pi_C over the blinded database. A port of `core/torusdb_core/expr_eval.py` (the reference); read its
//! header for the full "who computes what" account. In short:
//!
//! * the SERVER holds blinded scalars `s~ = s + r` and plaintext columns, no key, no mask. It only
//!   (i) sums stored blinded cells for LINEAR `SUM(...)` arguments (Pi_lin) and (ii) multiplies the two
//!   openings `e*g` of each Beaver product (Pi_mult), both on values uniform and independent of the data;
//! * the OWNER (this process) unmasks the cells it reads, applies every linear gate and every public
//!   multiplication or division locally, draws a fresh triple per ciphertext product, reconstructs the
//!   product and inverts encrypted denominators. Products and quotients are therefore NOT offloaded: the
//!   owner already holds both operands of every product (review packet 3.3, F-3);
//! * one batched `mult_combine_batch` exchange per multiplicative LEVEL: rounds == depth;
//! * an intermediate (a product, a quotient) exists only here. It reaches the server only inside the
//!   next level's opening `e = x - u` with a fresh uniform `u` (the Pi_boot re-mask);
//! * a zero denominator does NOT abort: the protocol runs to its last round with a dummy inverse and only
//!   then raises `DivisionByZero`, so the request sequence does not reveal the zero;
//! * all arithmetic is exact in Z/nZ; only the final decode can fail, and it raises `OutOfBudget`.

use crate::error::{Error, Kind};
use crate::expr::{Expr, ExprInfo, Frac};
use crate::field::{decode, encode_int, encode_rational, md, mod_inv, n, rand_scalar, Decoded};
use crate::{arr, big, CellIn, Client, MAX_DIGITS};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde_json::json;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, Error>;

/// What an expression cost the owner (the last successful `expr` / `join_expr`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExprCost {
    /// sequential ciphertext x ciphertext product levels
    pub depth: usize,
    /// batched `mult_combine_batch` owner round trips (== depth)
    pub mult_rounds: usize,
    /// Beaver triples spent (one per product per row)
    pub products: usize,
    /// owner-assisted inversions
    pub inversions: usize,
    /// Pi_lin sums computed by the server
    pub linear_sums: usize,
}

/// What `Client::expr` / `join_expr` return.
#[derive(Clone, Debug, PartialEq)]
pub enum ExprValue {
    /// an aggregate expression: one value (`None` for an AVG over no rows)
    Scalar(Option<Decoded>),
    /// a per-row expression: one value per selected row (`None` where an operand is NULL)
    Rows(Vec<Option<Decoded>>),
}

type Vecn = Vec<Option<BigInt>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Lit,
    Col,
    Count,
    LinSum,
    Neg,
    Sum,
    Avg,
    Inv,
    Add,
    Sub,
    SMul,
    CMul,
}

enum Data {
    None,
    Lit(Frac),
    Col(String),
    Lin(&'static str, Lin),
}

struct ENode {
    op: Op,
    args: Vec<usize>,
    level: usize,
    enc: bool,
    row: bool,
    data: Data,
}

#[derive(Clone)]
struct Lin {
    coef: Vec<(String, Frac)>, // insertion order (the request order depends on it)
    konst: Frac,
}

fn scaled(coef: &[(String, Frac)], f: impl Fn(&Frac) -> Frac) -> Vec<(String, Frac)> {
    coef.iter().map(|(k, v)| (k.clone(), f(v))).collect()
}

/// If `e` is a linear form over ENCRYPTED columns only (no product of two columns, no division by a
/// column, no PLAIN column), its coefficients; else None. Such a SUM is a Pi_lin aggregate.
fn linear(e: &Expr, is_enc: &dyn Fn(&str) -> bool) -> Option<Lin> {
    match e {
        Expr::Lit(v) => Some(Lin { coef: vec![], konst: v.clone() }),
        Expr::Col(n) => {
            if is_enc(n) {
                Some(Lin { coef: vec![(n.clone(), Frac::int(1))], konst: Frac::int(0) })
            } else {
                None
            }
        }
        Expr::Neg(o) => {
            let r = linear(o, is_enc)?;
            Some(Lin { coef: scaled(&r.coef, |v| v.neg()), konst: r.konst.neg() })
        }
        Expr::Bin(op, le, re) => {
            let l = linear(le, is_enc)?;
            let r = linear(re, is_enc)?;
            match op {
                '+' | '-' => {
                    let neg = *op == '-';
                    let mut coef = l.coef.clone();
                    for (k, v) in &r.coef {
                        let v = if neg { v.neg() } else { v.clone() };
                        match coef.iter_mut().find(|(n, _)| n == k) {
                            Some((_, cur)) => *cur = cur.add(&v),
                            None => coef.push((k.clone(), v)),
                        }
                    }
                    let rk = if neg { r.konst.neg() } else { r.konst.clone() };
                    Some(Lin { coef, konst: l.konst.add(&rk) })
                }
                '*' => {
                    if l.coef.is_empty() {
                        Some(Lin { coef: scaled(&r.coef, |v| l.konst.mul(v)), konst: l.konst.mul(&r.konst) })
                    } else if r.coef.is_empty() {
                        Some(Lin { coef: scaled(&l.coef, |v| r.konst.mul(v)), konst: l.konst.mul(&r.konst) })
                    } else {
                        None
                    }
                }
                _ => {
                    if r.coef.is_empty() && !r.konst.is_zero() {
                        Some(Lin { coef: scaled(&l.coef, |v| v.div(&r.konst)), konst: l.konst.div(&r.konst) })
                    } else {
                        None
                    }
                }
            }
        }
        Expr::Agg(..) => None,
    }
}

fn enc_frac(v: &Frac) -> Result<BigInt> {
    if v.is_int() {
        encode_int(&v.num)
    } else {
        encode_rational(&v.num, &v.den)
    }
}

/// A folded public coefficient as a ring element WITHOUT the representability check of `encode`: the
/// coefficient of a linear form may be a product of literals that is not representable on its own (only
/// the final result has to be).
fn ring(k: &Frac) -> BigInt {
    md(&(md(&k.num) * mod_inv(&md(&k.den))))
}

/// Evaluate one planned expression over a list of row tuples.
pub(crate) struct ExprRunner<'a> {
    c: &'a mut Client,
    expr: &'a Expr,
    info: &'a ExprInfo,
    /// alias -> table, in tuple order
    inst: &'a [(String, String)],
    /// column reference -> (alias, bare column)
    locs: &'a HashMap<String, (String, String)>,
    tuples: &'a [Vec<Option<i64>>],
    nodes: Vec<ENode>,
    colcache: HashMap<(String, String), Vecn>,
    cost: ExprCost,
    zero: Option<String>, // set when a denominator was 0 (raised after the last round)
}

impl<'a> ExprRunner<'a> {
    pub(crate) fn new(
        c: &'a mut Client,
        expr: &'a Expr,
        info: &'a ExprInfo,
        inst: &'a [(String, String)],
        locs: &'a HashMap<String, (String, String)>,
        tuples: &'a [Vec<Option<i64>>],
    ) -> Self {
        ExprRunner { c, expr, info, inst, locs, tuples, nodes: vec![], colcache: HashMap::new(), cost: ExprCost::default(), zero: None }
    }

    fn pos(&self, alias: &str) -> usize {
        self.inst.iter().position(|(a, _)| a == alias).expect("alias in scope")
    }
    fn table(&self, alias: &str) -> &str {
        &self.inst[self.pos(alias)].1
    }
    fn loc(&self, name: &str) -> &(String, String) {
        &self.locs[name]
    }
    fn is_enc_col(&self, name: &str) -> bool {
        let (alias, col) = self.loc(name);
        self.c.col(self.table(alias), col).map(|c| c.policy != "plain").unwrap_or(true)
    }

    // ── compile the tree into a DAG with multiplicative levels ──
    fn add(&mut self, n: ENode) -> usize {
        self.nodes.push(n);
        self.nodes.len() - 1
    }
    fn node(op: Op, args: Vec<usize>, level: usize, enc: bool, row: bool, data: Data) -> ENode {
        ENode { op, args, level, enc, row, data }
    }

    fn compile(&mut self, e: &Expr) -> usize {
        match e {
            Expr::Lit(v) => self.add(Self::node(Op::Lit, vec![], 0, false, false, Data::Lit(v.clone()))),
            Expr::Col(name) => {
                let enc = self.is_enc_col(name);
                self.add(Self::node(Op::Col, vec![], 0, enc, true, Data::Col(name.clone())))
            }
            Expr::Neg(o) => {
                let a = self.compile(o);
                let (level, enc, row) = (self.nodes[a].level, self.nodes[a].enc, self.nodes[a].row);
                self.add(Self::node(Op::Neg, vec![a], level, enc, row, Data::None))
            }
            Expr::Agg(f, arg) => {
                if *f == "COUNT" {
                    return self.add(Self::node(Op::Count, vec![], 0, false, false, Data::None));
                }
                let arg = arg.as_ref().unwrap();
                let lin = {
                    let me: &Self = self;
                    linear(arg, &|n| me.is_enc_col(n))
                };
                if let Some(l) = lin {
                    if !l.coef.is_empty() {
                        return self.add(Self::node(Op::LinSum, vec![], 0, true, false, Data::Lin(f, l)));
                    }
                }
                let a = self.compile(arg);
                let (level, enc) = (self.nodes[a].level, self.nodes[a].enc);
                let op = if *f == "SUM" { Op::Sum } else { Op::Avg };
                self.add(Self::node(op, vec![a], level, enc, false, Data::None))
            }
            Expr::Bin(op, le, re) => {
                let a = self.compile(le);
                let mut b = self.compile(re);
                let mut op = *op;
                if op == '/' {
                    if let Expr::Lit(k) = &**re {
                        // x / k, k public: multiply by k^-1 mod n (= encode(1/k)); no inversion step
                        let f = Frac::int(1).div(k);
                        self.nodes.pop(); // drop the literal's own node
                        b = self.add(Self::node(Op::Lit, vec![], 0, false, false, Data::Lit(f)));
                    } else {
                        let (level, enc, row) = (self.nodes[b].level, self.nodes[b].enc, self.nodes[b].row);
                        b = self.add(Self::node(Op::Inv, vec![b], level, enc, row, Data::None));
                    }
                    op = '*';
                }
                let (na, nb) = (&self.nodes[a], &self.nodes[b]);
                let row = na.row || nb.row;
                let enc = na.enc || nb.enc;
                let lvl = na.level.max(nb.level);
                if op == '*' {
                    if na.enc && nb.enc {
                        return self.add(Self::node(Op::CMul, vec![a, b], lvl + 1, true, row, Data::None));
                    }
                    return self.add(Self::node(Op::SMul, vec![a, b], lvl, enc, row, Data::None));
                }
                self.add(Self::node(if op == '+' { Op::Add } else { Op::Sub }, vec![a, b], lvl, enc, row, Data::None))
            }
        }
    }

    // ── leaves ──
    fn col_vector(&mut self, name: &str) -> Result<Vecn> {
        let (alias, col) = self.loc(name).clone();
        let key = (alias.clone(), col.clone());
        if let Some(v) = self.colcache.get(&key) {
            return Ok(v.clone());
        }
        let table = self.table(&alias).to_string();
        let p = self.pos(&alias);
        let ids: Vec<Option<i64>> = self.tuples.iter().map(|t| t[p]).collect();
        let plain = self.c.col(&table, &col)?.policy == "plain";
        let out: Vecn = if plain {
            let cells = self.c.column(&table, &col, &ids)?;
            let mut o = vec![];
            for v in cells {
                o.push(match v {
                    CellIn::Null => None,
                    CellIn::Int(b) => Some(enc_frac(&Frac::new(b, BigInt::one()))?),
                    CellIn::Rational(a, b) => Some(enc_frac(&Frac::new(a, b))?),
                    _ => {
                        return Err(Error::new(
                            Kind::Server("ExecError".into()),
                            format!("column '{}' holds a non-numeric value in an expression", name),
                        ))
                    }
                });
            }
            o
        } else {
            let mut uniq: Vec<i64> = ids.iter().flatten().copied().collect();
            uniq.sort_unstable();
            uniq.dedup();
            let ss = if uniq.is_empty() { vec![] } else { self.c.unblind_cells(&table, &col, &uniq)? };
            let by: HashMap<i64, BigInt> = uniq.iter().copied().zip(ss).collect();
            ids.iter().map(|i| i.map(|i| by[&i].clone())).collect()
        };
        self.colcache.insert(key, out.clone());
        Ok(out)
    }

    fn valid_tuples(&self, names: &[String]) -> Vec<&'a Vec<Option<i64>>> {
        let mut aliases: Vec<&str> = names.iter().map(|n| self.loc(n).0.as_str()).collect();
        aliases.sort_unstable();
        aliases.dedup();
        let poss: Vec<usize> = aliases.iter().map(|a| self.pos(a)).collect();
        let tuples: &'a [Vec<Option<i64>>] = self.tuples;
        tuples.iter().filter(|t| poss.iter().all(|&p| t[p].is_some())).collect()
    }

    fn linsum(&mut self, f: &str, lin: &Lin) -> Result<Vecn> {
        let names: Vec<String> = lin.coef.iter().map(|(k, _)| k.clone()).collect();
        let valid = self.valid_tuples(&names);
        let nn = n();
        let mut total = if !lin.konst.is_zero() { md(&(ring(&lin.konst) * BigInt::from(valid.len()))) } else { BigInt::zero() };
        for (name, k) in &lin.coef {
            if k.is_zero() {
                continue;
            }
            let (alias, col) = self.loc(name).clone();
            let p = self.pos(&alias);
            let ids: Vec<i64> = valid.iter().map(|t| t[p].unwrap()).collect();
            let table = self.table(&alias).to_string();
            let s = if ids.is_empty() { BigInt::zero() } else { self.c.sum_scalar(&table, &col, &ids)? };
            total = (total + ring(k) * s) % nn;
            self.cost.linear_sums += 1;
        }
        if f == "AVG" {
            if valid.is_empty() {
                return Ok(vec![None]);
            }
            return Ok(vec![Some(md(&(total * mod_inv(&BigInt::from(valid.len())))))]);
        }
        Ok(vec![Some(total)])
    }

    /// Python `v * n` for a list (repeat it n times) when its length is not already n.
    fn bc(v: &Vecn, n: usize) -> Vecn {
        if v.len() == n {
            return v.clone();
        }
        let mut out = Vec::with_capacity(v.len() * n);
        for _ in 0..n {
            out.extend(v.iter().cloned());
        }
        out
    }

    fn local(&mut self, i: usize, vals: &HashMap<usize, Vecn>) -> Result<Vecn> {
        let nn = n();
        let op = self.nodes[i].op;
        match op {
            Op::Lit => {
                let Data::Lit(v) = &self.nodes[i].data else { unreachable!() };
                return Ok(vec![Some(enc_frac(v)?)]);
            }
            Op::Col => {
                let Data::Col(name) = &self.nodes[i].data else { unreachable!() };
                let name = name.clone();
                return self.col_vector(&name);
            }
            Op::Count => return Ok(vec![Some(BigInt::from(self.tuples.len()))]),
            Op::LinSum => {
                let (f, lin) = match &self.nodes[i].data {
                    Data::Lin(f, l) => (*f, l.clone()),
                    _ => unreachable!(),
                };
                return self.linsum(f, &lin);
            }
            _ => {}
        }
        let a = &vals[&self.nodes[i].args[0]];
        match op {
            Op::Neg => return Ok(a.iter().map(|x| x.as_ref().map(|x| md(&-x))).collect()),
            Op::Sum => {
                let mut s = BigInt::zero();
                for x in a.iter().flatten() {
                    s += x;
                }
                return Ok(vec![Some(s % nn)]);
            }
            Op::Avg => {
                let live: Vec<&BigInt> = a.iter().flatten().collect();
                if live.is_empty() {
                    return Ok(vec![None]);
                }
                let mut s = BigInt::zero();
                for x in &live {
                    s += *x;
                }
                return Ok(vec![Some(md(&((s % nn) * mod_inv(&BigInt::from(live.len())))))]);
            }
            Op::Inv => {
                let row = self.nodes[i].row;
                let mut out = Vec::with_capacity(a.len());
                let mut zero_msg: Option<String> = None;
                let mut inversions = 0;
                for (k, x) in a.iter().enumerate() {
                    match x {
                        None => out.push(None),
                        Some(x) if md(x).is_zero() => {
                            // Do NOT stop here: aborting would show the server (as a missing request) that a
                            // denominator was zero. Carry on with a dummy 0 so the request sequence is
                            // independent of the data, and raise at the end.
                            if zero_msg.is_none() {
                                zero_msg = Some(if row { format!(" (result row {})", k) } else { String::new() });
                            }
                            out.push(Some(BigInt::zero()));
                        }
                        Some(x) => {
                            out.push(Some(mod_inv(x)));
                            inversions += 1;
                        }
                    }
                }
                self.cost.inversions += inversions;
                if self.zero.is_none() {
                    self.zero = zero_msg;
                }
                return Ok(out);
            }
            _ => {}
        }
        let b = &vals[&self.nodes[i].args[1]];
        let w = a.len().max(b.len());
        let (aa, bb) = (Self::bc(a, w), Self::bc(b, w));
        let mut out = Vec::with_capacity(w);
        for (x, y) in aa.iter().zip(bb.iter()) {
            out.push(match (x, y) {
                (Some(x), Some(y)) => Some(match op {
                    Op::Add => (x + y) % nn,
                    Op::Sub => md(&(x - y)),
                    Op::SMul => (x * y) % nn, // public scalar x value: NOT a ciphertext product
                    _ => unreachable!("internal: unknown operator"),
                }),
                _ => None,
            });
        }
        Ok(out)
    }

    /// ONE owner round for every ciphertext x ciphertext product of a level (Pi_mult, batched).
    fn mult_round(&mut self, level_nodes: &[usize], vals: &mut HashMap<usize, Vecn>) -> Result<()> {
        let mut ops: Vec<(usize, usize)> = vec![];
        let mut triples: Vec<(BigInt, BigInt, BigInt)> = vec![];
        let mut openings: Vec<(BigInt, BigInt)> = vec![];
        let mut shapes: HashMap<usize, usize> = HashMap::new();
        for &i in level_nodes {
            let (a0, b0) = (&vals[&self.nodes[i].args[0]], &vals[&self.nodes[i].args[1]]);
            let w = a0.len().max(b0.len());
            let (a, b) = (Self::bc(a0, w), Self::bc(b0, w));
            shapes.insert(i, w);
            for (k, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                let (Some(x), Some(y)) = (x, y) else { continue };
                let (u, v) = (rand_scalar(), rand_scalar()); // a fresh triple per product, never reused
                let w3 = md(&(&u * &v));
                openings.push((md(&(x - &u)), md(&(y - &v))));
                triples.push((u, v, w3));
                ops.push((i, k));
            }
        }
        let max_items = self.c.info.limits.as_ref().and_then(|l| l.max_items).unwrap_or(100_000);
        let step = max_items.clamp(1, 100_000);
        let mut egs: Vec<BigInt> = vec![];
        for part in openings.chunks(step) {
            let wire: Vec<serde_json::Value> = part.iter().map(|(e, g)| json!([e.to_string(), g.to_string()])).collect();
            let v = self.c.call_max("mult_combine_batch", json!([wire]), part.len() * (MAX_DIGITS + 8) + 4096)?;
            for x in arr(&v, "mult_combine_batch", None)? {
                egs.push(big(x, "mult_combine_batch")?);
            }
        }
        if egs.len() != openings.len() {
            return Err(Error::new(Kind::Integrity, "server returned the wrong number of product terms"));
        }
        for &i in level_nodes {
            vals.insert(i, vec![None; shapes[&i]]);
        }
        let auth = self.c.opts.authenticated;
        for (j, &(i, k)) in ops.iter().enumerate() {
            let (e, g) = &openings[j];
            let (u, v, w) = &triples[j];
            if auth && md(&egs[j]) != md(&(e * g)) {
                return Err(Error::new(
                    Kind::Integrity,
                    "server returned a forged product term in an expression (e*g mismatch)",
                ));
            }
            vals.get_mut(&i).unwrap()[k] = Some(md(&(w + e * v + g * u + &egs[j])));
        }
        self.cost.mult_rounds += 1;
        self.cost.products += openings.len();
        Ok(())
    }

    /// Evaluate. Returns the decoded value (agg) or one decoded value (or None) per row.
    pub(crate) fn run(mut self) -> Result<(ExprValue, ExprCost)> {
        let root = self.compile(self.expr);
        let depth = self.nodes.iter().map(|n| n.level).max().unwrap_or(0);
        if depth != self.info.depth {
            // planner/engine disagree: never guess
            return Err(Error::new(
                Kind::Server("ExecError".into()),
                format!("internal: planned multiplicative depth {} != compiled depth {}", self.info.depth, depth),
            ));
        }
        let mut vals: HashMap<usize, Vecn> = HashMap::new();
        for lvl in 0..=depth {
            if lvl > 0 {
                let muls: Vec<usize> =
                    (0..self.nodes.len()).filter(|&i| self.nodes[i].op == Op::CMul && self.nodes[i].level == lvl).collect();
                if !muls.is_empty() {
                    self.mult_round(&muls, &mut vals)?;
                }
            }
            for i in 0..self.nodes.len() {
                if self.nodes[i].level == lvl && self.nodes[i].op != Op::CMul {
                    let v = self.local(i, &vals)?;
                    vals.insert(i, v);
                }
            }
        }
        if let Some(sfx) = &self.zero {
            return Err(Error::new(Kind::DivisionByZero, format!("division by zero: a denominator is 0{}", sfx)));
        }
        self.cost.depth = depth;
        let out = &vals[&root];
        let dec = |v: &Option<BigInt>| -> Result<Option<Decoded>> {
            match v {
                None => Ok(None),
                Some(s) => Ok(Some(decode(s)?)),
            }
        };
        let value = if self.info.kind == "row" {
            let rows = if self.tuples.is_empty() { vec![] } else { Self::bc(out, self.tuples.len()) };
            ExprValue::Rows(rows.iter().map(dec).collect::<Result<Vec<_>>>()?)
        } else {
            ExprValue::Scalar(dec(&out[0])?)
        };
        Ok((value, self.cost))
    }
}
