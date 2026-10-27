// SPDX-License-Identifier: Apache-2.0
//! Owner-side evaluation of `fhe_expr.rs`'s plan: aggregate v0.6.1/v0.6.2 expressions over FHE
//! columns, reached through `Client::expr` / `Client::expr_as` / `Client::join_expr` once the
//! expression references at least one FHE column (dispatch lives in `lib.rs`'s `expr_plan`). A
//! parallel path to `expr_eval.rs` / `expr_shared.rs`: FHE columns never use shared wires (the
//! server holds no key and no share of anything), so every "product" here is either a direct
//! `fhe_mul` RPC (delegated mode, decrypted with the existing `decrypt_dot` - same GT blob shape as
//! `fhe_dot`) or, in local mode, a plaintext multiply after `fhe_reveal` / `fhe_sum`. This mirrors
//! `core/torusdb_core/fhe_expr.py`'s `FheExprRunner` (read its header for the full WHO COMPUTES WHAT
//! account) and the reference port `drivers/typescript/src/torusdb.ts` (search `runFheExpr`,
//! `fheTermValue`, `fheMulDelegated`) line-by-line.
//!
//! **Who computes what**: the SERVER (holds no key, no mask, receives no ciphertext from the owner)
//! performs, in delegated mode, only PUBLIC curve/pairing arithmetic on cells it already stores: a
//! linear combination of the operand ciphertexts with the query's public integer coefficients, then
//! the pairing of the two combined halves (`fhe_mul`); the reply is a GT ciphertext only the owner
//! can open. In local mode the server only ever serves `fhe_sum` aggregates or `fhe_reveal`'d cells
//! (each tag-checked when authenticated); the owner does the multiplication itself. Either way the
//! wire never carries a secret scalar or a plaintext value: only table/column names, row ids, and the
//! small public integers of the query (checked by the wire-audit test).
//!
//! Scope: aggregate expressions only (`SUM(L*R)`, `AL*AR`, plain `SUM`/`AVG`), one table, no joins -
//! exactly what `fhe_expr.rs`'s `analyze_fhe_expr` accepts and what the TypeScript port implements.
//! The core engine additionally offers an un-aggregated per-row *projection* (`analyze(...,
//! allow_row=True)`, e.g. `SELECT a*b FROM t`, `fhe_mul` mode `"row"`); neither this driver nor the
//! TypeScript one expose that entry point, so it stays out of scope here too.

use crate::error::{Error, Kind};
use crate::expr::Frac;
use crate::fhe::{mul_dots, FHE_DOT_BYTES};
use crate::fhe_expr::{operand_at, peval_poly, FheExprPlan, Term};
use crate::field::Decoded;
use crate::{blob, Client, ExprValue, FheDotMode, FHE_DOT_CHUNK, FHE_SUM_CHUNK};
use num_bigint::BigInt;
use num_traits::Signed;
use serde_json::json;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, Error>;

/// Cost of evaluating one FHE-column expression (`Client::last_fhe_expr_cost`); kept separate from
/// `ExprCost` (shared-wire / owner-transport expressions, `expr_eval.rs` / `expr_shared.rs`) because
/// FHE expressions never run over shared wires - there is no server-held share of anything to keep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FheExprCost {
    /// `fhe_mul` RPCs sent (one per row chunk, or one per chunk PAIR for an `AL*AR` term) - delegated mode only.
    pub server_products: usize,
    /// pairings the server computed (4 per row for a `SUM(L*R)` chunk, 4 per chunk pair for `AL*AR`) - delegated mode only.
    pub pairings: usize,
    /// GT ciphertexts opened with `FheKey::decrypt_dot` - delegated mode only.
    pub gt_results: usize,
    /// FHE cells decrypted (`fhe_reveal`) to multiply per-row products locally - local mode only.
    pub decrypted_cells: usize,
    /// product terms in the expression (`SUM(L*R)` / `AL*AR`).
    pub products: usize,
}

fn frac_of(v: BigInt) -> Frac {
    Frac::new(v, BigInt::from(1))
}

impl Client {
    /// `local` mode: the owner reads every operand cell (tag-verified when authenticated) or the
    /// verified SUMs and multiplies the plaintexts itself. `delegated` (the default unless
    /// authenticated): the server pairs the operand ciphertexts and the owner opens the result.
    /// Exactly the same choice `fhe_dot` makes (`ConnectOptions::fhe_dot_mode`).
    fn fhe_expr_local_mode(&self) -> bool {
        match self.opts.fhe_dot_mode {
            FheDotMode::Local => true,
            FheDotMode::Delegated => false,
            FheDotMode::Auto => self.opts.authenticated && !self.opts.fhe_allow_unverified_dot,
        }
    }

    /// Run a validated FHE expression plan over `ids` (already filtered by the WHERE predicate).
    pub(crate) fn run_fhe_expr(&mut self, table: &str, fx: &FheExprPlan, ids: &[i64]) -> Result<ExprValue> {
        self.last_fhe_expr_cost = None;
        self.fhe_key()?; // throws early if no key is loaded, exactly like `fhe_dot` / the TS/Python ports
        let n = ids.len() as i64;
        let local = self.fhe_expr_local_mode();
        let mut cost = FheExprCost { products: fx.products, ..Default::default() };
        let mut sums: HashMap<String, i64> = HashMap::new();
        let mut cols: HashMap<String, Vec<i64>> = HashMap::new();
        let run = (|| -> Result<Option<Frac>> {
            let mut total = match peval_poly(&fx.const_, n) {
                Some(c) => c,
                None => return Ok(None), // AVG over no rows: the result is NULL
            };
            for (coef, term) in &fx.terms {
                let f = match peval_poly(coef, n) {
                    Some(f) => f,
                    None => return Ok(None),
                };
                if n == 0 {
                    continue;
                }
                let v = self.fhe_term_value(table, ids, term, local, &mut sums, &mut cols, &mut cost)?;
                total = total.add(&f.mul(&frac_of(v)));
            }
            Ok(Some(total))
        })();
        self.last_fhe_expr_cost = Some(cost);
        let total = run?;
        Ok(ExprValue::Scalar(total.map(|t| if t.is_int() { Decoded::Int(t.num) } else { Decoded::Rational(t.num, t.den) })))
    }

    /// One term of an FHE expression: a plain `SUM(col)` (reuses `fhe_sum`), or a product term,
    /// computed either locally or by the server's pairing (`fhe_mul`, decrypted once by the owner).
    #[allow(clippy::too_many_arguments)]
    fn fhe_term_value(
        &mut self,
        table: &str,
        ids: &[i64],
        term: &Term,
        local: bool,
        sums: &mut HashMap<String, i64>,
        cols: &mut HashMap<String, Vec<i64>>,
        cost: &mut FheExprCost,
    ) -> Result<BigInt> {
        match term {
            Term::Sum(col) => Ok(BigInt::from(self.fhe_sum_cached(table, col, ids, sums)?)),
            Term::SumProd(l, r) | Term::AggProd(l, r) => {
                let is_sum = matches!(term, Term::SumProd(..));
                let n = ids.len() as i64;
                let (lt, lc) = operand_at(l, n)?;
                let (rt, rc) = operand_at(r, n)?;
                if local {
                    let key = self.fhe_key()?.clone();
                    let v = if is_sum {
                        let a = self.fhe_lin_rows(table, &lt, lc, ids, cols, cost)?;
                        let b = self.fhe_lin_rows(table, &rt, rc, ids, cols, cost)?;
                        let mut total = BigInt::from(0);
                        for (x, y) in a.iter().zip(b.iter()) {
                            total += x * y;
                        }
                        total
                    } else {
                        let mut a = BigInt::from(lc);
                        for (col, k) in &lt {
                            a += BigInt::from(*k) * BigInt::from(self.fhe_sum_cached(table, col, ids, sums)?);
                        }
                        let mut b = BigInt::from(rc);
                        for (col, k) in &rt {
                            b += BigInt::from(*k) * BigInt::from(self.fhe_sum_cached(table, col, ids, sums)?);
                        }
                        a * b
                    };
                    if v.abs() > BigInt::from(key.range()) {
                        return Err(Error::budget("result is outside the key's value range (or the ciphertext is invalid)"));
                    }
                    Ok(v)
                } else {
                    let blob = self.fhe_mul_delegated(table, ids, is_sum, &lt, lc, &rt, rc, cost)?;
                    cost.gt_results += 1;
                    let key = self.fhe_key()?.clone();
                    Ok(BigInt::from(key.decrypt_dot(&blob)?))
                }
            }
            Term::Lin(_) | Term::Prod(..) => {
                Err(Error::new(Kind::Server("ExecError".into()), "internal: unexpected row-level FHE term in an aggregate expression"))
            }
        }
    }

    fn fhe_sum_cached(&mut self, table: &str, col: &str, ids: &[i64], cache: &mut HashMap<String, i64>) -> Result<i64> {
        if let Some(v) = cache.get(col) {
            return Ok(*v);
        }
        let v = self.fhe_sum(table, col, ids, &BigInt::from(1))?;
        cache.insert(col.to_string(), v);
        Ok(v)
    }

    /// The per-row value `c + Σ k·col[i]` of a validated operand, revealing (and caching) each
    /// referenced column once.
    #[allow(clippy::needless_range_loop)] // `row` indexes every one of `terms`' column vectors together
    fn fhe_lin_rows(
        &mut self,
        table: &str,
        terms: &[(String, i64)],
        c: i64,
        ids: &[i64],
        cache: &mut HashMap<String, Vec<i64>>,
        cost: &mut FheExprCost,
    ) -> Result<Vec<BigInt>> {
        let mut colvals: Vec<Vec<i64>> = Vec::with_capacity(terms.len());
        for (col, _) in terms {
            if let Some(v) = cache.get(col) {
                colvals.push(v.clone());
                continue;
            }
            let v = self.fhe_reveal(table, col, ids)?;
            cost.decrypted_cells += v.len();
            cache.insert(col.clone(), v.clone());
            colvals.push(v);
        }
        let mut out = Vec::with_capacity(ids.len());
        for row in 0..ids.len() {
            let mut v = BigInt::from(c);
            for (ci, (_, k)) in terms.iter().enumerate() {
                v += BigInt::from(*k) * BigInt::from(colvals[ci][row]);
            }
            out.push(v);
        }
        Ok(out)
    }

    /// `fhe_mul` RPC, chunked: `is_sum` is `SUM(L*R)` (rows chunked, blobs combine by bilinearity);
    /// else `AL*AR` (both sides chunked, m^2 requests for m chunks, the operand constants riding on
    /// chunk 0 only - matching `proto/fhe-wire.md`'s `fhe_mul` and the TypeScript port exactly,
    /// including sizing every chunk for the `pyecc` back end (no `backend` hint is sent: the server's
    /// own default decides, and the blob's own tag byte says which one answered).
    #[allow(clippy::too_many_arguments)]
    fn fhe_mul_delegated(
        &mut self,
        table: &str,
        ids: &[i64],
        is_sum: bool,
        lt: &[(String, i64)],
        lc: i64,
        rt: &[(String, i64)],
        rc: i64,
        cost: &mut FheExprCost,
    ) -> Result<Vec<u8>> {
        let lterms: Vec<serde_json::Value> = lt.iter().map(|(c, k)| json!([c, k])).collect();
        let rterms: Vec<serde_json::Value> = rt.iter().map(|(c, k)| json!([c, k])).collect();
        let lim = self.info.limits.as_ref().and_then(|l| l.fhe.as_ref());
        let mut total: Option<Vec<u8>> = None;
        if is_sum {
            let mut cap = lim.and_then(|f| f.recommended_dot_rows.pyecc).unwrap_or(FHE_DOT_CHUNK).max(1);
            cap = cap.min(lim.and_then(|f| f.max_dot_rows.pyecc).unwrap_or(cap)).max(1);
            if let Some(work) = lim.and_then(|f| f.max_mul_work.pyecc) {
                cap = cap.min(work / (lt.len() + rt.len()).max(1)).max(1);
            }
            for part in ids.chunks(cap) {
                let args = json!([table, "sum", part, serde_json::Value::Null, lterms, lc, rterms, rc]);
                let b = blob(&self.call_max("fhe_mul", args, 8192)?, "fhe_mul", FHE_DOT_BYTES)?;
                total = Some(match total {
                    None => b,
                    Some(t) => mul_dots(&t, &b)?,
                });
                cost.pairings += 4 * part.len();
                cost.server_products += 1;
            }
            return Ok(total.unwrap());
        }
        let step = lim
            .and_then(|f| f.max_mul_agg_rows.pyecc)
            .unwrap_or_else(|| FHE_SUM_CHUNK.min(lim.and_then(|f| f.max_sum_rows).unwrap_or(FHE_SUM_CHUNK)))
            .max(1);
        let chunks: Vec<&[i64]> = ids.chunks(step).collect();
        for (u, cu) in chunks.iter().enumerate() {
            for (v, cv) in chunks.iter().enumerate() {
                let args = json!([
                    table,
                    "agg",
                    cu,
                    cv,
                    lterms,
                    if u == 0 { lc } else { 0 },
                    rterms,
                    if v == 0 { rc } else { 0 }
                ]);
                let b = blob(&self.call_max("fhe_mul", args, 8192)?, "fhe_mul", FHE_DOT_BYTES)?;
                total = Some(match total {
                    None => b,
                    Some(t) => mul_dots(&t, &b)?,
                });
                cost.pairings += 4;
                cost.server_products += 1;
            }
        }
        Ok(total.unwrap())
    }
}
