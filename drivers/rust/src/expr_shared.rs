// SPDX-License-Identifier: Apache-2.0
//! Shared-wire evaluation of TorusSQL v0.6 arithmetic expressions (`ExprMode::Shared`, the default): the
//! paper's circuit composition Pi_C (Lee, "No-Key Delegation of EC-FHE", Construction 20) with every wire
//! held as a TWO-PARTY ADDITIVE SHARING over Z/nZ - the owner's half of the protocol. A port of
//! `core/torusdb_core/expr_shared.py` (the reference; the server half is `wires.py`). Read the header of that
//! file for the full account; in short:
//!
//! Every wire X (a column, a literal-scaled sum, a product, a quotient...) is X = X_S + X_O (mod n). A stored
//! cell is x~ = x + r, so a LOADED wire has X_S = x~ (the server's own stored value) and X_O = -r (the mask the
//! owner already holds). Nothing else is ever sent about a loaded column.
//!
//! * the SERVER (a session-scoped wire store) applies every linear gate to ITS share, computes ITS share of
//!   every Beaver product and keeps the result as a NEW server-resident wire. It never receives a key, a mask,
//!   a MAC key or anything derived from a plaintext except uniform shares and openings; it never decodes; it
//!   never learns a product, quotient or the result (it only SENDS its share of the result wire(s) to the
//!   owner).
//! * the OWNER (this file) applies the same linear gates to ITS shares (local arithmetic), deals one Beaver
//!   triple (u, v, w = uv) per product ELEMENT - the server gets only its additive SHARES of it - computes ITS
//!   share of each product and finally adds the server's share of the result wire to its own and decodes
//!   (strict: OutOfBudget). It fetches no operand cell and unmasks no operand or intermediate. (This O(rows)
//!   owner work is inherent to unconditionally secure two-party computation; the owner is also the DEALER, so
//!   a curious owner process could derive the operands from its own openings - that is a property of this
//!   code, not a cryptographic guarantee; see docs/crypto-review-packet.md 3.3.)
//! * one request/response per multiplicative level (batched over all products and rows of the level); a
//!   division by an ENCRYPTED y deals a fresh uniform non-zero rho, forms [t] = [rho]*[y] by a Beaver product,
//!   OPENS t = rho*y (MAC-checked in authenticated mode, BEFORE the zero test), and sets [1/y] = t^-1 * [rho]
//!   (a public-scalar multiplication). A zero t is replaced by a fresh random non-zero dummy before anything
//!   goes back, the protocol runs to its last request, and only then `DivisionByZero` is raised: the request
//!   sequence is the same whether or not a denominator was zero.
//! * authenticated mode: every wire carries a share of its SPDZ tag alpha*X (alpha known only to the owner);
//!   every opening and the revealed result are MAC-checked by the owner.
//! * every wire the query created is dropped with `wire_free` on EVERY exit path (success needs none: the
//!   last request frees everything after the reveal).

use crate::error::{Error, Kind};
use crate::expr_eval::{ring, Data, ExprCost, ExprMode, ExprRunner, ExprValue, Op, Vecn};
use crate::field::{decode, md, mod_inv, n, rand_scalar};
use crate::WireLimits;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

type Result<T> = std::result::Result<T, Error>;

const MAX_RING_DIGITS: usize = 80;

fn integrity(m: impl Into<String>) -> Error {
    Error::new(Kind::Integrity, m)
}
fn proto(m: impl Into<String>) -> Error {
    Error::new(Kind::Protocol, m)
}

/// A node's value. Public (`wid` None): `pubv` holds the ring elements (None = dead). Shared: `wid` is the
/// server wire, `own` the owner's value shares, `ownm` its tag shares (authenticated mode) and `live` the
/// positions that exist (None = all).
#[derive(Clone, Default)]
struct V {
    w: usize,
    pubv: Option<Vecn>,
    wid: Option<String>,
    own: Vec<BigInt>,
    ownm: Option<Vec<BigInt>>,
    live: Option<Vec<bool>>,
}

/// Triple shares (server side or owner side).
#[derive(Clone, Default)]
struct Tri {
    u: Vec<BigInt>,
    v: Vec<BigInt>,
    w: Vec<BigInt>,
    mu: Vec<BigInt>,
    mv: Vec<BigInt>,
    mw: Vec<BigInt>,
}

struct MulJob {
    a: usize,
    b: usize,
    res: usize,
    lo: usize,
    k: usize,
    eo: Vec<BigInt>,
    go: Vec<BigInt>,
    o: Tri,
}

enum Handler {
    None,
    Mul(Box<MulJob>),
    Reveal { sink: usize, lo: usize, k: usize },
}

struct Pend {
    op: Value,
    cost: usize,
    h: Handler,
}

#[derive(Default)]
struct Sink {
    z: Vec<BigInt>,
    m: Vec<BigInt>,
}

enum Post {
    /// the opened t = rho*y of a division is ready: build the multipliers t^-1
    Inv { i: usize, y_live: Option<Vec<bool>>, rho: usize, prod: usize, sink: usize },
}

struct InvState {
    rho: usize,
    tinv: Vec<BigInt>,
    live: Option<Vec<bool>>,
}

#[derive(Default)]
struct Counters {
    openings: usize,
    wires: usize,
    requests: usize,
    reveals: usize,
}

fn svec(v: &[BigInt]) -> Value {
    Value::Array(v.iter().map(|x| Value::String(x.to_string())).collect())
}

fn rep<T: Clone>(xs: &[T], n: usize) -> Vec<T> {
    let mut out = Vec::with_capacity(xs.len() * n);
    for _ in 0..n {
        out.extend(xs.iter().cloned());
    }
    out
}

/// Liveness of a binary result at width `w` (a position is live iff it is live in both operands).
fn and_live(a: &Option<Vec<bool>>, b: &Option<Vec<bool>>, w: usize) -> Option<Vec<bool>> {
    if a.is_none() && b.is_none() {
        return None;
    }
    let x = match a {
        None => vec![true; w],
        Some(a) if a.len() == w => a.clone(),
        Some(a) => rep(a, w),
    };
    let y = match b {
        None => vec![true; w],
        Some(b) if b.len() == w => b.clone(),
        Some(b) => rep(b, w),
    };
    Some(x.iter().zip(&y).map(|(p, q)| *p && *q).collect())
}

fn ring_str(v: &Value, what: &str) -> Result<BigInt> {
    match v.as_str() {
        Some(s) if !s.is_empty() && s.len() <= MAX_RING_DIGITS && s.bytes().all(|c| c.is_ascii_digit()) => {
            Ok(s.parse::<BigInt>().expect("digits"))
        }
        _ => Err(proto(format!("bad ring element in {}", what))),
    }
}

fn vec_or_null(v: &Value, what: &str) -> Result<Option<Vec<BigInt>>> {
    match v {
        Value::Null => Ok(None),
        Value::Array(xs) => xs.iter().map(|x| ring_str(x, what)).collect::<Result<Vec<_>>>().map(Some),
        _ => Err(proto(format!("{}: expected a list", what))),
    }
}

pub(crate) struct SharedRunner<'a> {
    b: ExprRunner<'a>,
    auth: bool,
    alpha: BigInt,
    nn: BigInt,
    qid: String,
    seq: usize,
    pending: Vec<Pend>,
    post: Vec<Post>,
    tofree: Vec<String>,
    live_ids: BTreeSet<String>,
    arena: Vec<V>,
    sinks: Vec<Sink>,
    inv: HashMap<usize, InvState>,
    mask_cache: HashMap<(String, i64, String), BigInt>,
    budget: usize,
    max_ops: usize,
    chunk: usize,
    cc: Counters,
}

impl<'a> SharedRunner<'a> {
    pub(crate) fn new(b: ExprRunner<'a>) -> Self {
        let auth = b.c.opts.authenticated;
        let alpha = if auth { b.c.alpha.clone() } else { BigInt::zero() };
        let mut q = [0u8; 6];
        for x in q.iter_mut() {
            *x = rand::random::<u8>();
        }
        let qid: String = q.iter().map(|x| format!("{:02x}", x)).collect();
        SharedRunner {
            b: b.with_inv_levels(1),
            auth,
            alpha,
            nn: n().clone(),
            qid,
            seq: 0,
            pending: vec![],
            post: vec![],
            tofree: vec![],
            live_ids: BTreeSet::new(),
            arena: vec![],
            sinks: vec![],
            inv: HashMap::new(),
            mask_cache: HashMap::new(),
            budget: 100_000,
            max_ops: 10_000,
            chunk: 11_111,
            cc: Counters::default(),
        }
    }

    // ── plumbing ─────────────────────────────────────────────────────────────
    fn setup_limits(&mut self) -> Result<()> {
        let lim: Option<WireLimits> = self.b.c.info.limits.as_ref().and_then(|l| l.wires.clone());
        let Some(lim) = lim else {
            return Err(Error::new(
                Kind::Server("ExecError".into()),
                "this server does not offer the shared-wire RPCs (wire_exec); connect with \
                 expression_mode: ExprMode::Owner (expr_mode='owner' in the Python driver) to evaluate expressions the v0.6 \
                 way (the owner unmasks the operand cells), or upgrade the server",
            ));
        };
        self.budget = lim.max_request_elements.unwrap_or(self.budget);
        self.max_ops = lim.max_ops.unwrap_or(self.max_ops);
        self.chunk = (self.budget / 9).max(1);
        Ok(())
    }

    fn new_wire(&mut self) -> String {
        self.seq += 1;
        let wid = format!("{}.{}", self.qid, self.seq);
        self.live_ids.insert(wid.clone());
        self.cc.wires += 1;
        wid
    }

    fn push(&mut self, v: V) -> usize {
        self.arena.push(v);
        self.arena.len() - 1
    }

    fn emit(&mut self, op: Value, cost: usize, h: Handler) {
        self.pending.push(Pend { op, cost, h });
    }

    fn free_after(&mut self, wid: &Option<String>) {
        if let Some(w) = wid {
            self.tofree.push(w.clone());
        }
    }

    fn shared(&self, v: usize) -> bool {
        self.arena[v].wid.is_some()
    }

    fn wid(&self, v: usize) -> String {
        self.arena[v].wid.clone().expect("a shared value")
    }

    fn m(&self, a: &BigInt) -> BigInt {
        md(a)
    }

    fn vec_ok(&self, x: Option<Vec<BigInt>>, k: usize, what: &str) -> Result<Vec<BigInt>> {
        match x {
            Some(v) if v.len() == k && v.iter().all(|e| *e < self.nn) => Ok(v),
            _ => Err(integrity(format!("server returned a malformed {}", what))),
        }
    }

    fn flush(&mut self) -> Result<()> {
        let mut pend = std::mem::take(&mut self.pending);
        let mut freed: Vec<String> = vec![];
        if !self.tofree.is_empty() {
            freed = std::mem::take(&mut self.tofree);
            for part in freed.chunks(2000) {
                pend.push(Pend { op: json!(["free", part]), cost: 0, h: Handler::None });
            }
        }
        let mut groups: Vec<Vec<Pend>> = vec![];
        let (mut cur, mut used): (Vec<Pend>, usize) = (vec![], 0);
        for ent in pend {
            if !cur.is_empty() && (used + ent.cost > self.budget || cur.len() >= self.max_ops) {
                groups.push(std::mem::take(&mut cur));
                used = 0;
            }
            used += ent.cost;
            cur.push(ent);
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
        for grp in groups {
            let mut reply_elems = 0usize;
            for e in &grp {
                match e.op[0].as_str() {
                    Some("mul") => reply_elems += 4 * e.op[4]["u"].as_array().map(|a| a.len()).unwrap_or(0),
                    Some("reveal") => reply_elems += 2 * e.op[3].as_u64().unwrap_or(0) as usize,
                    _ => {}
                }
            }
            let ops: Vec<Value> = grp.iter().map(|e| e.op.clone()).collect();
            let max_reply = reply_elems * (MAX_RING_DIGITS + 8) + ops.len() * 16 + 4096;
            let reply = self.b.c.call_max("wire_exec", json!([ops]), max_reply)?;
            self.cc.requests += 1;
            let res = match reply.as_array() {
                Some(r) if r.len() == grp.len() => r.clone(),
                _ => return Err(integrity("server answered the wrong number of wire operations")),
            };
            // decode every reply first (a malformed one is a typed error before any handler runs)
            let mut decoded: Vec<Vec<Option<Vec<BigInt>>>> = vec![];
            for (ent, r) in grp.iter().zip(&res) {
                decoded.push(match ent.op[0].as_str() {
                    Some("mul") => {
                        let a = r.as_array().filter(|a| a.len() == 4).ok_or_else(|| integrity("server returned a malformed product reply"))?;
                        a.iter().map(|x| vec_or_null(x, "mul")).collect::<Result<Vec<_>>>()?
                    }
                    Some("reveal") => {
                        let a = r.as_array().filter(|a| a.len() == 2).ok_or_else(|| integrity("server returned a malformed reveal reply"))?;
                        a.iter().map(|x| vec_or_null(x, "reveal")).collect::<Result<Vec<_>>>()?
                    }
                    _ => vec![],
                });
            }
            for (ent, r) in grp.into_iter().zip(decoded) {
                match ent.h {
                    Handler::None => {}
                    Handler::Mul(job) => self.on_mul(r, *job)?,
                    Handler::Reveal { sink, lo, k } => self.on_reveal(r, sink, lo, k)?,
                }
            }
        }
        for w in &freed {
            self.live_ids.remove(w); // only now: a failed flush must still free them
        }
        for p in std::mem::take(&mut self.post) {
            self.run_post(p)?;
        }
        Ok(())
    }

    /// Drop whatever this query still holds on the server (best effort, never fails).
    fn cleanup(&mut self) {
        self.pending.clear();
        self.post.clear();
        let mut ids: Vec<String> = self.live_ids.iter().cloned().collect();
        for t in &self.tofree {
            if !self.live_ids.contains(t) {
                ids.push(t.clone());
            }
        }
        self.live_ids.clear();
        self.tofree.clear();
        for part in ids.chunks(2000) {
            if self.b.c.call_max("wire_free", json!([part]), 4096).is_err() {
                return;
            }
        }
    }

    // ── public-value helpers ─────────────────────────────────────────────────
    fn span_ops(&mut self, name: &str, out: &str, a: &str, vec: &[BigInt], w: usize) {
        if vec.is_empty() {
            self.emit(json!([name, out, a, [], 0, w]), 0, Handler::None);
            return;
        }
        let mut lo = 0;
        while lo < vec.len() {
            let part = &vec[lo..(lo + self.chunk).min(vec.len())];
            self.emit(json!([name, out, a, svec(part), lo, w]), part.len(), Handler::None);
            lo += self.chunk;
        }
    }

    fn bcast(&mut self, v: usize, w: usize) -> Result<usize> {
        let vv = self.arena[v].clone();
        if vv.w == w {
            return Ok(v);
        }
        if vv.w != 1 {
            return Err(Error::new(Kind::Server("ExecError".into()), "internal: operand widths are neither equal nor scalar"));
        }
        if vv.wid.is_none() {
            let p = rep(vv.pubv.as_ref().unwrap(), w);
            return Ok(self.push(V { w, pubv: Some(p), ..Default::default() }));
        }
        let out = self.new_wire();
        self.emit(json!(["bc", out, vv.wid.clone().unwrap(), w]), 0, Handler::None);
        self.free_after(&Some(out.clone()));
        Ok(self.push(V {
            w,
            pubv: None,
            wid: Some(out),
            own: rep(&vv.own, w),
            ownm: vv.ownm.as_ref().map(|m| rep(m, w)),
            live: vv.live.as_ref().map(|l| rep(l, w)),
        }))
    }

    fn wd(&self, a: usize, b: usize) -> usize {
        let (x, y) = (self.arena[a].w, self.arena[b].w);
        if x == 0 || y == 0 {
            0
        } else {
            x.max(y)
        }
    }

    // ── gates on shared values (owner shares + server ops) ───────────────────
    fn g_neg(&mut self, a: usize) -> usize {
        let av = self.arena[a].clone();
        let out = self.new_wire();
        self.emit(json!(["neg", out, av.wid.clone().unwrap()]), 0, Handler::None);
        let own = av.own.iter().map(|x| self.m(&-x)).collect();
        let ownm = av.ownm.as_ref().map(|m| m.iter().map(|x| self.m(&-x)).collect());
        self.push(V { w: av.w, pubv: None, wid: Some(out), own, ownm, live: av.live })
    }

    /// `live`: `None` = keep the operand's liveness; `Some(l)` = replace it by `l` (itself optional).
    fn g_mulc(&mut self, a: usize, k: &BigInt, live: Option<Option<Vec<bool>>>) -> usize {
        let av = self.arena[a].clone();
        let out = self.new_wire();
        let k = self.m(k);
        self.emit(json!(["mulc", out, av.wid.clone().unwrap(), k.to_string()]), 0, Handler::None);
        let nn = &self.nn;
        let own = av.own.iter().map(|x| x * &k % nn).collect();
        let ownm = av.ownm.as_ref().map(|m| m.iter().map(|x| x * &k % nn).collect());
        let live = match live {
            None => av.live.clone(),
            Some(l) => l,
        };
        self.push(V { w: av.w, pubv: None, wid: Some(out), own, ownm, live })
    }

    fn g_mulv(&mut self, a: usize, vec: &[BigInt], live: Option<Vec<bool>>) -> usize {
        let av = self.arena[a].clone();
        let out = self.new_wire();
        self.span_ops("mulv", &out, av.wid.as_ref().unwrap(), vec, av.w);
        let nn = &self.nn;
        let own = av.own.iter().zip(vec).map(|(x, y)| x * y % nn).collect();
        let ownm = av.ownm.as_ref().map(|m| m.iter().zip(vec).map(|(x, y)| x * y % nn).collect());
        self.push(V { w: av.w, pubv: None, wid: Some(out), own, ownm, live })
    }

    fn g_addc(&mut self, a: usize, c: &BigInt, live: Option<Vec<bool>>) -> usize {
        let av = self.arena[a].clone();
        let out = self.new_wire();
        let c = self.m(c);
        self.emit(json!(["addc", out, av.wid.clone().unwrap(), c.to_string()]), 0, Handler::None);
        let ownm = av.ownm.as_ref().map(|m| m.iter().map(|x| (x + &self.alpha * &c) % &self.nn).collect());
        self.push(V { w: av.w, pubv: None, wid: Some(out), own: av.own.clone(), ownm, live })
    }

    fn g_addv(&mut self, a: usize, vec: &[BigInt], live: Option<Vec<bool>>) -> usize {
        let av = self.arena[a].clone();
        let out = self.new_wire();
        self.span_ops("addv", &out, av.wid.as_ref().unwrap(), vec, av.w);
        let ownm = av.ownm.as_ref().map(|m| m.iter().zip(vec).map(|(x, y)| (x + &self.alpha * y) % &self.nn).collect());
        self.push(V { w: av.w, pubv: None, wid: Some(out), own: av.own.clone(), ownm, live })
    }

    fn g_addsub(&mut self, op: &str, a: usize, b: usize) -> Result<usize> {
        let w = self.wd(a, b);
        let (a, b) = (self.bcast(a, w)?, self.bcast(b, w)?);
        let (av, bv) = (self.arena[a].clone(), self.arena[b].clone());
        let out = self.new_wire();
        self.emit(json!([op, out, av.wid.clone().unwrap(), bv.wid.clone().unwrap()]), 0, Handler::None);
        let add = op == "add";
        let nn = &self.nn;
        let f = |x: &BigInt, y: &BigInt| if add { (x + y) % nn } else { md(&(x - y)) };
        let own = av.own.iter().zip(&bv.own).map(|(x, y)| f(x, y)).collect();
        let ownm = match (&av.ownm, &bv.ownm) {
            (Some(x), Some(y)) => Some(x.iter().zip(y).map(|(p, q)| f(p, q)).collect()),
            _ => None,
        };
        let live = and_live(&av.live, &bv.live, w);
        Ok(self.push(V { w, pubv: None, wid: Some(out), own, ownm, live }))
    }

    /// (scalar, vector, live) of a public operand; dead -> 0. Exactly one of scalar / vector is Some.
    fn pub_parts(&self, p: usize) -> (Option<BigInt>, Option<Vec<BigInt>>, Option<Vec<bool>>) {
        let pv = &self.arena[p];
        let vals = pv.pubv.as_ref().unwrap();
        if pv.w == 1 {
            return match &vals[0] {
                None => (Some(BigInt::zero()), None, Some(vec![false])),
                Some(x) => (Some(x.clone()), None, None),
            };
        }
        let v: Vec<BigInt> = vals.iter().map(|x| x.clone().unwrap_or_else(BigInt::zero)).collect();
        let alive: Vec<bool> = vals.iter().map(|x| x.is_some()).collect();
        let live = if alive.iter().all(|x| *x) { None } else { Some(alive) };
        (None, Some(v), live)
    }

    /// Shared `s` with public `p`: op in add / sub / smul (`flip`: p - s).
    fn g_pub(&mut self, op: &str, s: usize, p: usize, flip: bool) -> Result<usize> {
        let (mut sc, mut vec, plive) = self.pub_parts(p);
        let mut s = s;
        let pw = self.arena[p].w;
        if vec.is_some() && self.arena[s].w != pw {
            s = self.bcast(s, pw)?;
        }
        let sw = self.arena[s].w;
        let mut live = self.arena[s].live.clone();
        if let Some(pl) = plive {
            live = if vec.is_none() {
                Some(vec![false; sw]) // a dead scalar kills every position
            } else {
                match live {
                    None => Some(pl),
                    Some(l) => Some(l.iter().zip(&pl).map(|(x, y)| *x && *y).collect()),
                }
            };
        }
        if op == "smul" {
            return Ok(match &vec {
                None => self.g_mulc(s, sc.as_ref().unwrap(), Some(live)),
                Some(v) => self.g_mulv(s, v, live),
            });
        }
        if flip {
            s = self.g_neg(s); // p - s = (-s) + p
            let wid = self.arena[s].wid.clone();
            self.free_after(&wid);
        } else if op == "sub" {
            sc = sc.map(|x| md(&-x));
            vec = vec.map(|v| v.iter().map(|x| md(&-x)).collect());
        }
        Ok(match &vec {
            None => self.g_addc(s, sc.as_ref().unwrap(), live),
            Some(v) => self.g_addv(s, v, live),
        })
    }

    fn g_sum(&mut self, a: usize) -> usize {
        let mut a = a;
        let dead = matches!(&self.arena[a].live, Some(l) if !l.iter().all(|x| *x));
        if dead {
            // dead positions must not contribute
            let mask: Vec<BigInt> = self.arena[a].live.as_ref().unwrap().iter().map(|x| if *x { BigInt::one() } else { BigInt::zero() }).collect();
            a = self.g_mulv(a, &mask, None);
            let wid = self.arena[a].wid.clone();
            self.free_after(&wid);
        }
        let av = self.arena[a].clone();
        let out = self.new_wire();
        self.emit(json!(["sum", out, av.wid.clone().unwrap()]), 0, Handler::None);
        let sum = |xs: &Vec<BigInt>| -> BigInt { xs.iter().fold(BigInt::zero(), |p, q| p + q) % &self.nn };
        let own = vec![sum(&av.own)];
        let ownm = av.ownm.as_ref().map(|m| vec![sum(m)]);
        self.push(V { w: 1, pubv: None, wid: Some(out), own, ownm, live: None })
    }

    // ── leaves ───────────────────────────────────────────────────────────────
    fn mask_of(&mut self, table: &str, id: i64, col: &str) -> Result<BigInt> {
        let key = (table.to_string(), id, col.to_string());
        if let Some(m) = self.mask_cache.get(&key) {
            return Ok(m.clone());
        }
        let m = self.b.c.mask(table, id, col)?.clone();
        self.mask_cache.insert(key, m.clone());
        Ok(m)
    }

    fn load(&mut self, name: &str) -> Result<usize> {
        let (alias, col) = self.b.loc(name).clone();
        let table = self.b.table(&alias).to_string();
        let p = self.b.pos(&alias);
        let ids: Vec<Option<i64>> = self.b.tuples.iter().map(|t| t[p]).collect();
        let mut own = Vec::with_capacity(ids.len());
        let mut ownm = if self.auth { Some(Vec::with_capacity(ids.len())) } else { None };
        for id in &ids {
            match id {
                None => {
                    own.push(BigInt::zero());
                    if let Some(m) = ownm.as_mut() {
                        m.push(BigInt::zero());
                    }
                }
                Some(i) => {
                    own.push(md(&-self.mask_of(&table, *i, &col)?));
                    if self.auth {
                        let mk = self.mask_of(&table, *i, &format!("__mac__{}", col))?;
                        ownm.as_mut().unwrap().push(md(&-mk));
                    }
                }
            }
        }
        let out = self.new_wire();
        if ids.is_empty() {
            self.emit(json!(["load", out, table, col, [], self.auth, 0, 0]), 0, Handler::None);
        }
        let mut lo = 0;
        while lo < ids.len() {
            let part = &ids[lo..(lo + self.chunk).min(ids.len())];
            self.emit(json!(["load", out, table, col, part, self.auth, lo, ids.len()]), part.len(), Handler::None);
            lo += self.chunk;
        }
        let live = if ids.iter().all(|i| i.is_some()) { None } else { Some(ids.iter().map(|i| i.is_some()).collect()) };
        Ok(self.push(V { w: ids.len(), pubv: None, wid: Some(out), own, ownm, live }))
    }

    fn linsum(&mut self, i: usize) -> Result<usize> {
        let (f, lin) = match &self.b.nodes[i].data {
            Data::Lin(f, l) => (*f, l.clone()),
            _ => unreachable!(),
        };
        let names: Vec<String> = lin.coef.iter().map(|(k, _)| k.clone()).collect();
        let valid: Vec<Vec<Option<i64>>> = self.b.valid_tuples(&names).into_iter().cloned().collect();
        let cnt = valid.len();
        let mut acc: Option<usize> = None;
        for (name, k) in &lin.coef {
            if k.is_zero() {
                continue;
            }
            let (alias, col) = self.b.loc(name).clone();
            let table = self.b.table(&alias).to_string();
            let p = self.b.pos(&alias);
            let ids: Vec<i64> = valid.iter().map(|t| t[p].unwrap()).collect();
            self.b.cost.linear_sums += 1;
            if ids.is_empty() {
                continue;
            }
            let out = self.new_wire();
            let mut lo = 0;
            while lo < ids.len() {
                let part = &ids[lo..(lo + self.chunk).min(ids.len())];
                self.emit(json!(["loadsum", out, table, col, part, self.auth, lo > 0]), part.len(), Handler::None);
                lo += self.chunk;
            }
            let (mut sm, mut smm) = (BigInt::zero(), BigInt::zero());
            for id in &ids {
                sm += self.mask_of(&table, *id, &col)?;
                if self.auth {
                    smm += self.mask_of(&table, *id, &format!("__mac__{}", col))?;
                }
            }
            let v0 = self.push(V {
                w: 1,
                pubv: None,
                wid: Some(out.clone()),
                own: vec![md(&-sm)],
                ownm: if self.auth { Some(vec![md(&-smm)]) } else { None },
                live: None,
            });
            let v = self.g_mulc(v0, &ring(k), None);
            self.free_after(&Some(out));
            acc = Some(match acc {
                None => v,
                Some(a) => {
                    let nw = self.g_addsub("add", a, v)?;
                    let (wa, wv) = (self.arena[a].wid.clone(), self.arena[v].wid.clone());
                    self.free_after(&wa);
                    self.free_after(&wv);
                    nw
                }
            });
        }
        let c0 = if !lin.konst.is_zero() { ring(&lin.konst) * BigInt::from(cnt) % &self.nn } else { BigInt::zero() };
        let total = match acc {
            None => self.push(V { w: 1, pubv: Some(vec![Some(c0)]), ..Default::default() }),
            Some(a) if !c0.is_zero() => {
                let t = self.g_addc(a, &c0, None);
                let wa = self.arena[a].wid.clone();
                self.free_after(&wa);
                t
            }
            Some(a) => a,
        };
        if f == "AVG" {
            if valid.is_empty() {
                return Ok(self.push(V { w: 1, pubv: Some(vec![None]), ..Default::default() }));
            }
            let inv = mod_inv(&BigInt::from(cnt));
            if !self.shared(total) {
                let x = self.arena[total].pubv.as_ref().unwrap()[0].clone().unwrap();
                return Ok(self.push(V { w: 1, pubv: Some(vec![Some(x * inv % &self.nn)]), ..Default::default() }));
            }
            let out = self.g_mulc(total, &inv, None);
            let wt = self.arena[total].wid.clone();
            self.free_after(&wt);
            return Ok(out);
        }
        Ok(total)
    }

    // ── the pass over the DAG ────────────────────────────────────────────────
    fn compute_node(&mut self, i: usize, vals: &mut [Option<usize>]) -> Result<()> {
        if self.inv.contains_key(&i) {
            // an inversion started one level earlier
            let v = self.inv_finish(i);
            vals[i] = Some(v);
            return Ok(());
        }
        let op = self.b.nodes[i].op;
        let enc = self.b.nodes[i].enc;
        let args = self.b.nodes[i].args.clone();
        let avs: Vec<usize> = args.iter().map(|a| vals[*a].expect("operand alive")).collect();
        if !enc || (!avs.is_empty() && !avs.iter().any(|v| self.shared(*v))) {
            // public subtree: plain list arithmetic at the owner (both parties know it)
            let mut pubvals: HashMap<usize, Vecn> = HashMap::new();
            for (a, v) in args.iter().zip(&avs) {
                pubvals.insert(*a, self.arena[*v].pubv.clone().expect("public operand"));
            }
            let lst = self.b.local(i, &pubvals)?;
            vals[i] = Some(self.push(V { w: lst.len(), pubv: Some(lst), ..Default::default() }));
            return Ok(());
        }
        let v = match op {
            Op::Col => {
                let name = match &self.b.nodes[i].data {
                    Data::Col(n) => n.clone(),
                    _ => unreachable!(),
                };
                self.load(&name)?
            }
            Op::LinSum => self.linsum(i)?,
            Op::Neg => self.g_neg(avs[0]),
            Op::Sum => self.g_sum(avs[0]),
            Op::Avg => {
                let a = avs[0];
                let live = match &self.arena[a].live {
                    None => self.arena[a].w,
                    Some(l) => l.iter().filter(|x| **x).count(),
                };
                if live == 0 {
                    self.push(V { w: 1, pubv: Some(vec![None]), ..Default::default() })
                } else {
                    let s = self.g_sum(a);
                    let out = self.g_mulc(s, &mod_inv(&BigInt::from(live)), None);
                    let ws = self.arena[s].wid.clone();
                    self.free_after(&ws);
                    out
                }
            }
            Op::Add | Op::Sub | Op::SMul => {
                let (a, b) = (avs[0], avs[1]);
                let name = match op {
                    Op::Add => "add",
                    Op::Sub => "sub",
                    _ => "smul",
                };
                if self.shared(a) && self.shared(b) {
                    if op == Op::SMul {
                        return Err(Error::new(
                            Kind::Server("ExecError".into()),
                            "internal: a product of two shared wires must be a Beaver gate",
                        ));
                    }
                    self.g_addsub(name, a, b)?
                } else if self.shared(a) {
                    self.g_pub(name, a, b, false)?
                } else {
                    self.g_pub(name, b, a, op == Op::Sub)?
                }
            }
            _ => return Err(Error::new(Kind::Server("ExecError".into()), "internal: unknown operator")),
        };
        vals[i] = Some(v);
        Ok(())
    }

    // — Beaver gate: Z = X*Y ---------------------------------------------------
    /// k fresh triples, additively shared: (server shares, owner shares).
    fn deal(&self, k: usize) -> (Tri, Tri) {
        let nn = &self.nn;
        let al = &self.alpha;
        let (mut s, mut o) = (Tri::default(), Tri::default());
        for _ in 0..k {
            let (u_s, u_o, v_s, v_o, w_s) = (rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar());
            let (u, v) = ((&u_s + &u_o) % nn, (&v_s + &v_o) % nn);
            let w = &u * &v % nn;
            s.u.push(u_s);
            o.u.push(u_o);
            s.v.push(v_s);
            o.v.push(v_o);
            o.w.push(md(&(&w - &w_s)));
            s.w.push(w_s);
            if self.auth {
                let (mu_s, mv_s, mw_s) = (rand_scalar(), rand_scalar(), rand_scalar());
                o.mu.push(md(&(al * &u - &mu_s)));
                s.mu.push(mu_s);
                o.mv.push(md(&(al * &v - &mv_s)));
                s.mv.push(mv_s);
                o.mw.push(md(&(al * &w - &mw_s)));
                s.mw.push(mw_s);
            }
        }
        (s, o)
    }

    fn emit_mul(&mut self, a: usize, b: usize) -> Result<usize> {
        let w = self.wd(a, b);
        let (a, b) = (self.bcast(a, w)?, self.bcast(b, w)?);
        let (av, bv) = (self.arena[a].clone(), self.arena[b].clone());
        let out = self.new_wire();
        let res = self.push(V {
            w,
            pubv: None,
            wid: Some(out.clone()),
            own: vec![BigInt::zero(); w],
            ownm: if self.auth { Some(vec![BigInt::zero(); w]) } else { None },
            live: and_live(&av.live, &bv.live, w),
        });
        let per = if self.auth { 8 } else { 5 };
        let mut lo = 0;
        while lo < w.max(1) {
            let k = self.chunk.min(w - lo);
            let (s, o) = self.deal(k);
            let eo: Vec<BigInt> = av.own[lo..lo + k].iter().zip(&o.u).map(|(x, u)| md(&(x - u))).collect();
            let go: Vec<BigInt> = bv.own[lo..lo + k].iter().zip(&o.v).map(|(y, v)| md(&(y - v))).collect();
            let mut tri = serde_json::Map::new();
            tri.insert("u".into(), svec(&s.u));
            tri.insert("v".into(), svec(&s.v));
            tri.insert("w".into(), svec(&s.w));
            if self.auth {
                tri.insert("mu".into(), svec(&s.mu));
                tri.insert("mv".into(), svec(&s.mv));
                tri.insert("mw".into(), svec(&s.mw));
            }
            tri.insert("eo".into(), svec(&eo));
            tri.insert("go".into(), svec(&go));
            let op = json!(["mul", out, av.wid.clone().unwrap(), bv.wid.clone().unwrap(), Value::Object(tri), lo, w]);
            self.emit(op, k * per, Handler::Mul(Box::new(MulJob { a, b, res, lo, k, eo, go, o })));
            lo += self.chunk;
        }
        self.b.cost.products += w;
        Ok(res)
    }

    fn on_mul(&mut self, r: Vec<Option<Vec<BigInt>>>, job: MulJob) -> Result<()> {
        let MulJob { a, b, res, lo, k, eo, go, o } = job;
        let mut it = r.into_iter();
        let e_s = self.vec_ok(it.next().flatten(), k, "reply")?;
        let g_s = self.vec_ok(it.next().flatten(), k, "reply")?;
        let (mut me_s, mut mg_s) = (vec![], vec![]);
        let (n3, n4) = (it.next().flatten(), it.next().flatten());
        if self.auth {
            me_s = self.vec_ok(n3, k, "reply")?;
            mg_s = self.vec_ok(n4, k, "reply")?;
        }
        let nn = self.nn.clone();
        let al = self.alpha.clone();
        for j in 0..k {
            let (e, g) = ((&e_s[j] + &eo[j]) % &nn, (&g_s[j] + &go[j]) % &nn);
            if self.auth {
                // MAC-check both openings: the server's reported tag share of e (resp. g) plus the owner's
                // must equal alpha*e (resp. alpha*g)
                let am = self.arena[a].ownm.as_ref().expect("tagged")[lo + j].clone();
                let bm = self.arena[b].ownm.as_ref().expect("tagged")[lo + j].clone();
                if !md(&((&me_s[j] + &am - &o.mu[j]) - &al * &e)).is_zero() || !md(&((&mg_s[j] + &bm - &o.mv[j]) - &al * &g)).is_zero() {
                    return Err(integrity("MAC check failed on a multiplication opening -- the server tampered with a wire share"));
                }
            }
            let own = (&o.w[j] + &e * &o.v[j] + &g * &o.u[j]) % &nn;
            self.arena[res].own[lo + j] = own;
            if self.auth {
                let m = (&o.mw[j] + &e * &o.mv[j] + &g * &o.mu[j] + &al * &e % &nn * &g) % &nn;
                self.arena[res].ownm.as_mut().unwrap()[lo + j] = m;
            }
        }
        self.cc.openings += 2 * k;
        Ok(())
    }

    fn public_mul(&mut self, a: usize, b: usize) -> Result<usize> {
        if !self.shared(a) && !self.shared(b) {
            let w = self.wd(a, b);
            let (a, b) = (self.bcast(a, w)?, self.bcast(b, w)?);
            let (pa, pb) = (self.arena[a].pubv.clone().unwrap(), self.arena[b].pubv.clone().unwrap());
            let out: Vecn = pa
                .iter()
                .zip(&pb)
                .map(|(x, y)| match (x, y) {
                    (Some(x), Some(y)) => Some(x * y % &self.nn),
                    _ => None,
                })
                .collect();
            return Ok(self.push(V { w, pubv: Some(out), ..Default::default() }));
        }
        if self.shared(a) {
            self.g_pub("smul", a, b, false)
        } else {
            self.g_pub("smul", b, a, false)
        }
    }

    // — reveal (the only thing the server ever sends back about a result) —
    fn emit_reveal(&mut self, v: usize) -> usize {
        let (w, wid) = (self.arena[v].w, self.wid(v));
        self.sinks.push(Sink { z: vec![BigInt::zero(); w], m: vec![BigInt::zero(); w] });
        let sink = self.sinks.len() - 1;
        let mut lo = 0;
        while lo < w {
            let k = self.chunk.min(w - lo);
            self.emit(json!(["reveal", wid, lo, k]), k * if self.auth { 2 } else { 1 }, Handler::Reveal { sink, lo, k });
            lo += self.chunk;
        }
        self.cc.reveals += 1;
        sink
    }

    fn on_reveal(&mut self, r: Vec<Option<Vec<BigInt>>>, sink: usize, lo: usize, k: usize) -> Result<()> {
        let mut it = r.into_iter();
        let z = self.vec_ok(it.next().flatten(), k, "reply")?;
        for (j, x) in z.into_iter().enumerate() {
            self.sinks[sink].z[lo + j] = x;
        }
        if self.auth {
            let m = self.vec_ok(it.next().flatten(), k, "reply")?;
            for (j, x) in m.into_iter().enumerate() {
                self.sinks[sink].m[lo + j] = x;
            }
        }
        Ok(())
    }

    /// z = server share + owner share per position, MAC-checked on live positions.
    fn open_wire(&self, v: usize, sink: usize) -> Result<Vec<BigInt>> {
        let vv = &self.arena[v];
        let mut out = Vec::with_capacity(vv.w);
        for j in 0..vv.w {
            let z = (&self.sinks[sink].z[j] + &vv.own[j]) % &self.nn;
            if self.auth && vv.live.as_ref().map(|l| l[j]).unwrap_or(true) {
                let m = &self.sinks[sink].m[j] + &vv.ownm.as_ref().expect("tagged")[j];
                if !md(&(m - &self.alpha * &z)).is_zero() {
                    return Err(integrity("MAC check failed on the revealed result -- the server returned a forged or inconsistent share"));
                }
            }
            out.push(z);
        }
        Ok(out)
    }

    // — division by an encrypted y: [t] = [rho]*[y], open t, [1/y] = t^-1 [rho] —
    fn nonzero(&self) -> BigInt {
        BigInt::one() + rand_scalar() % (&self.nn - BigInt::one()) // uniform NON-ZERO
    }

    fn inv_start(&mut self, i: usize, y: usize) -> Result<()> {
        let yv = self.arena[y].clone();
        let w = yv.w;
        let rho: Vec<BigInt> = (0..w).map(|_| self.nonzero()).collect();
        let r_s: Vec<BigInt> = (0..w).map(|_| rand_scalar()).collect();
        let r_o: Vec<BigInt> = rho.iter().zip(&r_s).map(|(r, s)| md(&(r - s))).collect();
        let (mut m_s, mut m_o) = (None, None);
        if self.auth {
            let ms: Vec<BigInt> = (0..w).map(|_| rand_scalar()).collect();
            m_o = Some(rho.iter().zip(&ms).map(|(r, s)| md(&(&self.alpha * r - s))).collect::<Vec<_>>());
            m_s = Some(ms);
        }
        let wid = self.new_wire();
        let step = self.chunk;
        if w == 0 {
            let empty_tag = if self.auth { json!([]) } else { Value::Null };
            self.emit(json!(["put", wid, [], empty_tag, 0, 0]), 0, Handler::None);
        }
        let mut lo = 0;
        while lo < w {
            let hi = (lo + step).min(w);
            let part = &r_s[lo..hi];
            let tag = match &m_s {
                None => Value::Null,
                Some(ms) => svec(&ms[lo..hi]),
            };
            self.emit(json!(["put", wid, svec(part), tag, lo, w]), part.len() * if self.auth { 2 } else { 1 }, Handler::None);
            lo += step;
        }
        let rho_v = self.push(V { w, pubv: None, wid: Some(wid), own: r_o, ownm: m_o, live: None });
        let prod = self.emit_mul(rho_v, y)?;
        let sink = self.emit_reveal(prod);
        let wp = self.arena[prod].wid.clone();
        self.free_after(&wp);
        self.post.push(Post::Inv { i, y_live: yv.live, rho: rho_v, prod, sink });
        Ok(())
    }

    fn run_post(&mut self, p: Post) -> Result<()> {
        match p {
            Post::Inv { i, y_live, rho, prod, sink } => {
                // t = rho*y, MAC-checked
                let ts = self.open_wire(prod, sink)?;
                let mut tinv = Vec::with_capacity(ts.len());
                for (j, t) in ts.iter().enumerate() {
                    let mut t = t.clone();
                    if t.is_zero() {
                        if y_live.as_ref().map(|l| l[j]).unwrap_or(true) && self.b.zero.is_none() {
                            self.b.zero = Some(if self.b.nodes[i].row { format!(" (result row {})", j) } else { String::new() });
                        }
                        t = self.nonzero(); // dummy: the server must not learn it
                    } else {
                        self.b.cost.inversions += 1;
                    }
                    tinv.push(mod_inv(&t));
                }
                self.cc.openings += ts.len();
                self.inv.insert(i, InvState { rho, tinv, live: y_live });
                Ok(())
            }
        }
    }

    fn inv_finish(&mut self, i: usize) -> usize {
        let InvState { rho, tinv, live } = self.inv.remove(&i).expect("inversion started");
        let rv = self.arena[rho].clone();
        let out = self.new_wire();
        self.span_ops("mulv", &out, rv.wid.as_ref().unwrap(), &tinv, rv.w);
        self.free_after(&rv.wid);
        let nn = &self.nn;
        let own = rv.own.iter().zip(&tinv).map(|(x, y)| x * y % nn).collect();
        let ownm = rv.ownm.as_ref().map(|m| m.iter().zip(&tinv).map(|(x, y)| x * y % nn).collect());
        self.push(V { w: rv.w, pubv: None, wid: Some(out), own, ownm, live })
    }

    // ── run ──────────────────────────────────────────────────────────────────
    pub(crate) fn run(mut self) -> Result<(ExprValue, ExprCost)> {
        let r = self.run_inner();
        self.cleanup();
        r
    }

    fn consume(&mut self, i: usize, refs: &mut [usize], vals: &mut [Option<usize>]) {
        for a in self.b.nodes[i].args.clone() {
            refs[a] -= 1;
            if refs[a] == 0 {
                if let Some(v) = vals[a] {
                    if self.shared(v) {
                        let wid = self.arena[v].wid.clone();
                        self.free_after(&wid);
                        vals[a] = None; // the owner's share is dead too
                    }
                }
            }
        }
    }

    fn run_inner(&mut self) -> Result<(ExprValue, ExprCost)> {
        let root = self.b.compile_root();
        let nn_nodes = self.b.nodes.len();
        let depth = self.b.nodes.iter().map(|n| n.level).max().unwrap_or(0);
        self.setup_limits()?;
        let mut refs = vec![0usize; nn_nodes];
        for nd in &self.b.nodes {
            for a in &nd.args {
                refs[*a] += 1;
            }
        }
        refs[root] += 1;
        let mut vals: Vec<Option<usize>> = vec![None; nn_nodes];
        let mut sink = usize::MAX;
        for lvl in 0..=depth {
            for i in 0..nn_nodes {
                if self.b.nodes[i].level == lvl && self.b.nodes[i].op != Op::CMul {
                    let started = self.inv.contains_key(&i);
                    self.compute_node(i, &mut vals)?;
                    if !started {
                        // an inversion consumed its argument at its start
                        self.consume(i, &mut refs, &mut vals);
                    }
                }
            }
            let mut muls = 0;
            for i in 0..nn_nodes {
                if self.b.nodes[i].level != lvl + 1 {
                    continue;
                }
                let op = self.b.nodes[i].op;
                if op == Op::CMul {
                    let (a, b) = (vals[self.b.nodes[i].args[0]].unwrap(), vals[self.b.nodes[i].args[1]].unwrap());
                    if self.shared(a) && self.shared(b) {
                        vals[i] = Some(self.emit_mul(a, b)?);
                        muls += 1;
                    } else {
                        // an operand turned out public (empty AVG)
                        vals[i] = Some(self.public_mul(a, b)?);
                    }
                    self.consume(i, &mut refs, &mut vals);
                } else if op == Op::Inv && self.b.nodes[i].enc && self.shared(vals[self.b.nodes[i].args[0]].unwrap()) {
                    let y = vals[self.b.nodes[i].args[0]].unwrap();
                    self.inv_start(i, y)?;
                    self.consume(i, &mut refs, &mut vals);
                    muls += 1;
                }
            }
            if muls > 0 {
                self.b.cost.mult_rounds += 1;
            }
            if lvl == depth {
                let rootv = vals[root].unwrap();
                if self.shared(rootv) {
                    sink = self.emit_reveal(rootv);
                }
                // the last request also drops everything the query still holds (after the reveal)
                let mut all: BTreeSet<String> = self.tofree.iter().cloned().collect();
                all.extend(self.live_ids.iter().cloned());
                self.tofree = all.into_iter().collect();
            }
            self.flush()?;
        }
        let rootv = vals[root].unwrap();
        let outv: Vecn = if self.shared(rootv) {
            let zs = self.open_wire(rootv, sink)?;
            let live = self.arena[rootv].live.clone();
            zs.into_iter().enumerate().map(|(j, z)| if live.as_ref().map(|l| l[j]).unwrap_or(true) { Some(z) } else { None }).collect()
        } else {
            self.arena[rootv].pubv.clone().unwrap()
        };
        if let Some(sfx) = &self.b.zero {
            return Err(Error::new(Kind::DivisionByZero, format!("division by zero: a denominator is 0{}", sfx)));
        }
        let mut cost = self.b.cost.clone();
        cost.depth = depth;
        cost.mode = ExprMode::Shared;
        cost.openings = self.cc.openings;
        cost.wires = self.cc.wires;
        cost.requests = self.cc.requests;
        cost.reveals = self.cc.reveals;
        let dec = |v: &Option<BigInt>| -> Result<Option<crate::Decoded>> {
            match v {
                None => Ok(None),
                Some(s) => Ok(Some(decode(s)?)),
            }
        };
        let value = if self.b.info.kind == "row" {
            let rows = if self.b.tuples.is_empty() { vec![] } else { ExprRunner::bc(&outv, self.b.tuples.len()) };
            ExprValue::Rows(rows.iter().map(dec).collect::<Result<Vec<_>>>()?)
        } else {
            ExprValue::Scalar(dec(&outv[0])?)
        };
        Ok((value, cost))
    }
}
