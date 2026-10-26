// SPDX-License-Identifier: Apache-2.0
//! Shared-wire expressions (`ExprMode::Shared`, the default) against a REAL keyless server: the cross-language
//! vectors (value, error class, cost, and the SHAPE of every wire request must equal the Python reference), a
//! live Python peer against the same server, the abort-oracle trace, integrity (tampering / swap / replay in
//! authenticated mode), caps / TTL / old-server errors, wire cleanup on every exit path, and an audit of
//! everything the server is sent (with controls proving the audit can fail).
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use torusdb::*;

mod common;
use common::fake::{base, fake, raw_rpc, recorder, recorder_hooks, Hooks, Reply};
use common::*;

// ── helpers ──────────────────────────────────────────────────────────────────
fn vec_json() -> Value {
    serde_json::from_str(&std::fs::read_to_string(expr_vectors_path()).unwrap()).unwrap()
}
fn bi(v: i64) -> BigInt {
    BigInt::from(v)
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(bi(v))
}
fn cell_value(s: &Value) -> CellIn {
    match s.as_str() {
        None => CellIn::Null,
        Some(t) => match t.split_once('/') {
            Some((n, d)) => CellIn::Rational(n.parse().unwrap(), d.parse().unwrap()),
            None => CellIn::Int(t.parse().unwrap()),
        },
    }
}
fn show1(v: &Option<Decoded>) -> Value {
    match v {
        None => Value::Null,
        Some(Decoded::Int(b)) => json!(b.to_string()),
        Some(Decoded::Rational(n, d)) => json!(format!("{}/{}", n, d)),
    }
}
fn show(v: &ExprValue) -> Value {
    match v {
        ExprValue::Scalar(x) => show1(x),
        ExprValue::Rows(rows) => Value::Array(rows.iter().map(show1).collect()),
    }
}
fn rows_of(v: ExprValue) -> Vec<Option<Decoded>> {
    match v {
        ExprValue::Rows(r) => r,
        other => panic!("expected rows, got {:?}", other),
    }
}
fn scalar_int(v: ExprValue) -> BigInt {
    match v {
        ExprValue::Scalar(Some(Decoded::Int(b))) => b,
        o => panic!("{:?}", o),
    }
}
fn opts(auth: bool) -> ConnectOptions {
    ConnectOptions { authenticated: auth, ..Default::default() }
}
fn connect(addr: &str, auth: bool) -> Client {
    Client::connect_with(addr, &opts(auth)).unwrap()
}

fn load_tables(db: &mut Client, v: &Value) {
    for t in v["exec"]["tables"].as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        let cols: Vec<Column> = t["columns"].as_array().unwrap().iter().map(|c| col(c[0].as_str().unwrap(), c[1].as_str().unwrap(), c[2].as_str().unwrap())).collect();
        db.create_table(name, cols.clone()).unwrap();
        let rows: Vec<Vec<(&str, CellIn)>> = t["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| cols.iter().enumerate().map(|(k, c)| (c.name.as_str(), cell_value(&r[k]))).collect())
            .collect();
        if !rows.is_empty() {
            db.insert_many(name, rows).unwrap();
        }
    }
}

fn where_pred(w: &Value) -> Value {
    let (c, op) = (w["col"].as_str().unwrap(), w["op"].as_str().unwrap());
    match op {
        "IN" => is_in(c, &w["val"].as_array().unwrap().iter().map(|x| ci(x.as_i64().unwrap())).collect::<Vec<_>>()).unwrap(),
        _ => cmp(c, op, &ci(w["val"].as_i64().unwrap())).unwrap(),
    }
}

fn run_case(db: &mut Client, c: &Value) -> Result<ExprValue, Error> {
    db.set_max_mult_depth(c.get("max_depth").and_then(|m| m.as_u64()).unwrap_or(8) as usize);
    let e = c["expr"].as_str().unwrap();
    if let Some(j) = c.get("join") {
        let steps: Vec<JoinStep> = j["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let mut st = JoinStep::new(s["table"].as_str().unwrap(), s["left_col"].as_str().unwrap(), s["right_col"].as_str().unwrap())
                    .alias(s["alias"].as_str().unwrap())
                    .left_alias(s["left_alias"].as_str().unwrap());
                if s["kind"] == "left" {
                    st = st.left();
                }
                st
            })
            .collect();
        let jr = db.join(j["left"][0].as_str().unwrap(), &steps, &JoinOptions { alias: Some(j["left"][1].as_str().unwrap().into()), where_: None })?;
        return db.join_expr(&jr, e);
    }
    let pred = c.get("where").map(where_pred).unwrap_or_else(all);
    db.expr(c["table"].as_str().unwrap(), e, pred)
}

/// The cost fields the Python reference reports.
fn cost_json(c: &ExprCost, shared: bool) -> Value {
    let mut o = json!({"depth": c.depth, "mult_rounds": c.mult_rounds, "products": c.products,
                       "inversions": c.inversions, "linear_sums": c.linear_sums});
    if shared {
        o["openings"] = json!(c.openings);
        o["wires"] = json!(c.wires);
        o["requests"] = json!(c.requests);
        o["reveals"] = json!(c.reveals);
    }
    o
}

// ── the language-neutral shape of the wire requests (drivers/wire_shape.py) ───────────────────
fn is_wire_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 14
        && b[..12].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        && b[12] == b'.'
        && b[13..].iter().all(|c| c.is_ascii_digit())
}
fn op_shape(op: &Value, ids: &mut Vec<String>) -> Value {
    let name = op[0].as_str().unwrap();
    let mut row = vec![json!(name)];
    for (k, x) in op.as_array().unwrap().iter().enumerate().skip(1) {
        row.push(if (name == "mulc" || name == "addc") && k == 3 {
            json!("R")
        } else {
            match x {
                Value::Null | Value::Bool(_) | Value::Number(_) => x.clone(),
                Value::String(s) => {
                    if is_wire_id(s) {
                        let pos = ids.iter().position(|i| i == s).unwrap_or_else(|| {
                            ids.push(s.clone());
                            ids.len() - 1
                        });
                        json!(format!("#{}", pos))
                    } else {
                        json!("R")
                    }
                }
                Value::Array(a) => json!(["L", a.len()]),
                Value::Object(o) => {
                    let mut keys: Vec<&String> = o.keys().collect();
                    keys.sort();
                    json!(["D", keys.iter().map(|k| json!([k, o[*k].as_array().map(|a| a.len()).unwrap_or(0)])).collect::<Vec<_>>()])
                }
            }
        });
    }
    Value::Array(row)
}
fn wire_trace(log: &[(String, Value)]) -> Value {
    let mut out = vec![];
    for (m, a) in log {
        if m == "wire_exec" {
            let mut ids = vec![];
            let ops: Vec<Value> = a[0].as_array().unwrap().iter().map(|o| op_shape(o, &mut ids)).collect();
            out.push(json!(["exec", ops]));
        } else if m == "wire_free" {
            out.push(json!(["free", a[0].as_array().map(|x| x.len())]));
        }
    }
    Value::Array(out)
}
fn digest(t: &Value) -> String {
    sha256_hex(t.to_string().as_bytes())
}

fn wire_ids(log: &[(String, Value)]) -> Vec<String> {
    let mut ids = vec![];
    for (m, a) in log {
        if m == "wire_exec" {
            for op in a[0].as_array().unwrap() {
                for x in op.as_array().unwrap().iter().skip(1).take(3) {
                    if let Some(s) = x.as_str() {
                        if is_wire_id(s) && !ids.contains(&s.to_string()) {
                            ids.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    ids
}
fn n_methods(log: &[(String, Value)], m: &str) -> usize {
    log.iter().filter(|(x, _)| x == m).count()
}
/// True when the server still knows the wire (a `reveal` of 0 elements succeeds only on a live wire).
fn wire_alive(db: &mut Client, id: &str) -> bool {
    match db.raw_call("wire_exec", json!([[["reveal", id, 0, 0]]])) {
        Ok(_) => true,
        Err(e) => {
            assert!(e.kind == Kind::Server("WireError".into()) && e.message.contains("unknown wire"), "{}", e);
            false
        }
    }
}

// ── a small fixed table for the behavioural tests ────────────────────────────
fn schema() -> Vec<Column> {
    vec![
        col("id", "int", "plain"),
        col("dept", "int", "plain"),
        col("a", "int", "paired"),
        col("b", "int", "paired"),
        col("c", "int", "paired"),
        col("d", "int", "paired"),
        col("r", "rational", "paired"),
        col("s", "rational", "encrypted"),
    ]
}
#[derive(Clone)]
struct Row {
    id: i64,
    dept: i64,
    a: i64,
    b: i64,
    c: i64,
    d: i64,
    r: (i64, i64),
    s: (i64, i64),
}
fn rows() -> Vec<Row> {
    vec![
        Row { id: 1, dept: 5, a: 1_000_003, b: 2_000_011, c: 3_000_017, d: 5, r: (5_000_011, 7), s: (9_000_001, 3) },
        Row { id: 2, dept: 5, a: 1_000_033, b: -2_000_029, c: 3_000_041, d: -1, r: (-5_000_021, 11), s: (7_000_003, 5) },
        Row { id: 3, dept: 9, a: -1_000_037, b: 2_000_039, c: -3_000_043, d: 8, r: (5_000_047, 13), s: (-6_000_001, 7) },
        Row { id: 4, dept: 9, a: 1_000_051, b: 2_000_057, c: 3_000_059, d: 2, r: (5_000_063, 17), s: (8_000_009, 9) },
    ]
}
fn rcell((n, d): (i64, i64)) -> CellIn {
    CellIn::Rational(bi(n), bi(d))
}
fn row_cells(r: &Row) -> Vec<(&'static str, CellIn)> {
    vec![("id", ci(r.id)), ("dept", ci(r.dept)), ("a", ci(r.a)), ("b", ci(r.b)), ("c", ci(r.c)), ("d", ci(r.d)), ("r", rcell(r.r)), ("s", rcell(r.s))]
}
fn seed_rows(db: &mut Client, t: &str, rs: &[Row]) {
    db.create_table(t, schema()).unwrap();
    db.insert_many(t, rs.iter().map(row_cells).collect()).unwrap();
}
fn seed(db: &mut Client, t: &str) {
    seed_rows(db, t, &rows())
}

// exact rationals for the expected values
#[derive(Clone, Debug, PartialEq)]
struct Fr(BigInt, BigInt);
fn fr(n: BigInt, d: BigInt) -> Fr {
    use num_integer::Integer;
    let (mut n, mut d) = (n, d);
    if d < BigInt::zero() {
        n = -n;
        d = -d;
    }
    let g = n.gcd(&d);
    if g > BigInt::one() {
        n /= &g;
        d /= &g;
    }
    Fr(n, d)
}
fn fi(n: i64) -> Fr {
    fr(bi(n), BigInt::one())
}
fn fadd(x: &Fr, y: &Fr) -> Fr {
    fr(&x.0 * &y.1 + &y.0 * &x.1, &x.1 * &y.1)
}
fn fsub(x: &Fr, y: &Fr) -> Fr {
    fr(&x.0 * &y.1 - &y.0 * &x.1, &x.1 * &y.1)
}
fn fmul(x: &Fr, y: &Fr) -> Fr {
    fr(&x.0 * &y.0, &x.1 * &y.1)
}
fn fdiv(x: &Fr, y: &Fr) -> Fr {
    fr(&x.0 * &y.1, &x.1 * &y.0)
}
fn fshow(x: &Fr) -> Value {
    if x.1.is_one() {
        json!(x.0.to_string())
    } else {
        json!(format!("{}/{}", x.0, x.1))
    }
}
fn column(name: &str) -> Vec<Fr> {
    rows()
        .iter()
        .map(|r| match name {
            "a" => fi(r.a),
            "b" => fi(r.b),
            "c" => fi(r.c),
            "d" => fi(r.d),
            "r" => fr(bi(r.r.0), bi(r.r.1)),
            "s" => fr(bi(r.s.0), bi(r.s.1)),
            _ => unreachable!(),
        })
        .collect()
}
fn prod(names: &[&str]) -> Vec<Fr> {
    let cols: Vec<Vec<Fr>> = names.iter().map(|n| column(n)).collect();
    (0..rows().len()).map(|i| cols.iter().fold(fi(1), |p, c| fmul(&p, &c[i]))).collect()
}
fn fshows(v: &[Fr]) -> Value {
    Value::Array(v.iter().map(fshow).collect())
}
fn fsum(v: &[Fr]) -> Fr {
    v.iter().fold(fi(0), |p, q| fadd(&p, q))
}

// ── the shared vectors: value, error, cost AND the shape of every wire request ───────────────
fn vectors(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let v = vec_json();
    let mut db = connect(&rec.addr, auth);
    assert_eq!(db.expression_mode(), ExprMode::Shared);
    load_tables(&mut db, &v);
    let (mut ok, mut bad, mut divisions) = (0, 0, 0);
    for c in v["exec"]["cases"].as_array().unwrap() {
        let want = &c["shared"];
        let what = format!("{} {} {}", c.get("table").unwrap_or(&json!("join")), c["expr"], c.get("where").unwrap_or(&Value::Null));
        let n0 = rec.len();
        let got = run_case(&mut db, c);
        if let Some(err) = want.get("error").and_then(|e| e.as_str()) {
            let e = got.expect_err(&what);
            assert_eq!(e.kind_name(), err, "{}: {}", what, e);
            assert!(db.last_expr_cost().is_none(), "{}", what);
            bad += 1;
        } else {
            let got = got.unwrap_or_else(|e| panic!("{}: {}", what, e));
            assert_eq!(show(&got), want["value"], "{}", what);
            let cost = db.last_expr_cost().unwrap();
            assert_eq!(cost.mode, ExprMode::Shared, "{}", what);
            assert_eq!(cost_json(cost, true), want["cost"], "{}", what);
            if want["cost"]["inversions"].as_u64().unwrap() > 0 {
                divisions += 1;
            }
            ok += 1;
        }
        let trace = digest(&wire_trace(&rec.log()[n0..]));
        let expect = if auth { c["shared_auth_trace"].as_str().unwrap() } else { want["trace"].as_str().unwrap() };
        assert_eq!(trace, expect, "wire trace: {}", what);
    }
    assert!(ok > 300 && bad > 50 && divisions > 50, "{} ok / {} errors / {} with a division", ok, bad, divisions);
}
#[test]
fn vectors_shared_plain() {
    vectors(false)
}
#[test]
fn vectors_shared_authenticated() {
    vectors(true)
}

#[test]
fn the_owner_transport_is_still_there_with_the_old_costs_and_no_wire_request() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let v = vec_json();
    let mut db = Client::connect_with(&rec.addr, &ConnectOptions { expression_mode: ExprMode::Owner, ..Default::default() }).unwrap();
    assert_eq!(db.expression_mode(), ExprMode::Owner);
    load_tables(&mut db, &v);
    for c in v["exec"]["cases"].as_array().unwrap().iter().take(120) {
        let got = run_case(&mut db, c);
        if let Some(err) = c.get("error").and_then(|e| e.as_str()) {
            assert_eq!(got.unwrap_err().kind_name(), err);
            continue;
        }
        assert_eq!(show(&got.unwrap()), c["value"], "{}", c["expr"]);
        assert_eq!(db.last_expr_cost().unwrap().mode, ExprMode::Owner);
        assert_eq!(db.last_expr_cost().unwrap().requests, 0);
    }
    assert!(!rec.log().iter().any(|(m, _)| m.starts_with("wire_")));
    db.set_expression_mode(ExprMode::Shared);
    assert_eq!(db.expression_mode(), ExprMode::Shared);
}

// ── a live Python peer (shared mode) against the same server ─────────────────────────────────
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 33) as f64) / ((1u64 << 31) as f64)
    }
}
fn gen_tree(r: &mut Lcg, depth: usize, leaves: &[&str]) -> String {
    if depth == 0 || r.next() < 0.25 {
        if r.next() < 0.7 {
            return leaves[(r.next() * leaves.len() as f64) as usize].to_string();
        }
        let lits = ["2", "3", "(-4)", "7", "1", "FRAC(1,3)", "FRAC(-5,2)"];
        return lits[(r.next() * lits.len() as f64) as usize].to_string();
    }
    if r.next() < 0.1 {
        return format!("(-{})", gen_tree(r, depth - 1, leaves));
    }
    let op = ['+', '-', '*', '/'][(r.next() * 4.0) as usize];
    format!("({}{}{})", gen_tree(r, depth - 1, leaves), op, gen_tree(r, depth - 1, leaves))
}
const FIXED: [&str; 23] = [
    "a*b*c", "a*b*c*d", "(a+b)*(c-d)*a+s/2", "SUM(a*b*c)/COUNT(*)", "a/b", "r/c*a", "SUM(a)/SUM(c)", "100/c", "AVG(a*b)", "a*b/(c*d)",
    "SUM(a+2*b-s/4)", "a/0", "a*name", "SUM(id*2)", "s*a*b", "a*(b-b)", "1/(a-a)", "a/b/c/d", "a/b/c/d/a", "(a*b)/(c*d)", "SUM(a/b*c)",
    "AVG(a/b)", "SUM(a)/(SUM(b)-SUM(b))",
];

fn peer_check(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let seed_: u64 = std::env::var("TORUSDB_PEER_SEED").ok().and_then(|x| x.parse().ok()).unwrap_or(20260626) + auth as u64;
    let mut r = Lcg(seed_);
    let mut exprs: Vec<String> = FIXED.iter().map(|x| x.to_string()).collect();
    while exprs.len() < 190 {
        let depth = 1 + (r.next() * 4.0) as usize;
        let t = gen_tree(&mut r, depth, &["a", "b", "c", "d", "r", "q"]);
        if t.chars().all(|c| c.is_ascii_lowercase()) {
            continue;
        }
        exprs.push(t);
    }
    let vec: Value = vec_json();
    let tdef = vec["exec"]["tables"].as_array().unwrap().iter().find(|t| t["name"] == "t").unwrap();
    let cols: Vec<Column> = tdef["columns"].as_array().unwrap().iter().map(|c| col(c[0].as_str().unwrap(), c[1].as_str().unwrap(), c[2].as_str().unwrap())).collect();
    let (py_t, rs_t) = if auth { ("py_t_auth", "rs_t_auth") } else { ("py_t", "rs_t") };
    let queries: Vec<Value> = exprs.iter().map(|e| json!({"table": py_t, "expr": e})).collect();
    let spec = json!({"auth": auth, "mode": "shared", "tables": [{"name": py_t, "columns": tdef["columns"], "rows": tdef["rows"]}], "queries": queries});
    let host_port: Vec<&str> = s.addr.split(':').collect();
    let peer = run_expr_peer(host_port[0], s.port, &spec);
    let peer = peer.as_array().unwrap();
    assert_eq!(peer.len(), exprs.len());

    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, auth);
    db.create_table(rs_t, cols.clone()).unwrap();
    let rws: Vec<Vec<(&str, CellIn)>> =
        tdef["rows"].as_array().unwrap().iter().map(|row| cols.iter().enumerate().map(|(k, c)| (c.name.as_str(), cell_value(&row[k]))).collect()).collect();
    db.insert_many(rs_t, rws).unwrap();
    let (mut ok, mut errs, mut divs) = (0, 0, 0);
    for (i, e) in exprs.iter().enumerate() {
        let n0 = rec.len();
        let mut got: Value = match db.expr(rs_t, e, all()) {
            Ok(v) => {
                let c = db.last_expr_cost().unwrap();
                ok += 1;
                if c.inversions > 0 {
                    divs += 1;
                }
                json!({"value": show(&v), "cost": cost_json(c, true)})
            }
            Err(err) => {
                errs += 1;
                json!({"error": err.kind_name()})
            }
        };
        got["trace"] = json!(digest(&wire_trace(&rec.log()[n0..])));
        assert_eq!(got, peer[i], "{}", e);
    }
    assert!(ok > 60 && errs > 10 && divs > 10, "{} ok / {} errors / {} divisions", ok, errs, divs);
}
#[test]
fn python_shared_and_this_driver_agree_plain() {
    peer_check(false)
}
#[test]
fn python_shared_and_this_driver_agree_authenticated() {
    peer_check(true)
}

// ── results over the wire ────────────────────────────────────────────────────
fn products_and_sums(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, auth);
    seed(&mut db, "t");
    for (names, depth) in [(vec!["a", "b", "c"], 2usize), (vec!["a", "b", "c", "d"], 3), (vec!["a", "b", "c", "d", "a", "b"], 5)] {
        let n0 = rec.len();
        let got = db.expr("t", &names.join("*"), all()).unwrap();
        assert_eq!(show(&got), fshows(&prod(&names)));
        let c = db.last_expr_cost().unwrap().clone();
        assert_eq!(c.mode, ExprMode::Shared);
        assert_eq!((c.mult_rounds, c.depth, c.requests), (depth, depth, depth + 1));
        let log = rec.log();
        assert_eq!(n_methods(&log[n0..], "wire_exec"), depth + 1);
        assert_eq!(n_methods(&log[n0..], "mult_combine_batch"), 0);
        assert_eq!(n_methods(&log[n0..], "blinded_cells"), 0, "the owner must not fetch operand cells");
    }
    let (a, b, c, d, sv) = (column("a"), column("b"), column("c"), column("d"), column("s"));
    let want: Vec<Fr> = (0..4)
        .map(|i| fadd(&fsub(&fmul(&fmul(&fadd(&a[i], &b[i]), &fsub(&c[i], &d[i])), &a[i]), &fdiv(&fmul(&b[i], &c[i]), &d[i])), &fdiv(&sv[i], &fi(2))))
        .collect();
    let ne2 = cmp("id", "!=", &ci(2)).unwrap();
    let got = db.expr("t", "(a+b)*(c-d)*a - b*c/d + s/2", ne2).unwrap();
    assert_eq!(show(&got), fshows(&[want[0].clone(), want[2].clone(), want[3].clone()]));
    assert_eq!(scalar_int(db.expr("t", "SUM(a*b*c*d)", all()).unwrap()), fsum(&prod(&["a", "b", "c", "d"])).0);
    assert_eq!(scalar_int(db.expr("t", "SUM(a*b)*SUM(c)", all()).unwrap()), fsum(&prod(&["a", "b"])).0 * fsum(&c).0);
    let g = db.expr("t", "SUM(a*b*c)/COUNT(*)", is_in("dept", &[ci(5)]).unwrap()).unwrap();
    let w = fdiv(&fsum(&prod(&["a", "b", "c"])[..2]), &fi(2));
    assert_eq!(show(&g), fshow(&w));
}
#[test]
fn products_mixed_operators_and_sums_plain() {
    products_and_sums(false)
}
#[test]
fn products_mixed_operators_and_sums_authenticated() {
    products_and_sums(true)
}

fn division(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, auth);
    seed(&mut db, "t");
    let (a, b, c, r) = (column("a"), column("b"), column("c"), column("r"));
    let q = |x: &[Fr], y: &[Fr]| -> Value { fshows(&x.iter().zip(y).map(|(p, q)| fdiv(p, q)).collect::<Vec<_>>()) };
    assert_eq!(show(&db.expr("t", "a/b", all()).unwrap()), q(&a, &b));
    let cst = db.last_expr_cost().unwrap();
    assert_eq!((cst.mult_rounds, cst.inversions, cst.reveals), (2, 4, 2)); // rho*y, then x*(1/y); t and the result
    assert_eq!(show(&db.expr("t", "r/c", all()).unwrap()), q(&r, &c));
    assert_eq!(show(&db.expr("t", "12/c", all()).unwrap()), q(&vec![fi(12); 4], &c));
    let want: Vec<Fr> = (0..4).map(|i| fmul(&fdiv(&a[i], &fmul(&b[i], &c[i])), &r[i])).collect();
    assert_eq!(show(&db.expr("t", "a/(b*c)*r", all()).unwrap()), fshows(&want));
    assert_eq!(show(&db.expr("t", "SUM(a*b)/SUM(c)", all()).unwrap()), fshow(&fdiv(&fsum(&prod(&["a", "b"])), &fsum(&c))));
    assert_eq!(db.last_expr_cost().unwrap().inversions, 1);
    let e = db.expr("t", "a/(d-d)", all()).unwrap_err();
    assert!(e.kind == Kind::DivisionByZero && e.message.contains("division by zero"), "{}", e);
    assert!(db.last_expr_cost().is_none());
    for (_, a) in rec.log().iter().filter(|(m, _)| m == "wire_exec") {
        for op in a[0].as_array().unwrap() {
            let name = op[0].as_str().unwrap();
            assert!(
                ["load", "loadsum", "put", "neg", "mulc", "addc", "mulv", "addv", "add", "sub", "bc", "sum", "mul", "reveal", "free"].contains(&name),
                "{}",
                name
            );
        }
    }
}
#[test]
fn division_by_an_encrypted_value_plain() {
    division(false)
}
#[test]
fn division_by_an_encrypted_value_authenticated() {
    division(true)
}

#[test]
fn cost_accounting_and_one_extra_level_per_division() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    seed(&mut db, "t");
    let n = 4;
    db.expr("t", "a*b*c", all()).unwrap();
    let c = db.last_expr_cost().unwrap().clone();
    assert_eq!((c.mult_rounds, c.depth, c.products, c.openings), (2, 2, 2 * n, 4 * n));
    assert!(c.reveals == 1 && c.requests == 3 && c.wires >= 5, "{:?}", c);
    db.expr("t", "a*b + c*d + a*d", all()).unwrap();
    let c = db.last_expr_cost().unwrap().clone();
    assert_eq!((c.mult_rounds, c.products, c.requests), (1, 3 * n, 2));
    db.expr("t", "SUM(a+2*b)", all()).unwrap(); // linear: a single exchange
    let c = db.last_expr_cost().unwrap().clone();
    assert_eq!((c.mult_rounds, c.requests, c.products, c.linear_sums), (0, 1, 0, 2));
    for (x, rounds) in [("a*b*c", 2), ("a*b/c", 2), ("a*b*c/d", 3), ("(a*b)/(c*d)", 3)] {
        db.expr("t", x, all()).unwrap();
        assert_eq!(db.last_expr_cost().unwrap().mult_rounds, rounds, "{}", x);
    }
}

#[test]
fn the_depth_cap_counts_the_extra_level_of_a_division_and_is_enforced_before_any_request() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = Client::connect_with(&rec.addr, &ConnectOptions { max_mult_depth: 3, ..Default::default() }).unwrap();
    seed(&mut db, "t");
    db.expr("t", "a/b", all()).unwrap(); // 2 levels: ok
    let n0 = rec.len();
    let e = db.expr("t", "a/b/c/d", all()).unwrap_err();
    assert!(e.kind == Kind::DepthLimitExceeded && e.message.contains("max_mult_depth") && e.message.contains("extra level"), "{}", e);
    assert_eq!(db.expr("t", "a*b*c*d*a", all()).unwrap_err().kind, Kind::DepthLimitExceeded);
    assert_eq!(rec.len(), n0, "a request was sent before the depth check");
    assert_eq!(db.analyze_expr("t", "a/b").unwrap().depth, 1, "analyze_expr reports the dialect depth, not the shared one");
    db.set_max_mult_depth(0);
    db.expr("t", "a/3+s", all()).unwrap(); // public division: no level
    assert_eq!(db.expr("t", "a/b", all()).unwrap_err().kind, Kind::DepthLimitExceeded);
}

#[test]
fn null_operands_empty_selections_and_the_empty_aggregate() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    db.create_table("t", vec![col("id", "int", "plain"), col("w", "int", "plain"), col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
    let r = |id: i64, w: Option<i64>, a: i64, b: i64| vec![("id", ci(id)), ("w", w.map(ci).unwrap_or(CellIn::Null)), ("a", ci(a)), ("b", ci(b))];
    db.insert_many("t", vec![r(1, Some(2), 3, 4), r(2, None, 5, 6), r(3, Some(3), 7, 8)]).unwrap();
    let i = |v: i64| Some(Decoded::Int(bi(v)));
    assert_eq!(rows_of(db.expr("t", "a*b*w", all()).unwrap()), vec![i(24), None, i(168)]);
    assert_eq!(scalar_int(db.expr("t", "SUM(a*b*w)", all()).unwrap()), bi(192));
    assert_eq!(show(&db.expr("t", "AVG(a*b*w)", all()).unwrap()), json!("96"));
    let none = || cmp("id", ">", &ci(99)).unwrap();
    assert!(rows_of(db.expr("t", "a*b", none()).unwrap()).is_empty());
    assert_eq!(scalar_int(db.expr("t", "SUM(a*b)", none()).unwrap()), bi(0));
    assert_eq!(db.expr("t", "AVG(a*b)", none()).unwrap(), ExprValue::Scalar(None));
    assert_eq!(scalar_int(db.expr("t", "COUNT(*)", none()).unwrap()), bi(0));
    assert_eq!(
        rows_of(db.expr("t", "a/b*w", all()).unwrap()),
        vec![Some(Decoded::Rational(bi(3), bi(2))), None, Some(Decoded::Rational(bi(21), bi(8)))]
    );
    assert_eq!(db.expr("t", "SUM(a)/COUNT(*)", none()).unwrap_err().kind, Kind::DivisionByZero);
}

// ── the abort oracle: a zero denominator does not change what the server sees ─────────────────
fn abort_oracle(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, auth);
    seed(&mut db, "t");
    let rs = rows();
    for x in ["a/b", "c*d/(a-a+b)*a", "SUM(a/b*c)", "a*c/(b+d-d)", "1/(a*b-c*d)", "100/(b-b+b)", "a/b/c"] {
        let trace = |db: &mut Client, expect_err: bool| -> String {
            let n0 = rec.len();
            let r = db.expr("t", x, all());
            if expect_err {
                assert_eq!(r.unwrap_err().kind, Kind::DivisionByZero, "{}", x);
            } else {
                r.unwrap();
            }
            wire_trace(&rec.log()[n0..]).to_string()
        };
        let clean = trace(&mut db, false);
        db.update("t", vec![("b", ci(0))], is_in("id", &[ci(2), ci(4)]).unwrap()).unwrap();
        if x == "1/(a*b-c*d)" {
            db.update("t", vec![("a", ci(1)), ("b", ci(6)), ("c", ci(6)), ("d", ci(1))], eq_int("id", 1)).unwrap();
        }
        let zero = trace(&mut db, true);
        db.update("t", vec![("a", ci(rs[0].a)), ("b", ci(rs[0].b)), ("c", ci(rs[0].c)), ("d", ci(rs[0].d))], eq_int("id", 1)).unwrap();
        db.update("t", vec![("b", ci(rs[1].b))], eq_int("id", 2)).unwrap();
        db.update("t", vec![("b", ci(rs[3].b))], eq_int("id", 4)).unwrap();
        assert_eq!(zero, clean, "the request sequence depends on a zero denominator for {}", x);
        assert!(clean.matches("\"exec\"").count() >= 2 && clean.contains("\"mul\""), "{}", x);
    }
}
#[test]
fn a_zero_denominator_does_not_change_the_request_sequence_plain() {
    abort_oracle(false)
}
#[test]
fn a_zero_denominator_does_not_change_the_request_sequence_authenticated() {
    abort_oracle(true)
}

// ── lifecycle: wires are freed on every exit path ──────────────────────────────────────────────
#[test]
fn wires_are_freed_after_every_query_success_or_error() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, true);
    seed(&mut db, "t");
    let check = |db: &mut Client, n0: usize, expect_free_call: bool, label: &str| {
        let log = rec.log()[n0..].to_vec();
        let ids = wire_ids(&log);
        assert!(ids.len() >= 3, "{}", label);
        for id in &ids {
            assert!(!wire_alive(db, id), "{}: wire {} survived", label, id);
        }
        assert_eq!(n_methods(&log, "wire_free") > 0, expect_free_call, "{}", label);
    };
    let mut n0 = rec.len();
    db.expr("t", "a*b*c*d", all()).unwrap();
    check(&mut db, n0, false, "success");
    db.update("t", vec![("b", ci(0))], eq_int("id", 2)).unwrap();
    n0 = rec.len();
    assert_eq!(db.expr("t", "a/b", all()).unwrap_err().kind, Kind::DivisionByZero); // runs to the end, then raises
    check(&mut db, n0, false, "division by zero");
    db.insert("t", vec![("id", ci(9)), ("dept", ci(9)), ("a", CellIn::Int(BigInt::from(2).pow(70))), ("b", CellIn::Int(BigInt::from(2).pow(70))), ("c", ci(1)), ("d", ci(1)), ("r", ci(1)), ("s", ci(1))])
        .unwrap();
    n0 = rec.len();
    assert_eq!(db.expr("t", "a*b*c", eq_int("id", 9)).unwrap_err().kind, Kind::OutOfBudget);
    check(&mut db, n0, false, "out of budget");
    // an abort in mid-protocol (the MAC check on an opening fails at the first level): explicit wire_free
    raw_rpc(&s.addr, "update_cell", json!(["t", 0, "b", {"t": "i", "v": "123456789"}]));
    n0 = rec.len();
    assert_eq!(db.expr("t", "a*b*c*d", all()).unwrap_err().kind, Kind::Integrity);
    check(&mut db, n0, true, "integrity abort");
}

#[test]
fn a_lost_connection_mid_protocol_is_a_connection_error_and_the_server_drops_the_dead_sessions_wires() {
    let Some(s) = Server::start(&["--wire-max-total-elements", "40"]) else { return };
    let kill: Arc<common::fake::KillReply> = Arc::new(|m: &str, nth: usize| m == "wire_exec" && nth == 2);
    let px = recorder_hooks(&s.addr, Hooks { kill: Some(kill), ..Default::default() });
    let mut db = Client::connect_with(&px.addr, &ConnectOptions { timeout: Some(std::time::Duration::from_secs(5)), ..Default::default() }).unwrap();
    db.create_table("t", vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired")]).unwrap();
    db.insert_many("t", vec![vec![("a", ci(1)), ("b", ci(2)), ("c", ci(3))], vec![("a", ci(4)), ("b", ci(5)), ("c", ci(6))]]).unwrap();
    assert_eq!(db.expr("t", "a*b*c", all()).unwrap_err().kind, Kind::Connection);
    // the budget is server-wide: if the dead session still held its wires this query would not fit
    let mut other = Client::connect(&s.addr).unwrap();
    other.create_table("t2", vec![col("a", "int", "paired")]).unwrap();
    other.insert_many("t2", (0..18).map(|i| vec![("a", ci(i))]).collect()).unwrap();
    let mut ok = false;
    for _ in 0..50 {
        match other.expr("t2", "-a", all()) {
            Ok(_) => {
                ok = true;
                break;
            }
            Err(e) => {
                assert_eq!(e.kind, Kind::Server("WireError".into()), "{}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    assert!(ok, "the dead session's wires were never released");
}

#[test]
fn a_transaction_end_frees_the_sessions_wires_and_wires_are_private_to_their_session() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    seed(&mut db, "t");
    let load = |c: &mut Client, wid: &str| c.raw_call("wire_exec", json!([[["load", wid, "t", "a", [0, 1, 2], false]]])).unwrap();
    db.begin().unwrap();
    load(&mut db, "w1");
    assert!(wire_alive(&mut db, "w1"));
    db.rollback().unwrap();
    assert!(!wire_alive(&mut db, "w1"));
    db.begin().unwrap();
    load(&mut db, "w1");
    db.commit().unwrap();
    assert!(!wire_alive(&mut db, "w1"));
    load(&mut db, "w2");
    let mut other = Client::connect(&s.addr).unwrap();
    assert!(!wire_alive(&mut other, "w2"), "another session sees this session's wire");
    assert_eq!(other.raw_call("wire_free", json!([["w2"]])).unwrap(), json!(0), "freed another session's wire");
    assert!(wire_alive(&mut db, "w2"));
    db.raw_call("wire_free", json!([["w2"]])).unwrap();
    assert!(!wire_alive(&mut db, "w2"));
}

#[test]
fn expressions_see_the_open_transaction_rollback_restores_and_a_vault_reload_works() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s.addr, true);
    seed(&mut db, "t");
    let sum = |db: &mut Client| scalar_int(db.expr("t", "SUM(a*b*c)", all()).unwrap());
    let before = sum(&mut db);
    let r0 = rows()[0].clone();
    db.begin().unwrap();
    db.insert("t", vec![("id", ci(6)), ("dept", ci(5)), ("a", ci(10)), ("b", ci(10)), ("c", ci(10)), ("d", ci(1)), ("r", ci(1)), ("s", ci(1))]).unwrap();
    db.update("t", vec![("b", ci(0))], eq_int("id", 1)).unwrap();
    assert_eq!(sum(&mut db), &before + bi(1000) - bi(r0.a) * bi(r0.b) * bi(r0.c));
    assert_eq!(db.expr("t", "a/b", all()).unwrap_err().kind, Kind::DivisionByZero);
    db.rollback().unwrap();
    assert_eq!(sum(&mut db), before);
    assert_eq!(rows_of(db.expr("t", "a/b", all()).unwrap())[0], Some(Decoded::Rational(bi(1000003), bi(2000011))));
    let vf = tmpdir("exprvault").join("v.json");
    db.save_vault(Some(&vf)).unwrap();
    drop(db);
    let mut db2 = Client::connect_with(&s.addr, &ConnectOptions { authenticated: true, vault_path: Some(vf), ..Default::default() }).unwrap();
    assert_eq!(rows_of(db2.expr("t", "a*b*c", eq_int("id", 1)).unwrap()), vec![Some(Decoded::Int(bi(r0.a) * bi(r0.b) * bi(r0.c)))]);
}

// ── server caps, TTL, old servers, roles ───────────────────────────────────────────────────────
#[test]
fn caps_are_clear_wire_errors_and_leave_nothing_behind() {
    for (flags, expr, msg) in [
        (vec!["--wire-max-elements", "14"], "a*b*c*d", "memory cap"),
        (vec!["--wire-max-wires", "3"], "a*b*c*d + a*b - c*d", "too many live wires"),
        (vec!["--wire-max-total-elements", "12"], "a*b*c*d", "server-wide"),
    ] {
        let Some(s) = Server::start(&flags) else { return };
        let rec = recorder(&s.addr, None);
        let mut db = Client::connect(&rec.addr).unwrap();
        seed(&mut db, "t");
        if flags[0] == "--wire-max-elements" {
            db.expr("t", "SUM(a+b)", all()).unwrap(); // a few width-1 wires: fine
        }
        let n0 = rec.len();
        let e = db.expr("t", expr, all()).unwrap_err();
        assert!(e.kind == Kind::Server("WireError".into()) && e.message.contains(msg), "{:?}: {}", flags, e);
        assert!(db.last_expr_cost().is_none());
        for id in wire_ids(&rec.log()[n0..]) {
            assert!(!wire_alive(&mut db, &id), "{:?}: {}", flags, id);
        }
    }
}

#[test]
fn unused_wires_expire_after_the_ttl() {
    let Some(s) = Server::start(&["--wire-ttl", "0.3"]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    seed(&mut db, "t");
    db.raw_call("wire_exec", json!([[["load", "w1", "t", "a", [0, 1, 2], false]]])).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let e = db.raw_call("wire_exec", json!([[["reveal", "w1", 0, 3]]])).unwrap_err();
    assert!(e.kind == Kind::Server("WireError".into()) && e.message.contains("expired"), "{}", e);
    assert_eq!(rows_of(db.expr("t", "a*b", all()).unwrap()).len(), 4); // normal queries are unaffected
}

#[test]
fn a_server_without_the_wire_rpcs_gets_a_clear_error_before_any_wire_request_and_owner_mode_still_works() {
    let Some(s) = Server::start(&[]) else { return };
    let strip: Arc<common::fake::Mutate> = Arc::new(|m: &str, _a: &Value, mut reply: Value, _n: usize| {
        if m == "hello" {
            if let Some(l) = reply["ok"]["limits"].as_object_mut() {
                l.remove("wires");
            }
        }
        reply
    });
    let rec = recorder(&s.addr, Some(strip));
    let mut db = Client::connect(&rec.addr).unwrap();
    assert!(db.server_info().limits.as_ref().unwrap().wires.is_none());
    seed(&mut db, "t");
    let n0 = rec.len();
    let e = db.expr("t", "a*b*c", all()).unwrap_err();
    assert!(
        e.kind == Kind::Server("ExecError".into()) && e.message.contains("ExprMode::Owner") && e.message.contains("expr_mode='owner'"),
        "{}",
        e
    );
    assert!(db.last_expr_cost().is_none());
    assert!(!rec.log()[n0..].iter().any(|(m, _)| m.starts_with("wire_")), "a wire RPC was sent to a server that does not offer it");
    db.set_expression_mode(ExprMode::Owner);
    assert_eq!(show(&db.expr("t", "a*b*c", all()).unwrap()), fshows(&prod(&["a", "b", "c"])));
}

#[test]
fn the_read_only_role_may_run_shared_expressions_and_still_cannot_write() {
    let dir = tmpdir("exprauth");
    let f = dir.join("tokens");
    std::fs::write(&f, format!("admin:{}\nrw:{}\nro:{}\n", ADMIN, RW, RO)).unwrap();
    let Some(s) = Server::start(&["--token-file", f.to_str().unwrap()]) else { return };
    let vf = dir.join("vault.json");
    let with = |tok: &str| ConnectOptions { token: Some(tok.into()), vault_path: Some(vf.clone()), ..Default::default() };
    let mut rw = Client::connect_with(&s.addr, &with(RW)).unwrap();
    seed(&mut rw, "t");
    rw.save_vault(Some(&vf)).unwrap();
    let mut ro = Client::connect_with(&s.addr, &with(RO)).unwrap();
    assert_eq!(show(&ro.expr("t", "a*b*c", all()).unwrap()), fshows(&prod(&["a", "b", "c"])));
    assert_eq!(ro.update("t", vec![("a", ci(1))], eq_int("id", 1)).unwrap_err().kind, Kind::Forbidden);
    let reply = raw_rpc(&s.addr, "wire_exec", json!([[]])); // no token
    assert!(reply["err"].as_str().unwrap().starts_with("Unauthenticated"), "{}", reply);
}

#[test]
fn a_server_limit_on_the_request_size_splits_every_level_within_the_advertised_caps() {
    let Some(s) = Server::start(&[]) else { return };
    let small: Arc<common::fake::Mutate> = Arc::new(|m: &str, _a: &Value, mut reply: Value, _n: usize| {
        if m == "hello" {
            reply["ok"]["limits"]["wires"]["max_request_elements"] = json!(90);
            reply["ok"]["limits"]["wires"]["max_ops"] = json!(5);
        }
        reply
    });
    let rec = recorder(&s.addr, Some(small));
    let mut db = connect(&rec.addr, true);
    db.create_table("t", vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired"), col("q", "int", "plain")]).unwrap();
    let data: Vec<(i64, i64, i64, i64)> = (0..45).map(|i| (i - 20, 2 * i + 1, 7 - i, i % 3 + 1)).collect();
    db.insert_many("t", data.iter().map(|(a, b, c, q)| vec![("a", ci(*a)), ("b", ci(*b)), ("c", ci(*c)), ("q", ci(*q))]).collect()).unwrap();
    let n0 = rec.len();
    let got = db.expr("t", "(a*b*c + q)/q - a/b", all()).unwrap();
    let want: Vec<Fr> = data.iter().map(|(a, b, c, q)| fsub(&fdiv(&fi(a * b * c + q), &fi(*q)), &fdiv(&fi(*a), &fi(*b)))).collect();
    assert_eq!(show(&got), fshows(&want));
    assert!(db.last_expr_cost().unwrap().requests > 6);
    for (m, a) in rec.log()[n0..].iter().filter(|(m, _)| m == "wire_exec") {
        let _ = m;
        let ops = a[0].as_array().unwrap();
        assert!(ops.len() <= 5, "{} ops in one request", ops.len());
        let mut n = 0;
        for op in ops {
            let len = |v: &Value| v.as_array().map(|x| x.len()).unwrap_or(0);
            match op[0].as_str().unwrap() {
                "load" | "loadsum" => n += len(&op[4]),
                "mulv" | "addv" => n += len(&op[3]),
                "put" => n += len(&op[2]) * if op[3].is_null() { 1 } else { 2 },
                "mul" => n += op[4].as_object().unwrap().values().map(len).sum::<usize>(),
                "reveal" => n += 2 * op[3].as_u64().unwrap() as usize,
                _ => {}
            }
        }
        assert!(n <= 90, "{} elements in one request", n);
    }
    let sum: i64 = data.iter().map(|(a, b, c, _)| a * b * c).sum();
    assert_eq!(scalar_int(db.expr("t", "SUM(a*b*c)", all()).unwrap()), bi(sum));
}

// ── a malicious server (reply level): integrity in authenticated mode, typed errors always ────
fn plus(x: &Value, d: &BigInt) -> Value {
    let v: BigInt = x.as_str().unwrap().parse().unwrap();
    json!(((v + d) % n()).to_string())
}
/// Rewrite the results of every `wire_exec` reply: f(ops, results, nth wire_exec).
fn wire_tamper(f: impl Fn(&[Value], &mut Vec<Value>, usize) + Send + Sync + 'static) -> Arc<common::fake::Mutate> {
    let nth_exec = std::sync::atomic::AtomicUsize::new(0);
    Arc::new(move |m: &str, a: &Value, mut reply: Value, _n: usize| {
        if m == "wire_exec" && reply.get("ok").is_some() {
            let k = nth_exec.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let mut res = reply["ok"].as_array().unwrap().clone();
            f(a[0].as_array().unwrap(), &mut res, k);
            reply["ok"] = Value::Array(res);
        }
        reply
    })
}

#[test]
fn authenticated_tampered_reveal_opening_share_and_tags_are_detected_unauthenticated_is_pinned_as_undetected() {
    let Some(s) = Server::start(&[]) else { return };
    let one = bi(1);
    // the final reveal
    let rec = recorder(
        &s.addr,
        Some(wire_tamper(move |ops, res, _| {
            for (i, op) in ops.iter().enumerate() {
                if op[0] == "reveal" {
                    res[i][0][0] = plus(&res[i][0][0], &bi(1));
                }
            }
        })),
    );
    let mut db = connect(&rec.addr, true);
    seed(&mut db, "t1");
    let e = db.expr("t1", "a*b*c", all()).unwrap_err();
    assert!(e.kind == Kind::Integrity && e.message.contains("MAC check failed"), "{}", e);
    // an opening share e_S (its tag share stays honest)
    let rec = recorder(
        &s.addr,
        Some(wire_tamper(|ops, res, _| {
            for (i, op) in ops.iter().enumerate() {
                if op[0] == "mul" {
                    res[i][0][2] = plus(&res[i][0][2], &bi(3));
                }
            }
        })),
    );
    let mut db = connect(&rec.addr, true);
    seed(&mut db, "t2");
    let e = db.expr("t2", "a*b*c", all()).unwrap_err();
    assert!(e.kind == Kind::Integrity && e.message.contains("MAC check failed on a multiplication opening"), "{}", e);
    // the tag share of the opening
    let rec = recorder(
        &s.addr,
        Some(wire_tamper(|ops, res, _| {
            for (i, op) in ops.iter().enumerate() {
                if op[0] == "mul" {
                    res[i][2][1] = plus(&res[i][2][1], &bi(1));
                }
            }
        })),
    );
    let mut db = connect(&rec.addr, true);
    seed(&mut db, "t3");
    assert_eq!(db.expr("t3", "a*b*c", all()).unwrap_err().kind, Kind::Integrity);
    assert!(db.last_expr_cost().is_none());
    // WITHOUT authentication a lying server shifts the result by a delta of its choosing and nothing notices
    let rec = recorder(
        &s.addr,
        Some(wire_tamper(|ops, res, nth| {
            if nth > 1 {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "reveal" {
                        res[i][0][0] = plus(&res[i][0][0], &bi(17));
                    }
                }
            }
        })),
    );
    let mut db = connect(&rec.addr, false);
    seed(&mut db, "t4");
    let got = rows_of(db.expr("t4", "a*b+0", all()).unwrap());
    let honest: Vec<BigInt> = rows().iter().map(|r| bi(r.a) * bi(r.b)).collect();
    assert_eq!(got[0], Some(Decoded::Int(&honest[0] + bi(17))));
    for k in 1..4 {
        assert_eq!(got[k], Some(Decoded::Int(honest[k].clone())));
    }
    let _ = one;
}

#[test]
fn authenticated_a_server_computing_with_other_shares_than_it_reports_is_caught() {
    let Some(s) = Server::start(&[]) else { return };
    for (target, sql) in [("put", "a/b"), ("mulv", "a/b"), ("mul_w", "a*b*c"), ("mul_eo", "a*b*c")] {
        let req: Arc<common::fake::MutateReq> = Arc::new(move |m: &str, a: &mut Value| {
            if m != "wire_exec" {
                return;
            }
            for op in a[0].as_array_mut().unwrap() {
                let name = op[0].as_str().unwrap().to_string();
                if name == "put" && target == "put" {
                    op[2][0] = plus(&op[2][0], &bi(1));
                }
                if name == "mulv" && target == "mulv" {
                    op[3][0] = plus(&op[3][0], &bi(1));
                }
                if name == "mul" && target == "mul_w" {
                    op[4]["w"][0] = plus(&op[4]["w"][0], &bi(1)); // its product share is shifted
                }
                if name == "mul" && target == "mul_eo" {
                    let eo: Vec<Value> = op[4]["eo"].as_array().unwrap().iter().map(|x| plus(x, &bi(1))).collect(); // e' = e + 1
                    op[4]["eo"] = Value::Array(eo);
                }
            }
        });
        let px = recorder_hooks(&s.addr, Hooks { req: Some(req), ..Default::default() });
        let mut db = connect(&px.addr, true);
        let t = format!("tw_{}", target);
        seed(&mut db, &t);
        assert_eq!(db.expr(&t, sql, all()).unwrap_err().kind, Kind::Integrity, "{}", target);
    }
}

fn denominator_tamper(zero_row: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(
        &s.addr,
        Some(wire_tamper(|ops, res, _| {
            if ops.iter().any(|o| o[0] == "mul") {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "reveal" {
                        res[i][0][3] = plus(&res[i][0][3], &bi(12345));
                    }
                }
            }
        })),
    );
    let mut db = connect(&rec.addr, true);
    let mut rs = rows();
    if zero_row {
        rs[3].b = 0;
    }
    seed_rows(&mut db, "t", &rs);
    assert_eq!(db.expr("t", "a/b", all()).unwrap_err().kind, Kind::Integrity);
}
#[test]
fn authenticated_tampering_with_the_denominator_is_an_integrity_error_not_a_zero_oracle_non_zero() {
    denominator_tamper(false)
}
#[test]
fn authenticated_tampering_with_the_denominator_is_an_integrity_error_not_a_zero_oracle_zero_row() {
    denominator_tamper(true)
}

#[test]
fn malformed_wire_replies_are_typed_errors_never_a_wrong_number() {
    let Some(s) = Server::start(&[]) else { return };
    type Fix = Box<dyn Fn(&[Value], Vec<Value>) -> Value + Send + Sync>;
    let cases: Vec<(&str, Fix, Kind)> = vec![
        ("too few results", Box::new(|_o, res| Value::Array(res[1..].to_vec())), Kind::Integrity),
        ("not a list", Box::new(|_o, _r| Value::Null), Kind::Integrity),
        (
            "a non-numeric element",
            Box::new(|ops, mut res| {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "mul" {
                        res[i][0][0] = json!("x");
                    }
                }
                Value::Array(res)
            }),
            Kind::Protocol,
        ),
        (
            "an element >= n",
            Box::new(|ops, mut res| {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "mul" {
                        res[i][1][0] = json!(n().to_string());
                    }
                }
                Value::Array(res)
            }),
            Kind::Integrity,
        ),
        (
            "a short vector",
            Box::new(|ops, mut res| {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "mul" {
                        let v = res[i][0].as_array().unwrap()[1..].to_vec();
                        res[i][0] = Value::Array(v);
                    }
                }
                Value::Array(res)
            }),
            Kind::Integrity,
        ),
        (
            "a malformed reveal",
            Box::new(|ops, mut res| {
                for (i, op) in ops.iter().enumerate() {
                    if op[0] == "reveal" {
                        res[i] = json!([res[i][0].clone()]);
                    }
                }
                Value::Array(res)
            }),
            Kind::Integrity,
        ),
    ];
    for (k, (label, fix, want)) in cases.into_iter().enumerate() {
        let m: Arc<common::fake::Mutate> = Arc::new(move |m: &str, a: &Value, mut reply: Value, _n: usize| {
            if m == "wire_exec" && reply.get("ok").is_some() {
                let res = reply["ok"].as_array().unwrap().clone();
                reply["ok"] = fix(a[0].as_array().unwrap(), res);
            }
            reply
        });
        let rec = recorder(&s.addr, Some(m));
        let mut db = Client::connect(&rec.addr).unwrap();
        let t = format!("mal{}", k);
        seed(&mut db, &t);
        assert_eq!(db.expr(&t, "a*b*c", all()).unwrap_err().kind, want, "{}", label);
        assert!(db.last_expr_cost().is_none());
    }
}

// ── stored cells tampered, swapped, replayed (authenticated) ──────────────────────────────────
fn cell_of(addr: &str, t: &str, c: &str, id: i64) -> Value {
    raw_rpc(addr, "blinded_cells", json!([t, c, [id]]))["ok"][0].clone()
}
fn set_cell(addr: &str, t: &str, id: i64, c: &str, v: &Value) {
    let r = raw_rpc(addr, "update_cell", json!([t, id, c, v]));
    assert!(r.get("err").is_none(), "{}", r);
}

#[test]
fn authenticated_a_tampered_stored_cell_is_detected_whatever_the_expression() {
    let Some(s) = Server::start(&[]) else { return };
    for (k, sql) in ["a*b*c*d", "a/b", "SUM(a+b)", "SUM(a*b)/SUM(c)", "b*2+a"].iter().enumerate() {
        let mut db = connect(&s.addr, true);
        let t = format!("tc{}", k);
        seed(&mut db, &t);
        let cell = cell_of(&s.addr, &t, "b", 1);
        set_cell(&s.addr, &t, 1, "b", &json!({"t": "i", "v": plus(&cell["v"], &bi(5))}));
        assert_eq!(db.expr(&t, sql, all()).unwrap_err().kind, Kind::Integrity, "{}", sql);
        set_cell(&s.addr, &t, 1, "b", &cell);
        db.expr(&t, sql, all()).unwrap();
    }
}

#[test]
fn authenticated_swapped_replayed_and_mac_only_tampered_cells_are_detected() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s.addr, true);
    seed(&mut db, "t");
    let (a1, a2) = (cell_of(&s.addr, "t", "a", 1), cell_of(&s.addr, "t", "a", 2));
    let (m1, m2) = (cell_of(&s.addr, "t", "__mac__a", 1), cell_of(&s.addr, "t", "__mac__a", 2));
    for (r, v, m) in [(1, &a2, &m2), (2, &a1, &m1)] {
        set_cell(&s.addr, "t", r, "a", v);
        set_cell(&s.addr, "t", r, "__mac__a", m);
    }
    assert_eq!(db.expr("t", "a*b*c", all()).unwrap_err().kind, Kind::Integrity);
    for (r, v, m) in [(1, &a1, &m1), (2, &a2, &m2)] {
        set_cell(&s.addr, "t", r, "a", v);
        set_cell(&s.addr, "t", r, "__mac__a", m);
    }
    db.expr("t", "a*b*c", all()).unwrap();
    // replay: a consistent stale (cell, tag) pair from before an UPDATE
    let (old, oldm) = (cell_of(&s.addr, "t", "a", 2), cell_of(&s.addr, "t", "__mac__a", 2));
    db.update("t", vec![("a", ci(999))], eq_int("id", 3)).unwrap();
    set_cell(&s.addr, "t", 2, "a", &old);
    set_cell(&s.addr, "t", 2, "__mac__a", &oldm);
    assert_eq!(db.expr("t", "SUM(a*b)/SUM(c)", all()).unwrap_err().kind, Kind::Integrity);
    // only the MAC cell
    seed(&mut db, "t2");
    let mb = cell_of(&s.addr, "t2", "__mac__b", 3);
    set_cell(&s.addr, "t2", 3, "__mac__b", &json!({"t": "i", "v": plus(&mb["v"], &bi(1))}));
    assert_eq!(db.expr("t2", "a*b*c", all()).unwrap_err().kind, Kind::Integrity);
}

#[test]
fn pinned_limitation_unauthenticated_shared_wires_leak_a_zero_oracle_to_an_active_server_authenticated_ones_do_not() {
    let Some(s) = Server::start(&[]) else { return };
    for auth in [false, true] {
        let mut outcomes = vec![];
        for (k, guess) in [7i64, 107].iter().enumerate() {
            let mut db = connect(&s.addr, auth);
            let t = format!("zo{}_{}", auth as u8, k);
            db.create_table(&t, vec![col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
            db.insert_many(&t, vec![vec![("a", ci(3)), ("b", ci(7))]]).unwrap();
            let cell = cell_of(&s.addr, &t, "b", 0); // the active server shifts the stored share of y by -guess
            set_cell(&s.addr, &t, 0, "b", &json!({"t": "i", "v": plus(&cell["v"], &(n() - bi(*guess)))}));
            outcomes.push(match db.expr(&t, "a/b", all()) {
                Ok(_) => "ok",
                Err(e) if e.kind == Kind::DivisionByZero => "zero",
                Err(e) if e.kind == Kind::Integrity => "integrity",
                Err(_) => "other",
            });
        }
        assert_eq!(outcomes, if auth { vec!["integrity", "integrity"] } else { vec!["zero", "ok"] }, "auth={}", auth);
    }
}

// ── the wire audit: what the server is sent ─────────────────────────────────────────────────────
const ALLOWED: [&str; 6] = ["wire_exec", "wire_free", "matching_rowids", "plain_cells", "schema", "tables"];

fn collect_ints(v: &Value, out: &mut HashSet<String>) {
    match v {
        Value::Number(x) => {
            out.insert(x.to_string());
        }
        Value::String(s) => {
            if !s.is_empty() && s.trim_start_matches('-').bytes().all(|c| c.is_ascii_digit()) {
                out.insert(s.clone());
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_ints(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_ints(x, out)),
        _ => {}
    }
}
/// The banned values (decimal strings) that appear anywhere in the requests of `log`.
fn leaked(log: &[(String, Value)], banned: &HashSet<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    for (_, a) in log {
        collect_ints(a, &mut seen);
    }
    let mut v: Vec<String> = banned.iter().filter(|b| seen.contains(*b)).cloned().collect();
    v.sort();
    v
}

const CHI2_LIMIT: f64 = 50.0; // 16 bins, df = 15: P(> 50) ~ 1e-5
fn bin(v: &BigInt) -> usize {
    (v * BigInt::from(16) / n()).to_string().parse::<usize>().unwrap().min(15)
}
fn chi2(vals: &[BigInt]) -> f64 {
    let mut cnt = [0f64; 16];
    for v in vals {
        cnt[bin(v)] += 1.0;
    }
    let exp = vals.len() as f64 / 16.0;
    cnt.iter().map(|o| (o - exp) * (o - exp) / exp).sum()
}
fn big_of(v: &Value) -> BigInt {
    v.as_str().unwrap().parse().unwrap()
}
/// Violations in what a server received: the ring elements of triples / openings and `put`s must be uniform and
/// never repeat. Empty = clean. Mirrors core/tests/test_expr_shared.py `audit`.
fn audit(log: &[(String, Value)]) -> Vec<String> {
    let mut bad = vec![];
    let mut pooled: std::collections::BTreeMap<String, Vec<BigInt>> = Default::default();
    let mut puts: Vec<BigInt> = vec![];
    for (m, a) in log {
        if m != "wire_exec" {
            continue;
        }
        for op in a[0].as_array().unwrap() {
            if op[0] == "mul" {
                for (k, v) in op[4].as_object().unwrap() {
                    pooled.entry(k.clone()).or_default().extend(v.as_array().unwrap().iter().map(big_of));
                }
            } else if op[0] == "put" {
                puts.extend(op[2].as_array().unwrap().iter().map(big_of));
                if let Some(t) = op[3].as_array() {
                    puts.extend(t.iter().map(big_of));
                }
            }
        }
    }
    for (k, vals) in &pooled {
        if vals.len() >= 1000 && chi2(vals) >= CHI2_LIMIT {
            bad.push(format!("mul.{}: not uniform", k));
        }
        if vals.iter().collect::<HashSet<_>>().len() != vals.len() {
            bad.push(format!("mul.{}: a value repeated (triple/mask reuse)", k));
        }
    }
    if !puts.is_empty() {
        if puts.iter().collect::<HashSet<_>>().len() != puts.len() {
            bad.push("put: a value repeated".into());
        }
        if puts.len() >= 1000 && chi2(&puts) >= CHI2_LIMIT {
            bad.push("put: not uniform".into());
        }
    }
    bad
}

fn identical_rows(addr: &str, auth: bool, t: &str, rows: usize) -> Client {
    let mut db = Client::connect_with(addr, &ConnectOptions { authenticated: auth, timeout: Some(std::time::Duration::from_secs(120)), ..Default::default() }).unwrap();
    db.create_table(t, vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired"), col("d", "int", "paired")]).unwrap();
    db.insert_many(t, (0..rows).map(|_| vec![("a", ci(7)), ("b", ci(7)), ("c", ci(7)), ("d", ci(7))]).collect()).unwrap();
    db
}

fn uniform_audit(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = identical_rows(&rec.addr, auth, "z", 1200);
    let n0 = rec.len();
    let got = rows_of(db.expr("z", "a*b*c*d", all()).unwrap()); // 3 levels
    assert!(got.len() == 1200 && got.iter().all(|x| *x == Some(Decoded::Int(bi(2401)))));
    db.expr("z", "a/b", all()).unwrap(); // a division
    let sent = rec.log()[n0..].to_vec();
    assert_eq!(audit(&sent), Vec::<String>::new());
    let muls: Vec<&Value> = sent.iter().filter(|(m, _)| m == "wire_exec").flat_map(|(_, a)| a[0].as_array().unwrap().iter()).filter(|op| op[0] == "mul").collect();
    assert_eq!(muls.len(), 3 + 2);
    assert!(muls.iter().all(|op| op[4]["eo"].as_array().unwrap().len() == 1200 && op[4]["go"].as_array().unwrap().len() == 1200));
    // the control: the same audit flags a log in which the dealer did not mask its share
    let mut bad = sent.clone();
    for (m, a) in bad.iter_mut() {
        if m == "wire_exec" {
            for op in a[0].as_array_mut().unwrap() {
                if op[0] == "mul" {
                    let k = op[4]["eo"].as_array().unwrap().len();
                    op[4]["eo"] = Value::Array(vec![json!("123"); k]);
                    op[4]["go"] = Value::Array(vec![json!("456"); k]);
                }
            }
        }
    }
    let v = audit(&bad);
    assert!(v.iter().any(|x| x.contains("eo")) && v.iter().any(|x| x.contains("go")), "{:?}", v);
}
#[test]
fn wire_audit_identical_plaintexts_give_uniform_shares_at_every_level_plain() {
    uniform_audit(false)
}
#[test]
fn wire_audit_identical_plaintexts_give_uniform_shares_at_every_level_authenticated() {
    uniform_audit(true)
}

fn pinv(x: &BigInt) -> BigInt {
    (((x % n()) + n()) % n()).modpow(&(n() - 2), n())
}

fn nothing_secret(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, auth);
    seed(&mut db, "aud");
    db.update("aud", vec![("b", ci(2_000_099))], eq_int("id", 2)).unwrap();
    let mut rs = rows();
    rs[1].b = 2_000_099;
    let queries = [
        "a*b*c*d", "SUM(a*b*c*a)", "a/b", "r/c*a", "SUM(a*b)/COUNT(*)", "s/4+a*b*c", "SUM(a+b-s/2)", "(a+b)*(c-a)*b+s/3", "a/(b*c)*r", "100/b",
        "SUM(a)/SUM(b)", "a/b/c",
    ];
    let n0 = rec.len();
    for q in queries {
        db.expr("aud", q, all()).unwrap();
    }
    let sent = rec.log()[n0..].to_vec();
    let vf = tmpdir("audit-vault").join("v.json");
    db.save_vault(Some(&vf)).unwrap();
    let vault: Value = serde_json::from_str(&std::fs::read_to_string(&vf).unwrap()).unwrap();
    let masks: HashSet<String> = vault["masks"].as_array().unwrap().iter().map(|m| m[3].as_str().unwrap().to_string()).collect();
    assert!(masks.len() > 20);
    for (m, _) in &sent {
        assert!(ALLOWED.contains(&m.as_str()), "unexpected RPC {}", m);
    }
    assert!(sent.iter().any(|(m, _)| m == "wire_exec") && !sent.iter().any(|(m, _)| m == "blinded_cells" || m == "mult_combine_batch"));
    assert!(leaked(&sent, &masks).is_empty(), "a mask value reached the server");
    if auth {
        let alpha: HashSet<String> = [vault["alpha"].as_str().unwrap().to_string()].into();
        assert!(leaked(&sent, &alpha).is_empty(), "the MAC key reached the server");
    }
    let fr_ = |nn: BigInt, d: BigInt| encode_rational(&nn, &d).unwrap();
    let mut secrets: HashSet<String> = HashSet::new();
    for r in &rs {
        let (a, b, c, d) = (bi(r.a), bi(r.b), bi(r.c), bi(r.d));
        let (rn, rd, sn, sd) = (bi(r.r.0), bi(r.r.1), bi(r.s.0), bi(r.s.1));
        let mut vals: Vec<BigInt> = [
            a.clone(), b.clone(), c.clone(), d.clone(), &a * &b, &a * &b * &c, &a * &b * &c * &d, &a * &b * &c * &a, &a + &b, &c - &a, (&a + &b) * (&c - &a),
            (&a + &b) * (&c - &a) * &b,
        ]
        .iter()
        .map(|v| encode_int(v).unwrap())
        .collect();
        vals.extend([
            fr_(rn.clone(), rd.clone()), fr_(sn.clone(), sd.clone()), fr_(sn.clone(), &sd * 4), fr_(sn.clone(), &sd * 3), fr_(a.clone(), b.clone()),
            fr_(bi(1), b.clone()), fr_(bi(1), &b * &c), fr_(a.clone(), &b * &c), fr_(&a * &rn, &b * &c * &rd), fr_(rd.clone(), rn.clone()),
            fr_(rn.clone(), &rd * &c), fr_(&rn * &a, &rd * &c), fr_(bi(100), b.clone()), fr_(bi(1), c.clone()), fr_(&a * &c, &b * &c * &c),
        ]);
        vals.extend([pinv(&encode_int(&b).unwrap()), pinv(&encode_int(&c).unwrap()), pinv(&encode_int(&(&b * &c)).unwrap()), pinv(&encode_int(&d).unwrap()), pinv(&fr_(rn, rd))]);
        for v in vals {
            if v >= bi(1000) && v < n() - bi(1000) {
                secrets.insert(v.to_string());
            }
        }
    }
    for (p, q) in [(1, 4), (-1, 4), (1, 3), (-1, 3), (1, 2), (-1, 2)] {
        secrets.remove(&encode_rational(&bi(p), &bi(q)).unwrap().to_string()); // public constants of the queries
    }
    assert!(leaked(&sent, &secrets).is_empty(), "a plaintext / intermediate / inverse encoding reached the server");
    assert_eq!(audit(&sent), Vec::<String>::new());
    // the check has teeth: a mask, the MAC key or an encoded plaintext slipped into ANY request is found
    let mut doctored = sent.clone();
    let k = doctored.iter().position(|(m, _)| m == "wire_exec").unwrap();
    let m0 = masks.iter().next().unwrap().clone();
    doctored[k].1[0].as_array_mut().unwrap().push(json!(["free", [m0.clone()]]));
    assert_eq!(leaked(&doctored, &masks), vec![m0]);
    let s0 = secrets.iter().next().unwrap().clone();
    doctored[k].1[0].as_array_mut().unwrap().push(json!(["mulc", "x.1", "x.2", s0.clone()]));
    assert_eq!(leaked(&doctored, &secrets), vec![s0]);
    // every triple / opening share is a huge uniform-looking residue, never reused
    let mut shares: Vec<BigInt> = vec![];
    for (m, a) in &sent {
        if m == "wire_exec" {
            for op in a[0].as_array().unwrap() {
                if op[0] == "mul" {
                    for key in ["u", "v", "w", "eo", "go"] {
                        shares.extend(op[4][key].as_array().unwrap().iter().map(big_of));
                    }
                }
            }
        }
    }
    let big_ones = shares.iter().filter(|x| **x > n() / 100).count();
    assert!(shares.len() > 100 && big_ones as f64 > 0.95 * shares.len() as f64);
    assert_eq!(shares.iter().collect::<HashSet<_>>().len(), shares.len());
}
#[test]
fn wire_audit_nothing_derived_from_keys_masks_plaintexts_or_intermediates_reaches_the_server_plain() {
    nothing_secret(false)
}
#[test]
fn wire_audit_nothing_derived_from_keys_masks_plaintexts_or_intermediates_reaches_the_server_authenticated() {
    nothing_secret(true)
}

#[test]
fn wire_audit_two_different_plaintexts_give_indistinguishable_opening_shares() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = Client::connect_with(&rec.addr, &ConnectOptions { timeout: Some(std::time::Duration::from_secs(120)), ..Default::default() }).unwrap();
    db.create_table("t", vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired")]).unwrap();
    let mut data = vec![];
    for _ in 0..1500 {
        data.push(vec![("a", ci(0)), ("b", ci(0)), ("c", ci(0))]);
        data.push(vec![("a", ci(10_000_000_000_000)), ("b", ci(-4)), ("c", ci(123_456_789))]);
    }
    db.insert_many("t", data).unwrap();
    let n0 = rec.len();
    db.expr("t", "a*b*c", all()).unwrap();
    let muls: Vec<Value> = rec.log()[n0..].iter().filter(|(m, _)| m == "wire_exec").flat_map(|(_, a)| a[0].as_array().unwrap().clone()).filter(|op| op[0] == "mul").collect();
    let eo: Vec<BigInt> = muls[1][4]["eo"].as_array().unwrap().iter().map(big_of).collect(); // level 2: the operand is an intermediate
    let (mut ca, mut cb) = ([0f64; 16], [0f64; 16]);
    for (i, v) in eo.iter().enumerate() {
        if i % 2 == 0 {
            ca[bin(v)] += 1.0;
        } else {
            cb[bin(v)] += 1.0;
        }
    }
    let stat: f64 = (0..16).map(|k| (ca[k] - cb[k]).powi(2) / (ca[k] + cb[k]).max(1.0)).sum();
    assert!(stat < CHI2_LIMIT, "two-sample chi2 {}", stat);
    assert!(chi2(&eo) < CHI2_LIMIT);
}

#[test]
fn wire_audit_controls_a_reused_triple_is_caught_by_the_audit_helper() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = identical_rows(&rec.addr, false, "z", 1200);
    let n0 = rec.len();
    db.expr("z", "a*b*c", all()).unwrap();
    let mut sent = rec.log()[n0..].to_vec();
    assert_eq!(audit(&sent), Vec::<String>::new());
    let first_u = sent.iter().find(|(m, _)| m == "wire_exec").and_then(|(_, a)| a[0].as_array().unwrap().iter().find(|op| op[0] == "mul").map(|op| op[4]["u"].clone())).unwrap();
    let mut seen_first = false;
    for (m, a) in sent.iter_mut() {
        if m == "wire_exec" {
            for op in a[0].as_array_mut().unwrap() {
                if op[0] == "mul" {
                    if seen_first {
                        op[4]["u"] = first_u.clone(); // the second level reuses the first level's triple
                    }
                    seen_first = true;
                }
            }
        }
    }
    assert!(audit(&sent).iter().any(|x| x.contains("repeated")));
}

// ── a hostile fake server: the evaluator cleans up after itself ────────────────────────────────
#[test]
fn a_malformed_wire_exec_reply_aborts_with_a_typed_error_then_wire_free_names_every_wire_the_query_created() {
    let wires = json!({"max_wires": 4096, "max_elements": 4000000, "ttl": 120, "max_ops": 20000, "max_request_elements": 150000});
    let f = fake(base(move |m, _a, _n| match m {
        "hello" => Some(Reply::Json(json!({"ok": {"protocol": 2, "server": "fake", "auth_required": false, "max_frame": 33554432, "persistent": false,
                                                  "limits": {"max_items": 200000, "wires": wires.clone()}}}))),
        "insert_many" => Some(Reply::Json(json!({"ok": [0, 1]}))),
        "matching_rowids" => Some(Reply::Json(json!({"ok": [0, 1]}))),
        "wire_exec" => Some(Reply::Json(json!({"ok": []}))), // wrong number of results
        "wire_free" => Some(Reply::Json(json!({"ok": 0}))),
        _ => None,
    }));
    let mut db = Client::connect(&f.addr).unwrap();
    db.create_table("t", vec![col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
    db.insert_many("t", vec![vec![("a", ci(1)), ("b", ci(2))], vec![("a", ci(3)), ("b", ci(4))]]).unwrap();
    assert_eq!(db.expr("t", "a*b", all()).unwrap_err().kind, Kind::Integrity);
    assert!(db.last_expr_cost().is_none());
    let bodies: Vec<Value> = f.bodies().iter().map(|b| serde_json::from_str(b).unwrap()).collect();
    let execs: Vec<&Value> = bodies.iter().filter(|r| r["m"] == "wire_exec").collect();
    let frees: Vec<&Value> = bodies.iter().filter(|r| r["m"] == "wire_free").collect();
    assert_eq!((execs.len(), frees.len()), (1, 1));
    let created: HashSet<String> = wire_ids(&[("wire_exec".to_string(), execs[0]["a"].clone())]).into_iter().collect();
    assert!(created.len() >= 3);
    let freed: HashSet<String> = frees[0]["a"][0].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    assert_eq!(freed, created);
}

#[test]
fn the_multiplier_t_inverse_a_division_sends_is_uniform_nonzero_and_never_repeated_whether_or_not_y_was_zero() {
    let Some(s) = Server::start(&[]) else { return };
    let mut samples: Vec<(&str, Vec<BigInt>)> = vec![];
    for (label, yval) in [("nonzero", 123_456_789i64), ("zero", 0)] {
        let rec = recorder(&s.addr, None);
        let mut db = Client::connect_with(&rec.addr, &ConnectOptions { timeout: Some(std::time::Duration::from_secs(120)), ..Default::default() }).unwrap();
        let t = format!("tinv_{}", label);
        db.create_table(&t, vec![col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
        db.insert_many(&t, (0..2500).map(|_| vec![("a", ci(5)), ("b", ci(yval))]).collect()).unwrap();
        let n0 = rec.len();
        if yval != 0 {
            db.expr(&t, "a/b", all()).unwrap();
        } else {
            assert_eq!(db.expr(&t, "a/b", all()).unwrap_err().kind, Kind::DivisionByZero);
        }
        let mut tinv = vec![];
        for (m, a) in &rec.log()[n0..] {
            if m == "wire_exec" {
                for op in a[0].as_array().unwrap() {
                    if op[0] == "mulv" {
                        tinv.extend(op[3].as_array().unwrap().iter().map(big_of));
                    }
                }
            }
        }
        samples.push((label, tinv));
    }
    for (label, vals) in &samples {
        assert_eq!(vals.len(), 2500, "{}", label);
        assert!(!vals.contains(&BigInt::zero()), "{}: a zero multiplier reached the server", label);
        assert!(chi2(vals) < CHI2_LIMIT, "{}: not uniform", label);
        assert_eq!(vals.iter().collect::<HashSet<_>>().len(), vals.len(), "{}", label);
    }
    let (mut ca, mut cb) = ([0f64; 16], [0f64; 16]);
    for v in &samples[0].1 {
        ca[bin(v)] += 1.0;
    }
    for v in &samples[1].1 {
        cb[bin(v)] += 1.0;
    }
    let stat: f64 = (0..16).map(|k| (ca[k] - cb[k]).powi(2) / (ca[k] + cb[k]).max(1.0)).sum();
    assert!(stat < CHI2_LIMIT, "{}", stat);
}
