// SPDX-License-Identifier: Apache-2.0
//! Cross-implementation check: the SAME expressions run through the Python engine (a peer process) and this
//! driver against ONE real server; values, error classes and costs must be identical. Random expressions
//! (seed in TORUSDB_PEER_SEED) exercise precedence, division, zero denominators, NULLs and the budget.
use serde_json::{json, Value};
use torusdb::*;

mod common;
use common::*;

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

const FIXED: [&str; 17] = [
    "a*b*c", "a*b*c*d", "(a+b)*(c-d)*a+s/2", "SUM(a*b*c)/COUNT(*)", "a/b", "r/c*a", "SUM(a)/SUM(c)", "100/c", "AVG(a*b)", "a*b/(c*d)",
    "SUM(a+2*b-s/4)", "a/0", "a*name", "SUM(id*2)", "s*a*b", "a*(b-b)", "1/(a-a)",
];

fn show1(v: &Option<Decoded>) -> Value {
    match v {
        None => Value::Null,
        Some(Decoded::Int(b)) => json!(b.to_string()),
        Some(Decoded::Rational(n, d)) => json!(format!("{}/{}", n, d)),
    }
}

fn peer_check(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let seed: u64 = std::env::var("TORUSDB_PEER_SEED").ok().and_then(|x| x.parse().ok()).unwrap_or(20260626) + auth as u64;
    let mut r = Lcg(seed);
    let mut exprs: Vec<String> = FIXED.iter().map(|x| x.to_string()).collect();
    while exprs.len() < 190 {
        let depth = 1 + (r.next() * 4.0) as usize;
        let t = gen_tree(&mut r, depth, &["a", "b", "c", "d", "r", "q"]);
        if t.chars().all(|c| c.is_ascii_lowercase()) {
            continue;
        }
        exprs.push(t);
    }
    let vec: Value = serde_json::from_str(&std::fs::read_to_string(expr_vectors_path()).unwrap()).unwrap();
    let tdef = vec["exec"]["tables"].as_array().unwrap().iter().find(|t| t["name"] == "t").unwrap();
    let cols: Vec<Column> = tdef["columns"].as_array().unwrap().iter().map(|c| col(c[0].as_str().unwrap(), c[1].as_str().unwrap(), c[2].as_str().unwrap())).collect();
    let (py_t, ts_t) = if auth { ("py_t_auth", "rs_t_auth") } else { ("py_t", "rs_t") };
    let queries: Vec<Value> = exprs.iter().map(|e| json!({"table": py_t, "expr": e})).collect();
    let spec = json!({"auth": auth, "tables": [{"name": py_t, "columns": tdef["columns"], "rows": tdef["rows"]}], "queries": queries});
    let host_port: Vec<&str> = s.addr.split(':').collect();
    let peer = run_expr_peer(host_port[0], s.port, &spec);
    let peer = peer.as_array().unwrap();
    assert_eq!(peer.len(), exprs.len());

    let mut db = Client::connect_with(&s.addr, &ConnectOptions { authenticated: auth, ..Default::default() }).unwrap();
    db.create_table(ts_t, cols.clone()).unwrap();
    let cell = |v: &Value| -> CellIn {
        match v.as_str() {
            None => CellIn::Null,
            Some(t) => match t.split_once('/') {
                Some((n, d)) => CellIn::Rational(n.parse().unwrap(), d.parse().unwrap()),
                None => CellIn::Int(t.parse().unwrap()),
            },
        }
    };
    let rows: Vec<Vec<(&str, CellIn)>> =
        tdef["rows"].as_array().unwrap().iter().map(|row| cols.iter().enumerate().map(|(k, c)| (c.name.as_str(), cell(&row[k]))).collect()).collect();
    db.insert_many(ts_t, rows).unwrap();
    let (mut ok, mut errs) = (0, 0);
    for (i, e) in exprs.iter().enumerate() {
        let got: Value = match db.expr(ts_t, e, all()) {
            Ok(v) => {
                let c = db.last_expr_cost().unwrap();
                let value = match &v {
                    ExprValue::Scalar(x) => show1(x),
                    ExprValue::Rows(rows) => Value::Array(rows.iter().map(show1).collect()),
                };
                ok += 1;
                json!({"value": value, "cost": {"depth": c.depth, "mult_rounds": c.mult_rounds, "products": c.products,
                                                  "inversions": c.inversions, "linear_sums": c.linear_sums}})
            }
            Err(err) => {
                errs += 1;
                json!({"error": err.kind_name()})
            }
        };
        assert_eq!(got, peer[i], "{}", e);
    }
    assert!(ok > 60 && errs > 10, "{} ok / {} errors", ok, errs);
}

#[test]
fn python_engine_and_this_driver_agree_plain() {
    peer_check(false)
}
#[test]
fn python_engine_and_this_driver_agree_authenticated() {
    peer_check(true)
}
