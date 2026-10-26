// SPDX-License-Identifier: Apache-2.0
//! Dialect v0.6 expressions against a REAL keyless server (Python): the shared vectors (every result,
//! error and cost must equal the Python reference), rounds == depth, the depth cap, the abort-oracle
//! protection, integrity (authenticated mode) and an audit of everything the server is sent.
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use torusdb::*;

mod common;
use common::fake::{base, fake, raw_rpc, recorder, Reply};
use common::*;

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
fn int(v: i64) -> Option<Decoded> {
    Some(Decoded::Int(bi(v)))
}
fn big(v: BigInt) -> Option<Decoded> {
    Some(Decoded::Int(v))
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

// ── the shared vectors ───────────────────────────────────────────────────────
fn vectors(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let v = vec_json();
    let mut db = Client::connect_with(&s.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: auth, ..Default::default() }).unwrap();
    load_tables(&mut db, &v);
    let (mut ok, mut bad) = (0, 0);
    for c in v["exec"]["cases"].as_array().unwrap() {
        let what = format!("{} {} {}", c.get("table").unwrap_or(&json!("join")), c["expr"], c.get("where").unwrap_or(&Value::Null));
        let got = run_case(&mut db, c);
        if let Some(err) = c.get("error").and_then(|e| e.as_str()) {
            let e = got.expect_err(&what);
            assert_eq!(e.kind_name(), err, "{}: {}", what, e);
            assert!(db.last_expr_cost().is_none(), "{}", what);
            bad += 1;
        } else {
            let got = got.unwrap_or_else(|e| panic!("{}: {}", what, e));
            assert_eq!(show(&got), c["value"], "{}", what);
            let cost = db.last_expr_cost().unwrap();
            let want = &c["cost"];
            assert_eq!(
                (cost.depth as u64, cost.mult_rounds as u64, cost.products as u64, cost.inversions as u64, cost.linear_sums as u64),
                (
                    want["depth"].as_u64().unwrap(),
                    want["mult_rounds"].as_u64().unwrap(),
                    want["products"].as_u64().unwrap(),
                    want["inversions"].as_u64().unwrap(),
                    want["linear_sums"].as_u64().unwrap()
                ),
                "{}",
                what
            );
            assert_eq!(cost.mult_rounds, cost.depth, "{}", what);
            ok += 1;
        }
    }
    assert!(ok > 300 && bad > 50, "{} ok / {} errors", ok, bad);
}

#[test]
fn vectors_plain() {
    vectors(false)
}
#[test]
fn vectors_authenticated() {
    vectors(true)
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
    vec![
        ("id", ci(r.id)),
        ("dept", ci(r.dept)),
        ("a", ci(r.a)),
        ("b", ci(r.b)),
        ("c", ci(r.c)),
        ("d", ci(r.d)),
        ("r", rcell(r.r)),
        ("s", rcell(r.s)),
    ]
}
fn seed(db: &mut Client, t: &str) {
    db.create_table(t, schema()).unwrap();
    db.insert_many(t, rows().iter().map(row_cells).collect()).unwrap();
}
fn tiny(db: &mut Client, t: &str, vals: &[i64]) {
    db.create_table(t, vec![col("a", "int", "paired")]).unwrap();
    db.insert_many(t, vals.iter().map(|v| vec![("a", ci(*v))]).collect()).unwrap();
}
fn n_methods(log: &[(String, Value)], m: &str) -> usize {
    log.iter().filter(|(x, _)| x == m).count()
}

#[test]
fn rounds_follow_the_multiplicative_depth_checked_on_the_wire() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect_owner(&rec.addr).unwrap();
    seed(&mut db, "t");
    let cases: [(&str, usize); 13] = [
        ("a*b", 1), ("a*b*c", 2), ("a*b*c*d", 3), ("(a*b)*(c*d)", 2), ("a*b + c*d + a*d", 1), ("2*a*b*3", 1), ("a/b", 1),
        ("100/c", 0), ("s/4+a*3", 0), ("a*b*c*d*a*b", 5), ("SUM(a*b*c)", 2), ("SUM(a)/SUM(c)", 1), ("a/b/c", 2),
    ];
    for (x, depth) in cases {
        let n0 = rec.len();
        db.expr("t", x, all()).unwrap();
        assert_eq!(n_methods(&rec.log()[n0..], "mult_combine_batch"), depth, "{}", x);
        let c = db.last_expr_cost().unwrap();
        assert_eq!((c.depth, c.mult_rounds), (depth, depth), "{}", x);
    }
}

#[test]
fn the_depth_cap_is_enforced_before_any_request() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = Client::connect_with(&rec.addr, &ConnectOptions { expression_mode: ExprMode::Owner, max_mult_depth: 2, ..Default::default() }).unwrap();
    seed(&mut db, "t");
    assert_eq!(db.max_mult_depth(), 2);
    db.expr("t", "a*b*c", all()).unwrap(); // depth 2: allowed
    let n0 = rec.len();
    let e = db.expr("t", "a*b*c*d", all()).unwrap_err();
    assert_eq!(e.kind, Kind::DepthLimitExceeded);
    assert!(e.message.contains("max_mult_depth"), "{}", e);
    assert_eq!(rec.len(), n0, "a request was sent before the depth check");
    db.set_max_mult_depth(3);
    db.expr("t", "a*b*c*d", all()).unwrap();
    db.set_max_mult_depth(0);
    assert_eq!(db.expr("t", "a*b+0", all()).unwrap_err().kind, Kind::DepthLimitExceeded);
    db.expr("t", "s/2+a*3", all()).unwrap(); // depth 0 is always fine
    // the default is 8
    let mut d2 = connect_owner(&s.addr).unwrap();
    assert_eq!(d2.max_mult_depth(), 8);
    tiny(&mut d2, "cap8", &[1, -1]);
    let chain = |n: usize| vec!["a"; n].join("*");
    d2.expr("cap8", &chain(9), all()).unwrap(); // 8 products = depth 8
    assert_eq!(d2.expr("cap8", &chain(10), all()).unwrap_err().kind, Kind::DepthLimitExceeded);
}

#[test]
fn a_zero_denominator_does_not_change_the_request_sequence() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect_owner(&rec.addr).unwrap();
    seed(&mut db, "t");
    let shape = |log: &[(String, Value)]| -> Vec<(String, Vec<usize>)> {
        log.iter().map(|(m, a)| (m.clone(), a.as_array().unwrap().iter().map(|v| v.as_array().map_or(0, |x| x.len())).collect())).collect()
    };
    for x in ["a/b", "c*d/(a-a+b)*a", "SUM(a/b*c)", "a*c/(b+d-d)", "100/(b-b+b)"] {
        let n0 = rec.len();
        db.expr("t", x, all()).unwrap();
        let clean = shape(&rec.log()[n0..]);
        db.update("t", vec![("b", ci(0))], is_in("id", &[ci(2), ci(4)]).unwrap()).unwrap();
        let n1 = rec.len();
        let e = db.expr("t", x, all()).unwrap_err();
        assert_eq!(e.kind, Kind::DivisionByZero, "{}", x);
        let zero = shape(&rec.log()[n1..]);
        db.update("t", vec![("b", ci(2_000_011))], is_in("id", &[ci(2), ci(4)]).unwrap()).unwrap();
        assert_eq!(zero, clean, "the request sequence depends on a zero denominator for {}", x);
        if !x.starts_with("100/") {
            assert!(zero.iter().any(|(m, _)| m == "mult_combine_batch"), "{}", x);
        }
    }
}

#[test]
fn division_by_zero_semantics() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect_owner(&s.addr).unwrap();
    seed(&mut db, "t");
    db.update("t", vec![("b", ci(0))], eq_int("id", 2)).unwrap();
    let e = db.expr("t", "a/b", all()).unwrap_err();
    assert!(e.kind == Kind::DivisionByZero && e.message.contains("division by zero"), "{}", e);
    assert!(db.last_expr_cost().is_none());
    let other = cmp("id", "!=", &ci(2)).unwrap();
    let rows = rows_of(db.expr("t", "a/b", other).unwrap());
    assert_eq!(
        rows,
        vec![
            Some(Decoded::Rational(bi(1000003), bi(2000011))),
            Some(Decoded::Rational(bi(-1000037), bi(2000039))),
            Some(Decoded::Rational(bi(1000051), bi(2000057)))
        ]
    );
    assert_eq!(db.expr("t", "SUM(a)/COUNT(*)", cmp("id", ">", &ci(99)).unwrap()).unwrap_err().kind, Kind::DivisionByZero);
    assert_eq!(db.expr("t", "a/(b-b)", all()).unwrap_err().kind, Kind::DivisionByZero);
    assert_eq!(db.expr("t", "a/0", all()).unwrap_err().kind, Kind::PlanError);
}

#[test]
fn authenticated_mode_detects_tampered_operands() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect_with(&s.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: true, ..Default::default() }).unwrap();
    seed(&mut db, "t");
    raw_rpc(&s.addr, "update_cell", json!(["t", 1, "b", {"t": "i", "v": "123456789"}]));
    for x in ["a*b*c*d", "a/b", "SUM(a*b)/COUNT(*)", "SUM(a+b)", "b*2+a"] {
        assert_eq!(db.expr("t", x, all()).unwrap_err().kind, Kind::Integrity, "{}", x);
    }
    db.expr("t", "a*c*d", all()).unwrap(); // untouched columns still work
}

fn bump_products(by: i64, only_nth: Option<usize>) -> Arc<common::fake::Mutate> {
    Arc::new(move |m: &str, _a: &Value, reply: Value, nth: usize| {
        if m == "mult_combine_batch" && (only_nth.is_none() || only_nth == Some(nth)) && reply.get("ok").is_some() {
            let xs: Vec<Value> = reply["ok"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| json!(((x.as_str().unwrap().parse::<BigInt>().unwrap() + by) % n()).to_string()))
                .collect();
            return json!({"ok": xs});
        }
        reply
    })
}

#[test]
fn a_forged_product_term_at_any_level_is_detected_but_not_without_authentication() {
    let Some(s) = Server::start(&[]) else { return };
    for level in 1..=3 {
        let rec = recorder(&s.addr, Some(bump_products(1, Some(level))));
        let mut db = Client::connect_with(&rec.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: true, ..Default::default() }).unwrap();
        let t = format!("forge{}", level);
        seed(&mut db, &t);
        let e = db.expr(&t, "a*b*c*d", all()).unwrap_err();
        assert!(e.kind == Kind::Integrity && e.message.contains("forged product"), "level {}: {}", level, e);
    }
    // a reply with the wrong number of terms is an integrity failure too
    let drop_first: Arc<common::fake::Mutate> = Arc::new(|m: &str, _a: &Value, reply: Value, _n: usize| {
        if m == "mult_combine_batch" && reply.get("ok").is_some() {
            return json!({"ok": reply["ok"].as_array().unwrap()[1..].to_vec()});
        }
        reply
    });
    let rec = recorder(&s.addr, Some(drop_first));
    let mut db = connect_owner(&rec.addr).unwrap();
    seed(&mut db, "forge_len");
    assert_eq!(db.expr("forge_len", "a*b", all()).unwrap_err().kind, Kind::Integrity);
    // without authenticated mode nothing checks e*g (as for dot): the answer is silently wrong
    let rec2 = recorder(&s.addr, Some(bump_products(1, None)));
    let mut d2 = connect_owner(&rec2.addr).unwrap();
    seed(&mut d2, "forge_plain");
    let got = rows_of(d2.expr("forge_plain", "a*b*c", all()).unwrap());
    let want: Vec<Option<Decoded>> = rows().iter().map(|r| big(bi(r.a) * bi(r.b) * bi(r.c))).collect();
    assert_ne!(got, want);
}

#[test]
fn expressions_see_uncommitted_changes_rollback_restores_and_a_vault_reload_works() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect_with(&s.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: true, ..Default::default() }).unwrap();
    seed(&mut db, "t");
    let sum = |db: &mut Client| match db.expr("t", "SUM(a*b*c)", all()).unwrap() {
        ExprValue::Scalar(Some(Decoded::Int(b))) => b,
        o => panic!("{:?}", o),
    };
    let before = sum(&mut db);
    let r0 = &rows()[0];
    db.begin().unwrap();
    db.insert("t", vec![("id", ci(6)), ("dept", ci(5)), ("a", ci(10)), ("b", ci(10)), ("c", ci(10)), ("d", ci(1)), ("r", ci(1)), ("s", ci(1))]).unwrap();
    db.update("t", vec![("b", ci(0))], eq_int("id", 1)).unwrap();
    assert_eq!(sum(&mut db), &before + bi(1000) - bi(r0.a) * bi(r0.b) * bi(r0.c));
    assert_eq!(db.expr("t", "a/b", all()).unwrap_err().kind, Kind::DivisionByZero);
    db.rollback().unwrap();
    assert_eq!(sum(&mut db), before);
    assert_eq!(rows_of(db.expr("t", "a/b", all()).unwrap())[0], Some(Decoded::Rational(bi(1000003), bi(2000011))));
    db.transaction(|d| -> Result<(), Error> {
        d.update("t", vec![("a", ci(100))], eq_int("id", 1))?;
        assert_eq!(rows_of(d.expr("t", "a*b*c", eq_int("id", 1))?), vec![big(bi(100) * bi(r0.b) * bi(r0.c))]);
        Ok(())
    })
    .unwrap();
    let vf = tmpdir("exprvault").join("v.json");
    db.save_vault(Some(&vf)).unwrap();
    drop(db);
    let mut db2 = Client::connect_with(&s.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: true, vault_path: Some(vf), ..Default::default() }).unwrap();
    assert_eq!(rows_of(db2.expr("t", "a*b*c", eq_int("id", 1)).unwrap()), vec![big(bi(100) * bi(r0.b) * bi(r0.c))]);
}

#[test]
fn analyze_expr_sends_nothing_fhe_str_and_enc_rules() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect_owner(&rec.addr).unwrap();
    db.create_table(
        "an",
        vec![
            col("id", "int", "plain"),
            col("nm", "str", "plain"),
            col("e", "rational", "encrypted"),
            col("p", "int", "paired"),
            col("q", "int", "paired"),
            col("f", "int", "fhe"),
        ],
    )
    .unwrap();
    let n0 = rec.len();
    let i = db.analyze_expr("an", "p*q*p").unwrap();
    assert_eq!((i.kind, i.enc, i.depth, i.ct_muls, i.inversions, i.text.as_str()), ("row", true, 2, 2, 0, "p*q*p"));
    assert_eq!(db.analyze_expr("an", "SUM(p*q)/SUM(p)").unwrap().depth, 2);
    for x in ["f*f*f", "f/2", "f+1", "SUM(f)/COUNT(*)", "SUM(f*f)", "p*f*p", "f*2+p"] {
        let e = db.analyze_expr("an", x).unwrap_err();
        assert!(
            e.kind == Kind::PlanError && e.message.starts_with("FHE column 'f' cannot be used inside an arithmetic expression"),
            "{}: {}",
            x,
            e
        );
    }
    assert!(db.analyze_expr("an", "nm*2+p").unwrap_err().message.contains("STR column 'nm'"));
    assert!(db.analyze_expr("an", "e*p").unwrap_err().message.contains("requires PAIRED columns (column 'e' is ENC)"));
    assert!(db.analyze_expr("an", "p/e").unwrap_err().message.contains("PAIRED"));
    assert_eq!(rec.len(), n0, "analysis must not send anything");
}

#[test]
fn tables_learned_only_from_the_server_are_refused() {
    let Some(s) = Server::start(&[]) else { return };
    let mut owner = connect_owner(&s.addr).unwrap();
    seed(&mut owner, "t");
    let mut other = connect_owner(&s.addr).unwrap(); // syncs the schema: untrusted
    assert_eq!(other.expr("t", "a*b*c", all()).unwrap_err().kind, Kind::UntrustedSchema);
    other.trust_table("t").unwrap();
    let e = other.expr("t", "a*b*c", all()).unwrap_err(); // trusted now, but no masks: loud, not wrong
    assert!(e.message.contains("no mask"), "{}", e);
}

#[test]
fn a_98_level_expression_runs_exactly() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect_with(&s.addr, &ConnectOptions { expression_mode: ExprMode::Owner, max_mult_depth: 120, ..Default::default() }).unwrap();
    tiny(&mut db, "tall", &[1, -1]);
    assert_eq!(rows_of(db.expr("tall", &format!("a{}", "*a".repeat(98)), all()).unwrap()), vec![int(1), int(-1)]);
    assert_eq!(db.last_expr_cost().unwrap().mult_rounds, 98);
    assert_eq!(rows_of(db.expr("tall", &format!("a{}", "+a".repeat(98)), all()).unwrap()), vec![int(99), int(-99)]);
    assert_eq!(db.last_expr_cost().unwrap().mult_rounds, 0);
}

#[test]
fn a_linear_sum_is_a_pi_lin_aggregate() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect_owner(&rec.addr).unwrap();
    seed(&mut db, "t");
    let n0 = rec.len();
    let want: BigInt = rows().iter().map(|r| bi(r.a) + bi(2) * bi(r.b)).sum();
    assert_eq!(db.expr("t", "SUM(a+2*b)", all()).unwrap(), ExprValue::Scalar(big(want)));
    let log = rec.log();
    assert_eq!(n_methods(&log[n0..], "blinded_cells"), 0, "a linear SUM must use server-side sums");
    assert_eq!(n_methods(&log[n0..], "blinded_sum"), 2);
    let c = db.last_expr_cost().unwrap();
    assert_eq!((c.depth, c.mult_rounds, c.products, c.inversions, c.linear_sums), (0, 0, 0, 0, 2));
    // a coefficient beyond the budget is fine as long as the final result is representable
    let big_k = BigInt::from(2).pow(100);
    tiny(&mut db, "lin2", &[0, 0]);
    assert_eq!(db.expr("lin2", &format!("SUM(a*{}*{})", big_k, big_k), all()).unwrap(), ExprValue::Scalar(int(0)));
    assert_eq!(rows_of(db.expr("lin2", &format!("a*{}*{}", big_k, big_k), all()).unwrap()), vec![int(0), int(0)]);
}

#[test]
fn a_max_items_limit_chunks_each_level() {
    let Some(s) = Server::start(&[]) else { return };
    let hello_limit: Arc<common::fake::Mutate> = Arc::new(|m: &str, _a: &Value, mut reply: Value, _n: usize| {
        if m == "hello" && reply.get("ok").is_some() {
            reply["ok"]["limits"] = json!({"max_items": 7});
        }
        reply
    });
    let rec = recorder(&s.addr, Some(hello_limit));
    let mut db = connect_owner(&rec.addr).unwrap();
    assert_eq!(db.server_info().limits.as_ref().and_then(|l| l.max_items), Some(7));
    db.create_table("chunk", vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired")]).unwrap();
    let data: Vec<(i64, i64, i64)> = (0..20).map(|i| (i + 1, 2 * i - 5, i % 4 + 1)).collect();
    db.insert_many("chunk", data.iter().map(|&(a, b, c)| vec![("a", ci(a)), ("b", ci(b)), ("c", ci(c))]).collect()).unwrap();
    let n0 = rec.len();
    let got = rows_of(db.expr("chunk", "a*b*c", all()).unwrap());
    assert_eq!(got, data.iter().map(|&(a, b, c)| int(a * b * c)).collect::<Vec<_>>());
    let log = rec.log();
    let mults: Vec<&(String, Value)> = log[n0..].iter().filter(|(m, _)| m == "mult_combine_batch").collect();
    assert_eq!(mults.len(), 6); // 2 levels x ceil(20 / 7)
    assert!(mults.iter().all(|(_, a)| a[0].as_array().unwrap().len() <= 7));
    assert_eq!(db.last_expr_cost().unwrap().mult_rounds, 2);
}

#[test]
fn the_empty_selection_and_null_operands() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect_owner(&s.addr).unwrap();
    db.create_table("nul", vec![col("id", "int", "plain"), col("w", "int", "plain"), col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
    let data = [(1, Some(2), 3, 4), (2, None, 5, 6), (3, Some(3), 7, 8)];
    db.insert_many(
        "nul",
        data.iter().map(|&(i, w, a, b)| vec![("id", ci(i)), ("w", w.map_or(CellIn::Null, ci)), ("a", ci(a)), ("b", ci(b))]).collect(),
    )
    .unwrap();
    assert_eq!(rows_of(db.expr("nul", "a*b*w", all()).unwrap()), vec![int(24), None, int(168)]);
    assert_eq!(db.expr("nul", "SUM(a*b*w)", all()).unwrap(), ExprValue::Scalar(int(192)));
    assert_eq!(db.expr("nul", "AVG(a*b*w)", all()).unwrap(), ExprValue::Scalar(int(96)));
    let none = cmp("id", ">", &ci(99)).unwrap();
    assert_eq!(db.expr("nul", "a*b", none.clone()).unwrap(), ExprValue::Rows(vec![]));
    assert_eq!(db.expr("nul", "SUM(a*b)", none.clone()).unwrap(), ExprValue::Scalar(int(0)));
    assert_eq!(db.expr("nul", "AVG(a*b)", none.clone()).unwrap(), ExprValue::Scalar(None));
    assert_eq!(db.expr("nul", "COUNT(*)", none).unwrap(), ExprValue::Scalar(int(0)));
}

// ── the server never receives a key, a mask, a MAC key or a plaintext-derived value ──────────────
fn collect_ints(x: &Value, out: &mut HashSet<String>) {
    match x {
        Value::Number(n) => {
            out.insert(n.to_string());
        }
        Value::String(t) => {
            let d = t.strip_prefix('-').unwrap_or(t);
            if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()) {
                out.insert(t.clone());
            }
        }
        Value::Array(a) => a.iter().for_each(|v| collect_ints(v, out)),
        Value::Object(o) => o.values().for_each(|v| collect_ints(v, out)),
        _ => {}
    }
}
fn pinv(x: &BigInt) -> BigInt {
    md_pub(x).modpow(&(n() - 2), n())
}
fn md_pub(x: &BigInt) -> BigInt {
    ((x % n()) + n()) % n()
}

fn wire_audit(auth: bool) {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = Client::connect_with(&rec.addr, &ConnectOptions { expression_mode: ExprMode::Owner, authenticated: auth, ..Default::default() }).unwrap();
    seed(&mut db, "aud");
    db.update("aud", vec![("b", ci(2_000_099))], eq_int("id", 2)).unwrap();
    let mut rs = rows();
    rs[1].b = 2_000_099;
    let queries = [
        "a*b*c*d", "SUM(a*b*c*a)", "a/b", "r/c*a", "SUM(a*b)/COUNT(*)", "s/4+a*b*c", "SUM(a+b-s/2)", "(a+b)*(c-a)*b+s/3", "a/(b*c)*r",
        "100/b", "SUM(a)/SUM(b)",
    ];
    let n0 = rec.len();
    for q in queries {
        db.expr("aud", q, all()).unwrap();
    }
    let sent: Vec<(String, Value)> = rec.log()[n0..].to_vec();
    // the secrets the owner holds: masks and the MAC key are in the vault file
    let vf = tmpdir("audit-vault").join("v.json");
    db.save_vault(Some(&vf)).unwrap();
    let vault: Value = serde_json::from_str(&std::fs::read_to_string(&vf).unwrap()).unwrap();
    let masks: HashSet<String> = vault["masks"].as_array().unwrap().iter().map(|m| m[3].as_str().unwrap().to_string()).collect();
    assert!(masks.len() > 20);
    for (m, _) in &sent {
        assert!(
            ["blinded_cells", "blinded_sum", "blinded_scaled_sum", "mult_combine_batch", "matching_rowids", "plain_cells", "schema", "tables"].contains(&m.as_str()),
            "unexpected RPC {}",
            m
        );
    }
    assert!(sent.iter().any(|(m, _)| m == "mult_combine_batch"));
    let mut seen = HashSet::new();
    for (_, a) in &sent {
        collect_ints(a, &mut seen);
    }
    for m in &masks {
        assert!(!seen.contains(m), "a mask value reached the server");
    }
    if auth {
        let alpha = vault["alpha"].as_str().unwrap();
        assert!(!seen.contains(alpha), "the MAC key reached the server");
    }
    let fr = |nn: BigInt, d: BigInt| encode_rational(&nn, &d).unwrap();
    let mut secrets: HashSet<BigInt> = HashSet::new();
    for r in &rs {
        let (a, b, c, d) = (bi(r.a), bi(r.b), bi(r.c), bi(r.d));
        let (rn, rd, sn, sd) = (bi(r.r.0), bi(r.r.1), bi(r.s.0), bi(r.s.1));
        let mut vals: Vec<BigInt> = [
            a.clone(), b.clone(), c.clone(), d.clone(), &a * &b, &a * &b * &c, &a * &b * &c * &d, &a * &b * &c * &a, &a + &b, &c - &a,
            (&a + &b) * (&c - &a), (&a + &b) * (&c - &a) * &b,
        ]
        .iter()
        .map(|v| encode_int(v).unwrap())
        .collect();
        vals.extend([
            fr(rn.clone(), rd.clone()), fr(sn.clone(), sd.clone()), fr(sn.clone(), &sd * 4), fr(sn.clone(), &sd * 3), fr(a.clone(), b.clone()),
            fr(bi(1), b.clone()), fr(bi(1), &b * &c), fr(a.clone(), &b * &c), fr(&a * &rn, &b * &c * &rd), fr(rd.clone(), rn.clone()),
            fr(rn.clone(), &rd * &c), fr(&rn * &a, &rd * &c), fr(bi(100), b.clone()),
        ]);
        vals.extend([pinv(&encode_int(&b).unwrap()), pinv(&encode_int(&c).unwrap()), pinv(&encode_int(&(&b * &c)).unwrap()), pinv(&fr(rn, rd))]);
        for v in vals {
            if v >= bi(1000) && v < n() - bi(1000) {
                secrets.insert(v); // tiny values would collide with row ids
            }
        }
    }
    let leaked = secrets.iter().filter(|v| seen.contains(&v.to_string())).count();
    assert_eq!(leaked, 0, "{} plaintext/intermediate/inverse encodings reached the server", leaked);
    // the check has teeth: a value the owner did send is found, and so would a leaked secret be
    let some_secret = secrets.iter().next().unwrap().to_string();
    let mut tainted = seen.clone();
    tainted.insert(some_secret.clone());
    assert!(secrets.iter().any(|v| tainted.contains(&v.to_string())));
    assert!(sent.iter().any(|(m, _)| m == "matching_rowids") && seen.contains("0"), "row ids are expected on the wire");
    // the openings that did reach it are uniform-looking residues, never reused
    let mut opened: Vec<BigInt> = vec![];
    for (m, a) in &sent {
        if m == "mult_combine_batch" {
            for pair in a[0].as_array().unwrap() {
                for x in pair.as_array().unwrap() {
                    opened.push(x.as_str().unwrap().parse().unwrap());
                }
            }
        }
    }
    assert!(opened.len() > 100);
    assert_eq!(opened.iter().collect::<HashSet<_>>().len(), opened.len(), "an opening value repeated: a triple was reused");
    let big_ones = opened.iter().filter(|x| **x > n() / 100).count();
    assert!(big_ones as f64 > 0.95 * opened.len() as f64);
}

#[test]
fn wire_audit_plain() {
    wire_audit(false)
}
#[test]
fn wire_audit_authenticated() {
    wire_audit(true)
}

#[test]
fn identical_plaintexts_give_uniform_openings_at_every_level() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect_owner(&rec.addr).unwrap();
    db.create_table("uni", vec![col("a", "int", "paired"), col("b", "int", "paired"), col("c", "int", "paired"), col("d", "int", "paired")]).unwrap();
    db.insert_many("uni", (0..1200).map(|_| vec![("a", ci(7)), ("b", ci(7)), ("c", ci(7)), ("d", ci(7))]).collect()).unwrap();
    let n0 = rec.len();
    db.expr("uni", "a*b*c*d", all()).unwrap();
    let log = rec.log();
    let rounds: Vec<&(String, Value)> = log[n0..].iter().filter(|(m, _)| m == "mult_combine_batch").collect();
    assert_eq!(rounds.len(), 3);
    let mut all_v: Vec<BigInt> = vec![];
    for (_, a) in rounds {
        let ps = a[0].as_array().unwrap();
        assert_eq!(ps.len(), 1200);
        let mut bins = [0f64; 8];
        for p in ps {
            let e: BigInt = p[0].as_str().unwrap().parse().unwrap();
            bins[((&e * 8u32) / n()).to_usize().unwrap()] += 1.0;
            all_v.push(e);
            all_v.push(p[1].as_str().unwrap().parse().unwrap());
        }
        let chi: f64 = bins.iter().map(|o| (o - 150.0) * (o - 150.0) / 150.0).sum();
        assert!(chi < 40.0, "chi2 {}", chi); // df = 7: P(>40) ~ 1e-6
    }
    assert_eq!(all_v.iter().collect::<HashSet<_>>().len(), all_v.len());
    let _ = BigInt::zero();
}

#[test]
fn a_malformed_mult_combine_batch_reply_is_a_typed_error() {
    for reply in [json!({"ok": null}), json!({"ok": [1]}), json!({"ok": ["x", "y"]}), json!({"ok": [{}]}), json!({"ok": ["1", "2", "3"]})] {
        let rep = reply.clone();
        let f = fake(base(move |m, _a, _n| match m {
            "insert_many" => Some(Reply::Json(json!({"ok": [0, 1]}))),
            "matching_rowids" => Some(Reply::Json(json!({"ok": [0, 1]}))),
            "blinded_cells" => Some(Reply::Json(json!({"ok": [{"t": "i", "v": "5"}, {"t": "i", "v": "6"}]}))),
            "mult_combine_batch" => Some(Reply::Json(rep.clone())),
            _ => None,
        }));
        let mut db = connect_owner(&f.addr).unwrap();
        db.create_table("t", vec![col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
        db.insert_many("t", vec![vec![("a", ci(1)), ("b", ci(2))], vec![("a", ci(3)), ("b", ci(4))]]).unwrap();
        assert!(db.expr("t", "a*b", all()).is_err(), "{}", reply);
        assert!(db.last_expr_cost().is_none());
    }
}

#[test]
fn a_server_that_relabels_encrypted_columns_as_plain_gets_no_expression_request() {
    // the lie: `v` is announced as PLAIN although the owner never created this table; an expression over it
    // would use a blinded value as a public operand. It is refused before anything is sent.
    let f = fake(base(|m, _a, _n| match m {
        "tables" => Some(Reply::Json(json!({"ok": ["t"]}))),
        "schema" => Some(Reply::Json(json!({"ok": [["id", "int", "plain"], ["v", "int", "plain"], ["w", "int", "paired"]]}))),
        _ => None,
    }));
    let mut db = connect_owner(&f.addr).unwrap();
    let n0 = f.seen().len();
    for x in ["v*w+0", "w*v*w", "SUM(w+v)"] {
        assert_eq!(db.expr("t", x, all()).unwrap_err().kind, Kind::UntrustedSchema, "{}", x);
    }
    assert_eq!(f.seen().len(), n0, "an expression request reached the server");
    // also with a trusted-by-flag connection the missing masks are a loud error, never a wrong value
    let mut t = Client::connect_with(&f.addr, &ConnectOptions { expression_mode: ExprMode::Owner, trust_server_schema: true, ..Default::default() }).unwrap();
    assert!(t.expr("t", "w*w+0", all()).is_err());
}
