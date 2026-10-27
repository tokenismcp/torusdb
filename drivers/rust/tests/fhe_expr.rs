// SPDX-License-Identifier: Apache-2.0
//! v0.6.1/v0.6.2 expressions over FHE columns (docs/fhe-columns.md "Expressions over FHE columns";
//! proto/fhe-wire.md `fhe_mul`): the static accept/reject matrix (no server, mirrors
//! `parser/torussql_parser/fhe_expr.py` and the TypeScript port's `test/fheExpr.test.ts`) and
//! end-to-end evaluation against the REAL Python server, cross-checked against the Python engine
//! itself via `drivers/expr_peer.py` (a separate owner holding the same FHE key, its own copy of
//! the tables).
//!
//! One deliberate divergence from `drivers/typescript/src/fheExpr.ts` (see `src/fhe_expr.rs`'s
//! module doc comment): that port's `REJECT_BARE_COLUMN_PRODUCT` is still `true` (the pre-v0.6.1
//! text, `SUM(x*y)` of two bare FHE columns pinned as rejected in favour of `DOT`); the CURRENT
//! `parser/torussql_parser/fhe_expr.py` has moved this to `false` (v0.6.2: that spelling is accepted
//! through the same `fhe_mul` path as every other product shape). This Rust port follows the
//! current engine code, so the matrix below has `SUM(a*b)` ACCEPTED where the TypeScript one has it
//! rejected.
use num_bigint::BigInt;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use torusdb::*;

mod common;
use common::fake::recorder;
use common::*;

fn kind_of<T: std::fmt::Debug>(r: Result<T, Error>) -> Kind {
    r.unwrap_err().kind
}

// ── static analysis (no server): mirrors parser/torussql_parser/fhe_expr.py's accept/reject matrix ──
fn scope() -> Vec<Column> {
    vec![
        col("a", "int", "fhe"),
        col("b", "int", "fhe"),
        col("c", "int", "fhe"),
        col("d", "int", "fhe"),
        col("p", "int", "plain"),
        col("q", "int", "paired"),
    ]
}
fn resolver() -> impl Fn(&str) -> Result<Column, Error> {
    let cols = scope();
    move |r: &str| cols.iter().find(|c| c.name == r).cloned().ok_or_else(|| Error::new(Kind::PlanError, format!("no such column: '{}'", r)))
}
fn plan(expr: &str) -> Result<FheExprPlan, Error> {
    let resolve = resolver();
    let tree = parse_expression(expr)?;
    assert!(references_fhe_column(&tree, &resolve).unwrap_or(false), "{}: no FHE column reference (test setup error)", expr);
    analyze_fhe_expr(&tree, &resolve)
}

#[test]
fn fhe_expr_static_accepted_shapes() {
    let ok = [
        "SUM((a+b)*c)", // per-row product of two linear forms, aggregated
        "SUM((a+2*b)*(c-d))",
        "SUM(a)*SUM(b)", // product of two aggregates
        "(SUM(a)+2*SUM(b))*(SUM(c)-1)",
        "2*SUM(a*c)-SUM(b*d)/4+7", // public scale/add/divide after decryption
        "AVG(a*c)",
        "SUM(2*a*c)", // a coefficient defeats the bare-column-product special case
        "SUM((a+0)*c)",
        "SUM(a*c)*1",
        "SUM((a+0)*(a+0))", // the same column on both sides, spelled so it is not the bare x*y shape
        // v0.6.2 (REJECT_BARE_COLUMN_PRODUCT = false, see the module doc comment): a bare `x*y` of
        // two distinct FHE columns is now accepted too, unlike the TypeScript port.
        "SUM(a*b)",
        "SUM(b*a)",
    ];
    for e in ok {
        plan(e).unwrap_or_else(|err| panic!("{}: {}", e, err));
    }
}

#[test]
fn fhe_expr_static_rejected_shapes_with_a_precise_message() {
    for e in [
        "SUM(a*b)*SUM(c)",  // product of a product (depth 2)
        "SUM((a+b)*c*d)",   // triple product: depth > 1
        "SUM(a)/COUNT(*)",  // AVG spelled by hand: COUNT(*) is not FHE
        "a+1",              // per-row, non-aggregated
        "SUM(a)+p",         // FHE mixed with PLAIN
        "SUM(a/2*c)",       // non-integer operand coefficient
        "SUM(a)",           // no product anywhere: old "FHE column" message
        "AVG(a)*AVG(b)",    // AVG as a factor is not an integer-linear form
    ] {
        assert_eq!(kind_of(plan(e)), Kind::PlanError, "{}", e);
    }
}

#[test]
fn fhe_expr_static_mixed_with_paired_is_rejected_not_silently_accepted() {
    assert_eq!(kind_of(plan("SUM(a*c)+q")), Kind::PlanError);
}

#[test]
fn fhe_expr_static_depth_and_division_messages_are_specific() {
    let e = plan("SUM(a*b)*SUM(c)").unwrap_err();
    assert!(e.message.contains("a product of products"), "{}", e);
    let e = plan("SUM(a*b)/SUM(c)").unwrap_err();
    assert!(e.message.contains("FHE column"), "{}", e); // division by a non-literal
    let e = plan("a*b").unwrap_err();
    assert!(e.message.contains("per-row product"), "{}", e);
    // over the limits: more than 16 columns in one operand, and more than 16 products
    let many: Vec<Column> = (0..20).map(|i| col(&format!("x{}", i), "int", "fhe")).collect();
    let resolve = move |r: &str| -> Result<Column, Error> {
        many.iter().find(|c| c.name == r).cloned().ok_or_else(|| Error::new(Kind::PlanError, "no such column".to_string()))
    };
    let wide = format!("SUM(({})*x19)", (0..17).map(|i| format!("x{}", i)).collect::<Vec<_>>().join("+"));
    let tree = parse_expression(&wide).unwrap();
    let e = analyze_fhe_expr(&tree, &resolve).unwrap_err();
    assert!(e.message.contains("at most 16 columns"), "{}", e);
    let many_products = (0..17).map(|i| format!("SUM(x{}*x19)", i)).collect::<Vec<_>>().join("+");
    let tree = parse_expression(&many_products).unwrap();
    let e = analyze_fhe_expr(&tree, &resolve).unwrap_err();
    assert!(e.message.contains("at most 16 products"), "{}", e);
}

// ── end to end against the real server ───────────────────────────────────────
fn emp_cols() -> Vec<Column> {
    vec![
        col("id", "int", "plain"),
        col("dept", "int", "plain"),
        col("rate", "int", "fhe"),
        col("hours", "int", "fhe"),
        col("bonus", "int", "fhe"),
    ]
}
const ROWS: [[i64; 5]; 4] = [[1, 5, 40, 160, 3], [2, 5, 55, 150, 1], [3, 7, 30, 120, 0], [4, 5, 20, 100, 2]];
const RANGE: u64 = 10_000_000;

fn secret_hex() -> String {
    // any valid 32-byte secret in [1, n): a short literal padded to 64 hex chars is fine here
    format!("{:0>64}", "7f")
}
fn fhe_key() -> FheKey {
    FheKey::from_hex(&secret_hex(), RANGE).unwrap()
}
fn row(id: i64, dept: i64, rate: i64, hours: i64, bonus: i64) -> Vec<(&'static str, CellIn)> {
    vec![("id", ci(id)), ("dept", ci(dept)), ("rate", ci(rate)), ("hours", ci(hours)), ("bonus", ci(bonus))]
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn seed(db: &mut Client, t: &str) -> Vec<i64> {
    db.create_table(t, emp_cols()).unwrap();
    ROWS.iter().map(|r| db.insert(t, row(r[0], r[1], r[2], r[3], r[4])).unwrap()).collect()
}
fn expected(f: impl Fn(i64, i64, i64, i64) -> i64) -> i64 {
    ROWS.iter().map(|r| f(r[1], r[2], r[3], r[4])).sum()
}
fn connect(addr: &str, auth: bool, mode: FheDotMode) -> Client {
    Client::connect_with(
        addr,
        &ConnectOptions {
            fhe_key: Some(fhe_key()),
            authenticated: auth,
            fhe_dot_mode: mode,
            timeout: Some(Duration::from_secs(240)),
            ..Default::default()
        },
    )
    .unwrap()
}
fn scalar(v: ExprValue) -> Option<Decoded> {
    match v {
        ExprValue::Scalar(x) => x,
        other => panic!("FHE expressions are aggregates, got {:?}", other),
    }
}
fn int_of(v: ExprValue) -> BigInt {
    match scalar(v) {
        Some(Decoded::Int(b)) => b,
        other => panic!("expected an integer, got {:?}", other),
    }
}

#[test]
fn fhe_expr_sum_l_r_sum_a_sum_b_and_an_affine_combination_delegated_mode() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s.addr, false, FheDotMode::Auto); // unauthenticated: Auto == delegated
    let t = "emp";
    seed(&mut db, t);

    let sum_prod = expected(|_, rate, hours, bonus| (rate + bonus) * hours);
    assert_eq!(int_of(db.expr(t, "SUM((rate+bonus)*hours)", all()).unwrap()), BigInt::from(sum_prod));
    assert_eq!(db.last_fhe_expr_cost().unwrap().products, 1);
    assert!(db.last_fhe_expr_cost().unwrap().pairings > 0);
    assert!(db.last_fhe_expr_cost().unwrap().gt_results >= 1);
    let _ = db.last_fhe_expr_cost().unwrap().server_products; // sanity: field exists (0 in delegated "sum" mode's bilinear combine is not guaranteed, so no value assertion here)
    assert!(db.last_expr_cost().is_none(), "an FHE expression must not touch the shared-wire cost");

    let sum_rate = expected(|_, rate, _, _| rate);
    let sum_hours = expected(|_, _, hours, _| hours);
    assert_eq!(int_of(db.expr(t, "SUM(rate)*SUM(hours)", all()).unwrap()), BigInt::from(sum_rate * sum_hours));

    let affine = 2 * sum_prod - expected(|_, _, hours, bonus| bonus * hours) + 7;
    assert_eq!(int_of(db.expr(t, "2*SUM((rate+bonus)*hours)-SUM(bonus*hours)/4*4+7", all()).unwrap()), BigInt::from(affine));

    // AVG(a*c): SUM/n in exact (reduced) rational arithmetic
    let n = ROWS.len() as i64;
    let sum_rh = expected(|_, rate, hours, _| rate * hours);
    let avg = db.expr(t, "AVG(rate*hours)", all()).unwrap();
    let g = num_integer::Integer::gcd(&BigInt::from(sum_rh), &BigInt::from(n));
    match scalar(avg).unwrap() {
        Decoded::Int(v) if g == BigInt::from(n) => assert_eq!(v, BigInt::from(sum_rh) / BigInt::from(n)),
        Decoded::Rational(num, den) => {
            assert_eq!(num, BigInt::from(sum_rh) / &g);
            assert_eq!(den, BigInt::from(n) / &g);
        }
        other => panic!("AVG(rate*hours): unexpected {:?} (gcd {})", other, g),
    }

    // WHERE restricts the row set the server/owner sees
    let filtered: i64 = ROWS.iter().filter(|r| r[1] == 5).map(|r| (r[2] + r[4]) * r[3]).sum();
    assert_eq!(int_of(db.expr(t, "SUM((rate+bonus)*hours)", eq_int("dept", 5)).unwrap()), BigInt::from(filtered));
    assert_ne!(filtered, sum_prod); // sanity: the filter actually changed something given dept 7 exists
}

#[test]
fn fhe_expr_local_mode_authenticated_matches_delegated_mode() {
    let Some(s) = Server::start(&[]) else { return };
    // both connections authenticated (rows need integrity tags for local mode to read them);
    // `delegated` explicitly opts out of local verification for the FHE-product terms.
    let mut local = connect(&s.addr, true, FheDotMode::Auto);
    let t = "emp";
    seed(&mut local, t);
    let mut delegated = connect(&s.addr, true, FheDotMode::Delegated);

    let expr = "SUM((rate+2*bonus)*(hours-8))";
    let want = expected(|_, rate, hours, bonus| (rate + 2 * bonus) * (hours - 8));
    assert_eq!(int_of(delegated.expr(t, expr, all()).unwrap()), BigInt::from(want));
    assert_eq!(int_of(local.expr(t, expr, all()).unwrap()), BigInt::from(want));
    assert_eq!(delegated.last_fhe_expr_cost().unwrap().decrypted_cells, 0); // delegated: the server multiplies
    assert!(local.last_fhe_expr_cost().unwrap().decrypted_cells > 0); // local: the owner reads and verifies cells
    assert_eq!(local.last_fhe_expr_cost().unwrap().server_products, 0);
}

#[test]
fn fhe_expr_rejected_at_the_client_exactly_like_the_static_analyzer_zero_rpcs() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, false, FheDotMode::Auto);
    let t = "emp";
    seed(&mut db, t);
    let n0 = rec.len();
    // NOTE: `SUM(rate*hours)` (a bare x*y of two distinct FHE columns) is ACCEPTED here (v0.6.2, see
    // this file's and `fhe_expr.rs`'s module doc comments on the deliberate divergence from the
    // TypeScript port, which still rejects it) - so every case below is a genuine rejection.
    assert_eq!(kind_of(db.expr(t, "SUM(rate*hours)*SUM(bonus)", all())), Kind::PlanError); // product of a product
    assert_eq!(kind_of(db.expr(t, "rate+1", all())), Kind::PlanError); // per-row
    assert_eq!(kind_of(db.expr(t, "SUM(rate)+id", all())), Kind::PlanError); // FHE + PLAIN
    assert!(db.last_fhe_expr_cost().is_none());
    assert_eq!(rec.len(), n0, "a rejected FHE expression must send no RPC");
}

#[test]
fn fhe_expr_wire_audit_fhe_mul_carries_only_names_ids_small_integers() {
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, false, FheDotMode::Auto);
    let t = "emp";
    seed(&mut db, t);
    let n0 = rec.len();
    db.expr(t, "SUM((rate+2*bonus)*(hours-8))", all()).unwrap();
    let log = rec.log();
    let calls: Vec<&(String, Value)> = log[n0..].iter().filter(|(m, _)| m == "fhe_mul").collect();
    assert!(!calls.is_empty());
    for (_, args) in calls {
        let text = args.to_string();
        assert!(!text.to_lowercase().contains("secret"), "{}", text);
        assert!(!text.to_lowercase().contains("alpha"), "{}", text);
        assert!(!text.to_lowercase().contains("gamma"), "{}", text);
        // every string in the request is short: a column/table/mode name or a small decimal integer,
        // never a base64/hex ciphertext blob (384-byte GT elements decode to >500 printable chars)
        for s in args.as_array().unwrap() {
            check_small(s);
        }
    }
}
fn check_small(v: &Value) {
    match v {
        Value::String(s) => assert!(s.len() < 64, "unexpectedly long string in an fhe_mul request: {:?}", s),
        Value::Array(a) => {
            for x in a {
                check_small(x);
            }
        }
        Value::Number(n) => assert!(n.to_string().len() < 20, "unexpectedly large number: {}", n),
        _ => {}
    }
}

#[test]
fn fhe_expr_cross_checked_against_the_python_engine() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s.addr, false, FheDotMode::Auto);
    let ts_t = "ts_emp";
    let py_t = "py_emp";
    seed(&mut db, ts_t);
    let exprs = ["SUM((rate+bonus)*hours)", "SUM(rate)*SUM(hours)", "2*SUM(rate*hours)-SUM(bonus*hours)/4+7", "AVG(rate*hours)"];
    let mut rust_values = vec![];
    for e in exprs {
        let v = db.expr(ts_t, e, all()).unwrap();
        rust_values.push(match scalar(v) {
            None => "null".to_string(),
            Some(Decoded::Int(b)) => b.to_string(),
            Some(Decoded::Rational(n, d)) => format!("{}/{}", n, d),
        });
    }
    let addr: Vec<&str> = s.addr.rsplitn(2, ':').collect();
    let host = addr[1];
    let port: u16 = addr[0].parse().unwrap();
    let peer_cols: Vec<Value> = emp_cols().iter().map(|c| json!([c.name, c.ty, c.policy])).collect();
    let peer_rows: Vec<Vec<String>> = ROWS.iter().map(|r| r.iter().map(|x| x.to_string()).collect()).collect();
    let spec = json!({
        "fhe_key": {"secret": secret_hex(), "range": RANGE},
        "tables": [{"name": py_t, "columns": peer_cols, "rows": peer_rows}],
        "queries": exprs.iter().map(|e| json!({"table": py_t, "expr": e})).collect::<Vec<_>>(),
    });
    let out = run_expr_peer(host, port, &spec);
    let peer: &Vec<Value> = out.as_array().unwrap();
    for (i, e) in exprs.iter().enumerate() {
        assert!(peer[i].get("error").is_none(), "{}: python peer error {:?}", e, peer[i]);
        assert_eq!(rust_values[i], peer[i]["value"].as_str().unwrap(), "{}", e);
    }
}

#[test]
fn fhe_expr_in_a_join_query_is_rejected() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s.addr, false, FheDotMode::Auto);
    let t = "emp";
    seed(&mut db, t);
    db.create_table("other", vec![col("id", "int", "plain"), col("fk", "int", "plain")]).unwrap();
    let j = db.join(t, &[JoinStep::new("other", "id", "fk")], &JoinOptions::default()).unwrap();
    let e = db.join_expr(&j, "SUM(rate*hours)").unwrap_err();
    assert_eq!(e.kind, Kind::Interface);
    assert!(e.message.contains("join"), "{}", e);
}

#[test]
fn fhe_expr_no_distinct_rpc_bodies_repeat_a_secret_shaped_value() {
    // a lighter-weight companion to the wire audit: collect every distinct JSON body sent for
    // `fhe_mul` across several different expressions and check none of them is improbably large.
    let Some(s) = Server::start(&[]) else { return };
    let rec = recorder(&s.addr, None);
    let mut db = connect(&rec.addr, false, FheDotMode::Auto);
    let t = "emp";
    seed(&mut db, t);
    for e in ["SUM(rate*hours)", "SUM(rate)*SUM(bonus)", "AVG(rate*bonus)"] {
        db.expr(t, e, all()).unwrap();
    }
    let bodies: HashSet<String> = rec.log().iter().filter(|(m, _)| m == "fhe_mul").map(|(_, a)| a.to_string()).collect();
    for b in bodies {
        assert!(b.len() < 2000, "fhe_mul request body unexpectedly large ({} bytes): {}", b.len(), b);
    }
}
