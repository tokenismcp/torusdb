// SPDX-License-Identifier: Apache-2.0
//! Integration tests against a REAL keyless server (subprocess).
use num_bigint::BigInt;
use torusdb::*;

mod common;
use common::*;

fn int(v: i64) -> Decoded {
    Decoded::Int(BigInt::from(v))
}
fn rat(a: i64, b: i64) -> Decoded {
    Decoded::Rational(BigInt::from(a), BigInt::from(b))
}
fn big(v: i64) -> BigInt {
    BigInt::from(v)
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}

fn connect(s: &Server) -> Client {
    Client::connect(&s.addr).expect("connect")
}

fn seed_emp(db: &mut Client, t: &str) {
    db.create_table(t, emp_cols()).unwrap();
    for (id, dept, sal, rate, hours) in [(1, 5, 8000, 50, 40), (2, 5, 9000, 60, 35), (3, 9, 7000, 45, 40)] {
        db.insert(
            t,
            vec![
                ("id", ci(id)),
                ("dept", ci(dept)),
                ("salary", CellIn::Rational(big(sal), big(1))),
                ("rate", ci(rate)),
                ("hours", ci(hours)),
            ],
        )
        .unwrap();
    }
}

#[test]
fn hello_negotiates_protocol_2() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    assert_eq!(db.server_info().protocol, 2);
    assert!(!db.server_info().auth_required);
    assert!(db.ping().unwrap());
}

#[test]
fn sum_count_dot_with_and_without_where() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    seed_emp(&mut db, "emp");
    assert_eq!(db.sum("emp", "salary", all()).unwrap(), int(24000));
    assert_eq!(db.sum("emp", "salary", eq_int("dept", 5)).unwrap(), int(17000));
    assert_eq!(db.count("emp", all()).unwrap(), 3);
    assert_eq!(db.count("emp", eq_int("dept", 5)).unwrap(), 2);
    assert_eq!(db.dot("emp", "rate", "hours", all()).unwrap(), int(5900));
    assert_eq!(db.dot("emp", "rate", "hours", eq_int("dept", 5)).unwrap(), int(50 * 40 + 60 * 35));
    assert_eq!(db.sum("emp", "salary", eq_int("dept", 777)).unwrap(), int(0));
    assert_eq!(db.dot("emp", "rate", "hours", eq_int("dept", 777)).unwrap(), int(0));
}

#[test]
fn rational_sum_and_avg_are_exact() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    db.create_table("r", vec![col("k", "int", "plain"), col("v", "rational", "encrypted")]).unwrap();
    for (k, a, b) in [(1, 1, 2), (2, 1, 3), (3, -3, 5)] {
        db.insert("r", vec![("k", ci(k)), ("v", CellIn::Rational(big(a), big(b)))]).unwrap();
    }
    assert_eq!(db.sum("r", "v", all()).unwrap(), rat(7, 30));
    assert_eq!(db.avg("r", "v", or(&[eq_int("k", 1), eq_int("k", 2)])).unwrap(), Some(rat(5, 12)));
    assert_eq!(db.avg("r", "v", eq_int("k", 99)).unwrap(), None);
    assert_eq!(db.avg("r", "v", eq_int("k", 1)).unwrap(), Some(rat(1, 2)));
}

#[test]
fn predicates_in_comparison_and_or() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    seed_emp(&mut db, "emp");
    assert_eq!(db.count("emp", is_in("id", &[ci(1), ci(3)]).unwrap()).unwrap(), 2);
    assert_eq!(db.count("emp", cmp("id", ">", &ci(1)).unwrap()).unwrap(), 2);
    assert_eq!(db.count("emp", and(&[eq_int("dept", 5), cmp("id", ">", &ci(1)).unwrap()])).unwrap(), 1);
    assert_eq!(db.count("emp", or(&[eq_int("id", 1), eq_int("id", 3)])).unwrap(), 2);
    assert_eq!(
        db.sum("emp", "salary", and(&[or(&[eq_int("id", 1), eq_int("id", 3)]), eq_int("dept", 9)])).unwrap(),
        int(7000)
    );
}

#[test]
fn select_update_delete() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    seed_emp(&mut db, "emp");
    let rows = db.select("emp", &["id", "salary"], eq_int("dept", 5)).unwrap();
    assert_eq!(rows, vec![vec![ci(1), ci(8000)], vec![ci(2), ci(9000)]]);
    assert_eq!(db.update("emp", vec![("salary", ci(500))], eq_int("id", 1)).unwrap(), 1);
    assert_eq!(db.sum("emp", "salary", all()).unwrap(), int(500 + 9000 + 7000));
    assert_eq!(db.update("emp", vec![("dept", ci(9))], eq_int("dept", 5)).unwrap(), 2);
    assert_eq!(db.count("emp", eq_int("dept", 9)).unwrap(), 3);
    assert_eq!(db.update("emp", vec![("salary", ci(1))], eq_int("id", 4242)).unwrap(), 0);
    assert!(!db.in_transaction());
    assert_eq!(db.delete_rows("emp", eq_int("id", 2)).unwrap(), 1);
    assert_eq!(db.count("emp", all()).unwrap(), 2);
    assert_eq!(db.sum("emp", "salary", all()).unwrap(), int(500 + 7000));
    assert_eq!(db.delete_rows("emp", eq_int("id", 2)).unwrap(), 0);
    assert_eq!(db.table_info("emp").unwrap(), TableInfo { rows: 3, deleted: vec![1], indexes: vec![] });
}

#[test]
fn insert_many_uses_one_rpc_and_is_all_or_nothing() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    db.create_table("b", kv_cols()).unwrap();
    let rows: Vec<Vec<(&str, CellIn)>> = (0..200).map(|i| vec![("k", ci(i)), ("v", ci(i * 3))]).collect();
    let ids = db.insert_many("b", rows).unwrap();
    assert_eq!(ids, (0..200).collect::<Vec<i64>>());
    assert_eq!(db.sum("b", "v", all()).unwrap(), int(3 * (199 * 200 / 2)));
    assert_eq!(db.sum("b", "v", cmp("k", ">", &ci(99)).unwrap()).unwrap(), int(3 * (199 * 200 / 2 - 99 * 100 / 2)));
    assert!(db.insert_many("b", vec![]).unwrap().is_empty());
    assert!(db.stats().unwrap().to_string().contains("insert_many"));
    // a bad row anywhere rejects the batch before any RPC; no masks leak
    let masks = db.mask_count();
    let e = db
        .insert_many("b", vec![vec![("k", ci(1)), ("v", ci(1))], vec![("k", ci(2)), ("v", CellIn::Null)]])
        .unwrap_err();
    assert_eq!(e.kind, Kind::Interface);
    assert_eq!(db.mask_count(), masks);
    assert_eq!(db.count("b", all()).unwrap(), 200);
}

#[test]
fn schema_sync_and_second_connection_without_vault() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    seed_emp(&mut db, "emp");
    assert!(db.tables().unwrap().contains(&"emp".to_string()));
    let mut other = connect(&s);
    assert_eq!(other.count("emp", eq_int("dept", 5)).unwrap(), 2);
    assert_eq!(other.select("emp", &["id"], eq_int("dept", 9)).unwrap(), vec![vec![ci(3)]]);
    let e = other.sum("emp", "salary", all()).unwrap_err();
    assert_eq!(e.kind, Kind::Interface);
    assert!(e.message.contains("no mask"));
}

#[test]
fn budget_overflow_is_an_error_not_a_wrong_number() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    db.create_table("big", vec![col("v", "int", "encrypted")]).unwrap();
    let two126: BigInt = BigInt::from(1) << 126;
    db.insert("big", vec![("v", CellIn::Int(two126.clone()))]).unwrap();
    db.insert("big", vec![("v", CellIn::Int(two126.clone()))]).unwrap();
    assert_eq!(db.sum("big", "v", all()).unwrap_err().kind, Kind::OutOfBudget);
    let e = db.insert("big", vec![("v", CellIn::Int(BigInt::from(1) << 127))]).unwrap_err();
    assert_eq!(e.kind, Kind::OutOfBudget);
    assert_eq!(db.count("big", all()).unwrap(), 2);
}

#[test]
fn local_misuse_and_server_errors_are_typed() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    seed_emp(&mut db, "emp");
    let k = |r: Result<_, Error>| -> Kind { r.map(|_: ()| ()).unwrap_err().kind };
    assert_eq!(k(db.insert("emp", vec![("id", ci(1))]).map(|_| ())), Kind::Interface);
    assert_eq!(
        k(db.insert("emp", vec![("id", ci(1)), ("dept", ci(1)), ("salary", "x".into()), ("rate", ci(1)), ("hours", ci(1))]).map(|_| ())),
        Kind::Interface
    );
    assert_eq!(db.sum("nope", "v", all()).unwrap_err().kind, Kind::Interface);
    assert_eq!(db.sum("emp", "id", all()).unwrap_err().kind, Kind::Interface);
    let dup = db.create_table("emp", emp_cols()).unwrap_err();
    assert!(!dup.message.is_empty());
    let bad = db.count("emp", eq_int("nonexistent", 1)).unwrap_err();
    assert_eq!(bad.kind, Kind::BadRequest);
    assert!(bad.to_string().starts_with("BadRequest: "));
    // usable after an error reply
    assert_eq!(db.count("emp", all()).unwrap(), 3);
    // old-style String errors still work with `?`
    fn old_style(db: &mut Client) -> std::result::Result<usize, String> {
        Ok(db.count("emp", all())?)
    }
    assert_eq!(old_style(&mut db).unwrap(), 3);
    let _: Error = "x".to_string().into();
}

#[test]
fn admin_rpcs_without_auth() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = connect(&s);
    assert!(db.stats().unwrap().is_object());
    let _ = db.checkpoint(); // may legitimately report "not persistent"
    let _ = db.backup();
    assert!(db.ping().unwrap());
    seed_emp(&mut db, "emp");
    let n = db.mask_count();
    db.drop_table("emp").unwrap();
    assert_eq!(db.mask_count(), n - 9);
    assert!(!db.tables().unwrap().contains(&"emp".to_string()));
}
