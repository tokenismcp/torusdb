// SPDX-License-Identifier: Apache-2.0
//! JOIN tests (mirror torussql/tests/test_join_v05.py) against a REAL server.
use num_bigint::BigInt;
use torusdb::*;

mod common;
use common::*;

fn int(v: i64) -> Decoded {
    Decoded::Int(BigInt::from(v))
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn s(v: &str) -> CellIn {
    CellIn::Str(v.into())
}

fn org(srv: &Server) -> Client {
    let mut db = Client::connect(&srv.addr).unwrap();
    db.create_table(
        "emp",
        vec![
            col("eid", "int", "plain"),
            col("did", "int", "plain"),
            col("mgr", "int", "plain"),
            col("name", "str", "plain"),
            col("salary", "int", "encrypted"),
        ],
    )
    .unwrap();
    db.create_table("dept", vec![col("did", "int", "plain"), col("dname", "str", "plain")]).unwrap();
    db.create_table(
        "proj",
        vec![col("did", "int", "plain"), col("pname", "str", "plain"), col("budget", "int", "encrypted")],
    )
    .unwrap();
    db.insert_many(
        "dept",
        vec![
            vec![("did", ci(10)), ("dname", s("Eng"))],
            vec![("did", ci(20)), ("dname", s("Sales"))],
            vec![("did", ci(30)), ("dname", s("Empty"))],
        ],
    )
    .unwrap();
    let e = |eid, did, mgr: Option<i64>, name, sal| -> Vec<(&'static str, CellIn)> {
        vec![
            ("eid", ci(eid)),
            ("did", ci(did)),
            ("mgr", mgr.map(ci).unwrap_or(CellIn::Null)),
            ("name", s(name)),
            ("salary", ci(sal)),
        ]
    };
    db.insert_many(
        "emp",
        vec![e(1, 10, None, "Alice", 100), e(2, 10, Some(1), "Bob", 80), e(3, 20, Some(1), "Carol", 70), e(4, 99, Some(3), "Dave", 60)],
    )
    .unwrap();
    db.insert_many(
        "proj",
        vec![
            vec![("did", ci(10)), ("pname", s("Apollo")), ("budget", ci(1000))],
            vec![("did", ci(10)), ("pname", s("Gemini")), ("budget", ci(500))],
            vec![("did", ci(20)), ("pname", s("Mercury")), ("budget", ci(300))],
        ],
    )
    .unwrap();
    db
}

fn pairs(db: &mut Client, j: &JoinResult, a: (&str, &str), b: (&str, &str)) -> Vec<(CellIn, CellIn)> {
    let x = db.join_column(j, a.0, a.1).unwrap();
    let y = db.join_column(j, b.0, b.1).unwrap();
    let mut v: Vec<_> = x.into_iter().zip(y).collect();
    v.sort_by_key(|p| format!("{:?}", p));
    v
}

#[test]
fn inner_join_with_aliases() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let j = db
        .join("emp", &[JoinStep::new("dept", "did", "did").alias("d")], &JoinOptions { alias: Some("e".into()), ..Default::default() })
        .unwrap();
    assert_eq!(j.aliases, vec!["e", "d"]);
    assert_eq!(db.join_count(&j), 3);
    assert_eq!(
        pairs(&mut db, &j, ("e", "name"), ("d", "dname")),
        vec![(s("Alice"), s("Eng")), (s("Bob"), s("Eng")), (s("Carol"), s("Sales"))]
    );
}

#[test]
fn left_join_keeps_unmatched_with_null_side() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let opts = JoinOptions { alias: Some("e".into()), ..Default::default() };
    let j = db.join("emp", &[JoinStep::new("dept", "did", "did").alias("d").left()], &opts).unwrap();
    assert_eq!(db.join_count(&j), 4);
    assert_eq!(j.tuples.iter().filter(|t| t[1].is_none()).count(), 1);
    assert_eq!(
        pairs(&mut db, &j, ("e", "name"), ("d", "dname")),
        vec![(s("Alice"), s("Eng")), (s("Bob"), s("Eng")), (s("Carol"), s("Sales")), (s("Dave"), CellIn::Null)]
    );
    let inner = db.join("emp", &[JoinStep::new("dept", "did", "did")], &JoinOptions::default()).unwrap();
    assert_eq!(inner.count(), 3);
}

#[test]
fn self_join_with_aliases() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let j = db
        .join("emp", &[JoinStep::new("emp", "mgr", "eid").alias("m")], &JoinOptions { alias: Some("e".into()), ..Default::default() })
        .unwrap();
    assert_eq!(db.join_count(&j), 3);
    assert_eq!(
        pairs(&mut db, &j, ("e", "name"), ("m", "name")),
        vec![(s("Bob"), s("Alice")), (s("Carol"), s("Alice")), (s("Dave"), s("Carol"))]
    );
    assert_eq!(db.join_sum(&j, "m", "salary").unwrap(), int(100 + 100 + 70));
    assert_eq!(db.join_sum(&j, "e", "salary").unwrap(), int(80 + 70 + 60));
}

#[test]
fn three_table_join_with_sums_across_tables() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let steps = [
        JoinStep::new("dept", "did", "did").alias("d").left_alias("e"),
        JoinStep::new("proj", "did", "did").alias("p").left_alias("d"),
    ];
    let j = db.join("emp", &steps, &JoinOptions { alias: Some("e".into()), ..Default::default() }).unwrap();
    assert_eq!(db.join_count(&j), 5);
    assert_eq!(db.join_sum(&j, "e", "salary").unwrap(), int(100 * 2 + 80 * 2 + 70));
    assert_eq!(db.join_sum(&j, "p", "budget").unwrap(), int(1000 + 500 + 1000 + 500 + 300));
    // ON referencing the FROM table instead of the preceding one
    let steps = [
        JoinStep::new("dept", "did", "did").alias("d"),
        JoinStep::new("proj", "did", "did").alias("p").left_alias("e"),
    ];
    let j2 = db.join("emp", &steps, &JoinOptions { alias: Some("e".into()), ..Default::default() }).unwrap();
    assert_eq!(j2.count(), 5);
}

#[test]
fn left_join_aggregates_skip_null_side_and_where_on_left() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let opts = JoinOptions { alias: Some("d".into()), ..Default::default() };
    let j = db.join("dept", &[JoinStep::new("proj", "did", "did").alias("p").left()], &opts).unwrap();
    assert_eq!(j.count(), 4);
    assert_eq!(db.join_sum(&j, "p", "budget").unwrap(), int(1800));
    let opts = JoinOptions { alias: Some("e".into()), where_: Some(is_in("eid", &[ci(1), ci(3)])) };
    let j = db.join("emp", &[JoinStep::new("dept", "did", "did").alias("d")], &opts).unwrap();
    assert_eq!(j.count(), 2);
    assert_eq!(db.join_sum(&j, "e", "salary").unwrap(), int(170));
    let opts = JoinOptions { where_: Some(eq_int("did", 10)), ..Default::default() };
    assert_eq!(db.join("emp", &[JoinStep::new("dept", "did", "did")], &opts).unwrap().count(), 2);
}

#[test]
fn null_keys_never_match_and_empty_tables() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    for t in ["a", "b"] {
        db.create_table(t, vec![col("k", "int", "plain")]).unwrap();
    }
    db.insert_many("a", vec![vec![("k", CellIn::Null)], vec![("k", ci(1))]]).unwrap();
    db.insert_many("b", vec![vec![("k", CellIn::Null)], vec![("k", ci(1))]]).unwrap();
    let d = JoinOptions::default();
    assert_eq!(db.join("a", &[JoinStep::new("b", "k", "k")], &d).unwrap().count(), 1);
    assert_eq!(db.join("a", &[JoinStep::new("b", "k", "k").left()], &d).unwrap().count(), 2);
    db.create_table("e", vec![col("k", "int", "plain"), col("v", "int", "encrypted")]).unwrap();
    let l = db.join("a", &[JoinStep::new("e", "k", "k").left()], &d).unwrap();
    assert_eq!(l.tuples, vec![vec![Some(0), None], vec![Some(1), None]]);
    assert_eq!(db.join_sum(&l, "e", "v").unwrap(), int(0));
    assert!(db.join("a", &[JoinStep::new("e", "k", "k")], &d).unwrap().tuples.is_empty());
}

#[test]
fn tombstones_and_updates_in_joins() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    db.delete_rows("emp", eq_int("eid", 2)).unwrap();
    db.delete_rows("dept", eq_int("did", 20)).unwrap();
    let d = JoinOptions::default();
    assert_eq!(db.join("emp", &[JoinStep::new("dept", "did", "did")], &d).unwrap().count(), 1);
    let l = db.join("emp", &[JoinStep::new("dept", "did", "did").left()], &d).unwrap();
    assert_eq!(db.join_sum(&l, "emp", "salary").unwrap(), int(100 + 70 + 60));
    db.update("emp", vec![("salary", ci(500))], eq_int("eid", 1)).unwrap();
    let j = db.join("emp", &[JoinStep::new("dept", "did", "did")], &d).unwrap();
    assert_eq!(db.join_sum(&j, "emp", "salary").unwrap(), int(500));
}

#[test]
fn cross_table_dot() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    db.create_table("a", vec![col("k", "int", "plain"), col("x", "int", "paired")]).unwrap();
    db.create_table("b", vec![col("k", "int", "plain"), col("y", "int", "paired")]).unwrap();
    db.insert_many("a", vec![vec![("k", ci(1)), ("x", ci(3))], vec![("k", ci(2)), ("x", ci(4))]]).unwrap();
    db.insert("b", vec![("k", ci(1)), ("y", ci(10))]).unwrap();
    let d = JoinOptions::default();
    let inner = db.join("a", &[JoinStep::new("b", "k", "k")], &d).unwrap();
    assert_eq!(db.join_dot(&inner, "a", "x", "b", "y").unwrap(), int(30));
    let left = db.join("a", &[JoinStep::new("b", "k", "k").left()], &d).unwrap();
    assert_eq!(db.join_dot(&left, "a", "x", "b", "y").unwrap(), int(30));
    db.insert("b", vec![("k", ci(2)), ("y", ci(100))]).unwrap();
    let both = db.join("a", &[JoinStep::new("b", "k", "k")], &d).unwrap();
    assert_eq!(db.join_dot(&both, "a", "x", "b", "y").unwrap(), int(430));
}

#[test]
fn bad_joins_are_typed_errors() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = org(&srv);
    let d = JoinOptions::default();
    let kind = |r: std::result::Result<JoinResult, Error>| r.unwrap_err().kind;
    assert_eq!(kind(db.join("emp", &[JoinStep::new("dept", "salary", "did")], &d)), Kind::Interface);
    assert_eq!(kind(db.join("emp", &[JoinStep::new("dept", "did", "nope")], &d)), Kind::Interface);
    assert_eq!(kind(db.join("emp", &[JoinStep::new("emp", "mgr", "eid")], &d)), Kind::Interface); // duplicate alias
    assert_eq!(kind(db.join("emp", &[JoinStep::new("dept", "did", "did").left_alias("zz")], &d)), Kind::Interface);
    assert_eq!(kind(db.join("emp", &[JoinStep::new("nosuch", "did", "did")], &d)), Kind::Interface);
    let j = db.join("emp", &[JoinStep::new("dept", "did", "did").alias("d")], &d).unwrap();
    assert_eq!(db.join_sum(&j, "q", "salary").unwrap_err().kind, Kind::Interface);
}
