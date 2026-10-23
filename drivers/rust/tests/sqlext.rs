// SPDX-License-Identifier: Apache-2.0
//! BETWEEN / NOT IN / IS [NOT] NULL / [NOT] LIKE / OFFSET / indexes / IF [NOT] EXISTS
//! against a REAL server, memory and disk storage, with and without indexes.
//! Expected values are the CASES table of torussql/tests/test_sql_ext.py.
use num_bigint::BigInt;
use serde_json::Value;
use torusdb::*;

mod common;
use common::*;

fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn s(v: &str) -> CellIn {
    CellIn::Str(v.into())
}

const ROWS: [(i64, Option<&str>, Option<i64>); 6] = [
    (1, Some("alice"), Some(10)),
    (2, Some("bob"), Some(20)),
    (3, Some("carol"), None),
    (4, Some("alicia"), Some(40)),
    (5, None, Some(50)),
    (6, Some("a_b%c"), Some(60)),
];

fn cases() -> Vec<(&'static str, Value, Vec<i64>)> {
    let bt = |c: &str, a: i64, b: i64| between(c, &ci(a), &ci(b)).unwrap();
    vec![
        ("age BETWEEN 20 AND 50", bt("age", 20, 50), vec![2, 4, 5]),
        ("age BETWEEN 10 AND 10", bt("age", 10, 10), vec![1]),
        ("id NOT IN (1, 2, 3)", not_in("id", &[ci(1), ci(2), ci(3)]).unwrap(), vec![4, 5, 6]),
        ("age NOT IN (10, 20)", not_in("age", &[ci(10), ci(20)]).unwrap(), vec![4, 5, 6]),
        ("age IS NULL", is_null("age"), vec![3]),
        ("age IS NOT NULL", not_null("age"), vec![1, 2, 4, 5, 6]),
        ("name IS NULL", is_null("name"), vec![5]),
        ("name LIKE 'ali%'", like("name", "ali%"), vec![1, 4]),
        ("name LIKE '_ob'", like("name", "_ob"), vec![2]),
        ("name LIKE '%c%'", like("name", "%c%"), vec![1, 3, 4, 6]),
        ("name NOT LIKE 'ali%'", not_like("name", "ali%"), vec![2, 3, 6]),
        ("name LIKE 'a\\_b%'", like("name", "a\\_b%"), vec![]),
        ("name LIKE 'a_b%c'", like("name", "a_b%c"), vec![6]),
        ("age IS NULL OR name LIKE 'bob'", or(&[is_null("age"), like("name", "bob")]), vec![2, 3]),
        (
            "age BETWEEN 10 AND 40 AND name NOT LIKE '%a%'",
            and(&[bt("age", 10, 40), not_like("name", "%a%")]),
            vec![2],
        ),
    ]
}

#[test]
fn cases_equal_the_python_table() {
    let py = repo().join("tests/test_sql_ext.py");
    let Ok(src) = std::fs::read_to_string(&py) else { return }; // published crate: nothing to compare
    let start = src.find("CASES = [").expect("CASES in python test");
    let block = &src[start..src[start..].find("\n]\n").map(|i| start + i).unwrap()];
    let mut found: Vec<(String, Vec<i64>)> = vec![];
    for line in block.lines().skip(1) {
        let l = line.trim();
        if !l.starts_with("(\"") {
            continue;
        }
        let close = l.rfind("\", [").expect("case line");
        let w = l[2..close].replace("\\\\", "\\");
        let list = &l[close + 4..l.rfind(']').unwrap()];
        let ids = list.split(',').filter(|x| !x.trim().is_empty()).map(|x| x.trim().parse().unwrap()).collect();
        found.push((w, ids));
    }
    assert!(found.len() >= 15, "parsed {} python cases", found.len());
    let mine: Vec<(String, Vec<i64>)> = cases().into_iter().map(|(w, _, e)| (w.to_string(), e)).collect();
    assert_eq!(mine, found);
}

fn seed(db: &mut Client, t: &str) {
    db.create_table(
        t,
        vec![col("id", "int", "plain"), col("name", "str", "plain"), col("age", "int", "plain"), col("v", "int", "encrypted")],
    )
    .unwrap();
    let rows = ROWS
        .iter()
        .map(|(id, name, age)| {
            vec![
                ("id", ci(*id)),
                ("name", name.map(s).unwrap_or(CellIn::Null)),
                ("age", age.map(ci).unwrap_or(CellIn::Null)),
                ("v", ci(id * 100)),
            ]
        })
        .collect();
    db.insert_many(t, rows).unwrap();
}

fn ids(db: &mut Client, t: &str, w: Value) -> Vec<i64> {
    let mut v: Vec<i64> = db
        .select(t, &["id"], w)
        .unwrap()
        .into_iter()
        .map(|r| match &r[0] {
            CellIn::Int(i) => i.to_string().parse().unwrap(),
            other => panic!("{:?}", other),
        })
        .collect();
    v.sort();
    v
}

fn start(storage: &str) -> Option<(Server, PathBufGuard)> {
    let dir = tmpdir("sqlext");
    let srv = if storage == "disk" {
        Server::start(&["--db", dir.join("db").to_str().unwrap(), "--storage", "disk"])?
    } else {
        Server::start(&[])?
    };
    Some((srv, PathBufGuard(dir)))
}
struct PathBufGuard(#[allow(dead_code)] std::path::PathBuf);

#[test]
fn predicates_over_the_wire_memory_and_disk_with_and_without_indexes() {
    for storage in ["memory", "disk"] {
        let Some((srv, _g)) = start(storage) else { return };
        let mut db = Client::connect(&srv.addr).unwrap();
        seed(&mut db, "t");
        assert!(db.table_info("t").unwrap().indexes.is_empty());
        for round in 0..2 {
            for (w, p, expected) in cases() {
                assert_eq!(ids(&mut db, "t", p), expected, "{} [{}] round {}", w, storage, round);
            }
            assert_eq!(db.count("t", between("age", &ci(20), &ci(50)).unwrap()).unwrap(), 3);
            assert_eq!(
                db.sum("t", "v", not_in("id", &[ci(1), ci(2)]).unwrap()).unwrap(),
                Decoded::Int(BigInt::from(1800))
            );
            if round == 0 {
                for c in ["age", "name", "id"] {
                    db.create_index("t", c).unwrap();
                }
            }
        }
        let mut idx = db.table_info("t").unwrap().indexes;
        idx.sort();
        assert_eq!(idx, vec!["age", "id", "name"]);
        assert_eq!(db.delete_rows("t", between("age", &ci(40), &ci(60)).unwrap()).unwrap(), 3);
        assert_eq!(ids(&mut db, "t", not_null("age")), vec![1, 2]);
        db.update("t", vec![("age", ci(99))], like("name", "bob")).unwrap();
        assert_eq!(ids(&mut db, "t", between("age", &ci(90), &ci(100)).unwrap()), vec![2]);
        db.drop_index("t", "age").unwrap();
        assert_eq!(ids(&mut db, "t", between("age", &ci(90), &ci(100)).unwrap()), vec![2]);
        let mut idx = db.table_info("t").unwrap().indexes;
        idx.sort();
        assert_eq!(idx, vec!["id", "name"]);
    }
}

#[test]
fn rollback_undoes_index_changes_and_null_semantics_hold() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    seed(&mut db, "t");
    db.begin().unwrap();
    db.create_index("t", "age").unwrap();
    db.delete_rows("t", is_null("age")).unwrap();
    assert_eq!(db.table_info("t").unwrap().indexes, vec!["age"]);
    db.rollback().unwrap();
    assert!(db.table_info("t").unwrap().indexes.is_empty());
    assert_eq!(ids(&mut db, "t", is_null("age")), vec![3]);
    db.transaction(|db| db.create_index("t", "name")).unwrap();
    assert_eq!(db.table_info("t").unwrap().indexes, vec!["name"]);
    db.drop_index("t", "name").unwrap();
    assert_eq!(ids(&mut db, "t", not_like("name", "zzz")), vec![1, 2, 3, 4, 6]);
    assert_eq!(ids(&mut db, "t", not_in("name", &[s("bob")]).unwrap()), vec![1, 3, 4, 6]);
}

#[test]
fn validation() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    seed(&mut db, "t");
    for p in [
        like("id", "1%"),
        like("v", "1%"),
        is_null("v"),
        between("v", &ci(1), &ci(2)).unwrap(),
    ] {
        assert_eq!(db.count("t", p).unwrap_err().kind, Kind::Interface);
    }
    assert!(not_in("id", &[]).is_err());
    assert!(between("id", &CellIn::Rational(1.into(), 0.into()), &ci(2)).is_err());
    assert_eq!(db.create_index("t", "v").unwrap_err().kind, Kind::Interface);
    assert_eq!(db.create_index("t", "nope").unwrap_err().kind, Kind::Interface);
    assert_eq!(db.create_index("nosuch", "id").unwrap_err().kind, Kind::Interface);
}

#[test]
fn offset_limit_and_if_exists() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    seed(&mut db, "t");
    let mut col = |off: usize, lim: Option<usize>, p: Value| -> Vec<i64> {
        db.select_range("t", &["id"], p, off, lim)
            .unwrap()
            .into_iter()
            .map(|r| if let CellIn::Int(i) = &r[0] { i.to_string().parse().unwrap() } else { panic!() })
            .collect()
    };
    assert_eq!(col(1, Some(2), all()), vec![2, 3]);
    assert_eq!(col(4, None, all()), vec![5, 6]);
    assert!(col(99, Some(5), all()).is_empty());
    assert!(col(0, Some(0), all()).is_empty());
    assert_eq!(col(1, Some(2), between("age", &ci(10), &ci(60)).unwrap()), vec![2, 4]);

    let cols = || vec![col_def("id")];
    fn col_def(n: &str) -> Column {
        Column { name: n.into(), ty: "int".into(), policy: "plain".into() }
    }
    db.create_table_if_not_exists("x", cols()).unwrap();
    db.insert("x", vec![("id", ci(1))]).unwrap();
    db.create_table_if_not_exists("x", cols()).unwrap(); // no-op, data kept
    assert_eq!(db.count("x", all()).unwrap(), 1);
    assert!(db.create_table("x", cols()).unwrap_err().message.contains("already exists"));
    db.drop_table_if_exists("never").unwrap();
    db.drop_table_if_exists("x").unwrap();
    assert!(db.drop_table("x").unwrap_err().message.contains("no such table"));
}

#[test]
fn left_join_is_null_on_the_null_side() {
    let Some(srv) = Server::start(&[]) else { return };
    let mut db = Client::connect(&srv.addr).unwrap();
    db.create_table("a", vec![col("k", "int", "plain")]).unwrap();
    db.create_table("b", vec![col("k", "int", "plain"), col("w", "int", "plain"), col("s", "str", "plain")]).unwrap();
    db.insert_many("a", vec![vec![("k", ci(1))], vec![("k", ci(2))], vec![("k", ci(3))]]).unwrap();
    db.insert("b", vec![("k", ci(2)), ("w", ci(7)), ("s", s("x"))]).unwrap();
    let mut ks = |w: Value| -> Vec<i64> {
        let j = db
            .join("a", &[JoinStep::new("b", "k", "k").left()], &JoinOptions { alias: None, where_: Some(w) })
            .unwrap();
        let mut v: Vec<i64> = db
            .join_column(&j, "a", "k")
            .unwrap()
            .into_iter()
            .map(|c| if let CellIn::Int(i) = c { i.to_string().parse().unwrap() } else { panic!() })
            .collect();
        v.sort();
        v
    };
    assert_eq!(ks(on_alias("b", is_null("w"))), vec![1, 3]);
    assert_eq!(ks(on_alias("b", not_null("w"))), vec![2]);
    assert_eq!(ks(on_alias("b", not_like("s", "y%"))), vec![2]); // NULL side matches neither LIKE nor NOT LIKE
    assert_eq!(ks(on_alias("b", like("s", "x"))), vec![2]);
    assert_eq!(ks(on_alias("b", between("w", &ci(1), &ci(9)).unwrap())), vec![2]);
    assert!(ks(on_alias("b", not_in("w", &[ci(7)]).unwrap())).is_empty());
    assert_eq!(ks(or(&[on_alias("b", is_null("w")), eq_int("k", 2)])), vec![1, 2, 3]);
}

#[test]
fn index_rpcs_need_role_rw() {
    let dir = tmpdir("sqlext-auth");
    let f = dir.join("tokens");
    std::fs::write(&f, format!("admin:{}\nro:{}\n", ADMIN, RO)).unwrap();
    let Some(srv) = Server::start(&["--token-file", f.to_str().unwrap()]) else { return };
    let tok = |t: &str| ConnectOptions { token: Some(t.into()), trust_server_schema: true, ..Default::default() };
    let mut a = Client::connect_with(&srv.addr, &tok(ADMIN)).unwrap();
    seed(&mut a, "t");
    let mut r = Client::connect_with(&srv.addr, &tok(RO)).unwrap();
    assert_eq!(r.create_index("t", "age").unwrap_err().kind, Kind::Forbidden);
    a.create_index("t", "age").unwrap();
    assert_eq!(r.drop_index("t", "age").unwrap_err().kind, Kind::Forbidden);
    assert_eq!(r.table_info("t").unwrap().indexes, vec!["age"]);
}
