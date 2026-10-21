// SPDX-License-Identifier: Apache-2.0
//! Transactions against a REAL server: commit, rollback (server + mask state), dropped connection.
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
fn row(k: i64, v: i64) -> Vec<(&'static str, CellIn)> {
    vec![("k", ci(k)), ("v", ci(v))]
}
fn seeded(db: &mut Client, t: &str) {
    db.create_table(t, kv_cols()).unwrap();
    db.insert(t, row(1, 100)).unwrap();
    db.insert(t, row(2, 200)).unwrap();
}

#[test]
fn commit_is_visible_to_other_connections() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    seeded(&mut a, "t");
    let mut b = Client::connect(&s.addr).unwrap();
    a.begin().unwrap();
    assert!(a.in_transaction());
    a.insert("t", row(3, 300)).unwrap();
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(600));
    a.commit().unwrap();
    assert!(!a.in_transaction());
    assert_eq!(b.count("t", all()).unwrap(), 3);
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(600));
}

#[test]
fn rollback_of_insert_removes_row_and_masks() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    seeded(&mut a, "t");
    let masks = a.mask_count();
    a.begin().unwrap();
    a.insert("t", row(3, 300)).unwrap();
    assert_eq!(a.mask_count(), masks + 1);
    a.rollback().unwrap();
    assert_eq!(a.mask_count(), masks);
    assert_eq!(a.count("t", all()).unwrap(), 2);
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(300));
    assert_eq!(a.table_info("t").unwrap().rows, 2);
    a.insert("t", row(9, 7)).unwrap(); // rowid reused, decrypts fine
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(307));
}

#[test]
fn rollback_of_update_delete_and_create() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    seeded(&mut a, "t");
    a.begin().unwrap();
    a.update("t", vec![("v", ci(999))], eq_int("k", 1)).unwrap();
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(1199));
    a.delete_rows("t", eq_int("k", 2)).unwrap();
    a.create_table("t2", kv_cols()).unwrap();
    a.insert("t2", row(1, 1)).unwrap();
    a.rollback().unwrap();
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(300));
    assert_eq!(a.select("t", &["v"], eq_int("k", 1)).unwrap(), vec![vec![ci(100)]]);
    assert!(!a.tables().unwrap().contains(&"t2".to_string()));
    assert_eq!(a.count("t2", all()).unwrap_err().kind, Kind::Interface); // schema restored too
}

#[test]
fn transaction_closure_commits_on_ok_and_rolls_back_on_err() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    seeded(&mut a, "t");
    let out: std::result::Result<&str, Error> = a.transaction(|db| {
        db.insert("t", row(3, 3))?;
        Ok("done")
    });
    assert_eq!(out.unwrap(), "done");
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(303));

    let r: std::result::Result<(), Error> = a.transaction(|db| {
        db.insert("t", row(4, 4))?;
        Err(Error::new(Kind::Interface, "boom"))
    });
    assert_eq!(r.unwrap_err().message, "boom");
    assert!(!a.in_transaction());
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(303));
    assert_eq!(a.count("t", all()).unwrap(), 3);

    // a failing server call inside the closure rolls everything back
    let r: std::result::Result<(), Error> = a.transaction(|db| {
        db.insert("t", row(5, 5))?;
        db.count("t", eq_int("nonexistent", 1))?;
        Ok(())
    });
    assert_eq!(r.unwrap_err().kind, Kind::BadRequest);
    assert_eq!(a.count("t", all()).unwrap(), 3);

    // closures returning String errors work too (old-style code)
    let r: std::result::Result<(), String> = a.transaction(|db| {
        db.insert("t", row(6, 6))?;
        Ok(())
    });
    assert!(r.is_ok());
    assert_eq!(a.sum("t", "v", all()).unwrap(), int(309));
}

#[test]
fn dropped_connection_mid_transaction_rolls_back() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    seeded(&mut a, "t");
    a.begin().unwrap();
    a.insert("t", row(3, 3)).unwrap();
    drop(a); // crash: no commit, no rollback
    let mut b = Client::connect(&s.addr).unwrap();
    assert_eq!(b.count("t", all()).unwrap(), 2);
    b.begin().unwrap(); // lock is free again
    b.rollback().unwrap();
}

#[test]
fn begin_twice_and_noop_commit_rollback() {
    let Some(s) = Server::start(&[]) else { return };
    let mut a = Client::connect(&s.addr).unwrap();
    a.commit().unwrap();
    a.rollback().unwrap();
    a.begin().unwrap();
    assert_eq!(a.begin().unwrap_err().kind, Kind::Interface);
    a.rollback().unwrap();
}
