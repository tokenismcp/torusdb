// SPDX-License-Identifier: Apache-2.0
//! Vault persistence against a REAL server.
use num_bigint::BigInt;
use torusdb::*;

mod common;
use common::*;

fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}

#[test]
fn save_is_0600_atomic_and_load_restores_decryption() {
    let Some(s) = Server::start(&[]) else { return };
    let dir = tmpdir("vault");
    let file = dir.join("vault.json");
    let mut a = Client::connect(&s.addr).unwrap();
    a.create_table("t", vec![col("k", "int", "plain"), col("v", "rational", "encrypted")]).unwrap();
    a.insert("t", vec![("k", ci(1)), ("v", CellIn::Rational(1.into(), 3.into()))]).unwrap();
    a.insert("t", vec![("k", ci(2)), ("v", CellIn::Rational(2.into(), 3.into()))]).unwrap();
    a.save_vault(Some(&file)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names.len(), 1, "temp file left behind: {:?}", names);
    a.save_vault(Some(&file)).unwrap(); // overwrite
    drop(a);

    let mut none = Client::connect(&s.addr).unwrap();
    assert!(none.sum("t", "v", all()).unwrap_err().message.contains("no mask"));
    let mut b = Client::connect_with(&s.addr, &ConnectOptions { vault_path: Some(file.clone()), ..Default::default() }).unwrap();
    assert_eq!(b.sum("t", "v", all()).unwrap(), Decoded::Int(1.into()));
    b.insert("t", vec![("k", ci(3)), ("v", ci(5))]).unwrap();
    b.save_vault(None).unwrap();
    let mut c = Client::connect(&s.addr).unwrap();
    c.load_vault(Some(&file)).unwrap();
    assert_eq!(c.sum("t", "v", all()).unwrap(), Decoded::Int(6.into()));
    assert!(c.find_orphans().unwrap().is_empty());
    assert!(none.find_orphans().unwrap().contains_key("t"));
}

#[test]
fn corrupt_vault_is_rejected() {
    let Some(s) = Server::start(&[]) else { return };
    let f = tmpdir("vault2").join("v.json");
    std::fs::write(&f, "{not json").unwrap();
    let mut c = Client::connect(&s.addr).unwrap();
    assert_eq!(c.load_vault(Some(&f)).unwrap_err().kind, Kind::Interface);
}
