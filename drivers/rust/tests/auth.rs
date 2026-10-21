// SPDX-License-Identifier: Apache-2.0
//! Authentication and roles against a REAL server started with --token-file.
use num_bigint::BigInt;
use std::io::{Read, Write};
use torusdb::*;

mod common;
use common::*;

fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn row(k: i64, v: i64) -> Vec<(&'static str, CellIn)> {
    vec![("k", ci(k)), ("v", ci(v))]
}
fn authed() -> Option<(Server, std::path::PathBuf)> {
    let dir = tmpdir("auth");
    let f = dir.join("tokens");
    std::fs::write(&f, format!("admin:{}\nrw:{}\nro:{}\n", ADMIN, RW, RO)).unwrap();
    Server::start(&["--token-file", f.to_str().unwrap()]).map(|s| (s, f))
}
fn with(tok: &str) -> ConnectOptions {
    ConnectOptions { token: Some(tok.into()), ..Default::default() }
}

#[test]
fn missing_token_is_a_clear_error() {
    let Some((s, _)) = authed() else { return };
    let e = Client::connect(&s.addr).err().unwrap();
    assert_eq!(e.kind, Kind::Unauthenticated);
    assert!(e.message.contains("requires a token"));
}

#[test]
fn wrong_token_rejected_and_never_echoed() {
    let Some((s, _)) = authed() else { return };
    let bad = "wrong-token-0123456789xyz";
    let e = Client::connect_with(&s.addr, &with(bad)).err().unwrap();
    assert_eq!(e.kind, Kind::Unauthenticated);
    assert!(!e.to_string().contains(bad));
    assert!(!format!("{:?}", e).contains(bad));
}

#[test]
fn raw_unauthenticated_rpc_is_refused() {
    let Some((s, _)) = authed() else { return };
    let mut sock = std::net::TcpStream::connect(&s.addr).unwrap();
    let body = br#"{"m":"tables","a":[]}"#;
    sock.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    sock.write_all(body).unwrap();
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr).unwrap();
    let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
    sock.read_exact(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("Unauthenticated"));
}

#[test]
fn rw_reads_and_writes_ro_only_reads() {
    let Some((s, _)) = authed() else { return };
    let mut w = Client::connect_with(&s.addr, &with(RW)).unwrap();
    assert!(w.server_info().auth_required);
    w.create_table("t", kv_cols()).unwrap();
    w.insert("t", row(1, 10)).unwrap();
    w.insert("t", row(2, 20)).unwrap();
    assert_eq!(w.sum("t", "v", all()).unwrap(), Decoded::Int(BigInt::from(30)));

    let mut r = Client::connect_with(&s.addr, &with(RO)).unwrap();
    assert_eq!(r.count("t", all()).unwrap(), 2);
    assert_eq!(r.insert("t", row(3, 5)).unwrap_err().kind, Kind::Forbidden);
    assert_eq!(r.delete_rows("t", eq_int("k", 1)).unwrap_err().kind, Kind::Forbidden);
    assert_eq!(r.create_table("u", kv_cols()).unwrap_err().kind, Kind::Forbidden);
    assert_eq!(r.begin().unwrap_err().kind, Kind::Forbidden);
    assert!(!r.in_transaction());
    assert_eq!(r.mask_count(), 0);
    assert_eq!(w.count("t", all()).unwrap(), 2);
}

#[test]
fn only_admin_gets_stats_checkpoint_backup_drop() {
    let Some((s, _)) = authed() else { return };
    let mut w = Client::connect_with(&s.addr, &with(RW)).unwrap();
    assert_eq!(w.stats().unwrap_err().kind, Kind::Forbidden);
    assert_eq!(w.checkpoint().unwrap_err().kind, Kind::Forbidden);
    assert_eq!(w.backup().unwrap_err().kind, Kind::Forbidden);
    w.create_table("t", kv_cols()).unwrap();
    assert_eq!(w.drop_table("t").unwrap_err().kind, Kind::Forbidden);
    assert!(w.tables().unwrap().contains(&"t".to_string()));
    let mut a = Client::connect_with(&s.addr, &with(ADMIN)).unwrap();
    assert!(a.stats().unwrap().is_object());
    assert!(a.ping().unwrap());
    a.drop_table("t").unwrap();
    assert!(!a.tables().unwrap().contains(&"t".to_string()));
}
