// SPDX-License-Identifier: Apache-2.0
//! TLS against a REAL server (cargo test --features tls): verified by default,
//! explicit opt-out only.
#![cfg(feature = "tls")]
use std::process::Command;
use std::time::Duration;
use torusdb::*;

mod common;
use common::*;

fn tls_server() -> Option<(Server, Vec<u8>)> {
    let dir = tmpdir("tls");
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    let ok = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: openssl cannot generate a certificate");
        return None;
    }
    let s = Server::start(&["--tls", "--cert", cert.to_str().unwrap(), "--key", key.to_str().unwrap()])?;
    Some((s, std::fs::read(&cert).unwrap()))
}

fn opts() -> ConnectOptions {
    ConnectOptions { tls: true, timeout: Some(Duration::from_secs(5)), ..Default::default() }
}

#[test]
fn self_signed_is_rejected_by_default() {
    let Some((s, _)) = tls_server() else { return };
    let e = Client::connect_with(&format!("localhost:{}", s.port), &opts()).err().unwrap();
    assert_eq!(e.kind, Kind::Connection);
    assert!(e.message.to_lowercase().contains("certificate") || e.message.contains("UnknownIssuer"), "{}", e);
}

#[test]
fn trusting_the_ca_works_and_hostname_is_verified() {
    let Some((s, ca)) = tls_server() else { return };
    let o = ConnectOptions { ca_pem: Some(ca.clone()), ..opts() };
    let mut db = Client::connect_with(&format!("localhost:{}", s.port), &o).unwrap();
    assert!(db.ping().unwrap());
    let mut ip = Client::connect_with(&format!("127.0.0.1:{}", s.port), &o).unwrap();
    assert!(ip.ping().unwrap());
    // name not on the certificate is refused even with the right CA
    assert!(Client::connect_with(&format!("127.0.0.2:{}", s.port), &o).is_err());
}

#[test]
fn insecure_must_be_explicit() {
    let Some((s, _)) = tls_server() else { return };
    let o = ConnectOptions { tls_insecure: true, ..opts() };
    let mut db = Client::connect_with(&format!("localhost:{}", s.port), &o).unwrap();
    assert!(db.ping().unwrap());
}

#[test]
fn plain_tcp_to_a_tls_server_fails_cleanly() {
    let Some((s, _)) = tls_server() else { return };
    let o = ConnectOptions { timeout: Some(Duration::from_millis(1500)), ..Default::default() };
    assert!(Client::connect_with(&s.addr, &o).is_err());
}
