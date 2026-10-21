// SPDX-License-Identifier: Apache-2.0
//! Transport robustness against a scripted FAKE server (no Python needed):
//! protocol negotiation, v1 fallback, timeouts, connection loss.
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use torusdb::*;

enum Reply {
    Json(Value),
    Drop,
    Hang,
}

fn fake<F>(handler: F) -> (String, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str, &Value) -> Reply + Send + Sync + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(vec![]));
    let seen2 = seen.clone();
    let h = Arc::new(handler);
    std::thread::spawn(move || {
        for sock in l.incoming() {
            let Ok(mut sock) = sock else { break };
            let (h, seen) = (h.clone(), seen2.clone());
            std::thread::spawn(move || serve(&mut sock, &*h, &seen));
        }
    });
    (addr, seen)
}

fn serve(sock: &mut TcpStream, h: &dyn Fn(&str, &Value) -> Reply, seen: &Mutex<Vec<String>>) {
    loop {
        let mut hdr = [0u8; 4];
        if sock.read_exact(&mut hdr).is_err() {
            return;
        }
        let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
        if sock.read_exact(&mut buf).is_err() {
            return;
        }
        let req: Value = serde_json::from_slice(&buf).unwrap();
        let m = req["m"].as_str().unwrap().to_string();
        seen.lock().unwrap().push(m.clone());
        match h(&m, &req["a"]) {
            Reply::Drop => return,
            Reply::Hang => std::thread::sleep(Duration::from_secs(5)),
            Reply::Json(v) => {
                let body = v.to_string();
                let _ = sock.write_all(&(body.len() as u32).to_be_bytes());
                let _ = sock.write_all(body.as_bytes());
            }
        }
    }
}

fn hello(m: &str) -> Option<Reply> {
    match m {
        "hello" => Some(Reply::Json(json!({"ok": {"protocol": 2, "auth_required": false}}))),
        "tables" => Some(Reply::Json(json!({"ok": []}))),
        _ => None,
    }
}

#[test]
fn protocol_1_server_is_accepted() {
    let (addr, _) = fake(|m, _| match m {
        "hello" => Reply::Json(json!({"err": "BadRequest: unknown method"})),
        "tables" => Reply::Json(json!({"ok": []})),
        _ => Reply::Json(json!({"ok": null})),
    });
    let db = Client::connect(&addr).unwrap();
    assert_eq!(db.server_info().protocol, 1);
    assert!(!db.server_info().auth_required);
}

#[test]
fn newer_protocol_is_refused() {
    let (addr, _) = fake(|m, _| match m {
        "hello" => Reply::Json(json!({"ok": {"protocol": 3, "auth_required": false}})),
        _ => Reply::Json(json!({"ok": null})),
    });
    let e = Client::connect(&addr).err().unwrap();
    assert_eq!(e.kind, Kind::Interface);
    assert!(e.message.contains("protocol 3"));
}

#[test]
fn auth_flow() {
    let (addr, seen) = fake(|m, a| match m {
        "hello" => Reply::Json(json!({"ok": {"protocol": 2, "auth_required": true}})),
        "auth" if a[0] == "good-token-0123456789" => Reply::Json(json!({"ok": {"role": "rw"}})),
        "auth" => Reply::Json(json!({"err": "Unauthenticated: invalid token"})),
        _ => Reply::Json(json!({"ok": []})),
    });
    assert_eq!(Client::connect(&addr).err().unwrap().kind, Kind::Unauthenticated);
    assert!(!seen.lock().unwrap().contains(&"auth".to_string()));
    let o = ConnectOptions { token: Some("good-token-0123456789".into()), ..Default::default() };
    Client::connect_with(&addr, &o).unwrap();
    let o = ConnectOptions { token: Some("bad".into()), ..Default::default() };
    assert_eq!(Client::connect_with(&addr, &o).err().unwrap().kind, Kind::Unauthenticated);
}

#[test]
fn silent_server_times_out_instead_of_hanging() {
    let (addr, _) = fake(|m, _| hello(m).unwrap_or(Reply::Hang));
    let o = ConnectOptions { timeout: Some(Duration::from_millis(250)), ..Default::default() };
    let mut db = Client::connect_with(&addr, &o).unwrap();
    let t0 = Instant::now();
    assert_eq!(db.ping().unwrap_err().kind, Kind::Timeout);
    assert!(t0.elapsed() < Duration::from_secs(3));
    assert!(db.is_closed()); // a late reply could desynchronize the stream
    assert!(db.ping().is_err());
}

#[test]
fn connection_loss_is_a_connection_error_and_later_calls_fail_fast() {
    let (addr, _) = fake(|m, _| hello(m).unwrap_or(Reply::Drop));
    let mut db = Client::connect(&addr).unwrap();
    assert_eq!(db.ping().unwrap_err().kind, Kind::Connection);
    assert!(db.ping().is_err());
    assert!(db.count("x", all()).is_err());
}

#[test]
fn connection_refused_is_a_connection_error() {
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let o = ConnectOptions { timeout: Some(Duration::from_secs(2)), ..Default::default() };
    assert_eq!(Client::connect_with(&addr, &o).err().unwrap().kind, Kind::Connection);
}

#[test]
fn malformed_reply_and_error_parsing() {
    let (addr, _) = fake(|m, _| {
        hello(m).unwrap_or_else(|| match m {
            "ping" => Reply::Json(json!({"weird": true})),
            _ => Reply::Json(json!({"err": "InternalError: internal server error (ref=ab12)"})),
        })
    });
    let mut db = Client::connect(&addr).unwrap();
    assert_eq!(db.ping().unwrap_err().kind, Kind::Protocol);
    let e = db.stats().unwrap_err();
    assert_eq!(e.kind, Kind::InternalError);
    assert!(e.message.contains("ref=ab12"));
    assert_eq!(Error::from_server("Weird: x").kind, Kind::Server("Weird".into()));
    assert_eq!(Error::from_server("no prefix here").kind_name(), "ServerError");
}

#[test]
fn tls_without_feature_or_with_bad_ca_is_a_clean_error() {
    // plain fake server: a TLS handshake against it must fail, never hang
    let (addr, _) = fake(|m, _| hello(m).unwrap_or(Reply::Hang));
    let o = ConnectOptions { tls: true, timeout: Some(Duration::from_millis(500)), ..Default::default() };
    assert!(Client::connect_with(&addr, &o).is_err());
}
