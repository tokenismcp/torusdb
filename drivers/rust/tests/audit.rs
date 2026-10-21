// SPDX-License-Identifier: Apache-2.0
//! Regression tests for the independent audit findings (F1..F17).
use num_bigint::BigInt;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use torusdb::*;

mod common;
use common::fake::{base, fake, proxy, raw_rpc, Reply};
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
fn kv_schema(m: &str) -> Option<Reply> {
    match m {
        "tables" => Some(Reply::Json(json!({"ok": ["t"]}))),
        "schema" => Some(Reply::Json(json!({"ok": [["k", "int", "plain"], ["v", "int", "encrypted"]]}))),
        _ => None,
    }
}
fn trusting() -> ConnectOptions {
    ConnectOptions { trust_server_schema: true, ..Default::default() }
}

// ── F1: lost COMMIT reply ────────────────────────────────────────────────────
#[test]
fn f1_commit_reply_lost_but_committed_keeps_masks() {
    let Some(s) = Server::start(&[]) else { return };
    let px = proxy(&s.addr);
    let mut db = Client::connect(&px.addr).unwrap();
    db.create_table("t", kv_cols()).unwrap();
    db.insert("t", row(1, 100)).unwrap();
    db.begin().unwrap();
    db.insert("t", row(2, 200)).unwrap();
    px.lose("tx_commit", true, false);
    db.commit().unwrap(); // settled via tx_status -> committed
    assert!(!db.in_transaction());
    assert_eq!(db.sum("t", "v", all()).unwrap(), int(300));
    let mut other = Client::connect(&s.addr).unwrap();
    assert_eq!(other.count("t", all()).unwrap(), 2);
}

#[test]
fn f1_commit_request_lost_rolls_the_vault_back() {
    let Some(s) = Server::start(&[]) else { return };
    let px = proxy(&s.addr);
    let mut db = Client::connect(&px.addr).unwrap();
    db.create_table("t", kv_cols()).unwrap();
    db.insert("t", row(1, 100)).unwrap();
    let masks = db.mask_count();
    db.begin().unwrap();
    db.insert("t", row(2, 200)).unwrap();
    px.lose("tx_commit", false, false);
    assert_eq!(db.commit().unwrap_err().kind, Kind::Connection);
    assert_eq!(db.mask_count(), masks);
    assert!(!db.in_transaction());
    let mut other = Client::connect(&s.addr).unwrap();
    assert_eq!(other.count("t", all()).unwrap(), 1);
}

#[test]
fn f1_outcome_unobtainable_is_in_doubt_and_resolvable() {
    for committed in [true, false] {
        let Some(s) = Server::start(&[]) else { return };
        let px = proxy(&s.addr);
        let mut db = Client::connect(&px.addr).unwrap();
        db.create_table("t", kv_cols()).unwrap();
        db.insert("t", row(1, 100)).unwrap();
        let masks = db.mask_count();
        db.begin().unwrap();
        db.insert("t", row(2, 200)).unwrap();
        px.lose("tx_commit", true, true); // server commits, reply lost, proxy goes DOWN
        let e = db.commit().unwrap_err();
        assert_eq!(e.kind, Kind::TransactionInDoubt);
        let txid = e.txid.clone().unwrap();
        assert_eq!(txid.len(), 32);
        assert_eq!(db.in_doubt_transactions(), vec![txid.clone()]);
        assert_eq!(db.mask_count(), masks + 1); // NOT restored
        assert!(db.insert("t", row(3, 3)).unwrap_err().message.contains("in-doubt"));
        px.resume();
        db.reconnect().unwrap();
        if committed {
            assert!(db.resolve_transaction(&txid, None).unwrap());
            assert_eq!(db.sum("t", "v", all()).unwrap(), int(300));
        } else {
            assert!(!db.resolve_transaction(&txid, Some(false)).unwrap());
            assert_eq!(db.mask_count(), masks);
        }
        assert!(db.in_doubt_transactions().is_empty());
    }
}

#[test]
fn f1_busy_timed_out_drops_the_local_tx_at_once() {
    let f = fake(base(|m, _a, n| match m {
        "insert" if n > 1 => Some(Reply::Json(json!({"err": "Busy: transaction timed out and was rolled back; issue ROLLBACK"}))),
        "insert" => Some(Reply::Json(json!({"ok": 0}))),
        _ => None,
    }));
    let mut db = Client::connect(&f.addr).unwrap();
    db.create_table("t", kv_cols()).unwrap();
    db.insert("t", row(1, 1)).unwrap();
    let masks = db.mask_count();
    db.begin().unwrap();
    let begin = f.bodies().into_iter().find(|b| b.contains("\"tx_begin\"")).unwrap();
    let id = serde_json::from_str::<Value>(&begin).unwrap()["a"][0].as_str().unwrap().len();
    assert_eq!(id, 32);
    assert_eq!(db.insert("t", row(2, 2)).unwrap_err().kind, Kind::Busy);
    assert!(!db.in_transaction());
    assert_eq!(db.mask_count(), masks);
    assert_eq!(f.seen().last().unwrap(), "tx_rollback");
}

// ── F2: untrusted schema ─────────────────────────────────────────────────────
#[test]
fn f2_relabelled_columns_never_receive_plaintext() {
    let f = fake(base(|m, _, _| match m {
        "tables" => Some(Reply::Json(json!({"ok": ["t"]}))),
        "schema" => Some(Reply::Json(json!({"ok": [["k", "int", "plain"], ["v", "int", "plain"]]}))), // the lie
        _ => None,
    }));
    let mut db = Client::connect(&f.addr).unwrap();
    assert_eq!(db.insert("t", row(1, 424242)).unwrap_err().kind, Kind::UntrustedSchema);
    assert_eq!(db.insert_many("t", vec![row(1, 424242)]).unwrap_err().kind, Kind::UntrustedSchema);
    assert_eq!(db.update("t", vec![("v", ci(424242))], all()).unwrap_err().kind, Kind::UntrustedSchema);
    assert!(!f.saw("insert") && !f.saw("insert_many") && !f.saw("update_cell"));
    assert!(f.bodies().iter().all(|b| !b.contains("424242")));
}

#[test]
fn f2_vault_policies_are_the_trust_anchor() {
    let dir = tmpdir("f2");
    let vf = dir.join("v.json");
    {
        let f1 = fake(base(|_, _, _| None));
        let mut a = Client::connect(&f1.addr).unwrap();
        a.create_table("t", kv_cols()).unwrap(); // v is ENCRYPTED locally
        a.save_vault(Some(&vf)).unwrap();
    }
    let f2 = fake(base(|m, _, _| match m {
        "tables" => Some(Reply::Json(json!({"ok": ["t"]}))),
        "schema" => Some(Reply::Json(json!({"ok": [["k", "int", "plain"], ["v", "int", "plain"]]}))),
        "insert" => Some(Reply::Json(json!({"ok": 0}))),
        _ => None,
    }));
    let mut b = Client::connect_with(&f2.addr, &ConnectOptions { vault_path: Some(vf), ..Default::default() }).unwrap();
    b.insert("t", row(1, 424242)).unwrap();
    let body = f2.bodies().into_iter().find(|b| b.contains("\"insert\"")).unwrap();
    let sent: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sent["a"][1]["k"]["v"], "1");
    assert_ne!(sent["a"][1]["v"]["v"], "424242"); // blinded, not plaintext
}

#[test]
fn f2_unknown_policy_is_encrypted_and_trust_flag_opts_in() {
    let f = fake(base(|m, _, _| match m {
        "tables" => Some(Reply::Json(json!({"ok": ["t"]}))),
        "schema" => Some(Reply::Json(json!({"ok": [["k", "int", "plain"], ["v", "int", "super-secret"]]}))),
        "insert" => Some(Reply::Json(json!({"ok": 0}))),
        _ => None,
    }));
    let mut db = Client::connect_with(&f.addr, &trusting()).unwrap();
    db.insert("t", row(1, 424242)).unwrap();
    let body = f.bodies().into_iter().find(|b| b.contains("\"insert\"")).unwrap();
    assert!(!body.contains("\"424242\""));
}

#[test]
fn f2_plain_reads_allowed_trust_table_lifts_write_block() {
    let Some(s) = Server::start(&[]) else { return };
    let mut w = Client::connect(&s.addr).unwrap();
    w.create_table("t", kv_cols()).unwrap();
    w.insert("t", row(5, 1)).unwrap();
    let mut r = Client::connect(&s.addr).unwrap();
    assert_eq!(r.count("t", all()).unwrap(), 1);
    assert_eq!(r.select("t", &["k"], all()).unwrap(), vec![vec![ci(5)]]);
    assert_eq!(r.insert("t", row(6, 2)).unwrap_err().kind, Kind::UntrustedSchema);
    r.trust_table("t").unwrap();
    r.insert("t", row(6, 2)).unwrap();
}

// ── F4: total deadlines ──────────────────────────────────────────────────────
#[test]
fn f4_drip_fed_reply_hits_a_total_deadline() {
    let f = fake(base(|m, _, _| if m == "stats" { Some(Reply::Drip(100, 100)) } else { None }));
    let o = ConnectOptions { timeout: Some(Duration::from_millis(500)), ..Default::default() };
    let mut db = Client::connect_with(&f.addr, &o).unwrap();
    let t0 = Instant::now();
    assert_eq!(db.stats().unwrap_err().kind, Kind::Timeout);
    assert!(t0.elapsed() < Duration::from_millis(2000), "took {:?}", t0.elapsed());
    assert!(db.is_closed());
}

#[cfg(feature = "tls")]
#[test]
fn f4_tls_handshake_has_a_deadline() {
    // a TCP listener that accepts and never speaks TLS
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let _keep: Vec<_> = l.incoming().take(1).collect();
        std::thread::sleep(Duration::from_secs(10));
    });
    let o = ConnectOptions { tls: true, timeout: Some(Duration::from_millis(500)), ..Default::default() };
    let t0 = Instant::now();
    let e = Client::connect_with(&addr, &o).err().unwrap();
    assert_eq!(e.kind, Kind::Timeout);
    assert!(t0.elapsed() < Duration::from_secs(3));
}

// ── F5: caps ─────────────────────────────────────────────────────────────────
#[test]
fn f5_lying_header_and_hello_max_frame() {
    let f = fake(base(|m, _, _| if m == "stats" { Some(Reply::Hdr(0xffff_ffff)) } else { None }));
    let mut db = Client::connect(&f.addr).unwrap();
    let t0 = Instant::now();
    assert_eq!(db.stats().unwrap_err().kind, Kind::Protocol);
    assert!(t0.elapsed() < Duration::from_secs(2));
    let g = fake(base(|m, _, _| match m {
        "hello" => Some(Reply::Json(json!({"ok": {"protocol": 2, "auth_required": false, "max_frame": 4096}}))),
        "stats" => Some(Reply::Hdr(5000)),
        _ => None,
    }));
    let mut d2 = Client::connect(&g.addr).unwrap();
    assert_eq!(d2.stats().unwrap_err().kind, Kind::Protocol);
}

#[test]
fn f5_digit_cap_and_array_lengths() {
    // digit string inside the frame cap but over the 90-digit cap
    let f = fake(base(|m, _, _| match m {
        "matching_rowids" => Some(Reply::Json(json!({"ok": [0]}))),
        "blinded_sum" => Some(Reply::Json(json!({"ok": "9".repeat(95)}))),
        other => kv_schema(other),
    }));
    let mut db = Client::connect_with(&f.addr, &trusting()).unwrap();
    assert_eq!(db.sum("t", "v", all()).unwrap_err().kind, Kind::Protocol);
    // wrong-length arrays
    let g = fake(base(|m, _, _| match m {
        "matching_rowids" => Some(Reply::Json(json!({"ok": [0, 1]}))),
        "blinded_cells" => Some(Reply::Json(json!({"ok": [{"t": "i", "v": "1"}]}))),
        other => kv_schema(other),
    }));
    let mut d2 = Client::connect_with(&g.addr, &trusting()).unwrap();
    assert_eq!(d2.select("t", &["v"], all()).unwrap_err().kind, Kind::Protocol);
    // a tiny-element flood is refused by the per-call reply cap before parsing
    let h = fake(base(|m, _, _| match m {
        "matching_rowids" => Some(Reply::Json(json!({"ok": [0, 1]}))),
        "blinded_cells" => Some(Reply::Raw(format!("{{\"ok\":[{}]}}", "0,".repeat(2_000_000) + "0").into_bytes())),
        other => kv_schema(other),
    }));
    let mut d3 = Client::connect_with(&h.addr, &trusting()).unwrap();
    assert_eq!(d3.select("t", &["v"], all()).unwrap_err().kind, Kind::Protocol);
}

#[test]
fn f5_extra_frame_is_unsolicited_data() {
    let f = fake(base(|m, _, _| {
        if m == "ping" { Some(Reply::Frames(vec![json!({"ok": "pong"}), json!({"ok": "pong"})])) } else { None }
    }));
    let mut db = Client::connect(&f.addr).unwrap();
    let e = db.ping();
    // the first reply may be delivered before the second lands; either way the NEXT call must not
    // be answered with a stale frame
    let _ = e;
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(db.ping().unwrap_err().kind, Kind::Protocol);
}

// ── F8: MAC mode ─────────────────────────────────────────────────────────────
#[test]
fn f8_mac_mode_catches_a_lying_server() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect_with(&s.addr, &ConnectOptions { authenticated: true, ..Default::default() }).unwrap();
    db.create_table("t", vec![col("k", "int", "plain"), col("a", "int", "paired"), col("b", "int", "paired")]).unwrap();
    db.insert_many(
        "t",
        vec![vec![("k", ci(1)), ("a", ci(3)), ("b", ci(10))], vec![("k", ci(2)), ("a", ci(4)), ("b", ci(100))]],
    )
    .unwrap();
    assert_eq!(db.sum("t", "a", all()).unwrap(), int(7));
    assert_eq!(db.dot("t", "a", "b", all()).unwrap(), int(430));
    assert_eq!(db.select("t", &["a"], all()).unwrap(), vec![vec![ci(3)], vec![ci(4)]]);
    db.update("t", vec![("a", ci(5))], eq_int("k", 1)).unwrap();
    assert_eq!(db.sum("t", "a", all()).unwrap(), int(9));
    let forged = json!({"t": "i", "v": "123456789"});
    assert!(raw_rpc(&s.addr, "update_cell", json!(["t", 0, "a", forged]))["ok"].is_null());
    assert_eq!(db.sum("t", "a", all()).unwrap_err().kind, Kind::Integrity);
    assert_eq!(db.select("t", &["a"], all()).unwrap_err().kind, Kind::Integrity);
    assert_eq!(db.dot("t", "a", "b", all()).unwrap_err().kind, Kind::Integrity);
    db.create_table("u", vec![col("a", "int", "paired")]).unwrap();
    db.insert("u", vec![("a", ci(9))]).unwrap();
    assert_eq!(db.sum("u", "a", all()).unwrap(), int(9));
    raw_rpc(&s.addr, "update_cell", json!(["u", 0, "__mac__a", forged]));
    assert_eq!(db.sum("u", "a", all()).unwrap_err().kind, Kind::Integrity);
}

#[test]
fn f8_mac_key_survives_the_vault() {
    let Some(s) = Server::start(&[]) else { return };
    let vf = tmpdir("f8").join("v.json");
    let auth = ConnectOptions { authenticated: true, ..Default::default() };
    let mut a = Client::connect_with(&s.addr, &auth).unwrap();
    a.create_table("t", vec![col("a", "int", "encrypted")]).unwrap();
    a.insert("t", vec![("a", ci(7))]).unwrap();
    a.save_vault(Some(&vf)).unwrap();
    let mut b = Client::connect_with(&s.addr, &ConnectOptions { vault_path: Some(vf.clone()), ..auth.clone() }).unwrap();
    assert_eq!(b.sum("t", "a", all()).unwrap(), int(7));
    let e = Client::connect_with(&s.addr, &ConnectOptions { vault_path: Some(vf), ..Default::default() }).err().unwrap();
    assert!(e.message.contains("authenticated"));
}

// ── F10: secrets are redacted ────────────────────────────────────────────────
#[test]
fn f10_debug_never_shows_secrets() {
    let o = ConnectOptions { token: Some("super-secret-token-0123456789".into()), ca_pem: Some(vec![1, 2, 3]), ..Default::default() };
    let d = format!("{:?} {:#?}", o, o);
    assert!(!d.contains("super-secret"));
    assert!(d.contains("redacted"));
    let f = fake(base(|_, _, _| None));
    let mut db = Client::connect_with(&f.addr, &ConnectOptions { token: Some("super-secret-token-0123456789".into()), ..Default::default() }).unwrap();
    db.create_table("t", kv_cols()).unwrap();
    db.insert("t", row(1, 1)).unwrap_or(0);
    let d = format!("{:?}", db);
    assert!(!d.contains("super-secret"));
    assert!(d.contains("redacted"));
}

// ── F11 ──────────────────────────────────────────────────────────────────────
#[test]
fn f11_find_orphans_ignores_hostile_rows_count() {
    let f = fake(base(|m, _, _| match m {
        "table_info" => Some(Reply::Json(json!({"ok": {"rows": 1e18, "deleted": []}}))),
        "matching_rowids" => Some(Reply::Json(json!({"ok": [0, 1]}))),
        other => kv_schema(other),
    }));
    let mut db = Client::connect(&f.addr).unwrap();
    let t0 = Instant::now();
    let o = db.find_orphans().unwrap();
    assert_eq!(o["t"], vec![0, 1]);
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert!(!f.saw("table_info"));
}

// ── F13: no silent filtering ─────────────────────────────────────────────────
#[test]
fn f13_malformed_items_are_protocol_errors() {
    let bad_ids = [json!(["a"]), json!([1, "x"]), json!([-1]), json!([1.5]), json!(null), json!({})];
    for bad in bad_ids {
        let b2 = bad.clone();
        let f = fake(base(move |m, _, _| match m {
            "matching_rowids" => Some(Reply::Json(json!({"ok": b2}))),
            other => kv_schema(other),
        }));
        let mut db = Client::connect(&f.addr).unwrap();
        assert_eq!(db.count("t", all()).unwrap_err().kind, Kind::Protocol, "{}", bad);
    }
    for (m, v) in [
        ("tables", json!([1])),
        ("tables", json!("x")),
        ("table_info", json!({"rows": "x", "deleted": []})),
        ("table_info", json!({"rows": 1, "deleted": ["a"]})),
        ("checkpoint", json!("x")),
        ("backup", json!(5)),
        ("stats", json!([])),
    ] {
        let (mm, vv) = (m.to_string(), v.clone());
        let f = fake(base(move |x, _, _| if x == mm { Some(Reply::Json(json!({"ok": vv}))) } else { None }));
        let o = ConnectOptions { sync_schema: m != "tables", ..Default::default() };
        let r = Client::connect_with(&f.addr, &o).and_then(|mut db| match m {
            "tables" => db.tables().map(|_| ()),
            "table_info" => db.table_info("t").map(|_| ()),
            "checkpoint" => db.checkpoint().map(|_| ()),
            "backup" => db.backup().map(|_| ()),
            _ => db.stats().map(|_| ()),
        });
        assert_eq!(r.unwrap_err().kind, Kind::Protocol, "{} {}", m, v);
    }
    for h in [json!({"protocol": "2", "auth_required": false}), json!({"protocol": -1, "auth_required": false}),
              json!({"protocol": 1.5, "auth_required": false}), json!({"protocol": 2, "auth_required": "no"}), json!([])] {
        let h2 = h.clone();
        let f = fake(base(move |m, _, _| if m == "hello" { Some(Reply::Json(json!({"ok": h2}))) } else { None }));
        assert_eq!(Client::connect(&f.addr).err().unwrap().kind, Kind::Protocol, "{}", h);
    }
    // predicates reject invalid fractions instead of altering them
    assert_eq!(cmp("k", "=", &CellIn::Rational(1.into(), 0.into())).unwrap_err().kind, Kind::Interface);
    assert!(is_in("k", &[CellIn::Rational(1.into(), 0.into())]).is_err());
    assert!(cmp("k", "LIKE", &ci(1)).is_err());
}

// ── F14 ──────────────────────────────────────────────────────────────────────
#[test]
fn f14_vault_validation_and_directories() {
    let f = fake(base(|_, _, _| None));
    let mut db = Client::connect(&f.addr).unwrap();
    let d = tmpdir("f14");
    let p = d.join("v.json");
    let cases = [
        json!({"version": 2, "masks": [["t", -1, "v", "5"]]}),
        json!({"version": 2, "masks": [["t", 1.5, "v", "5"]]}),
        json!({"version": 2, "masks": [["t", 1, "v", "0x10"]]}),
        json!({"version": 2, "masks": [["t", 1, "v", "-5"]]}),
        json!({"version": 2, "masks": [["t", 1, "v", n().to_string()]]}),
        json!({"version": 2, "masks": [["t", 1, "v", "9".repeat(5000)]]}),
        json!({"version": 2, "masks": [], "schema": {"t": [["a", "int"]]}}),
        json!({"version": 9, "masks": []}),
    ];
    for c in cases {
        std::fs::write(&p, c.to_string()).unwrap();
        assert_eq!(db.load_vault(Some(&p)).unwrap_err().kind, Kind::Interface, "{}", c);
    }
    std::fs::write(&p, "{garbage").unwrap();
    assert_eq!(db.load_vault(Some(&p)).unwrap_err().kind, Kind::Interface);
    assert_eq!(db.mask_count(), 0);
    let nested = d.join("a").join("b").join("vault.json");
    db.save_vault(Some(&nested)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn f14_undo_journal_restores_a_large_vault() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    db.create_table("t", kv_cols()).unwrap();
    db.insert_many("t", (0..2000).map(|i| row(i, i)).collect()).unwrap();
    let before = db.sum("t", "v", all()).unwrap();
    db.begin().unwrap();
    db.update("t", vec![("v", ci(1))], eq_int("k", 7)).unwrap();
    db.rollback().unwrap();
    assert_eq!(db.sum("t", "v", all()).unwrap(), before);
}

// ── F16 ──────────────────────────────────────────────────────────────────────
#[test]
fn f16_option_validation() {
    let tok = Some("x".repeat(20));
    let e = Client::connect_with("192.0.2.1:1", &ConnectOptions { token: tok.clone(), ..Default::default() }).err().unwrap();
    assert!(e.message.contains("unencrypted"));
    for o in [
        ConnectOptions { ca_pem: Some(vec![1]), ..Default::default() },
        ConnectOptions { tls_insecure: true, ..Default::default() },
        ConnectOptions { timeout: Some(Duration::ZERO), ..Default::default() },
    ] {
        assert_eq!(Client::connect_with("127.0.0.1:1", &o).err().unwrap().kind, Kind::Interface);
    }
    // loopback may carry a token in the clear
    let f = fake(base(|_, _, _| None));
    Client::connect_with(&f.addr, &ConnectOptions { token: tok, ..Default::default() }).unwrap();
}

#[test]
fn f16_requests_over_max_frame_are_refused_locally() {
    let f = fake(base(|m, _, _| match m {
        "hello" => Some(Reply::Json(json!({"ok": {"protocol": 2, "auth_required": false, "max_frame": 2048}}))),
        "insert_many" => Some(Reply::Json(json!({"ok": []}))),
        other => kv_schema(other),
    }));
    let mut db = Client::connect_with(&f.addr, &trusting()).unwrap();
    let rows: Vec<_> = (0..200).map(|i| row(i, i)).collect();
    assert_eq!(db.insert_many("t", rows).unwrap_err().kind, Kind::Interface);
    assert!(!f.saw("insert_many"));
    assert!(db.ping().unwrap()); // the connection survived
}

// ── F17 ──────────────────────────────────────────────────────────────────────
#[test]
fn f17_dot_rules_and_join_where_over_joined_tables() {
    let Some(s) = Server::start(&[]) else { return };
    let mut db = Client::connect(&s.addr).unwrap();
    db.create_table("t", vec![col("k", "int", "plain"), col("e", "int", "encrypted"), col("p", "int", "paired"), col("r", "rational", "paired")]).unwrap();
    db.insert("t", vec![("k", ci(1)), ("e", ci(1)), ("p", ci(2)), ("r", CellIn::Rational(1.into(), 2.into()))]).unwrap();
    assert_eq!(db.dot("t", "e", "p", all()).unwrap_err().kind, Kind::PlanError);
    assert_eq!(db.dot("t", "p", "r", all()).unwrap_err().kind, Kind::PlanError);
    assert_eq!(db.dot("t", "p", "p", all()).unwrap(), int(4));

    db.create_table("emp", vec![col("eid", "int", "plain"), col("did", "int", "plain"), col("sal", "int", "encrypted")]).unwrap();
    db.create_table("dept", vec![col("did", "int", "plain"), col("dname", "str", "plain")]).unwrap();
    let dn = |id, n: &str| vec![("did", ci(id)), ("dname", CellIn::Str(n.into()))];
    db.insert_many("dept", vec![dn(10, "Eng"), dn(20, "Sales")]).unwrap();
    let e = |eid, did, sal| vec![("eid", ci(eid)), ("did", ci(did)), ("sal", ci(sal))];
    db.insert_many("emp", vec![e(1, 10, 100), e(2, 10, 80), e(3, 20, 70), e(4, 99, 60)]).unwrap();
    let step = || JoinStep::new("dept", "did", "did").alias("d");
    let eng = || cmp_in("d", "dname", "=", &CellIn::Str("Eng".into())).unwrap();
    let o = |w: Value| JoinOptions { alias: Some("e".into()), where_: Some(w) };
    let j1 = db.join("emp", &[step()], &o(eng())).unwrap();
    assert_eq!(j1.count(), 2);
    assert_eq!(db.join_sum(&j1, "e", "sal").unwrap(), int(180));
    let w = or(&[cmp_in("d", "dname", "=", &CellIn::Str("Sales".into())).unwrap(), cmp_in("e", "eid", "=", &ci(1)).unwrap()]);
    assert_eq!(db.join("emp", &[step().left()], &o(w)).unwrap().count(), 2);
    assert_eq!(db.join("emp", &[step().left()], &o(eng())).unwrap().count(), 2); // NULL side never matches
    assert_eq!(db.count("emp", cmp_in("e", "eid", "=", &ci(1)).unwrap()).unwrap_err().kind, Kind::Interface);
    let bad = cmp_in("e", "sal", "=", &ci(1)).unwrap();
    assert_eq!(db.join("emp", &[step()], &o(bad)).unwrap_err().kind, Kind::Interface);
}
