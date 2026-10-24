// SPDX-License-Identifier: Apache-2.0
//! FHE columns (EC-FHE on BN254): known-answer vectors, rejection tests, key files, and end-to-end
//! flows against the REAL Python server (memory and disk storage), with the Python reference as a
//! cross-implementation peer and a lying-server proxy for the integrity checks.
use num_bigint::BigInt;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use torusdb::*;

mod common;
use common::*;

fn vec_json() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/fhe-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hex(s: &Value) -> Vec<u8> {
    fhe_internals::unhex(s.as_str().unwrap())
}
fn hexes(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(hex).collect()
}
fn i64s(v: &Value) -> Vec<i64> {
    v.as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect()
}
fn vec_key() -> FheKey {
    let v = vec_json();
    FheKey::from_hex(v["secret"].as_str().unwrap(), v["range"].as_u64().unwrap()).unwrap()
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn kind_of(r: Result<impl std::fmt::Debug, Error>) -> Kind {
    r.expect_err("expected an error").kind
}
fn int(d: Decoded) -> i64 {
    match d {
        Decoded::Int(i) => i64::try_from(i).unwrap(),
        other => panic!("not an integer: {:?}", other),
    }
}
fn one() -> BigInt {
    BigInt::from(1)
}

// ── known-answer tests (no server) ───────────────────────────────────────────
#[test]
fn vectors_every_cell_sum_scaled_sum_and_dot_blob_decrypts() {
    let v = vec_json();
    let key = vec_key();
    let a = hexes(&v["cells_a"]);
    let b = hexes(&v["cells_b"]);
    assert_eq!(a.iter().map(|c| key.decrypt_cell(c).unwrap()).collect::<Vec<_>>(), i64s(&v["values_a"]));
    assert_eq!(b.iter().map(|c| key.decrypt_cell(c).unwrap()).collect::<Vec<_>>(), i64s(&v["values_b"]));
    assert_eq!(key.decrypt_sum(&hex(&v["sum_blob"])).unwrap(), v["sum_expected"].as_i64().unwrap());
    assert_eq!(key.decrypt_sum(&hex(&v["scaled3_sum_blob"])).unwrap(), v["scaled3_expected"].as_i64().unwrap());
    let dot = v["dot_expected"].as_i64().unwrap();
    let (dp, dm) = (hex(&v["dot_blob_pyecc"]), hex(&v["dot_blob_mcl"]));
    assert_eq!((dp[0], dm[0]), (1, 2));
    assert_eq!(key.decrypt_dot(&dp).unwrap(), dot); // tag 0x01, g_pyecc
    assert_eq!(key.decrypt_dot(&dm).unwrap(), dot); // tag 0x02, g_mcl
    // our own sums of the vector cells
    assert_eq!(key.decrypt_sum(&fhe_sum_cells(&a, &one()).unwrap()).unwrap(), 105);
    assert_eq!(key.decrypt_sum(&fhe_sum_cells(&a, &BigInt::from(3)).unwrap()).unwrap(), 315);
    assert_eq!(key.decrypt_sum(&fhe_sum_cells(&a, &BigInt::from(-2)).unwrap()).unwrap(), -210);
    let (l, r) = (fhe_sum_cells(&a[..2], &one()).unwrap(), fhe_sum_cells(&a[2..], &one()).unwrap());
    assert_eq!(key.decrypt_sum(&fhe_add_sums(&l, &r).unwrap()).unwrap(), 105);
    // partial DOT blobs combine by component-wise GT multiplication
    assert_eq!(key.decrypt_dot(&fhe_mul_dots(&dp, &dp).unwrap()).unwrap(), 2 * dot);
    assert_eq!(key.decrypt_dot(&fhe_mul_dots(&dm, &dm).unwrap()).unwrap(), 2 * dot);
    assert_eq!(kind_of(fhe_mul_dots(&dp, &dm)), Kind::Protocol);
}

#[test]
fn vectors_s2_derivation_q_g1_and_q2_g2() {
    let v = vec_json();
    let key = vec_key();
    assert_eq!(fhe_internals::hex(&key.s2_bytes()), v["s2"].as_str().unwrap());
    let (q1, q2) = key.public_key().unwrap();
    assert_eq!(fhe_internals::hex(&q1), v["q_g1"].as_str().unwrap());
    assert_eq!(fhe_internals::hex(&q2), v["q2_g2"].as_str().unwrap());
    assert_ne!(v["s2"], v["secret"]);
}

#[test]
fn vectors_gt_generators_are_the_published_constants_and_have_order_n() {
    let v = vec_json();
    let g = &v["gt_generators"];
    assert_eq!(fhe_internals::hex(&fhe_internals::gt_generator_bytes(1)), g["pyecc_tag01"].as_str().unwrap());
    assert_eq!(fhe_internals::hex(&fhe_internals::gt_generator_bytes(2)), g["mcl_tag02"].as_str().unwrap());
    assert!(fhe_internals::gt_generator_has_order_n(1));
    assert!(fhe_internals::gt_generator_has_order_n(2));
    assert!(fhe_internals::curves_ok());
}

#[test]
fn vectors_mac_alpha_gamma_tag_cells_and_tag_sum_blob() {
    let v = vec_json();
    let key = vec_key();
    let m = &v["mac"];
    let (table, col) = (m["table"].as_str().unwrap(), m["column"].as_str().unwrap());
    let ids = i64s(&m["row_ids"]);
    assert_eq!(format!("0x{:x}", key.alpha()), m["alpha"].as_str().unwrap());
    let gam: Vec<String> = ids.iter().map(|i| format!("0x{:x}", key.gamma(table, col, *i))).collect();
    let want: Vec<String> = m["gamma"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    assert_eq!(gam, want);
    let (vb, tb) = (hex(&v["sum_blob"]), hex(&m["tag_sum_blob"]));
    assert_eq!(key.decrypt_sum_verified(&vb, &tb, table, col, &ids, &one()).unwrap(), 105);
    let (cells, tags) = (hexes(&v["cells_a"]), hexes(&m["tag_cells"]));
    let vals = i64s(&v["values_a"]);
    for k in 0..4 {
        assert_eq!(
            key.decrypt_cell_verified(Some(&cells[k]), Some(&tags[k]), table, col, ids[k]).unwrap(),
            vals[k]
        );
    }
    // our own tag verifies; every tampering is an Integrity error
    let t = key.tag(7, "emp", "rate", 2).unwrap();
    assert_eq!(key.decrypt_cell_verified(Some(&key.encrypt(7).unwrap()), Some(&t), "emp", "rate", 2).unwrap(), 7);
    let bad = |r: Result<i64, Error>| assert_eq!(r.unwrap_err().kind, Kind::Integrity);
    bad(key.decrypt_sum_verified(&vb, &tb, table, col, &[0, 1, 2], &one()));
    bad(key.decrypt_sum_verified(&vb, &tb, table, col, &ids, &BigInt::from(2)));
    bad(key.decrypt_sum_verified(&hex(&v["scaled3_sum_blob"]), &tb, table, col, &ids, &one()));
    bad(key.decrypt_sum_verified(&vb, &tb, table, "other", &ids, &one()));
    bad(key.decrypt_cell_verified(Some(&cells[0]), Some(&tags[1]), table, col, 0));
    bad(key.decrypt_cell_verified(Some(&cells[0]), Some(&tags[0]), table, col, 1));
    bad(key.decrypt_cell_verified(Some(&cells[0]), None, table, col, 0));
    bad(key.decrypt_cell_verified(Some(&key.encrypt(41).unwrap()), Some(&tags[0]), table, col, 0));
}

// ── scheme properties and rejections (no server) ─────────────────────────────
#[test]
fn encrypt_decrypt_edge_values_range_and_fresh_randomness() {
    let key = FheKey::generate(5000).unwrap();
    for v in [0i64, 1, -1, 4999, -4999, 5000, -5000] {
        assert_eq!(key.decrypt_cell(&key.encrypt(v).unwrap()).unwrap(), v);
    }
    assert_eq!(kind_of(key.encrypt(5001)), Kind::OutOfBudget);
    assert_eq!(kind_of(key.encrypt(-5001)), Kind::OutOfBudget);
    assert_eq!(kind_of(key.encrypt(i64::MIN)), Kind::OutOfBudget);
    let (a, b) = (key.encrypt(5).unwrap(), key.encrypt(5).unwrap());
    assert_eq!(a.len(), FHE_CELL_BYTES);
    assert_ne!(a, b); // randomised
    assert_ne!(a[..64], b[..64]);
    // a sum beyond the range raises instead of wrapping
    let small = FheKey::generate(100).unwrap();
    let blob = fhe_sum_cells(&[small.encrypt(90).unwrap(), small.encrypt(90).unwrap()], &one()).unwrap();
    assert_eq!(kind_of(small.decrypt_sum(&blob)), Kind::OutOfBudget);
    let none: Vec<Vec<u8>> = vec![];
    assert_eq!(small.decrypt_sum(&fhe_sum_cells(&none, &one()).unwrap()).unwrap(), 0);
    // a tag is an arbitrary scalar: decrypting it as a value fails; the SUM blob of a cell is its first 128 bytes
    let tag = small.tag(5, "t", "c", 1).unwrap();
    assert_eq!(kind_of(small.decrypt_cell(&tag)), Kind::OutOfBudget);
    let c = small.encrypt(9).unwrap();
    assert_eq!(fhe_sum_cells(std::slice::from_ref(&c), &one()).unwrap(), c[..128].to_vec());
    assert_eq!(fhe_cell_to_sum(&c).unwrap(), c[..128].to_vec());
}

#[test]
fn rejections_malformed_cells_points_blobs_and_keys() {
    let key = FheKey::generate(1000).unwrap();
    let c = key.encrypt(3).unwrap();
    let p = Kind::Protocol;
    assert_eq!(kind_of(key.decrypt_cell(&c[..383])), p);
    assert_eq!(kind_of(key.decrypt_cell(&[c.clone(), vec![0]].concat())), p);
    assert_eq!(kind_of(key.decrypt_cell(&[])), p);
    let mut off = c.clone();
    off[70] ^= 0x55; // C2 no longer on the curve
    assert_eq!(kind_of(key.decrypt_cell(&off)), p);
    let mut big = c.clone();
    big[..32].fill(0xff); // x >= p
    assert_eq!(kind_of(key.decrypt_cell(&big)), p);
    assert_eq!(kind_of(fhe_sum_cells(&[&c[..100]], &one())), p);
    assert_eq!(kind_of(key.decrypt_sum(&[0u8; 127])), p);
    assert_eq!(kind_of(fhe_add_sums(&[0u8; 128], &[0u8; 5])), p);
    // DOT blobs
    let v = vec_json();
    let dot = hex(&v["dot_blob_pyecc"]);
    let k2 = vec_key();
    assert_eq!(kind_of(k2.decrypt_dot(&dot[..1536])), p);
    let mut t3 = dot.clone();
    t3[0] = 3;
    assert_eq!(kind_of(k2.decrypt_dot(&t3)), p);
    let mut hi = dot.clone();
    hi[1..33].fill(0xff); // coefficient >= p
    assert_eq!(kind_of(k2.decrypt_dot(&hi)), p);
    // wrong back-end tag for the data: garbage, never a wrong number
    let mut swapped = dot.clone();
    swapped[0] = 2;
    assert_eq!(kind_of(k2.decrypt_dot(&swapped)), Kind::OutOfBudget);
    // a hostile server answer that is not in the target group (small-subgroup oracle on the secret)
    let mut hostile = dot.clone();
    hostile[385..769].fill(0);
    hostile[385 + 31] = 2; // c01 = 2: its order is not n
    assert_eq!(kind_of(k2.decrypt_dot(&hostile)), p);
    // keys
    let i = Kind::Interface;
    assert_eq!(kind_of(FheKey::from_secret_bytes(&[1u8; 31], 1000)), i);
    assert_eq!(kind_of(FheKey::from_secret_bytes(&[0u8; 32], 1000)), i); // s = 0
    assert_eq!(kind_of(FheKey::from_secret_bytes(&[0xffu8; 32], 1000)), i); // s >= n
    assert_eq!(kind_of(FheKey::from_hex("zz", 1000)), i);
    assert_eq!(kind_of(FheKey::generate(0)), i);
    assert_eq!(kind_of(FheKey::generate(FHE_MAX_RANGE + 1)), i);
}

#[test]
fn the_secret_never_shows_in_debug_output() {
    let v = vec_json();
    let secret = v["secret"].as_str().unwrap();
    let key = FheKey::from_hex(secret, 1000).unwrap();
    let opts = ConnectOptions { fhe_key: Some(key.clone()), ..Default::default() };
    for s in [format!("{:?}", key), format!("{:#?}", key), format!("{:?}", opts)] {
        assert!(!s.contains(secret), "{}", s);
        assert!(s.contains("redacted"));
    }
}

#[test]
fn key_files_plain_and_sealed_round_trip_wrong_passphrase_damaged_and_foreign() {
    let dir = tmpdir("fhekey");
    let key = FheKey::generate(12345).unwrap();
    let (sealed, plain) = (dir.join("sealed.key"), dir.join("plain.key"));
    key.save(&sealed, Some("correct horse")).unwrap();
    key.save(&plain, None).unwrap();
    let raw = std::fs::read_to_string(&sealed).unwrap();
    assert!(raw.starts_with("TORUSFHEKEY1 sealed "));
    assert!(!raw.contains(&fhe_internals::hex(&key.secret_bytes())));
    assert!(std::fs::read_to_string(&plain).unwrap().starts_with("TORUSFHEKEY1 plain\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777, 0o600);
    }
    for (f, pw) in [(&sealed, Some("correct horse")), (&plain, None)] {
        let k = FheKey::load(f, pw).unwrap();
        assert_eq!(k.range(), 12345);
        assert_eq!(k.secret_bytes(), key.secret_bytes());
        assert_eq!(k.decrypt_cell(&key.encrypt(77).unwrap()).unwrap(), 77);
    }
    assert_eq!(kind_of(FheKey::load(&sealed, Some("wrong"))), Kind::Interface);
    assert!(FheKey::load(&sealed, None).unwrap_err().message.contains("passphrase is required"));
    let mut dmg = std::fs::read(&sealed).unwrap();
    let last = dmg.len() - 5;
    dmg[last] = if dmg[last] == b'0' { b'1' } else { b'0' };
    std::fs::write(dir.join("dmg.key"), dmg).unwrap();
    assert_eq!(kind_of(FheKey::load(&dir.join("dmg.key"), Some("correct horse"))), Kind::Interface);
    std::fs::write(dir.join("foreign"), "hello").unwrap();
    assert!(FheKey::load(&dir.join("foreign"), None).unwrap_err().message.contains("not an FHE key file"));
    assert_eq!(kind_of(FheKey::load(&dir.join("missing"), None)), Kind::Interface);
}

#[test]
fn performance_probe_encrypt_100_cells_decrypt_and_dlog_tables() {
    let key = FheKey::generate(1_000_000).unwrap();
    let t = Instant::now();
    key.encrypt(1).unwrap(); // builds the fixed-base tables
    let first = t.elapsed();
    let t = Instant::now();
    let cells: Vec<Vec<u8>> = (0..100).map(|i| key.encrypt(i * 7 - 300).unwrap()).collect();
    let enc = t.elapsed();
    let t = Instant::now();
    let vals: Vec<i64> = cells.iter().map(|c| key.decrypt_cell(c).unwrap()).collect();
    let dec = t.elapsed();
    assert_eq!(vals[..3], [-300, -293, -286]);
    let t = Instant::now();
    let v = vec_json();
    let k2 = FheKey::from_hex(v["secret"].as_str().unwrap(), 1_000_000).unwrap();
    k2.decrypt_dot(&hex(&v["dot_blob_pyecc"])).unwrap(); // builds the GT table (range 1e6)
    let gt = t.elapsed();
    let t = Instant::now();
    k2.decrypt_dot(&hex(&v["dot_blob_mcl"])).unwrap();
    let gt2 = t.elapsed();
    eprintln!(
        "# perf: first encrypt (tables) {:?}, 100 encrypts {:?}, 100 decrypts {:?}, first DOT decrypt (GT table) {:?}, next {:?}",
        first, enc, dec, gt, gt2
    );
    assert!(enc < Duration::from_secs(60));
}

// ── end to end against the real server ───────────────────────────────────────
const ROWS: [[i64; 4]; 4] = [[1, 5, 40, 160], [2, 5, 55, 150], [3, 7, 30, 120], [4, 5, 20, 100]];
const DOT_ALL: i64 = 40 * 160 + 55 * 150 + 30 * 120 + 20 * 100; // 20250
const DOT_D5: i64 = 40 * 160 + 55 * 150 + 20 * 100; // 16650

fn secret() -> String {
    vec_json()["secret"].as_str().unwrap().to_string()
}
fn emp_fhe_cols() -> Vec<Column> {
    vec![col("id", "int", "plain"), col("dept", "int", "plain"), col("rate", "int", "fhe"), col("hours", "int", "fhe")]
}
fn row(id: i64, dept: i64, rate: i64, hours: i64) -> Vec<(&'static str, CellIn)> {
    vec![("id", ci(id)), ("dept", ci(dept)), ("rate", ci(rate)), ("hours", ci(hours))]
}
fn opts(key: &FheKey, auth: bool, unverified: bool) -> ConnectOptions {
    ConnectOptions {
        fhe_key: Some(key.clone()),
        authenticated: auth,
        fhe_allow_unverified_dot: unverified,
        timeout: Some(Duration::from_secs(240)),
        ..Default::default()
    }
}
fn connect_to(addr: &str, key: &FheKey, auth: bool) -> Client {
    Client::connect_with(addr, &opts(key, auth, false)).unwrap()
}
fn key100k() -> FheKey {
    FheKey::from_hex(&secret(), 100_000).unwrap()
}
fn seed(db: &mut Client, t: &str, rows: &[[i64; 4]]) -> Vec<i64> {
    db.create_table(t, emp_fhe_cols()).unwrap();
    rows.iter().map(|r| db.insert(t, row(r[0], r[1], r[2], r[3])).unwrap()).collect()
}
fn dept(d: i64) -> Value {
    eq("dept", &ci(d)).unwrap()
}
fn id_is(i: i64) -> Value {
    eq("id", &ci(i)).unwrap()
}

fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).ok()?;
    let mut b = vec![0u8; u32::from_be_bytes(h) as usize];
    s.read_exact(&mut b).ok()?;
    Some(b)
}
fn write_frame(s: &mut TcpStream, b: &[u8]) -> bool {
    s.write_all(&(b.len() as u32).to_be_bytes()).is_ok() && s.write_all(b).is_ok()
}
/// One raw RPC on its own connection (what a hostile or buggy client could do).
fn raw_call(addr: &str, method: &str, args: Value) -> Value {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    write_frame(&mut s, json!({"m": method, "a": args}).to_string().as_bytes());
    serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap()
}
fn b64(b: &[u8]) -> String {
    // reuse the server's own encoder through the wire format: tiny local implementation
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}
fn xcell(b: &[u8]) -> Value {
    json!({"t": "x", "v": b64(b)})
}

/// A proxy in front of the server that rewrites `fhe_sum` requests (a lying server) or kills the
/// connection when an integrity tag is written. Modes: 0 none, 1 scale, 2 drop a row,
/// 3 duplicate a row, 4 wrong column, 5 kill on tag write.
struct Proxy {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    addr: String,
    mode: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
}
impl Proxy {
    fn start(upstream: String) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (mode, stop) = (Arc::new(AtomicU8::new(0)), Arc::new(AtomicBool::new(false)));
        let (m2, s2) = (mode.clone(), stop.clone());
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(vec![]));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                if s2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut cli) = conn else { continue };
                let (up, m3, seen3) = (upstream.clone(), m2.clone(), seen2.clone());
                std::thread::spawn(move || {
                    let mut srv = TcpStream::connect(up).unwrap();
                    while let Some(req) = read_frame(&mut cli) {
                        let mut r: Value = serde_json::from_slice(&req).unwrap();
                        let mode = m3.load(Ordering::SeqCst);
                        let method = r["m"].as_str().unwrap_or("").to_string();
                        seen3.lock().unwrap().push(method.clone());
                        let col = r["a"][1].as_str().unwrap_or("").to_string();
                        if method == "fhe_sum" && !col.starts_with("__fmac__") {
                            let ids = r["a"][2].as_array().cloned().unwrap_or_default();
                            match mode {
                                1 => {
                                    let args = r["a"].as_array_mut().unwrap();
                                    let k = args.get(3).and_then(|k| k.as_i64()).unwrap_or(1);
                                    args.truncate(3);
                                    args.push(json!(k * 2));
                                }
                                2 => r["a"][2] = json!(ids[..ids.len() - 1]),
                                3 => {
                                    let mut d = ids.clone();
                                    d.push(ids[0].clone());
                                    r["a"][2] = json!(d);
                                }
                                4 => r["a"][1] = json!("hours"),
                                _ => {}
                            }
                        }
                        let tag_write = (method == "update_cell" && r["a"][2].as_str().unwrap_or("").starts_with("__fmac__"))
                            || (method == "update_cells"
                                && r["a"][1].as_array().is_some_and(|v| v.iter().any(|it| it[1].as_str().unwrap_or("").starts_with("__fmac__"))));
                        if mode == 5 && tag_write {
                            return; // drop both sockets: the tag write never arrives
                        }
                        if !write_frame(&mut srv, r.to_string().as_bytes()) {
                            return;
                        }
                        let Some(resp) = read_frame(&mut srv) else { return };
                        if !write_frame(&mut cli, &resp) {
                            return;
                        }
                    }
                });
            }
        });
        Proxy { seen, addr, mode, stop }
    }
    fn count(&self, m: &str) -> usize {
        self.seen.lock().unwrap().iter().filter(|x| *x == m).count()
    }
    fn set(&self, m: u8) {
        self.mode.store(m, Ordering::SeqCst);
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr); // wake the accept loop
    }
}

fn server(extra: &[&str]) -> Option<Server> {
    Server::start(extra)
}
fn native_server() -> Option<Server> {
    let p = mcl_path()?;
    Server::start_env(&[], &[("PYTHONPATH", &p)])
}

#[test]
fn end_to_end_memory_and_disk_insert_select_sum_avg_scaled_dot_update_delete_rollback() {
    for storage in ["memory", "disk"] {
        let dir = tmpdir("fhe-e2e");
        let db_path = dir.join("db");
        let extra: Vec<&str> = if storage == "disk" {
            vec!["--db", db_path.to_str().unwrap(), "--storage", "disk"]
        } else {
            vec![]
        };
        let Some(s) = server(&extra) else { return };
        let key = key100k();
        let mut db = connect_to(&s.addr, &key, false);
        let t = "emp";
        let ids = seed(&mut db, t, &ROWS);
        assert_eq!(ids, vec![0, 1, 2, 3]);
        // the server stores opaque 384-byte ciphertexts
        let raw = raw_call(&s.addr, "plain_cells", json!([t, "rate", ids]));
        let cells = raw["ok"].as_array().unwrap();
        assert_eq!(cells.len(), 4);
        for w in cells {
            assert_eq!(w["t"], "x");
            assert_eq!(w["v"].as_str().unwrap().len(), 512); // 384 bytes in base64
        }
        let rows = db.select(t, &["id", "rate", "hours"], dept(5)).unwrap();
        assert_eq!(rows, vec![vec![ci(1), ci(40), ci(160)], vec![ci(2), ci(55), ci(150)], vec![ci(4), ci(20), ci(100)]]);
        let big = db.select(t, &["rate"], cmp("id", ">", &ci(2)).unwrap()).unwrap();
        assert_eq!(big, vec![vec![ci(30)], vec![ci(20)]]);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 145);
        assert_eq!(int(db.sum(t, "rate", dept(5)).unwrap()), 115);
        assert_eq!(int(db.sum(t, "rate", dept(99)).unwrap()), 0);
        assert_eq!(db.avg(t, "rate", dept(5)).unwrap(), Some(Decoded::Rational(115.into(), 3.into())));
        assert_eq!(db.avg(t, "rate", dept(99)).unwrap(), None);
        assert_eq!(db.avg(t, "hours", dept(7)).unwrap(), Some(Decoded::Int(120.into())));
        assert_eq!(db.count(t, dept(5)).unwrap(), 3);
        assert_eq!(int(db.scaled_sum(t, "rate", 3, all()).unwrap()), 435);
        assert_eq!(int(db.scaled_sum(t, "hours", -2, dept(5)).unwrap()), -820);
        assert_eq!(int(db.scaled_sum(t, "hours", 0, all()).unwrap()), 0);
        let py = Some(FheBackend::Pyecc);
        assert_eq!(int(db.dot_with_backend(t, "rate", "hours", all(), py).unwrap()), DOT_ALL);
        assert_eq!(int(db.dot_with_backend(t, "rate", "hours", dept(5), py).unwrap()), DOT_D5);
        assert_eq!(int(db.dot(t, "rate", "hours", dept(99)).unwrap()), 0);

        // update: a fresh ciphertext per row; delete; rollback restores
        assert_eq!(db.update(t, vec![("rate", ci(60))], id_is(1)).unwrap(), 1);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 165);
        assert_eq!(db.update(t, vec![("rate", ci(-7)), ("hours", ci(0))], dept(7)).unwrap(), 1);
        assert_eq!(db.select(t, &["rate", "hours"], id_is(3)).unwrap(), vec![vec![ci(-7), ci(0)]]);
        db.begin().unwrap();
        db.update(t, vec![("rate", ci(1))], all()).unwrap();
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 4);
        db.rollback().unwrap();
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 128);
        assert_eq!(db.delete_rows(t, id_is(4)).unwrap(), 1);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 108);
        let r: std::result::Result<(), Error> = db.transaction(|db| {
            db.insert(t, row(9, 1, 2, 3))?;
            Err(Error::new(Kind::Interface, "x"))
        });
        assert!(r.is_err());
        assert_eq!(db.count(t, all()).unwrap(), 3);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 108);

        // insert_many + a second client holding only the key (no vault, no masks) reads everything
        let t2 = "many";
        db.create_table(t2, emp_fhe_cols()).unwrap();
        let rows: Vec<Vec<(&str, CellIn)>> = (0..30).map(|i| row(i, i % 3, i, -i)).collect();
        assert_eq!(db.insert_many(t2, rows).unwrap().len(), 30);
        let mut other = connect_to(&s.addr, &FheKey::from_hex(&secret(), 100_000).unwrap(), false);
        assert_eq!(int(other.sum(t2, "rate", all()).unwrap()), 435);
        assert_eq!(int(other.sum(t2, "hours", dept(1)).unwrap()), -145);
        assert_eq!(other.avg(t2, "rate", all()).unwrap(), Some(Decoded::Rational(29.into(), 2.into())));
        // untrusted schema: reads work, writes are refused until the caller vouches for the table
        assert_eq!(other.select(t2, &["rate"], id_is(7)).unwrap(), vec![vec![ci(7)]]);
        assert_eq!(kind_of(other.insert(t2, row(99, 0, 1, 1))), Kind::UntrustedSchema);
        assert_eq!(kind_of(other.update(t2, vec![("rate", ci(1))], id_is(1))), Kind::UntrustedSchema);
        other.trust_table(t2).unwrap();
        other.insert(t2, row(99, 0, 1, 1)).unwrap();
        assert_eq!(int(db.sum(t2, "rate", all()).unwrap()), 436);
        // a client with no key can still use the server but not FHE columns
        let mut nokey = Client::connect_with(&s.addr, &ConnectOptions { timeout: Some(Duration::from_secs(240)), ..Default::default() }).unwrap();
        assert_eq!(nokey.count(t2, all()).unwrap(), 31);
        assert!(nokey.sum(t2, "rate", all()).unwrap_err().message.contains("no FHE key"));
        assert!(nokey.select(t2, &["rate"], all()).unwrap_err().message.contains("no FHE key"));
        nokey.trust_table(t2).unwrap();
        assert!(nokey.insert(t2, row(1, 1, 1, 1)).unwrap_err().message.contains("no FHE key"));
        // find_orphans ignores FHE columns (they need no masks)
        assert!(db.find_orphans().unwrap().is_empty());
        db.drop_table(t2).unwrap();
        db.drop_table(t).unwrap();
    }
}

#[test]
fn validation_parity_int_only_no_predicates_index_join_range_values_mixed_dot() {
    let Some(s) = server(&[]) else { return };
    let key = FheKey::from_hex(&secret(), 1000).unwrap();
    let mut db = connect_to(&s.addr, &key, false);
    let i = Kind::Interface;
    assert_eq!(kind_of(db.create_table("bad", vec![col("s", "str", "fhe")])), i);
    assert_eq!(kind_of(db.create_table("bad", vec![col("s", "rational", "fhe")])), i);
    let mut cols = emp_fhe_cols();
    cols.push(col("p", "int", "paired"));
    cols.push(col("s", "str", "plain"));
    db.create_table("val", cols).unwrap();
    let full = |id: i64, rate: CellIn, hours: CellIn, sv: CellIn| {
        vec![("id", ci(id)), ("dept", ci(1)), ("rate", rate), ("hours", hours), ("p", ci(7)), ("s", sv)]
    };
    let x = || CellIn::Str("x".into());
    db.insert("val", full(1, ci(5), ci(6), x())).unwrap();
    db.insert("val", full(2, ci(-1000), ci(1000), x())).unwrap(); // the range limits are inclusive
    for bad in [CellIn::Null, CellIn::Bool(true), CellIn::Str("5".into()), CellIn::Rational(1.into(), 2.into())] {
        assert_eq!(kind_of(db.insert("val", full(3, bad, ci(1), x()))), i);
    }
    assert_eq!(kind_of(db.insert("val", full(3, ci(1001), ci(1), x()))), Kind::OutOfBudget);
    assert_eq!(kind_of(db.insert("val", full(3, ci(1), ci(-1001), x()))), Kind::OutOfBudget);
    let huge = CellIn::Int(BigInt::from(1u8) << 100);
    assert_eq!(kind_of(db.insert("val", full(3, huge, ci(1), x()))), Kind::OutOfBudget);
    assert_eq!(db.insert_many("val", vec![full(3, CellIn::Rational(4.into(), 2.into()), ci(6), x())]).unwrap(), vec![2]); // 4/2 = 2
    assert_eq!(kind_of(db.update("val", vec![("rate", ci(5000))], id_is(1))), Kind::OutOfBudget);
    assert_eq!(db.count("val", all()).unwrap(), 3);
    assert_eq!(int(db.sum("val", "rate", all()).unwrap()), 5 - 1000 + 2);
    // no WHERE / index / join / per-row scaling on FHE columns
    assert_eq!(kind_of(db.count("val", eq("rate", &ci(5)).unwrap())), i);
    assert_eq!(kind_of(db.select("val", &["id"], cmp("hours", ">", &ci(1)).unwrap())), i);
    assert_eq!(kind_of(db.update("val", vec![("id", ci(1))], eq("rate", &ci(5)).unwrap())), i);
    assert_eq!(kind_of(db.create_index("val", "rate")), i);
    assert_eq!(kind_of(db.scaled_sum("val", "p", 2, all())), i);
    assert_eq!(kind_of(db.scaled_sum("val", "id", 2, all())), i);
    assert_eq!(kind_of(db.scaled_sum("val", "rate", 1 << 41, all())), i);
    assert_eq!(kind_of(db.scaled_sum("val", "rate", 1000, all())), Kind::OutOfBudget); // k*sum beyond the range
    let j = db.join("val", &[JoinStep::new("val", "id", "id").alias("b")], &JoinOptions::default()).unwrap();
    assert_eq!(kind_of(db.join_sum(&j, "b", "rate")), i);
    assert_eq!(kind_of(db.join_column(&j, "b", "rate")), i);
    assert_eq!(kind_of(db.join_dot(&j, "val", "rate", "b", "hours")), Kind::PlanError);
    // DOT: two FHE columns only; FHE and PAIRED do not mix; unknown columns; backend only for FHE
    assert_eq!(kind_of(db.dot("val", "rate", "p", all())), Kind::PlanError);
    assert_eq!(kind_of(db.dot("val", "p", "hours", all())), Kind::PlanError);
    assert_eq!(kind_of(db.dot("val", "rate", "id", all())), Kind::PlanError);
    assert_eq!(kind_of(db.dot_with_backend("val", "p", "p", all(), Some(FheBackend::Pyecc))), i);
    // a key whose range is smaller than a result raises instead of wrapping
    let mut small = connect_to(&s.addr, &FheKey::from_hex(&secret(), 100).unwrap(), false);
    small.trust_table("val").unwrap();
    assert_eq!(kind_of(small.sum("val", "hours", all())), Kind::OutOfBudget); // 1012 > 100
    assert_eq!(kind_of(small.select("val", &["hours"], id_is(2))), Kind::OutOfBudget);
    // the server itself refuses binary values elsewhere, garbage in FHE columns, and over-long lists
    let a = &s.addr;
    let err = |v: Value| v["err"].as_str().unwrap_or("").to_string();
    assert!(err(raw_call(a, "update_cell", json!(["val", 0, "id", xcell(&[0u8; 384])]))).contains("not an FHE column"));
    assert!(err(raw_call(a, "update_cell", json!(["val", 0, "rate", xcell(&[0u8; 10])]))).contains("invalid FHE ciphertext"));
    assert!(err(raw_call(a, "update_cell", json!(["val", 0, "rate", {"t": "i", "v": "7"}]))).contains("FHE"));
    assert!(err(raw_call(a, "fhe_sum", json!(["val", "id", [0]]))).contains("not an FHE column"));
    assert!(err(raw_call(a, "fhe_sum", json!(["val", "rate", vec![0; 5001]]))).contains("at most"));
}

#[test]
fn sum_beyond_one_chunk_2100_rows_and_bulk_insert() {
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let mut db = connect_to(&s.addr, &key, false);
    db.create_table("big", vec![col("id", "int", "plain"), col("v", "int", "fhe")]).unwrap();
    let n = 2100i64;
    let rows: Vec<Vec<(&str, CellIn)>> = (0..n).map(|i| vec![("id", ci(i)), ("v", ci(i % 7 - 3))]).collect();
    assert_eq!(db.insert_many("big", rows).unwrap().len(), n as usize);
    let expected: i64 = (0..n).map(|i| i % 7 - 3).sum();
    assert_eq!(int(db.sum("big", "v", all()).unwrap()), expected);
    assert_eq!(int(db.scaled_sum("big", "v", 5, all()).unwrap()), 5 * expected);
    let sel = db.select_range("big", &["v"], all(), 2090, Some(10)).unwrap();
    let want: Vec<Vec<CellIn>> = (0..10).map(|i| vec![ci((2090 + i) % 7 - 3)]).collect();
    assert_eq!(sel, want);
}

#[test]
fn dot_backends_explicit_pyecc_server_default_and_native_when_the_server_has_mclbn256() {
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let mut db = connect_to(&s.addr, &key, false);
    seed(&mut db, "dot", &ROWS[..3]);
    let want = 40 * 160 + 55 * 150 + 30 * 120;
    assert_eq!(int(db.dot_with_backend("dot", "rate", "hours", all(), Some(FheBackend::Pyecc)).unwrap()), want);
    let Some(ns) = native_server() else {
        eprintln!("# skipped native DOT (set TORUSDB_MCL_PATH to a dir with mclbn256)");
        return;
    };
    let e = db.dot_with_backend("dot", "rate", "hours", all(), Some(FheBackend::Mcl)).unwrap_err();
    assert!(e.message.contains("unavailable") || e.message.contains("back end"), "{}", e);
    let mut nd = connect_to(&ns.addr, &key, false);
    nd.create_table("dotn", emp_fhe_cols()).unwrap();
    // 120 rows: the default back end (native) in chunks of 50, and the explicit ones
    let data: Vec<[i64; 4]> = (0..120).map(|i| [i, i % 2, (i % 11) - 5, (i % 13) - 6]).collect();
    nd.insert_many("dotn", data.iter().map(|r| row(r[0], r[1], r[2], r[3])).collect()).unwrap();
    let want: i64 = data.iter().map(|r| r[2] * r[3]).sum();
    assert_eq!(int(nd.dot("dotn", "rate", "hours", all()).unwrap()), want); // server default = mcl
    let m = Some(FheBackend::Mcl);
    assert_eq!(int(nd.dot_with_backend("dotn", "rate", "hours", all(), m).unwrap()), want); // chunks of 2000
    let want0: i64 = data.iter().filter(|r| r[1] == 0).map(|r| r[2] * r[3]).sum();
    assert_eq!(int(nd.dot("dotn", "rate", "hours", dept(0)).unwrap()), want0);
    let one_row = data[3][2] * data[3][3];
    let p = Some(FheBackend::Pyecc);
    assert_eq!(int(nd.dot_with_backend("dotn", "rate", "hours", id_is(3), p).unwrap()), one_row); // 1 row, pure Python
}

// ── authenticated mode ───────────────────────────────────────────────────────
#[test]
fn authenticated_memory_and_disk_tags_verified_reads_sums_tamper_detection_dot_opt_in() {
    for storage in ["memory", "disk"] {
        let dir = tmpdir("fhe-auth");
        let db_path = dir.join("db");
        let extra: Vec<&str> = if storage == "disk" {
            vec!["--db", db_path.to_str().unwrap(), "--storage", "disk"]
        } else {
            vec![]
        };
        let Some(s) = server(&extra) else { return };
        let key = key100k();
        let mut db = connect_to(&s.addr, &key, true);
        let t = "auth";
        seed(&mut db, t, &ROWS);
        // tags are stored server-side as one more 384-byte cell per row
        let tags = raw_call(&s.addr, "plain_cells", json!([t, "__fmac__rate", [0, 1, 2, 3]]));
        for w in tags["ok"].as_array().unwrap() {
            assert_eq!(w["v"].as_str().unwrap().len(), 512);
        }
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 145);
        assert_eq!(int(db.sum(t, "rate", dept(5)).unwrap()), 115);
        assert_eq!(int(db.scaled_sum(t, "rate", 3, all()).unwrap()), 435);
        assert_eq!(int(db.scaled_sum(t, "hours", -2, dept(5)).unwrap()), -820);
        assert_eq!(db.avg(t, "rate", dept(5)).unwrap(), Some(Decoded::Rational(115.into(), 3.into())));
        assert_eq!(db.select(t, &["id", "rate"], id_is(3)).unwrap(), vec![vec![ci(3), ci(30)]]);
        assert_eq!(db.update(t, vec![("rate", ci(60))], id_is(1)).unwrap(), 1);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 165);
        assert_eq!(db.delete_rows(t, id_is(4)).unwrap(), 1);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 145);
        // insert_many tags every row too
        let ids = db.insert_many(t, vec![row(10, 1, 1, 2), row(11, 1, 2, 3)]).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(int(db.sum(t, "rate", dept(1)).unwrap()), 3);
        assert_eq!(db.select(t, &["hours"], dept(1)).unwrap(), vec![vec![ci(2)], vec![ci(3)]]);
        assert_eq!(kind_of(db.insert(t, row(12, 1, 10_000_000, 1))), Kind::OutOfBudget);
        assert_eq!(db.count(t, all()).unwrap(), 5);
        // authenticated + auto = "local": verified, computed by the owner (no pairing, no server DOT call)
        let py = Some(FheBackend::Pyecc);
        assert_eq!(int(db.dot_with_backend(t, "rate", "hours", id_is(2), py).unwrap()), 55 * 150);
        assert_eq!(int(db.dot(t, "rate", "hours", dept(1)).unwrap()), 2 + 2 * 3);
        // the legacy flag selects "delegated" (server pairing, unverified)
        let mut lax = Client::connect_with(&s.addr, &opts(&key, true, true)).unwrap();
        lax.trust_table(t).unwrap();
        assert_eq!(int(lax.dot_with_backend(t, "rate", "hours", id_is(2), py).unwrap()), 55 * 150);

        // ── a lying storage layer: values altered through raw RPCs ──
        let cell = |i: i64, c: &str| raw_call(&s.addr, "plain_cells", json!([t, c, [i]]))["ok"][0].clone();
        let good = cell(1, "rate");
        let lie = key.encrypt(999).unwrap();
        assert!(raw_call(&s.addr, "update_cell", json!([t, 1, "rate", xcell(&lie)]))["ok"].is_null());
        for r in [
            db.sum(t, "rate", all()).map(|_| ()),
            db.scaled_sum(t, "rate", 2, all()).map(|_| ()),
            db.avg(t, "rate", all()).map(|_| ()),
            db.select(t, &["rate"], id_is(2)).map(|_| ()),
        ] {
            assert_eq!(r.unwrap_err().kind, Kind::Integrity);
        }
        raw_call(&s.addr, "update_cell", json!([t, 1, "rate", good]));
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 148);
        // a row swapped together with its tag
        let (r0, m0, r2, m2) = (cell(0, "rate"), cell(0, "__fmac__rate"), cell(2, "rate"), cell(2, "__fmac__rate"));
        raw_call(&s.addr, "update_cell", json!([t, 0, "rate", r2]));
        raw_call(&s.addr, "update_cell", json!([t, 0, "__fmac__rate", m2]));
        assert_eq!(db.select(t, &["rate"], id_is(1)).unwrap_err().kind, Kind::Integrity);
        assert_eq!(db.sum(t, "rate", all()).unwrap_err().kind, Kind::Integrity);
        raw_call(&s.addr, "update_cell", json!([t, 0, "rate", r0]));
        raw_call(&s.addr, "update_cell", json!([t, 0, "__fmac__rate", m0]));
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 148);
    }
}

#[test]
fn authenticated_untagged_data_is_refused_and_a_lying_server_is_caught() {
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let mut plainc = connect_to(&s.addr, &key, false);
    seed(&mut plainc, "untag", &ROWS);
    let mut auth = connect_to(&s.addr, &key, true);
    auth.trust_table("untag").unwrap();
    assert_eq!(kind_of(auth.sum("untag", "rate", all())), Kind::Integrity);
    assert_eq!(kind_of(auth.select("untag", &["rate"], all())), Kind::Integrity);
    assert_eq!(kind_of(auth.avg("untag", "rate", all())), Kind::Integrity);

    // a proxy that rewrites fhe_sum requests: scaled, dropping a row, duplicating a row, wrong column
    let proxy = Proxy::start(s.addr.clone());
    let mut w = connect_to(&s.addr, &key, true);
    seed(&mut w, "lie", &ROWS);
    let mut db = connect_to(&proxy.addr, &key, true);
    db.trust_table("lie").unwrap();
    assert_eq!(int(db.sum("lie", "rate", all()).unwrap()), 145);
    assert_eq!(int(db.scaled_sum("lie", "rate", 3, all()).unwrap()), 435);
    for mode in 1..=4u8 {
        proxy.set(mode);
        assert_eq!(kind_of(db.sum("lie", "rate", all())), Kind::Integrity, "mode {}", mode);
        assert_eq!(kind_of(db.scaled_sum("lie", "rate", 3, all())), Kind::Integrity, "mode {}", mode);
        assert_eq!(kind_of(db.avg("lie", "rate", all())), Kind::Integrity, "mode {}", mode);
    }
    proxy.set(0);
    assert_eq!(int(db.sum("lie", "rate", all()).unwrap()), 145);
    // WITHOUT authentication the same lies go undetected (the owner decrypts a wrong number)
    let mut naive = connect_to(&proxy.addr, &key, false);
    naive.trust_table("lie").unwrap();
    proxy.set(2);
    assert_ne!(int(naive.sum("lie", "rate", all()).unwrap()), 145);
    proxy.set(1);
    assert_eq!(int(naive.sum("lie", "rate", all()).unwrap()), 290);
}

#[test]
fn authenticated_insert_is_atomic_a_dropped_connection_on_the_tag_write_leaves_no_row() {
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let proxy = Proxy::start(s.addr.clone());
    let mut db = connect_to(&proxy.addr, &key, true);
    db.create_table("atom", vec![col("id", "int", "plain"), col("v", "int", "fhe")]).unwrap();
    db.insert("atom", vec![("id", ci(1)), ("v", ci(10))]).unwrap();
    proxy.set(5); // the connection dies when the tag is written
    let e = db.insert("atom", vec![("id", ci(2)), ("v", ci(20))]).unwrap_err();
    assert!(matches!(e.kind, Kind::Connection | Kind::Protocol | Kind::Timeout), "{}", e);
    assert!(!db.in_transaction());
    proxy.set(0);
    db.reconnect().unwrap();
    assert_eq!(db.table_info("atom").unwrap().rows, 1); // the half-written row was rolled back with the session
    assert_eq!(int(db.sum("atom", "v", all()).unwrap()), 10);
    db.insert("atom", vec![("id", ci(3)), ("v", ci(30))]).unwrap();
    assert_eq!(int(db.sum("atom", "v", all()).unwrap()), 40);
}

// ── cross-implementation: Rust <-> the Python reference ──────────────────────
#[test]
fn cross_implementation_cells_written_by_rust_are_read_by_python_and_vice_versa() {
    let Some(s) = server(&[]) else { return };
    for auth in [false, true] {
        let key = key100k();
        let mut db = Client::connect_with(&s.addr, &opts(&key, auth, true)).unwrap();
        let t = if auth { "xauth" } else { "xplain" };
        seed(&mut db, t, &ROWS); // Rust writes
        let port = s.port;
        let q = |sql: String| json!(["query", sql]);
        let spec = json!({"key": secret(), "range": 100_000, "auth": auth, "dot_unverified": true, "ops": [
            q(format!("SELECT id, rate, hours FROM {t} WHERE id = 2")),
            q(format!("SELECT SUM(rate), AVG(rate), COUNT(*) FROM {t} WHERE dept = 5")),
            q(format!("SELECT 3 * SUM(rate), -2 * SUM(hours) FROM {t}")),
            q(format!("SELECT DOT(rate, hours) FROM {t} WHERE dept = 5")),
            ["indep", t, "rate"],
            ["oracle", t, "rate", [40, 55, 30, 20]],
            // Python writes, Rust reads below
            ["exec", format!("INSERT INTO {t} (id, dept, rate, hours) VALUES (5, 5, -9, 11)")],
            ["exec", format!("UPDATE {t} SET rate = 77 WHERE id = 3")],
        ]});
        let res = run_peer("127.0.0.1", port, &spec);
        assert_eq!(res[0], json!([[2, 55, 150]]));
        assert_eq!(res[1], json!([[115, "115/3", 3]]));
        assert_eq!(res[2], json!([[435, -1060]]));
        assert_eq!(res[3], json!([[DOT_D5]]));
        assert_eq!(res[4], json!([true, true, true, true])); // r1 != r2 in every cell we wrote
        assert_eq!(res[5], json!([false, false, false, false])); // e(G2, C2 - v*G1) == e(Q2, C1) never holds: no value oracle
        assert_eq!(res[6], json!([true, true, true, true])); // control: with the broken Q2 = s*G2 it WOULD hold
        assert_eq!(db.select(t, &["id", "rate", "hours"], id_is(5)).unwrap(), vec![vec![ci(5), ci(-9), ci(11)]]);
        assert_eq!(int(db.sum(t, "rate", all()).unwrap()), 40 + 55 + 77 + 20 - 9);
        assert_eq!(int(db.scaled_sum(t, "hours", 2, all()).unwrap()), 2 * (160 + 150 + 120 + 100 + 11));
        let py = Some(FheBackend::Pyecc);
        assert_eq!(int(db.dot_with_backend(t, "rate", "hours", id_is(5), py).unwrap()), -99);
    }
}

#[test]
fn cross_implementation_sealed_key_files_interoperate_with_pythons_save_key_and_load_key() {
    let Some(s) = server(&[]) else { return };
    let dir = tmpdir("fhekeyx");
    let (py_file, py_plain, rs_file) = (dir.join("py.key"), dir.join("pyplain.key"), dir.join("rs.key"));
    let sec = secret();
    run_peer("127.0.0.1", s.port, &json!({"key": sec, "range": 4321, "ops": [
        ["keyfile", py_file.to_str().unwrap(), "pässwörd"], ["keyfile", py_plain.to_str().unwrap(), null]]}));
    let k = FheKey::load(&py_file, Some("pässwörd")).unwrap();
    assert_eq!(k.range(), 4321);
    assert_eq!(fhe_internals::hex(&k.secret_bytes()), sec);
    assert_eq!(FheKey::load(&py_plain, None).unwrap().range(), 4321);
    FheKey::from_hex(&sec, 777).unwrap().save(&rs_file, Some("hunter2")).unwrap();
    let out = run_peer("127.0.0.1", s.port, &json!({"key": sec, "ops": [["loadkey", rs_file.to_str().unwrap(), "hunter2"]]}));
    assert_eq!(out, json!([[sec, 777]]));
}

// ── batched cell writes (update_cells) and server-published limits ───────────
#[test]
fn authenticated_fhe_writes_use_one_update_cells_call_per_batch_and_update_cells_is_atomic() {
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let proxy = Proxy::start(s.addr.clone());
    let mut db = connect_to(&proxy.addr, &key, true);
    seed(&mut db, "batch", &ROWS);
    assert_eq!(proxy.count("update_cell"), 0);
    assert_eq!(proxy.count("update_cells"), 4); // one per single-row INSERT
    let rows: Vec<_> = (0..6).map(|i| row(10 + i, 1, i, i)).collect();
    db.insert_many("batch", rows).unwrap();
    assert_eq!(proxy.count("update_cells"), 5); // 6 rows x 2 tags = 12 cells, one RPC
    assert_eq!(db.update("batch", vec![("rate", ci(7))], dept(1)).unwrap(), 6);
    assert_eq!(proxy.count("update_cells"), 6); // 6 rows x (value + tag), one RPC
    assert_eq!(proxy.count("update_cell"), 0);
    assert_eq!(int(db.sum("batch", "rate", dept(1)).unwrap()), 42); // every tag verifies
    // atomicity on the server: the second item is invalid, so the first is rolled back too
    let c1 = raw_call(&s.addr, "plain_cells", json!(["batch", "rate", [0]]))["ok"][0].clone();
    let bad = json!(["batch", [[0, "rate", xcell(&key.encrypt(999).unwrap())], [1, "rate", xcell(&[0u8; 5])]]]);
    assert!(raw_call(&s.addr, "update_cells", bad)["err"].as_str().is_some());
    assert_eq!(raw_call(&s.addr, "plain_cells", json!(["batch", "rate", [0]]))["ok"][0], c1);
    assert_eq!(raw_call(&s.addr, "update_cells", json!(["batch", [[0, "rate", c1]]]))["ok"], json!(1));
}

fn fhe_fake(limits: Option<Value>, old_server: bool) -> (common::fake::Fake, FheKey) {
    use common::fake::{base, fake, hello, Reply};
    let key = key100k();
    let one = key.encrypt(1).unwrap();
    let dot = hex(&vec_json()["dot_blob_pyecc"]);
    let h = base(move |m, a, _| {
        let ok = |v: Value| Some(Reply::Json(json!({"ok": v})));
        match m {
            "hello" => {
                let mut h = hello();
                if let Some(l) = &limits {
                    h["ok"]["limits"] = l.clone();
                }
                Some(Reply::Json(h))
            }
            "tables" => ok(json!(["t"])),
            "schema" => ok(json!([["id", "int", "plain"], ["v", "int", "fhe"]])),
            "matching_rowids" => ok(json!((0..20).collect::<Vec<i64>>())),
            "fhe_sum" => {
                let n = a[2].as_array().unwrap().len();
                let cells: Vec<&[u8]> = vec![&one; n];
                ok(json!(b64(&fhe_sum_cells(&cells, &one_big()).unwrap())))
            }
            "fhe_dot" => {
                let mut d = dot.clone();
                if a.get(6).and_then(|b| b.as_str()) == Some("mcl") {
                    d[0] = 2;
                }
                ok(json!(b64(&d)))
            }
            "update_cells" if old_server => Some(Reply::Json(json!({"err": "BadRequest: unknown method 'update_cells'"}))),
            "update_cells" => ok(json!(a[1].as_array().unwrap().len())),
            "insert" => ok(json!(0)),
            "insert_many" => ok(json!((0..a[1].as_array().unwrap().len() as i64).collect::<Vec<_>>())),
            _ => None,
        }
    });
    (fake(h), key)
}
fn one_big() -> BigInt {
    BigInt::from(1)
}
fn sizes(f: &common::fake::Fake, method: &str, idx: usize, mcl: Option<bool>) -> Vec<usize> {
    f.bodies()
        .iter()
        .filter(|b| b.contains(&format!("\"{}\"", method)))
        .filter(|b| mcl.is_none_or(|m| b.contains("\"mcl\"") == m))
        .map(|b| serde_json::from_str::<Value>(b).unwrap()["a"][idx].as_array().unwrap().len())
        .collect()
}

#[test]
fn hello_limits_shrink_fhe_sum_fhe_dot_and_update_cells_chunks_and_defaults_apply_without_them() {
    let limits = json!({"max_items": 3, "fhe": {"max_sum_rows": 7, "max_dot_rows": {"pyecc": 5, "mcl": 6},
        "recommended_dot_rows": {"pyecc": 3, "mcl": 4}, "backends": ["pyecc"], "default_backend": "auto"}});
    for with in [true, false] {
        let (f, key) = fhe_fake(if with { Some(limits.clone()) } else { None }, false);
        let mut plain = Client::connect_with(&f.addr, &opts(&key, false, false)).unwrap();
        let mut db = Client::connect_with(&f.addr, &opts(&key, true, false)).unwrap();
        plain.trust_table("t").unwrap();
        db.trust_table("t").unwrap();
        assert_eq!(int(plain.sum("t", "v", all()).unwrap()), 20);
        assert_eq!(sizes(&f, "fhe_sum", 2, None), if with { vec![7, 7, 6] } else { vec![20] });
        // default back end: pyecc sizing (recommended 3 | 50)
        assert_eq!(int(plain.dot("t", "v", "v", all()).unwrap()), 844 * if with { 7 } else { 1 });
        assert_eq!(sizes(&f, "fhe_dot", 2, Some(false)), if with { vec![3, 3, 3, 3, 3, 3, 2] } else { vec![20] });
        let _ = plain.dot_with_backend("t", "v", "v", all(), Some(FheBackend::Mcl)); // mcl: recommended 4 (cap 6)
        assert_eq!(sizes(&f, "fhe_dot", 2, Some(true)), if with { vec![4, 4, 4, 4, 4] } else { vec![20] });
        // update_cells batches follow max_items (3) when published, else 2000
        let rows: Vec<_> = (0..4).map(|i| vec![("id", ci(i)), ("v", ci(i))]).collect();
        db.insert_many("t", rows).unwrap();
        assert_eq!(sizes(&f, "update_cells", 1, None), if with { vec![3, 1] } else { vec![4] });
    }
}

#[test]
fn an_old_server_without_update_cells_falls_back_to_update_cell_once_and_remembers_it() {
    let (f, key) = fhe_fake(None, true);
    let mut db = Client::connect_with(&f.addr, &opts(&key, true, false)).unwrap();
    db.trust_table("t").unwrap();
    let r = |id: i64, v: i64| vec![("id", ci(id)), ("v", ci(v))];
    db.insert("t", r(1, 5)).unwrap();
    db.insert("t", r(2, 6)).unwrap();
    db.insert_many("t", vec![r(3, 1), r(4, 2)]).unwrap();
    let seen = f.seen();
    assert_eq!(seen.iter().filter(|m| *m == "update_cells").count(), 1); // asked once only
    assert_eq!(seen.iter().filter(|m| *m == "update_cell").count(), 4); // 1 + 1 + 2 tags by repetition
}

// ── DOT modes: auto / local / delegated ──────────────────────────────────────
fn mode_client(addr: &str, key: &FheKey, auth: bool, mode: FheDotMode) -> Client {
    let mut o = opts(key, auth, false);
    o.fhe_dot_mode = mode;
    Client::connect_with(addr, &o).unwrap()
}

#[test]
fn dot_modes_local_is_verified_delegated_is_not_auto_depends_on_authentication() {
    assert_eq!(FheDotMode::parse("auto").unwrap(), FheDotMode::Auto);
    assert_eq!(FheDotMode::parse("local").unwrap(), FheDotMode::Local);
    assert_eq!(FheDotMode::parse("delegated").unwrap(), FheDotMode::Delegated);
    for bad in ["", "Local", "remote", "unverified"] {
        assert_eq!(kind_of(FheDotMode::parse(bad)), Kind::Interface);
    }
    let Some(s) = server(&[]) else { return };
    let key = key100k();
    let mut auth = mode_client(&s.addr, &key, true, FheDotMode::Auto);
    seed(&mut auth, "dm", &ROWS);
    let py = Some(FheBackend::Pyecc);
    let want = DOT_ALL;
    assert_eq!(int(auth.dot("dm", "rate", "hours", all()).unwrap()), want); // authenticated auto = local
    let mut local = mode_client(&s.addr, &key, true, FheDotMode::Local);
    let mut deleg = mode_client(&s.addr, &key, true, FheDotMode::Delegated);
    let mut plain = mode_client(&s.addr, &key, false, FheDotMode::Auto); // unauthenticated auto = delegated
    let mut plain_local = mode_client(&s.addr, &key, false, FheDotMode::Local);
    for c in [&mut local, &mut deleg, &mut plain, &mut plain_local] {
        c.trust_table("dm").unwrap();
    }
    assert_eq!(int(deleg.dot_with_backend("dm", "rate", "hours", dept(5), py).unwrap()), DOT_D5);
    assert_eq!(int(local.dot("dm", "rate", "hours", dept(5)).unwrap()), DOT_D5);
    assert_eq!(int(plain_local.dot("dm", "rate", "hours", dept(5)).unwrap()), DOT_D5);
    // which path ran: delegated/auto-unauthenticated call fhe_dot on the server, local never does
    let proxy = Proxy::start(s.addr.clone());
    let mut via_local = Client::connect_with(&proxy.addr, &{ let mut o = opts(&key, true, false); o.fhe_dot_mode = FheDotMode::Local; o }).unwrap();
    via_local.trust_table("dm").unwrap();
    via_local.dot("dm", "rate", "hours", all()).unwrap();
    assert_eq!(proxy.count("fhe_dot"), 0);
    let mut via_plain = connect_to(&proxy.addr, &key, false);
    via_plain.trust_table("dm").unwrap();
    assert_eq!(int(via_plain.dot_with_backend("dm", "rate", "hours", id_is(2), py).unwrap()), 55 * 150);
    assert_eq!(proxy.count("fhe_dot"), 1);
    // the server alters one operand cell (raw RPC): local detects it, delegated returns a WRONG number
    let lie = key.encrypt(400).unwrap();
    assert!(raw_call(&s.addr, "update_cell", json!(["dm", 1, "rate", xcell(&lie)]))["ok"].is_null());
    assert_eq!(kind_of(local.dot("dm", "rate", "hours", all())), Kind::Integrity);
    assert_eq!(kind_of(auth.dot("dm", "rate", "hours", all())), Kind::Integrity);
    let wrong = int(deleg.dot_with_backend("dm", "rate", "hours", all(), py).unwrap());
    assert_eq!(wrong, DOT_ALL - 55 * 150 + 400 * 150); // silently wrong: delegated DOT cannot be verified
    // the legacy alias selects delegated on an authenticated connection
    let mut legacy = Client::connect_with(&s.addr, &opts(&key, true, true)).unwrap();
    legacy.trust_table("dm").unwrap();
    assert_eq!(int(legacy.dot_with_backend("dm", "rate", "hours", all(), py).unwrap()), wrong);
}

#[test]
fn local_dot_has_no_range_limit_on_the_result() {
    let Some(s) = server(&[]) else { return };
    let key = FheKey::from_hex(&secret(), 1_000_000).unwrap();
    let mut db = mode_client(&s.addr, &key, true, FheDotMode::Auto);
    db.create_table("big", vec![col("a", "int", "fhe"), col("b", "int", "fhe")]).unwrap();
    for (a, b) in [(1_000_000i64, 1_000_000i64), (-1_000_000, 999_999), (7, 8)] {
        db.insert("big", vec![("a", ci(a)), ("b", ci(b))]).unwrap();
    }
    let want = 1_000_000_000_000i64 - 999_999_000_000 + 56;
    assert_eq!(int(db.dot("big", "a", "b", all()).unwrap()), want);
    let mut deleg = mode_client(&s.addr, &key, false, FheDotMode::Delegated);
    deleg.sync_schema().unwrap();
    deleg.trust_table("big").unwrap();
    assert_eq!(kind_of(deleg.dot_with_backend("big", "a", "b", id_is_all(), Some(FheBackend::Pyecc))), Kind::OutOfBudget);
}
fn id_is_all() -> Value {
    all()
}
