// SPDX-License-Identifier: Apache-2.0
//! Anchored table-state integrity (`integrity_anchor`): every attack runs against an anchored owner (must fail)
//! and, where it is observable without an anchor, against an owner WITHOUT one (the negative control: the same lie
//! silently succeeds, so the anchor - not the tags alone - is what stops it). Against the real Python server, with
//! the Python reference as a cross-implementation peer sharing the anchor FILE.
use num_bigint::BigInt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use torusdb::*;

mod common;
use common::*;

fn vec_json() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/fhe-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn secret() -> String {
    vec_json()["secret"].as_str().unwrap().to_string()
}
fn key() -> FheKey {
    FheKey::from_hex(&secret(), 100_000).unwrap()
}
fn ci(v: i64) -> CellIn {
    CellIn::Int(BigInt::from(v))
}
fn kind_of<T: std::fmt::Debug>(r: Result<T, Error>) -> Kind {
    r.expect_err("expected an error").kind
}
fn int(d: Decoded) -> i64 {
    match d {
        Decoded::Int(i) => i64::try_from(i).unwrap(),
        o => panic!("not an integer: {:?}", o),
    }
}
fn is_integrity(k: &Kind) -> bool {
    matches!(k, Kind::Integrity | Kind::StaleServer)
}

const ROWS: [[i64; 3]; 4] = [[1, 5, 40], [2, 5, 55], [3, 7, 30], [4, 5, 20]];

fn cols() -> Vec<Column> {
    vec![col("id", "int", "plain"), col("dept", "int", "plain"), col("rate", "int", "fhe")]
}
fn row(id: i64, dept: i64, rate: i64) -> Vec<(&'static str, CellIn)> {
    vec![("id", ci(id)), ("dept", ci(dept)), ("rate", ci(rate))]
}
fn dept(d: i64) -> Value {
    eq("dept", &ci(d)).unwrap()
}
fn id_is(i: i64) -> Value {
    eq("id", &ci(i)).unwrap()
}
fn anchor_file() -> PathBuf {
    tmpdir("anchor").join("anchor.json")
}

fn server() -> Option<Server> {
    match mcl_path() {
        Some(p) => Server::start_env(&[], &[("PYTHONPATH", &p)]),
        None => Server::start(&[]),
    }
}
fn opts(anchor: Option<&PathBuf>) -> ConnectOptions {
    ConnectOptions {
        fhe_key: Some(key()),
        authenticated: true,
        integrity_anchor: anchor.map(|p| AnchorSpec::File(p.clone())),
        timeout: Some(Duration::from_secs(240)),
        ..Default::default()
    }
}
fn owner(addr: &str, anchor: Option<&PathBuf>) -> Client {
    Client::connect_with(addr, &opts(anchor)).unwrap()
}
fn seeded(addr: &str, anchor: Option<&PathBuf>, table: &str) -> Client {
    let mut db = owner(addr, anchor);
    db.create_table(table, cols()).unwrap();
    for r in ROWS {
        db.insert(table, row(r[0], r[1], r[2])).unwrap();
    }
    db
}
fn dept5(db: &mut Client, t: &str) -> Result<(i64, usize), Error> {
    Ok((int(db.sum(t, "rate", dept(5))?), db.count(t, dept(5))?))
}
fn xc(b: &[u8]) -> Value {
    json!({"t": "x", "v": fhe_b64(b)})
}
fn fhe_b64(b: &[u8]) -> String {
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
fn ints(v: i64) -> Value {
    json!({"t": "i", "v": v.to_string()})
}
const CELLCOLS: [&str; 5] = ["id", "dept", "rate", "__fmac__rate", "__fnonce__rate"];
fn cells(addr: &str, t: &str, id: i64) -> BTreeMap<String, Value> {
    CELLCOLS.iter().map(|c| (c.to_string(), raw_rpc(addr, "plain_cells", json!([t, c, [id]]))["ok"][0].clone())).collect()
}
fn restore(addr: &str, t: &str, id: i64, st: &BTreeMap<String, Value>) {
    for (c, w) in st {
        assert!(raw_rpc(addr, "update_cell", json!([t, id, c, w]))["err"].is_null());
    }
}
fn raw_add_row(addr: &str, t: &str, id: i64, d: i64, rate: i64) {
    let r = raw_rpc(
        addr,
        "insert",
        json!([t, {"id": ints(id), "dept": ints(d), "rate": xc(&key().encrypt(rate).unwrap()),
                   "__fmac__rate": xc(&key().encrypt(0).unwrap()), "__fnonce__rate": ints(777)}]),
    );
    assert!(r["err"].is_null(), "{}", r);
}

// ── a proxy whose hooks can lie, swallow, kill or refuse ─────────────────────
enum Req {
    Forward,
    Kill,
    Reply(Value),
}
enum Resp {
    Keep,
    Replace(Value),
    Drop,
}
type ReqHook = Arc<dyn Fn(&Value) -> Req + Send + Sync>;
type RespHook = Arc<dyn Fn(&Value, &Value) -> Resp + Send + Sync>;
#[derive(Default)]
struct Hooks {
    req: Option<ReqHook>,
    resp: Option<RespHook>,
}
struct Proxy {
    addr: String,
    hooks: Arc<Mutex<Hooks>>,
    seen: Arc<Mutex<Vec<String>>>,
    refuse: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}
impl Proxy {
    fn start(upstream: String) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let hooks: Arc<Mutex<Hooks>> = Arc::default();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let (refuse, stop) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (h2, s2, r2, st2) = (hooks.clone(), seen.clone(), refuse.clone(), stop.clone());
        std::thread::spawn(move || {
            for conn in l.incoming() {
                if st2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut cli) = conn else { continue };
                if r2.load(Ordering::SeqCst) {
                    continue; // dropping the socket refuses the session
                }
                let (up, h3, s3) = (upstream.clone(), h2.clone(), s2.clone());
                std::thread::spawn(move || {
                    let Ok(mut srv) = TcpStream::connect(up) else { return };
                    while let Some(raw) = read_frame(&mut cli) {
                        let req: Value = serde_json::from_slice(&raw).unwrap();
                        s3.lock().unwrap().push(req["m"].as_str().unwrap_or("").to_string());
                        let (rh, ph) = {
                            let g = h3.lock().unwrap();
                            (g.req.clone(), g.resp.clone())
                        };
                        match rh.map(|f| f(&req)).unwrap_or(Req::Forward) {
                            Req::Kill => return,
                            Req::Reply(v) => {
                                if !write_frame(&mut cli, v.to_string().as_bytes()) {
                                    return;
                                }
                                continue;
                            }
                            Req::Forward => {}
                        }
                        if !write_frame(&mut srv, &raw) {
                            return;
                        }
                        let Some(resp_raw) = read_frame(&mut srv) else { return };
                        let mut resp: Value = serde_json::from_slice(&resp_raw).unwrap();
                        match ph.map(|f| f(&req, &resp)).unwrap_or(Resp::Keep) {
                            Resp::Drop => return,
                            Resp::Replace(v) => resp = v,
                            Resp::Keep => {}
                        }
                        if !write_frame(&mut cli, resp.to_string().as_bytes()) {
                            return;
                        }
                    }
                });
            }
        });
        Proxy { addr, hooks, seen, refuse, stop }
    }
    fn on_req(&self, f: impl Fn(&Value) -> Req + Send + Sync + 'static) {
        self.hooks.lock().unwrap().req = Some(Arc::new(f));
    }
    fn on_resp(&self, f: impl Fn(&Value, &Value) -> Resp + Send + Sync + 'static) {
        self.hooks.lock().unwrap().resp = Some(Arc::new(f));
    }
    fn clear(&self) {
        *self.hooks.lock().unwrap() = Hooks::default();
    }
    fn seen_len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn seen_since(&self, n: usize, m: &str) -> usize {
        self.seen.lock().unwrap()[n..].iter().filter(|x| *x == m).count()
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
    }
}

// ── the anchor store and the canonical encoding (no server) ──────────────────
fn big(n: i64) -> BigInt {
    BigInt::from(n)
}
fn one(t: &str, expect: Option<u64>, root: Option<i64>, count: u64) -> BTreeMap<String, AnchorChange> {
    BTreeMap::from([(t.to_string(), AnchorChange { expect_epoch: expect, root: root.map(big), count })])
}

fn store_semantics(a: &dyn Anchor) {
    assert!(a.get("t").unwrap().is_none());
    a.begin_commit(&one("t", None, Some(0), 0), Some("tx0")).unwrap(); // CREATE
    assert_eq!(a.get("t").unwrap().unwrap().pending.unwrap().epoch, 1);
    assert!(a.begin_commit(&one("t", Some(0), Some(5), 1), Some("tx1")).unwrap_err().message.contains("pending"));
    a.finish_commit(&["t".into()], Some("tx0")).unwrap();
    let e = a.get("t").unwrap().unwrap();
    assert_eq!((e.epoch, e.root.clone(), e.count, e.pending.clone()), (1, big(0), 0, None));
    a.begin_commit(&one("t", Some(1), Some(99), 2), Some("tx2")).unwrap();
    a.abort(&["t".into()], Some("tx2")).unwrap();
    let e = a.get("t").unwrap().unwrap();
    assert_eq!((e.epoch, e.root.clone(), e.pending.is_none()), (1, big(0), true));
    assert!(a.begin_commit(&one("t", Some(0), Some(7), 1), Some("tx3")).unwrap_err().message.contains("epoch"));
    a.begin_commit(&one("t", Some(1), Some(99), 2), Some("tx4")).unwrap();
    assert_eq!(kind_of(a.finish_commit(&["t".into()], Some("someone-else"))), Kind::AnchorConflict);
    a.finish_commit(&["t".into()], Some("tx4")).unwrap();
    a.finish_commit(&["t".into()], Some("tx4")).unwrap(); // idempotent
    let e = a.get("t").unwrap().unwrap();
    assert_eq!((e.epoch, e.root.clone(), e.count), (2, big(99), 2));
    assert_eq!(e.history.last().unwrap(), &(1, big(0), 0));
    let mut two = one("t", Some(2), Some(1), 1);
    two.extend(one("u", Some(5), Some(1), 1));
    assert_eq!(kind_of(a.begin_commit(&two, Some("tx5"))), Kind::AnchorConflict);
    assert!(a.get("t").unwrap().unwrap().pending.is_none());
    assert!(a.get("u").unwrap().is_none());
    a.begin_commit(&one("t", Some(2), None, 0), Some("tx6")).unwrap(); // drop
    a.finish_commit(&["t".into()], Some("tx6")).unwrap();
    assert!(a.get("t").unwrap().is_none());
    for i in 0..12u64 {
        a.set("h", &big(i as i64), i, if i == 0 { None } else { Some(i - 1) }).unwrap();
    }
    assert_eq!(a.get("h").unwrap().unwrap().history.len(), 8); // history keeps the last 8
    assert_eq!(kind_of(a.set("h", &big(1), 1, Some(3))), Kind::AnchorConflict);
}

#[test]
fn anchor_stores_compare_and_swap_pending_finish_abort_history() {
    store_semantics(&MemoryAnchor::new());
    store_semantics(&FileAnchor::new(anchor_file()).unwrap());
}

#[test]
fn file_anchor_is_0600_crash_safe_and_refuses_unsafe_files() {
    let dir = tmpdir("anchorfile");
    let p = dir.join("a.json");
    let a = FileAnchor::new(&p).unwrap();
    a.set("t", &big(123), 4, None).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(serde_json::from_str::<Value>(&std::fs::read_to_string(&p).unwrap()).unwrap()["v"], 1);
    let tmp_left = std::fs::read_dir(&dir).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(".tmp.")).count();
    assert_eq!(tmp_left, 0); // temporary files are gone
    assert_eq!(FileAnchor::new(&p).unwrap().get("t").unwrap().unwrap().root, big(123));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(a.get("t").unwrap_err().message.contains("permissions"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&p, "not json").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(a.get("t").unwrap_err().message.contains("corrupt")); // never silently start from empty
    std::fs::write(&p, json!({"format": "torussql-fhe-anchor", "v": 99, "tables": {}}).to_string()).unwrap();
    assert!(a.get("t").unwrap_err().message.contains("version"));
    std::fs::remove_file(&p).unwrap();
    #[cfg(unix)]
    {
        let target = dir.join("elsewhere.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert_eq!(kind_of(a.get("t")), Kind::AnchorFile);
        assert_eq!(kind_of(a.set("t", &big(1), 1, None)), Kind::AnchorFile);
    }
    assert!(FileAnchor::new(dir.join("nodir").join("a.json")).unwrap_err().message.contains("directory"));
}

#[test]
fn two_file_anchor_objects_on_one_file_are_serialised() {
    let p = anchor_file();
    let (a, b) = (FileAnchor::new(&p).unwrap(), FileAnchor::new(&p).unwrap());
    a.begin_commit(&one("t", None, Some(5), 1), Some("x")).unwrap();
    assert_eq!(kind_of(b.begin_commit(&one("t", Some(0), Some(6), 2), Some("y"))), Kind::AnchorConflict);
    a.finish_commit(&["t".into()], Some("x")).unwrap();
    b.begin_commit(&one("t", Some(1), Some(6), 2), Some("y")).unwrap();
    b.finish_commit(&["t".into()], Some("y")).unwrap();
    assert_eq!(a.get("t").unwrap().unwrap().epoch, 2);
}

#[test]
fn canonical_values_are_unambiguous() {
    assert_eq!(canon_value(&ci(5)), canon_value(&CellIn::Rational(5.into(), 1.into())));
    assert_eq!(canon_value(&ci(1)), canon_value(&CellIn::Bool(true)));
    let forms = [CellIn::Null, ci(0), CellIn::Str("0".into()), CellIn::Str("".into()), CellIn::Rational(1.into(), 2.into()), ci(1), CellIn::Str("1".into())];
    let set: std::collections::HashSet<Vec<u8>> = forms.iter().map(canon_value).collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn known_answers_canonical_row_material_and_leaf_equal_the_python_implementation() {
    let Some(s) = server() else { return };
    let cols = json!([["id", "int", "plain"], ["name", "str", "plain"], ["f", "rational", "plain"], ["rate", "int", "fhe"], ["h", "int", "fhe"]]);
    let cases = [
        (0i64, json!([{"t": "i", "v": "5"}, {"t": "s", "v": "caf\u{e9} \u{fc}\u{4e2d}\u{1f600}"}, {"t": "f", "n": "-7", "d": "3"}]),
         json!([["12345", "ab".repeat(32), "cd".repeat(32)], [null, null, null]])),
        ((1i64 << 40) + 3, json!([{"t": "i", "v": "-123456789012345678901234567890"}, {"t": "n"}, {"t": "i", "v": "0"}]),
         json!([["1000000000000000000000000000000", "00".repeat(32), "ff".repeat(32)], ["1", "11".repeat(32), "22".repeat(32)]])),
        (7, json!([{"t": "b", "v": true}, {"t": "s", "v": ""}, {"t": "f", "n": "4", "d": "2"}]),
         json!([[null, "01".repeat(32), null], ["99", null, "02".repeat(32)]])),
    ];
    let table = "t\u{e9}st";
    let ops: Vec<Value> = cases.iter().map(|(rid, plain, fhe)| json!(["leaf", table, cols, rid, plain, fhe])).collect();
    let out = run_peer("127.0.0.1", s.port, &json!({"key": secret(), "range": 100000, "ops": ops}));
    let triples: Vec<(String, String, String)> =
        cols.as_array().unwrap().iter().map(|c| (c[0].as_str().unwrap().into(), c[1].as_str().unwrap().into(), c[2].as_str().unwrap().into())).collect();
    let sdig = schema_digest(table, &triples);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    let unhex = |s: &str| -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    };
    for (k, (rid, plain, fhe)) in cases.iter().enumerate() {
        let vals: Vec<CellIn> = plain
            .as_array()
            .unwrap()
            .iter()
            .map(|w| match w["t"].as_str().unwrap() {
                "n" => CellIn::Null,
                "b" => CellIn::Bool(w["v"].as_bool().unwrap()),
                "i" => CellIn::Int(w["v"].as_str().unwrap().parse().unwrap()),
                "s" => CellIn::Str(w["v"].as_str().unwrap().into()),
                _ => match reduce(&w["n"].as_str().unwrap().parse().unwrap(), &w["d"].as_str().unwrap().parse().unwrap()) {
                    Decoded::Int(i) => CellIn::Int(i),
                    Decoded::Rational(a, b) => CellIn::Rational(a, b),
                },
            })
            .collect();
        let parts: Vec<FhePart> = fhe
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().map(|n| n.parse::<BigInt>().unwrap()), p[1].as_str().map(unhex), p[2].as_str().map(unhex)))
            .collect();
        let m = row_material(&sdig, &vals, &parts);
        assert_eq!(hex(&m), out[k][0].as_str().unwrap(), "material {}", k);
        assert_eq!(key().anchor_leaf(table, *rid, &m).to_string(), out[k][1].as_str().unwrap(), "leaf {}", k);
    }
}

#[test]
fn anchor_file_format_is_interchangeable_with_pythons_file_anchor_both_directions() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let a = FileAnchor::new(&p).unwrap();
    let root: BigInt = "12345678901234567890123456789".parse().unwrap();
    a.begin_commit(&BTreeMap::from([("t".to_string(), AnchorChange { expect_epoch: None, root: Some(root), count: 3 })]), Some("tx-rs")).unwrap();
    let dump = |steps: Value| run_peer("127.0.0.1", s.port, &json!({"key": secret(), "ops": [["anchor_ops", p.to_str().unwrap(), steps]]}))[0].clone();
    let pend = dump(json!([["get", "t"]]));
    assert_eq!(
        pend[0],
        json!({"epoch": 0, "root": "0", "count": 0, "history": [], "pending": {"epoch": 1, "root": "12345678901234567890123456789", "count": 3, "txid": "tx-rs", "drop": false, "created": true}})
    );
    a.finish_commit(&["t".into()], Some("tx-rs")).unwrap();
    let res = dump(json!([
        ["begin_commit", {"t": [1, "5", 4], "u\u{e9}": [null, "9", 1]}, "tx-py"], ["finish_commit", ["t", "u\u{e9}"], "tx-py"],
        ["set", "w", "77", 2, null], ["get", "t"], ["get", "u\u{e9}"], ["get", "w"]]));
    let short: Vec<Value> = res.as_array().unwrap().iter().map(|e| json!([e["epoch"], e["root"], e["count"], e["pending"]])).collect();
    assert_eq!(short, vec![json!([2, "5", 4, null]), json!([1, "9", 1, null]), json!([0, "77", 2, null])]);
    let b = FileAnchor::new(&p).unwrap();
    let t = b.get("t").unwrap().unwrap();
    assert_eq!((t.epoch, t.root.clone(), t.count), (2, big(5), 4));
    assert_eq!(t.history.iter().map(|h| h.0).collect::<Vec<_>>(), vec![0, 1]);
    assert_eq!(b.get("u\u{e9}").unwrap().unwrap().root, big(9));
    assert_eq!(b.tables().unwrap(), vec!["t".to_string(), "u\u{e9}".to_string(), "w".to_string()]);
    b.begin_commit(&one("t", Some(2), None, 0), Some("tx-drop")).unwrap();
    b.abort(&["t".into()], Some("tx-drop")).unwrap();
    b.remove("w", None).unwrap();
    let t2 = dump(json!([["get", "t"]]));
    assert_eq!((t2[0]["pending"].clone(), t2[0]["epoch"].clone()), (Value::Null, json!(2)));
    assert_eq!(serde_json::from_str::<Value>(&std::fs::read_to_string(&p).unwrap()).unwrap()["format"], "torussql-fhe-anchor");
}

// ── options ──────────────────────────────────────────────────────────────────
#[test]
fn integrity_anchor_needs_authentication_and_a_key() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut o = opts(Some(&p));
    o.authenticated = false;
    assert_eq!(kind_of(Client::connect_with(&s.addr, &o)), Kind::Interface);
    let mut o = opts(Some(&p));
    o.fhe_key = None;
    assert_eq!(kind_of(Client::connect_with(&s.addr, &o)), Kind::Interface);
    let mut db = owner(&s.addr, None);
    assert_eq!(kind_of(db.verify_table("x")), Kind::Interface);
    assert_eq!(kind_of(db.adopt_table("x", false)), Kind::Interface);
}

// ── honest flows ─────────────────────────────────────────────────────────────
#[test]
fn honest_flows_with_caching_per_epoch_null_semantics_and_transactions() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = owner(&s.addr, Some(&p));
    let t = "emp";
    db.create_table(t, vec![col("id", "int", "plain"), col("dept", "int", "plain"), col("rate", "int", "fhe"), col("note", "str", "plain")]).unwrap();
    let e0 = FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap();
    assert_eq!((e0.epoch, e0.root, e0.count), (1, big(0), 0)); // anchored from the first byte
    for r in ROWS {
        let note = if r[0] == 3 { CellIn::Null } else { CellIn::Str(format!("n{}", r[0])) };
        db.insert(t, vec![("id", ci(r[0])), ("dept", ci(r[1])), ("rate", ci(r[2])), ("note", note)]).unwrap();
    }
    assert_eq!(dept5(&mut db, t).unwrap(), (115, 3));
    assert_eq!(db.avg(t, "rate", dept(5)).unwrap(), Some(Decoded::Rational(115.into(), 3.into())));
    assert_eq!(int(db.scaled_sum(t, "rate", 3, all()).unwrap()), 435);
    let sel = db.select(t, &["id", "rate"], cmp("id", ">", &ci(2)).unwrap()).unwrap();
    assert_eq!(sel, vec![vec![ci(3), ci(30)], vec![ci(4), ci(20)]]);
    assert_eq!(db.select(t, &["id"], is_null("note")).unwrap(), vec![vec![ci(3)]]); // NULL semantics kept
    assert_eq!(db.count(t, eq("note", &CellIn::Str("n2".into())).unwrap()).unwrap(), 1);
    assert_eq!(int(db.dot(t, "rate", "rate", dept(5)).unwrap()), 40 * 40 + 55 * 55 + 20 * 20); // authenticated auto = local
    let scans = db.anchor_stats().0;
    for _ in 0..5 {
        db.sum(t, "rate", all()).unwrap();
    }
    assert_eq!(db.anchor_stats().0, scans); // cached: no rescan
    db.update(t, vec![("rate", ci(99)), ("note", CellIn::Str("x".into()))], id_is(2)).unwrap();
    db.update(t, vec![("dept", ci(8))], dept(7)).unwrap();
    assert_eq!(dept5(&mut db, t).unwrap(), (159, 3));
    assert_eq!(db.delete_rows(t, id_is(4)).unwrap(), 1);
    assert_eq!(dept5(&mut db, t).unwrap(), (139, 2));
    let rows = vec![
        vec![("id", ci(10)), ("dept", ci(5)), ("rate", ci(1)), ("note", CellIn::Str("a".into()))],
        vec![("id", ci(11)), ("dept", ci(5)), ("rate", ci(2)), ("note", CellIn::Str("b".into()))],
    ];
    assert_eq!(db.insert_many(t, rows).unwrap(), vec![4, 5]); // slot ids are never reused
    assert_eq!(dept5(&mut db, t).unwrap(), (142, 4));
    assert_eq!(db.anchor_stats().0, scans); // still no scan: deltas are tracked
    let v = db.verify_table(t).unwrap();
    assert_eq!((v.rows, v.slots), (5, 6));
    let ep = FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap().epoch;
    db.transaction(|db| -> Result<(), Error> {
        db.insert(t, vec![("id", ci(20)), ("dept", ci(1)), ("rate", ci(3)), ("note", CellIn::Str("t".into()))])?;
        db.update(t, vec![("rate", ci(4))], id_is(20))?;
        Ok(())
    })
    .unwrap();
    assert_eq!(FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap().epoch, ep + 1); // one anchor epoch for the whole transaction
    let mut other = owner(&s.addr, Some(&p)); // a fresh owner (new process) rescans once and agrees
    assert_eq!(int(other.sum(t, "rate", all()).unwrap()), 1 + 2 + 4 + 99 + 40 + 30);
    assert_eq!(other.anchor_stats().0, 1);
}

#[test]
fn mixed_tables_and_plain_only_tables_work_under_an_anchor() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = owner(&s.addr, Some(&p));
    db.create_table("mix", vec![col("id", "int", "plain"), col("x", "int", "paired"), col("y", "int", "fhe")]).unwrap();
    db.create_table("po", vec![col("id", "int", "plain"), col("s", "int", "encrypted")]).unwrap();
    db.insert("mix", vec![("id", ci(1)), ("x", ci(6)), ("y", ci(7))]).unwrap();
    db.insert("mix", vec![("id", ci(2)), ("x", ci(2)), ("y", ci(3))]).unwrap();
    db.insert("po", vec![("id", ci(1)), ("s", ci(5))]).unwrap();
    assert_eq!(int(db.sum("mix", "y", all()).unwrap()), 10);
    assert_eq!(int(db.sum("mix", "x", all()).unwrap()), 8);
    assert_eq!(int(db.dot("mix", "x", "x", all()).unwrap()), 40);
    assert_eq!(int(db.sum("po", "s", all()).unwrap()), 5);
    assert!(FileAnchor::new(&p).unwrap().get("po").unwrap().is_none()); // no FHE column: not anchored
    db.update("mix", vec![("x", ci(9)), ("y", ci(1))], id_is(1)).unwrap();
    assert_eq!(int(db.sum("mix", "x", all()).unwrap()), 11);
    assert_eq!(db.verify_table("mix").unwrap().rows, 2);
}

#[test]
fn drop_recreate_resets_the_anchor_rolled_back_create_leaves_nothing_failed_statement_rolls_back() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = owner(&s.addr, Some(&p));
    let a = FileAnchor::new(&p).unwrap();
    db.create_table("dr", cols()).unwrap();
    db.insert("dr", row(1, 1, 1)).unwrap();
    db.drop_table("dr").unwrap();
    assert!(a.get("dr").unwrap().is_none());
    db.create_table("dr", cols()).unwrap();
    let e = a.get("dr").unwrap().unwrap();
    assert_eq!((e.root, e.count), (big(0), 0));
    db.insert("dr", row(1, 1, 5)).unwrap();
    assert_eq!(int(db.sum("dr", "rate", all()).unwrap()), 5);
    db.begin().unwrap();
    db.create_table("rb", cols()).unwrap();
    db.rollback().unwrap();
    assert!(a.get("rb").unwrap().is_none());
    assert!(!db.tables().unwrap().contains(&"rb".to_string()));
    let ep = a.get("dr").unwrap().unwrap().epoch;
    db.insert("dr", row(2, 1, 6)).unwrap();
    assert_eq!(kind_of(db.update("dr", vec![("rate", ci(10_000_000))], all())), Kind::OutOfBudget);
    assert_eq!(a.get("dr").unwrap().unwrap().epoch, ep + 1);
    assert_eq!(int(db.sum("dr", "rate", all()).unwrap()), 11);
    assert_eq!(db.verify_table("dr").unwrap().rows, 2);
}

#[test]
fn scan_is_chunked_by_hello_limits_and_the_size_guard_refuses_oversized_tables() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    seeded(&s.addr, Some(&p), "ch");
    let px = Proxy::start(s.addr.clone());
    px.on_resp(|r, resp| {
        if r["m"] == "hello" {
            let mut v = resp.clone();
            v["ok"]["limits"]["fhe"]["max_scan_rows"] = json!(2);
            return Resp::Replace(v);
        }
        Resp::Keep
    });
    let mut small = owner(&px.addr, Some(&p));
    assert_eq!(small.verify_table("ch").unwrap().rows, 4);
    assert_eq!(px.seen_since(0, "fhe_rows"), 3); // 2 + 2 + terminal
    let mut o = opts(Some(&p));
    o.integrity_anchor_max_rows = Some(3);
    let mut guard = Client::connect_with(&s.addr, &o).unwrap();
    let e = guard.verify_table("ch").unwrap_err();
    assert!(e.kind == Kind::Interface && e.message.contains("limit"), "{}", e);
}

#[test]
fn adopt_a_preexisting_table_is_refused_until_adopted_and_honest_only_as_of_that_moment() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let _plain = seeded(&s.addr, None, "old");
    let mut a = owner(&s.addr, Some(&p));
    assert_eq!(kind_of(a.sum("old", "rate", all())), Kind::AnchorMissing);
    assert_eq!(kind_of(a.count("old", all())), Kind::AnchorMissing);
    a.trust_table("old").unwrap();
    let r = a.adopt_table("old", false).unwrap();
    assert_eq!((r.rows, r.slots), (4, 4));
    assert_eq!(dept5(&mut a, "old").unwrap(), (115, 3));
    assert!(a.adopt_table("old", false).unwrap_err().message.contains("already has an anchor entry"));
    // a lie told AT adoption becomes the truth
    raw_rpc(&s.addr, "delete_rows", json!(["old", [0]]));
    assert!(is_integrity(&kind_of(a.verify_table("old"))));
    assert_eq!(a.adopt_table("old", true).unwrap().rows, 3);
    assert_eq!(dept5(&mut a, "old").unwrap(), (75, 2)); // pinned: the lie is now the anchored state
}

// ── the attacks ──────────────────────────────────────────────────────────────
#[test]
fn selection_lie_undetected_without_an_anchor_irrelevant_with_one() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    seeded(&s.addr, Some(&p), "sl");
    let px = Proxy::start(s.addr.clone());
    px.on_resp(|r, resp| {
        if r["m"] == "matching_rowids" {
            if let Some(a) = resp["ok"].as_array() {
                return Resp::Replace(json!({"ok": a[..a.len() - 1]}));
            }
        }
        Resp::Keep
    });
    let mut control = owner(&px.addr, None);
    control.trust_table("sl").unwrap();
    assert_eq!(dept5(&mut control, "sl").unwrap(), (95, 2)); // WRONG, silently (true: 115, 3)
    let mut anchored = owner(&px.addr, Some(&p));
    let n0 = px.seen_len();
    assert_eq!(dept5(&mut anchored, "sl").unwrap(), (115, 3)); // right: the row set comes from the anchor
    assert_eq!(px.seen_since(n0, "matching_rowids"), 0);
}

#[test]
fn lying_scan_dropped_slot_dead_flag_extra_row_shape_forged_hash_forged_plain_value() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    seeded(&s.addr, Some(&p), "ls");
    let px = Proxy::start(s.addr.clone());
    let mode = Arc::new(Mutex::new(String::new()));
    let m2 = mode.clone();
    px.on_resp(move |r, resp| {
        let md = m2.lock().unwrap().clone();
        let rows = resp["ok"]["rows"].as_array().cloned().unwrap_or_default();
        if r["m"] != "fhe_rows" || md.is_empty() || rows.is_empty() {
            return Resp::Keep;
        }
        let edit = |f: &dyn Fn(&Value) -> Value| json!({"ok": {"n": resp["ok"]["n"], "rows": rows.iter().map(f).collect::<Vec<_>>()}});
        let at = |x: &Value, i: i64| x[0].as_i64() == Some(i);
        Resp::Replace(match md.as_str() {
            "dropped" => json!({"ok": {"n": resp["ok"]["n"], "rows": rows.iter().filter(|x| !at(x, 1)).cloned().collect::<Vec<_>>()}}),
            "dead" => edit(&|x| if at(x, 1) { json!([1, 1]) } else { x.clone() }),
            "extra" => {
                let mut v = rows.clone();
                v.push(json!([rows.len(), 0, rows[0][2], rows[0][3]]));
                json!({"ok": {"n": resp["ok"]["n"], "rows": v}})
            }
            "shape" => edit(&|x| if at(x, 0) { json!([0, 0, [x[2][0]], x[3]]) } else { x.clone() }),
            "hash" => edit(&|x| if at(x, 2) { json!([2, 0, x[2], [[x[3][0][0], "00".repeat(32), x[3][0][2]]]]) } else { x.clone() }),
            "plain" => edit(&|x| if at(x, 3) { json!([3, 0, [x[2][0], {"t": "i", "v": "6"}], x[3]]) } else { x.clone() }),
            "nonce" => edit(&|x| if at(x, 3) { json!([3, 0, x[2], [[{"t": "i", "v": "5"}, x[3][0][1], x[3][0][2]]]]) } else { x.clone() }),
            _ => edit(&|x| if at(x, 0) { json!([0, 0, x[2], [[{"t": "s", "v": "x"}, x[3][0][1], x[3][0][2]]]]) } else { x.clone() }),
        })
    });
    for m in ["dropped", "dead", "extra", "shape", "hash", "plain", "nonce", "junk"] {
        *mode.lock().unwrap() = m.to_string();
        let mut x = owner(&px.addr, Some(&p));
        let e = x.verify_table("ls").unwrap_err();
        assert!(is_integrity(&e.kind), "{}: {}", m, e);
    }
    *mode.lock().unwrap() = String::new();
    let mut ok = owner(&px.addr, Some(&p));
    assert_eq!(ok.verify_table("ls").unwrap().rows, 4);
}

#[test]
fn the_server_adds_a_row_invisible_to_a_cached_owner_caught_by_the_next_scan() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "ad");
    let mut plain = owner(&s.addr, None);
    plain.trust_table("ad").unwrap();
    raw_add_row(&s.addr, "ad", 9, 5, 1000);
    assert_eq!(dept5(&mut db, "ad").unwrap(), (115, 3)); // the cached owner never asks the server for the row set
    let mut fresh = owner(&s.addr, Some(&p));
    assert!(is_integrity(&kind_of(dept5(&mut fresh, "ad"))));
    assert!(is_integrity(&kind_of(fresh.verify_table("ad"))));
    assert_eq!(plain.count("ad", dept(5)).unwrap(), 4); // control: COUNT silently includes the planted row
    assert!(is_integrity(&kind_of(plain.sum("ad", "rate", all())))); // (its fake tag is caught by the tags alone)
}

#[test]
fn the_server_hides_a_row_via_delete_rows_caught_without_an_anchor_the_count_shrinks() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let _db = seeded(&s.addr, Some(&p), "hr");
    raw_rpc(&s.addr, "delete_rows", json!(["hr", [1]]));
    let mut fresh = owner(&s.addr, Some(&p));
    assert!(is_integrity(&kind_of(dept5(&mut fresh, "hr"))));
    let mut plain = owner(&s.addr, None);
    assert_eq!(dept5(&mut plain, "hr").unwrap(), (60, 2)); // control: silently wrong
}

#[test]
fn the_server_hides_a_delete_by_swallowing_delete_rows() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let px = Proxy::start(s.addr.clone());
    let mk = |file: Option<&PathBuf>, t: &str| seeded(&px.addr, file, t);
    let mut a = mk(Some(&p), "hd_a");
    let mut c = mk(None, "hd_c");
    px.on_req(|r| if r["m"] == "delete_rows" { Req::Reply(json!({"ok": r["a"][1].as_array().unwrap().len()})) } else { Req::Forward });
    assert_eq!(a.delete_rows("hd_a", id_is(1)).unwrap(), 1);
    assert_eq!(c.delete_rows("hd_c", id_is(1)).unwrap(), 1);
    px.clear();
    assert_eq!(dept5(&mut c, "hd_c").unwrap(), (115, 3)); // control: the "deleted" row is still there
    let mut fresh = owner(&s.addr, Some(&p));
    assert!(is_integrity(&kind_of(dept5(&mut fresh, "hd_a")))); // (the un-deleted state is the PREVIOUS epoch: stale)
}

#[test]
fn whole_table_rollback_is_a_stale_server_error_control_silently_accepted() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "rbk");
    let old = cells(&s.addr, "rbk", 0);
    db.update("rbk", vec![("rate", ci(41))], id_is(1)).unwrap();
    assert_eq!(int(db.sum("rbk", "rate", id_is(1)).unwrap()), 41);
    let mut plain = owner(&s.addr, None);
    plain.trust_table("rbk").unwrap();
    restore(&s.addr, "rbk", 0, &old); // the server restores a backup
    let mut fresh = owner(&s.addr, Some(&p));
    let e = fresh.sum("rbk", "rate", all()).unwrap_err();
    assert_eq!(e.kind, Kind::StaleServer, "{}", e);
    assert!(e.message.contains("behind the anchor"));
    assert_eq!(int(plain.sum("rbk", "rate", id_is(1)).unwrap()), 40); // control: the old value is served and every tag verifies
    // rolling back an INSERT (tombstoning the new row) is the same older state
    let q = anchor_file();
    let mut d2 = seeded(&s.addr, Some(&q), "rbk2");
    d2.insert("rbk2", row(5, 5, 5)).unwrap();
    raw_rpc(&s.addr, "delete_rows", json!(["rbk2", [4]]));
    let mut f2 = owner(&s.addr, Some(&q));
    assert_eq!(kind_of(f2.count("rbk2", all())), Kind::StaleServer);
}

#[test]
fn replay_of_one_old_row_version_is_caught_the_control_accepts_the_stale_value() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "rp");
    let old = cells(&s.addr, "rp", 0);
    db.update("rp", vec![("rate", ci(41))], id_is(1)).unwrap();
    db.update("rp", vec![("rate", ci(56))], id_is(2)).unwrap(); // so the state matches NO older epoch
    restore(&s.addr, "rp", 0, &old);
    let mut plain = owner(&s.addr, None);
    plain.trust_table("rp").unwrap();
    assert_eq!(int(plain.sum("rp", "rate", id_is(1)).unwrap()), 40); // control: silently stale
    let mut fresh = owner(&s.addr, Some(&p));
    assert_eq!(kind_of(fresh.sum("rp", "rate", all())), Kind::Integrity); // not "stale": it matches no earlier epoch
    // the cached owner notices at the cell level: the stored bytes differ from the anchored hashes
    assert_eq!(kind_of(db.select("rp", &["rate"], id_is(1))), Kind::Integrity);
    assert_eq!(kind_of(db.sum("rp", "rate", all())), Kind::Integrity);
}

#[test]
fn swapped_rows_plain_dept_exchanged_by_the_server() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "sw");
    raw_rpc(&s.addr, "update_cell", json!(["sw", 0, "dept", ints(7)]));
    raw_rpc(&s.addr, "update_cell", json!(["sw", 2, "dept", ints(5)]));
    let mut plain = owner(&s.addr, None);
    plain.trust_table("sw").unwrap();
    assert_eq!(dept5(&mut plain, "sw").unwrap(), (105, 3)); // control: silently different rows
    let mut fresh = owner(&s.addr, Some(&p));
    assert!(is_integrity(&kind_of(dept5(&mut fresh, "sw"))));
    assert_eq!(dept5(&mut db, "sw").unwrap(), (115, 3)); // the cached owner keeps answering from the anchored plain values
}

#[test]
fn honest_scan_other_cells_later_are_refused() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let _db = seeded(&s.addr, Some(&p), "oc");
    let px = Proxy::start(s.addr.clone());
    let mut o = owner(&px.addr, Some(&p));
    assert_eq!(o.verify_table("oc").unwrap().rows, 4);
    let other = raw_rpc(&s.addr, "plain_cells", json!(["oc", "rate", [3]]))["ok"][0].clone();
    px.on_resp(move |r, resp| {
        if r["m"] == "plain_cells" && r["a"][1] == "rate" {
            if let Some(a) = resp["ok"].as_array() {
                return Resp::Replace(json!({"ok": a.iter().map(|_| other.clone()).collect::<Vec<_>>()}));
            }
        }
        Resp::Keep
    });
    assert_eq!(kind_of(o.select("oc", &["rate"], id_is(1))), Kind::Integrity);
    px.clear();
    assert_eq!(o.select("oc", &["rate"], id_is(1)).unwrap(), vec![vec![ci(40)]]);
}

#[test]
fn local_dot_under_an_anchor_catches_a_tampered_operand_cell() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "ld");
    assert_eq!(int(db.dot("ld", "rate", "rate", all()).unwrap()), 40 * 40 + 55 * 55 + 30 * 30 + 20 * 20);
    raw_rpc(&s.addr, "update_cell", json!(["ld", 1, "rate", xc(&key().encrypt(1).unwrap())]));
    assert_eq!(kind_of(db.dot("ld", "rate", "rate", all())), Kind::Integrity);
}

// ── commit protocol ──────────────────────────────────────────────────────────
#[test]
fn lost_commit_reply_committed_is_finished_lost_before_processing_is_aborted() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let px = Proxy::start(s.addr.clone());
    let mut db = owner(&px.addr, Some(&p));
    db.create_table("lc", cols()).unwrap();
    db.insert("lc", row(1, 5, 10)).unwrap();
    let a = FileAnchor::new(&p).unwrap();
    let ep = a.get("lc").unwrap().unwrap().epoch;
    px.on_resp(|r, _| if r["m"] == "tx_commit" { Resp::Drop } else { Resp::Keep }); // forwarded, reply lost
    db.insert("lc", row(2, 5, 20)).unwrap(); // the driver reconnects and asks tx_status
    px.clear();
    let e = a.get("lc").unwrap().unwrap();
    assert_eq!((e.epoch, e.pending.is_none()), (ep + 1, true));
    assert_eq!(dept5(&mut db, "lc").unwrap(), (30, 2));
    assert_eq!(db.verify_table("lc").unwrap().rows, 2);
    px.on_req(|r| if r["m"] == "tx_commit" { Req::Kill } else { Req::Forward }); // never reached the server
    assert!(db.insert("lc", row(3, 5, 30)).is_err());
    px.clear();
    let e = a.get("lc").unwrap().unwrap();
    assert_eq!((e.epoch, e.pending.is_none()), (ep + 1, true));
    assert_eq!(dept5(&mut db, "lc").unwrap(), (30, 2));
    assert_eq!(db.verify_table("lc").unwrap().rows, 2);
    db.insert("lc", row(4, 5, 40)).unwrap();
    assert_eq!(dept5(&mut db, "lc").unwrap(), (70, 3));
}

#[test]
fn in_doubt_pending_stays_in_the_anchor_and_the_next_connect_settles_it() {
    let Some(s) = server() else { return };
    for committed in [true, false] {
        let p = anchor_file();
        let px = Proxy::start(s.addr.clone());
        let t = if committed { "id_c" } else { "id_n" };
        let mut db = owner(&px.addr, Some(&p));
        db.create_table(t, cols()).unwrap();
        db.insert(t, row(1, 5, 10)).unwrap();
        let ep = FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap().epoch;
        let refuse = px.refuse.clone();
        if committed {
            px.on_resp(move |r, _| if r["m"] == "tx_commit" { refuse.store(true, Ordering::SeqCst); Resp::Drop } else { Resp::Keep });
        } else {
            px.on_req(move |r| if r["m"] == "tx_commit" { refuse.store(true, Ordering::SeqCst); Req::Kill } else { Req::Forward });
        }
        assert_eq!(kind_of(db.insert(t, row(2, 5, 20))), Kind::TransactionInDoubt);
        let e1 = FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap();
        assert_eq!(e1.epoch, ep);
        assert_eq!(e1.pending.unwrap().epoch, ep + 1); // the anchor remembers what was about to happen
        drop(db);
        drop(px);
        let mut again = owner(&s.addr, Some(&p)); // direct connection
        let e2 = FileAnchor::new(&p).unwrap().get(t).unwrap().unwrap();
        assert!(e2.pending.is_none());
        assert_eq!(e2.epoch, if committed { ep + 1 } else { ep });
        assert_eq!(dept5(&mut again, t).unwrap(), if committed { (30, 2) } else { (10, 1) });
        assert_eq!(again.verify_table(t).unwrap().rows, if committed { 2 } else { 1 });
    }
}

#[test]
fn a_pending_record_whose_state_is_neither_old_nor_new_is_an_integrity_error_on_connect() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let px = Proxy::start(s.addr.clone());
    let mut db = seeded(&px.addr, Some(&p), "pn");
    let refuse = px.refuse.clone();
    px.on_resp(move |r, _| if r["m"] == "tx_commit" { refuse.store(true, Ordering::SeqCst); Resp::Drop } else { Resp::Keep });
    assert_eq!(kind_of(db.insert("pn", row(9, 5, 9))), Kind::TransactionInDoubt);
    drop(db);
    drop(px);
    assert!(FileAnchor::new(&p).unwrap().get("pn").unwrap().unwrap().pending.is_some());
    raw_rpc(&s.addr, "delete_rows", json!(["pn", [0]])); // the server then tampers
    let e = Client::connect_with(&s.addr, &opts(Some(&p))).unwrap_err();
    assert!(is_integrity(&e.kind) && e.message.contains("does not match the anchor"), "{}", e);
}

#[test]
fn two_owners_share_one_anchor_file_and_a_foreign_epoch_advance_aborts_an_open_transaction() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut a = seeded(&s.addr, Some(&p), "tw");
    let mut b = owner(&s.addr, Some(&p));
    b.trust_table("tw").unwrap();
    assert_eq!(dept5(&mut b, "tw").unwrap(), (115, 3));
    b.insert("tw", row(9, 5, 1)).unwrap();
    assert_eq!(dept5(&mut a, "tw").unwrap(), (116, 4)); // a notices the epoch moved and rescans
    a.insert("tw", row(10, 5, 2)).unwrap();
    assert_eq!(dept5(&mut b, "tw").unwrap(), (118, 5));
    a.begin().unwrap();
    a.insert("tw", row(11, 5, 3)).unwrap();
    let f = FileAnchor::new(&p).unwrap();
    let e = f.get("tw").unwrap().unwrap();
    f.begin_commit(&BTreeMap::from([("tw".to_string(), AnchorChange { expect_epoch: Some(e.epoch), root: Some(e.root.clone()), count: e.count })]), Some("other")).unwrap();
    f.finish_commit(&["tw".into()], Some("other")).unwrap();
    assert_eq!(kind_of(a.commit()), Kind::AnchorConflict);
    assert!(!a.in_transaction());
    assert_eq!(b.table_info("tw").unwrap().rows, 6); // the server rolled a's insert back
}

// ── Python <-> Rust, one anchor file, one server ─────────────────────────────
#[test]
fn cross_implementation_python_verifies_what_rust_wrote_and_back_on_one_anchor_file() {
    let Some(s) = server() else { return };
    let p = anchor_file();
    let mut db = seeded(&s.addr, Some(&p), "xan");
    db.update("xan", vec![("rate", ci(41))], id_is(1)).unwrap();
    db.delete_rows("xan", id_is(3)).unwrap();
    let q = |sql: &str| json!(["query", sql]);
    let res = run_peer(
        "127.0.0.1",
        s.port,
        &json!({"key": secret(), "range": 100000, "auth": true, "anchor": p.to_str().unwrap(), "ops": [
            ["verify", "xan"],
            q("SELECT SUM(rate), AVG(rate), COUNT(*) FROM xan WHERE dept = 5"),
            q("SELECT id, rate FROM xan WHERE id = 1"),
            ["exec", "INSERT INTO xan (id, dept, rate) VALUES (5, 5, 7)"],
            ["exec", "UPDATE xan SET rate = 77 WHERE id = 2"],
            ["exec", "DELETE FROM xan WHERE id = 4"],
            ["verify", "xan"]]}),
    );
    assert_eq!((res[0]["rows"].clone(), res[0]["slots"].clone()), (json!(3), json!(4)));
    assert_eq!(res[1], json!([[116, "116/3", 3]]));
    assert_eq!(res[2], json!([[1, 41]]));
    assert_eq!((res[3]["rows"].clone(), res[3]["slots"].clone()), (json!(3), json!(5)));
    assert_eq!(dept5(&mut db, "xan").unwrap(), (41 + 77 + 7, 3));
    assert_eq!(db.verify_table("xan").unwrap().rows, 3);
    db.insert("xan", row(6, 6, 6)).unwrap();
    let fin = run_peer("127.0.0.1", s.port, &json!({"key": secret(), "range": 100000, "auth": true, "anchor": p.to_str().unwrap(),
        "ops": [["verify", "xan"], q("SELECT COUNT(*) FROM xan")]}));
    assert_eq!(fin[0]["rows"], json!(4));
    assert_eq!(fin[1], json!([[4]]));
    // a Python-created table is read by Rust under the same anchor
    run_peer("127.0.0.1", s.port, &json!({"key": secret(), "range": 100000, "auth": true, "anchor": p.to_str().unwrap(), "ops": [
        ["exec", "CREATE TABLE pyc (id INT PLAIN, dept INT PLAIN, rate INT FHE)"],
        ["exec", "INSERT INTO pyc (id, dept, rate) VALUES (1, 5, 11)"], ["exec", "INSERT INTO pyc (id, dept, rate) VALUES (2, 5, 22)"]]}));
    db.sync_schema().unwrap();
    db.trust_table("pyc").unwrap();
    assert_eq!(dept5(&mut db, "pyc").unwrap(), (33, 2));
    assert_eq!(db.verify_table("pyc").unwrap().rows, 2);
}
