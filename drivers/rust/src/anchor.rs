// SPDX-License-Identifier: Apache-2.0
//! Anchored table-state integrity for authenticated FHE tables (port of `core/torusdb_core/fhe_anchor.py`).
//!
//! Tags make a changed VALUE detectable; they cannot tell the owner which rows exist or whether the table
//! is current. That needs a little owner-trusted state, the ANCHOR: per table `{epoch, root, count, pending}`.
//! `leaf(row) = PRF(K_anchor, table, rowid, canonical(row)) mod n`, `root = Σ leaf over live rows`. The
//! server cannot compute a leaf, so the only state it can present whose leaves sum to `root` is the anchored
//! one. [`FileAnchor`] is byte-compatible with the Python implementation (same JSON layout, 0600, temp file +
//! fsync + rename, `flock` on `<path>.lock`, epoch compare-and-swap, `pending`, last 8 roots), so a Python,
//! TypeScript or Rust owner can alternate on one anchor file.

use crate::error::{Error, Kind};
use crate::field::md;
use crate::hash::sha256;
use crate::{atom_matches, big, uwv, CellIn, Client};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, Error>;

pub const ANCHOR_FORMAT: &str = "torussql-fhe-anchor";
pub const ANCHOR_FORMAT_VERSION: i64 = 1;
pub const ANCHOR_HISTORY: usize = 8;
const MAX_FILE: u64 = 64 << 20;
const DEFAULT_MAX_ROWS: usize = 1_000_000;

fn integrity(m: impl Into<String>) -> Error {
    Error::new(Kind::Integrity, m)
}
fn file_err(m: impl Into<String>) -> Error {
    Error::new(Kind::AnchorFile, m)
}
fn conflict(m: impl Into<String>) -> Error {
    Error::new(Kind::AnchorConflict, m)
}

// ── anchor state ─────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// the epoch the table gets when the commit succeeds
    pub epoch: u64,
    pub root: BigInt,
    pub count: u64,
    /// the server transaction (lets another owner tell "in flight" from "dead")
    pub txid: Option<String>,
    /// the commit removes the table
    pub drop: bool,
    /// the entry itself was created by this pending commit
    pub created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub epoch: u64,
    pub root: BigInt,
    pub count: u64,
    pub pending: Option<Pending>,
    /// `(epoch, root, count)`, newest last (at most 8)
    pub history: Vec<(u64, BigInt, u64)>,
}

/// One table's part of a commit. `expect_epoch: None` = the anchor must not know the table yet;
/// `root: None` drops the table.
#[derive(Clone, Debug)]
pub struct Change {
    pub expect_epoch: Option<u64>,
    pub root: Option<BigInt>,
    pub count: u64,
}

/// The owner-trusted store. All operations are atomic; `expect_*` arguments are compare-and-swap. The
/// contract a custodian-quorum-backed implementation must provide: every change is a CAS on the epoch;
/// `begin_commit` records the NEW state as `pending` BEFORE the owner asks the server to commit;
/// `finish_commit` / `abort` settle it afterwards.
pub trait Anchor: Send + Sync {
    fn get(&self, table: &str) -> Result<Option<Entry>>;
    fn tables(&self) -> Result<Vec<String>>;
    fn begin_commit(&self, changes: &BTreeMap<String, Change>, txid: Option<&str>) -> Result<()>;
    fn finish_commit(&self, tables: &[String], txid: Option<&str>) -> Result<()>;
    fn abort(&self, tables: &[String], txid: Option<&str>) -> Result<()>;
    fn set(&self, table: &str, root: &BigInt, count: u64, expect_epoch: Option<u64>) -> Result<Entry>;
    fn remove(&self, table: &str, expect_epoch: Option<u64>) -> Result<()>;
}

type State = BTreeMap<String, Entry>;

fn op_begin(st: &mut State, changes: &BTreeMap<String, Change>, txid: Option<&str>) -> Result<()> {
    for (t, ch) in changes {
        match st.get(t) {
            None => {
                if let Some(e) = ch.expect_epoch {
                    return Err(conflict(format!("anchor: {} has no entry (expected epoch {})", t, e)));
                }
            }
            Some(e) if Some(e.epoch) != ch.expect_epoch => {
                return Err(conflict(format!(
                    "anchor: {} is at epoch {}, the transaction was based on {:?} (another owner committed)",
                    t, e.epoch, ch.expect_epoch
                )))
            }
            Some(e) if e.pending.is_some() => return Err(conflict(format!("anchor: {} already has a pending commit", t))),
            _ => {}
        }
    }
    for (t, ch) in changes {
        let created = !st.contains_key(t);
        let mut e = st.get(t).cloned().unwrap_or(Entry { epoch: 0, root: BigInt::zero(), count: 0, pending: None, history: vec![] });
        e.pending = Some(Pending {
            epoch: e.epoch + 1,
            root: md(ch.root.as_ref().unwrap_or(&BigInt::zero())),
            count: ch.count,
            txid: txid.map(String::from),
            drop: ch.root.is_none(),
            created,
        });
        st.insert(t.clone(), e);
    }
    Ok(())
}

fn push_hist(e: &Entry) -> Vec<(u64, BigInt, u64)> {
    let mut h = e.history.clone();
    h.push((e.epoch, e.root.clone(), e.count));
    if h.len() > ANCHOR_HISTORY {
        h.drain(..h.len() - ANCHOR_HISTORY);
    }
    h
}

fn op_finish(st: &mut State, tables: &[String], txid: Option<&str>) -> Result<()> {
    let mut todo = vec![];
    for t in tables {
        let Some(e) = st.get(t) else { continue };
        let Some(p) = &e.pending else { continue }; // already settled
        if txid.is_some() && p.txid.as_deref() != txid {
            return Err(conflict(format!("anchor: {} has a pending commit of another transaction", t)));
        }
        todo.push(t.clone());
    }
    for t in todo {
        let e = st[&t].clone();
        let p = e.pending.clone().unwrap();
        if p.drop {
            st.remove(&t);
            continue;
        }
        let hist = push_hist(&e);
        st.insert(t, Entry { epoch: p.epoch, root: p.root, count: p.count, pending: None, history: hist });
    }
    Ok(())
}

fn op_abort(st: &mut State, tables: &[String], txid: Option<&str>) -> Result<()> {
    for t in tables {
        let Some(e) = st.get(t).cloned() else { continue };
        let Some(p) = &e.pending else { continue };
        if txid.is_some() && p.txid.as_deref() != txid {
            continue;
        }
        if p.created {
            st.remove(t);
        } else {
            st.insert(t.clone(), Entry { pending: None, ..e });
        }
    }
    Ok(())
}

fn op_set(st: &mut State, table: &str, root: &BigInt, count: u64, expect: Option<u64>) -> Result<Entry> {
    let e = st.get(table).cloned();
    if e.as_ref().map(|e| e.epoch) != expect {
        return Err(conflict(format!("anchor: {} changed (expected epoch {:?})", table, expect)));
    }
    if e.as_ref().is_some_and(|e| e.pending.is_some()) {
        return Err(conflict(format!("anchor: {} has a pending commit", table)));
    }
    let ne = Entry {
        epoch: e.as_ref().map(|e| e.epoch + 1).unwrap_or(0),
        root: md(root),
        count,
        pending: None,
        history: e.as_ref().map(push_hist).unwrap_or_default(),
    };
    st.insert(table.to_string(), ne.clone());
    Ok(ne)
}

fn op_remove(st: &mut State, table: &str, expect: Option<u64>) -> Result<()> {
    let Some(e) = st.get(table) else { return Ok(()) };
    if expect.is_some_and(|x| x != e.epoch) {
        return Err(conflict(format!("anchor: {} changed (expected epoch {:?})", table, expect)));
    }
    st.remove(table);
    Ok(())
}

macro_rules! impl_anchor {
    ($ty:ty) => {
        impl Anchor for $ty {
            fn get(&self, table: &str) -> Result<Option<Entry>> {
                self.atomic(|st| Ok(st.get(table).cloned()), false)
            }
            fn tables(&self) -> Result<Vec<String>> {
                self.atomic(|st| Ok(st.keys().cloned().collect()), false)
            }
            fn begin_commit(&self, changes: &BTreeMap<String, Change>, txid: Option<&str>) -> Result<()> {
                if changes.is_empty() {
                    return Ok(());
                }
                self.atomic(|st| op_begin(st, changes, txid), true)
            }
            fn finish_commit(&self, tables: &[String], txid: Option<&str>) -> Result<()> {
                self.atomic(|st| op_finish(st, tables, txid), true)
            }
            fn abort(&self, tables: &[String], txid: Option<&str>) -> Result<()> {
                self.atomic(|st| op_abort(st, tables, txid), true)
            }
            fn set(&self, table: &str, root: &BigInt, count: u64, expect: Option<u64>) -> Result<Entry> {
                self.atomic(|st| op_set(st, table, root, count, expect), true)
            }
            fn remove(&self, table: &str, expect: Option<u64>) -> Result<()> {
                self.atomic(|st| op_remove(st, table, expect), true)
            }
        }
    };
}

/// In-memory anchor (tests, single-process experiments). Lost with the process.
#[derive(Default)]
pub struct MemoryAnchor {
    st: Mutex<State>,
}

impl MemoryAnchor {
    pub fn new() -> MemoryAnchor {
        MemoryAnchor::default()
    }
    fn atomic<T>(&self, f: impl FnOnce(&mut State) -> Result<T>, write: bool) -> Result<T> {
        let mut g = self.st.lock().unwrap();
        let mut work = g.clone();
        let out = f(&mut work)?;
        if write {
            *g = work;
        }
        Ok(out)
    }
}
impl_anchor!(MemoryAnchor);

// ── the file anchor ──────────────────────────────────────────────────────────
#[cfg(unix)]
mod sys {
    use std::os::raw::c_int;
    extern "C" {
        pub fn flock(fd: c_int, operation: c_int) -> c_int;
        pub fn geteuid() -> u32;
    }
}

/// JSON file, mode 0600, versioned; writes are crash-safe (temp file created O_EXCL, fsync, atomic rename,
/// fsync of the directory). Several owner PROCESSES (Python, TypeScript, Rust) may share the file: an
/// advisory `flock` on `<path>.lock` serialises read-modify-write. Refuses a symlink, a file that is not
/// ours, lax permissions, malformed content and unknown versions - it never silently starts from an empty
/// state when the file is damaged. Keep it where the server cannot reach, and back it up like the FHE key.
#[derive(Clone, Debug)]
pub struct FileAnchor {
    path: PathBuf,
}

struct LockGuard(#[allow(dead_code)] std::fs::File);

impl FileAnchor {
    pub fn new(path: impl AsRef<Path>) -> Result<FileAnchor> {
        let mut p = path.as_ref().to_path_buf();
        if !p.is_absolute() {
            p = std::env::current_dir().map_err(|e| file_err(e.to_string()))?.join(p);
        }
        let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
        if !dir.is_dir() {
            return Err(file_err(format!("anchor directory {} does not exist", dir.display())));
        }
        Ok(FileAnchor { path: p })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn check_meta(m: &std::fs::Metadata, what: &str) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        if !m.is_file() {
            return Err(file_err(format!("{} is not a regular file", what)));
        }
        if m.uid() != unsafe { sys::geteuid() } {
            return Err(file_err(format!("{} is owned by another user", what)));
        }
        if m.mode() & 0o077 != 0 {
            return Err(file_err(format!(
                "{} has lax permissions ({:o}); chmod 600 it (it is the owner's trust root)",
                what,
                m.mode() & 0o777
            )));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    fn check_meta(m: &std::fs::Metadata, what: &str) -> Result<()> {
        if !m.is_file() {
            return Err(file_err(format!("{} is not a regular file", what)));
        }
        Ok(())
    }

    fn read(&self) -> Result<State> {
        let lm = match std::fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::new()),
            Err(e) => return Err(file_err(format!("cannot open the anchor file {}: {}", self.path.display(), e))),
        };
        if lm.file_type().is_symlink() {
            return Err(file_err(format!("anchor file {} is a symlink", self.path.display())));
        }
        let mut f = std::fs::File::open(&self.path)
            .map_err(|e| file_err(format!("cannot open the anchor file {}: {}", self.path.display(), e)))?;
        let fm = f.metadata().map_err(|e| file_err(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if fm.ino() != lm.ino() || fm.dev() != lm.dev() {
                return Err(file_err("the anchor file changed while it was being opened"));
            }
        }
        Self::check_meta(&fm, &format!("anchor file {}", self.path.display()))?;
        if fm.len() > MAX_FILE {
            return Err(file_err("anchor file is implausibly large"));
        }
        let mut raw = vec![];
        std::io::Read::read_to_end(&mut f, &mut raw).map_err(|e| file_err(e.to_string()))?;
        let corrupt = |why: String| {
            file_err(format!(
                "anchor file {} is corrupt ({}); restore it from a backup - refusing to start from an empty state",
                self.path.display(),
                why
            ))
        };
        let doc: Value = serde_json::from_slice(&raw).map_err(|e| corrupt(e.to_string()))?;
        if doc["format"] != json!(ANCHOR_FORMAT) {
            return Err(corrupt("not an anchor file".into()));
        }
        if doc["v"] != json!(ANCHOR_FORMAT_VERSION) {
            return Err(file_err(format!(
                "anchor file version {} is not supported (this build reads version {})",
                doc["v"], ANCHOR_FORMAT_VERSION
            )));
        }
        let tables = doc["tables"].as_object().ok_or_else(|| corrupt("tables".into()))?;
        let mut st = State::new();
        for (t, e) in tables {
            st.insert(t.clone(), dec_entry(e).map_err(|m| file_err(format!("anchor entry is malformed ({})", m)))?);
        }
        Ok(st)
    }

    fn write(&self, st: &State) -> Result<()> {
        use std::io::Write;
        let tables: serde_json::Map<String, Value> = st.iter().map(|(t, e)| (t.clone(), enc_entry(e))).collect();
        let doc = json!({"format": ANCHOR_FORMAT, "v": ANCHOR_FORMAT_VERSION, "tables": tables});
        let body = serde_json::to_vec_pretty(&doc).map_err(|e| file_err(e.to_string()))?;
        let tmp = PathBuf::from(format!("{}.tmp.{}.{:08x}", self.path.display(), std::process::id(), rand::random::<u32>()));
        let io = |e: std::io::Error| file_err(format!("cannot write the anchor file: {}", e));
        let res = (|| -> std::io::Result<()> {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.path)?;
            if let Some(d) = self.path.parent() {
                std::fs::File::open(d)?.sync_all()?;
            }
            Ok(())
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(io(e));
        }
        Ok(())
    }

    /// Take the cross-process lock (`flock` on `<path>.lock`, the very lock Python takes).
    fn lock(&self) -> Result<LockGuard> {
        let lp = PathBuf::from(format!("{}.lock", self.path.display()));
        let mut o = std::fs::OpenOptions::new();
        o.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        if let Ok(m) = std::fs::symlink_metadata(&lp) {
            if m.file_type().is_symlink() {
                return Err(file_err("cannot lock the anchor file: the lock file is a symlink"));
            }
        }
        let f = o.open(&lp).map_err(|e| file_err(format!("cannot lock the anchor file: {}", e)))?;
        let m = f.metadata().map_err(|e| file_err(e.to_string()))?;
        Self::check_meta(&m, "anchor lock file")?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if unsafe { sys::flock(f.as_raw_fd(), 2) } != 0 {
                return Err(file_err(format!("cannot lock the anchor file: {}", std::io::Error::last_os_error())));
            }
        }
        Ok(LockGuard(f)) // dropping the file releases the flock
    }

    fn atomic<T>(&self, f: impl FnOnce(&mut State) -> Result<T>, write: bool) -> Result<T> {
        if !write {
            // the rename is atomic: a reader needs no lock
            let mut st = self.read()?;
            return f(&mut st);
        }
        let _g = self.lock()?;
        let st = self.read()?;
        let mut work = st.clone();
        let out = f(&mut work)?;
        if work != st {
            self.write(&work)?;
        }
        Ok(out)
    }
}
impl_anchor!(FileAnchor);

fn enc_entry(e: &Entry) -> Value {
    json!({
        "epoch": e.epoch, "root": e.root.to_string(), "count": e.count,
        "history": e.history.iter().map(|(a, b, c)| json!([a, b.to_string(), c])).collect::<Vec<_>>(),
        "pending": e.pending.as_ref().map(|p| json!({
            "epoch": p.epoch, "root": p.root.to_string(), "count": p.count,
            "txid": p.txid, "drop": p.drop, "created": p.created})),
    })
}

fn dec_entry(d: &Value) -> std::result::Result<Entry, String> {
    let bi = |v: &Value| -> std::result::Result<BigInt, String> {
        let s = v.as_str().ok_or("root")?;
        Ok(md(&s.parse::<BigInt>().map_err(|_| "root")?))
    };
    let un = |v: &Value, what: &str| v.as_u64().ok_or_else(|| what.to_string());
    let pending = match d.get("pending") {
        None | Some(Value::Null) => None,
        Some(p) => Some(Pending {
            epoch: un(&p["epoch"], "pending epoch")?,
            root: bi(&p["root"])?,
            count: un(&p["count"], "pending count")?,
            txid: p["txid"].as_str().map(String::from),
            drop: p["drop"].as_bool().unwrap_or(false),
            created: p["created"].as_bool().unwrap_or(false),
        }),
    };
    let mut history = vec![];
    for h in d["history"].as_array().cloned().unwrap_or_default() {
        let a = h.as_array().filter(|a| a.len() == 3).ok_or("history")?;
        history.push((un(&a[0], "history")?, bi(&a[1])?, un(&a[2], "history")?));
    }
    Ok(Entry { epoch: un(&d["epoch"], "epoch")?, root: bi(&d["root"])?, count: un(&d["count"], "count")?, pending, history })
}

/// How the connection reaches its anchor: a file path (a [`FileAnchor`]) or an [`Anchor`] object.
#[derive(Clone)]
pub enum AnchorSpec {
    File(PathBuf),
    Custom(Arc<dyn Anchor>),
}

impl std::fmt::Debug for AnchorSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorSpec::File(p) => write!(f, "AnchorSpec::File({})", p.display()),
            AnchorSpec::Custom(_) => write!(f, "AnchorSpec::Custom(..)"),
        }
    }
}
impl From<&str> for AnchorSpec {
    fn from(p: &str) -> AnchorSpec {
        AnchorSpec::File(p.into())
    }
}
impl From<PathBuf> for AnchorSpec {
    fn from(p: PathBuf) -> AnchorSpec {
        AnchorSpec::File(p)
    }
}
impl From<&Path> for AnchorSpec {
    fn from(p: &Path) -> AnchorSpec {
        AnchorSpec::File(p.into())
    }
}
impl From<Arc<dyn Anchor>> for AnchorSpec {
    fn from(a: Arc<dyn Anchor>) -> AnchorSpec {
        AnchorSpec::Custom(a)
    }
}

// ── canonical row material (bit-for-bit the Python encoding) ─────────────────
fn field(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Unambiguous encoding of a PLAIN value; bool and int share a form, a fraction with denominator 1 is the integer.
pub fn canon_value(v: &CellIn) -> Vec<u8> {
    match v {
        CellIn::Null => field(b'n', b""),
        CellIn::Bool(b) => field(b'i', if *b { b"1" } else { b"0" }),
        CellIn::Int(i) => field(b'i', i.to_string().as_bytes()),
        CellIn::Str(s) => field(b's', s.as_bytes()),
        CellIn::Rational(a, b) => {
            if b.is_one() {
                field(b'i', a.to_string().as_bytes())
            } else {
                field(b'f', format!("{}/{}", a, b).as_bytes())
            }
        }
    }
}

/// `json.dumps` string literal with `ensure_ascii`, as Python writes it.
fn py_json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e && (c as u32) != 0x7f => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Binds a leaf to the column names, types and policies: `SHA-256(JSON([table, [[name, type, policy], ...]]))`.
pub fn schema_digest(table: &str, cols: &[(String, String, String)]) -> [u8; 32] {
    let cs: Vec<String> = cols
        .iter()
        .map(|(n, t, p)| format!("[{},{},{}]", py_json_str(n), py_json_str(t), py_json_str(p)))
        .collect();
    sha256(format!("[{},[{}]]", py_json_str(table), cs.join(",")).as_bytes())
}

/// `(nonce, sha256(cell), sha256(tag))` of one FHE column of a row.
pub type FhePart = (Option<BigInt>, Option<[u8; 32]>, Option<[u8; 32]>);

pub fn row_material(sdig: &[u8; 32], plain: &[CellIn], parts: &[FhePart]) -> Vec<u8> {
    let mut out = b"torussql/anchor/row/v1".to_vec();
    out.extend_from_slice(sdig);
    for v in plain {
        out.extend(canon_value(v));
    }
    for (nonce, hc, ht) in parts {
        out.extend(canon_value(&nonce.clone().map(CellIn::Int).unwrap_or(CellIn::Null)));
        out.extend(field(b'c', hc.as_ref().map(|h| &h[..]).unwrap_or(b"")));
        out.extend(field(b't', ht.as_ref().map(|h| &h[..]).unwrap_or(b"")));
    }
    out
}

// ── the verified snapshot and the manager ────────────────────────────────────
#[derive(Clone)]
pub(crate) struct RowRec {
    pub vals: Vec<CellIn>,
    pub fhe: Vec<FhePart>,
    pub leaf: BigInt,
}

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub table: String,
    pub plain_cols: Vec<String>,
    pub fhe_cols: Vec<String>,
    pub sdig: [u8; 32],
    pub rows: BTreeMap<i64, RowRec>,
    pub nslots: i64,
    pub epoch: Option<u64>,
    pub base_root: BigInt,
    pub base_count: i64,
    pub root: BigInt,
    pub count: i64,
}

impl Snapshot {
    fn new(table: &str, plain_cols: Vec<String>, fhe_cols: Vec<String>, sdig: [u8; 32]) -> Snapshot {
        Snapshot {
            table: table.into(),
            plain_cols,
            fhe_cols,
            sdig,
            rows: BTreeMap::new(),
            nslots: 0,
            epoch: None,
            base_root: BigInt::zero(),
            base_count: 0,
            root: BigInt::zero(),
            count: 0,
        }
    }
    fn missing(&self, id: i64) -> Error {
        integrity(format!("row {} of {} is not part of the anchored table state", id, self.table))
    }
    pub fn live_ids(&self) -> Vec<i64> {
        self.rows.keys().copied().collect()
    }
    pub fn plain(&self, col: &str, ids: &[i64]) -> Result<Vec<CellIn>> {
        let i = self.plain_cols.iter().position(|c| c == col).ok_or_else(|| Error::interface(format!("no PLAIN column {}", col)))?;
        ids.iter().map(|id| self.rows.get(id).map(|r| r.vals[i].clone()).ok_or_else(|| self.missing(*id))).collect()
    }
    pub fn fhe_part(&self, col: &str, ids: &[i64]) -> Result<Vec<FhePart>> {
        let i = self.fhe_cols.iter().position(|c| c == col).ok_or_else(|| Error::interface(format!("no FHE column {}", col)))?;
        ids.iter().map(|id| self.rows.get(id).map(|r| r.fhe[i].clone()).ok_or_else(|| self.missing(*id))).collect()
    }
}

#[derive(Clone)]
struct TxT {
    epoch: Option<u64>,
    droot: BigInt,
    dcount: i64,
    reset: bool,
    dropped: bool,
}

enum Undo {
    Row { table: String, rid: i64, old: Option<RowRec>, root: BigInt, count: i64, nslots: i64, droot: BigInt, dcount: i64 },
    Create { table: String, had_snap: Option<Box<Snapshot>> },
    Drop { table: String, had_snap: Option<Box<Snapshot>> },
}

struct Tx {
    txid: Option<String>,
    tables: HashMap<String, TxT>,
    undo: Vec<Undo>,
    rescanned: HashSet<String>,
}

pub(crate) struct AnchorMgr {
    pub anchor: Arc<dyn Anchor>,
    pub snaps: HashMap<String, Snapshot>,
    tx: Option<Tx>,
    max_rows: usize,
    pending: Vec<String>,
    changes: BTreeMap<String, Change>,
    expect: HashMap<String, Option<(BigInt, u64)>>,
    in_flight: HashMap<String, bool>,
    pub scans: u64,
    pub scan_rows: u64,
}

impl AnchorMgr {
    pub fn new(anchor: Arc<dyn Anchor>, max_rows: Option<usize>) -> AnchorMgr {
        AnchorMgr {
            anchor,
            snaps: HashMap::new(),
            tx: None,
            max_rows: max_rows.unwrap_or(DEFAULT_MAX_ROWS),
            pending: vec![],
            changes: BTreeMap::new(),
            expect: HashMap::new(),
            in_flight: HashMap::new(),
            scans: 0,
            scan_rows: 0,
        }
    }

    pub fn begin(&mut self, txid: Option<String>) -> Result<()> {
        if self.tx.is_some() {
            return Err(Error::interface("an anchor transaction is already open"));
        }
        self.tx = Some(Tx { txid, tables: HashMap::new(), undo: vec![], rescanned: HashSet::new() });
        Ok(())
    }

    fn tt(&mut self, table: &str, epoch: Option<u64>) -> &mut TxT {
        self.tx
            .as_mut()
            .unwrap()
            .tables
            .entry(table.to_string())
            .or_insert(TxT { epoch, droot: BigInt::zero(), dcount: 0, reset: false, dropped: false })
    }

    /// Compare what the server presents with the anchor; settle a pending commit; or refuse.
    fn settle(&mut self, table: &str, a: Entry, got: &(BigInt, i64)) -> Result<Entry> {
        let eq = |r: &BigInt, c: u64| r == &got.0 && c as i64 == got.1;
        if eq(&a.root, a.count) {
            if let Some(p) = &a.pending {
                if !self.in_flight.get(p.txid.as_deref().unwrap_or("")).copied().unwrap_or(false) {
                    self.anchor.abort(&[table.to_string()], p.txid.as_deref())?;
                    return Ok(self.anchor.get(table)?.unwrap_or(a));
                }
            }
            return Ok(a);
        }
        if let Some(p) = &a.pending {
            if !p.drop && eq(&p.root, p.count) {
                match self.anchor.finish_commit(&[table.to_string()], p.txid.as_deref()) {
                    Ok(()) => {}
                    Err(e) if e.kind == Kind::AnchorConflict => {}
                    Err(e) => return Err(e),
                }
                if let Some(a2) = self.anchor.get(table)? {
                    if eq(&a2.root, a2.count) {
                        return Ok(a2);
                    }
                }
            }
        }
        if a.history.iter().any(|(_, r, c)| eq(r, *c)) {
            return Err(Error::new(
                Kind::StaleServer,
                format!(
                    "{}: the server is behind the anchor (its table state matches an older epoch than {}: a replica that has not \
                     caught up, or a rollback). Nothing was accepted; retry once the server has caught up",
                    table, a.epoch
                ),
            ));
        }
        Err(integrity(format!(
            "table state of {} does not match the anchor: rows added, dropped, rolled back or altered (server presents {} rows, the anchor records {})",
            table, got.1, a.count
        )))
    }

    fn apply(&mut self, table: &str, rid: i64, new: Option<RowRec>, old: Option<RowRec>) {
        let snap = self.snaps.get_mut(table).unwrap();
        let tt = self.tx.as_mut().unwrap().tables.get_mut(table).unwrap();
        let undo = Undo::Row {
            table: table.into(),
            rid,
            old: old.clone(),
            root: snap.root.clone(),
            count: snap.count,
            nslots: snap.nslots,
            droot: tt.droot.clone(),
            dcount: tt.dcount,
        };
        let d = md(&(new.as_ref().map(|n| n.leaf.clone()).unwrap_or_default() - old.as_ref().map(|o| o.leaf.clone()).unwrap_or_default()));
        let dn = new.is_some() as i64 - old.is_some() as i64;
        match new {
            Some(n) => {
                snap.rows.insert(rid, n);
                snap.nslots = snap.nslots.max(rid + 1);
            }
            None => {
                snap.rows.remove(&rid);
            }
        }
        snap.root = md(&(&snap.root + &d));
        snap.count += dn;
        tt.droot = md(&(&tt.droot + &d));
        tt.dcount += dn;
        self.tx.as_mut().unwrap().undo.push(undo);
    }

    pub fn ddl_create(&mut self, table: &str, plain: Vec<String>, fhe: Vec<String>, sdig: [u8; 32]) -> Result<()> {
        let a = self.anchor.get(table)?;
        let tx = self.tx.as_mut().ok_or_else(|| Error::interface("anchored tables are created inside a transaction"))?;
        tx.tables.insert(
            table.to_string(),
            TxT { epoch: a.map(|e| e.epoch), droot: BigInt::zero(), dcount: 0, reset: true, dropped: false },
        );
        let had_snap = self.snaps.insert(table.to_string(), Snapshot::new(table, plain, fhe, sdig));
        self.tx.as_mut().unwrap().undo.push(Undo::Create { table: table.into(), had_snap: had_snap.map(Box::new) });
        Ok(())
    }

    pub fn ddl_drop(&mut self, table: &str) -> Result<()> {
        let a = self.anchor.get(table)?;
        let tx = self.tx.as_mut().ok_or_else(|| Error::interface("anchored tables are dropped inside a transaction"))?;
        let tt = tx
            .tables
            .entry(table.to_string())
            .or_insert(TxT { epoch: a.map(|e| e.epoch), droot: BigInt::zero(), dcount: 0, reset: false, dropped: false });
        tt.dropped = true;
        let had_snap = self.snaps.remove(table);
        self.tx.as_mut().unwrap().undo.push(Undo::Drop { table: table.into(), had_snap: had_snap.map(Box::new) });
        Ok(())
    }

    /// Record `pending` in the anchor BEFORE the server is asked to commit. False when nothing anchored changed.
    pub fn prepare(&mut self) -> Result<bool> {
        let Some(tx) = &self.tx else { return Ok(false) };
        let mut changes: BTreeMap<String, Change> = BTreeMap::new();
        for (t, tt) in &tx.tables {
            if tt.dropped {
                changes.insert(t.clone(), Change { expect_epoch: tt.epoch, root: None, count: 0 });
                continue;
            }
            if tt.droot.is_zero() && tt.dcount == 0 && !tt.reset {
                continue;
            }
            let snap = &self.snaps[t];
            let (br, bc) = if tt.reset { (BigInt::zero(), 0) } else { (snap.base_root.clone(), snap.base_count) };
            changes.insert(
                t.clone(),
                Change { expect_epoch: tt.epoch, root: Some(md(&(br + &tt.droot))), count: (bc + tt.dcount) as u64 },
            );
        }
        if changes.is_empty() {
            return Ok(false);
        }
        self.anchor.begin_commit(&changes, tx.txid.as_deref())?;
        self.pending = changes.keys().cloned().collect();
        self.expect = changes.iter().map(|(t, ch)| (t.clone(), ch.root.clone().map(|r| (r, ch.count)))).collect();
        self.changes = changes;
        Ok(true)
    }

    pub fn finish(&mut self) -> Result<()> {
        let tx = self.tx.take();
        let pend = std::mem::take(&mut self.pending);
        let Some(tx) = tx else { return Ok(()) };
        let txid = tx.txid.as_deref();
        let r = (|| -> Result<()> {
            if !pend.is_empty() {
                self.anchor.finish_commit(&pend, txid)?;
                self.repair_aborted(&pend, txid)?;
                for t in &pend {
                    let e = self.anchor.get(t)?;
                    let want = self.expect.get(t).cloned().flatten();
                    let ok = match (&e, &want) {
                        (None, None) => true,
                        (Some(e), Some((r, c))) => e.pending.is_none() && &e.root == r && e.count == *c,
                        _ => false,
                    };
                    if !ok {
                        return Err(conflict(format!("{} is not in the state this commit recorded", t)));
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            if e.kind == Kind::AnchorConflict {
                self.snaps.clear();
                return Err(integrity(format!("the anchor does not hold this transaction's commit: {}", e.message)));
            }
            return Err(e);
        }
        for (t, tt) in &tx.tables {
            if tt.dropped {
                self.snaps.remove(t);
            } else if pend.contains(t) {
                if let (Some(a), Some(snap)) = (self.anchor.get(t)?, self.snaps.get_mut(t)) {
                    snap.epoch = Some(a.epoch);
                    snap.base_root = snap.root.clone();
                    snap.base_count = snap.count;
                }
            }
        }
        Ok(())
    }

    /// Our `pending` record was aborted behind our back although the server answered "committed": the anchor is
    /// still exactly at the state the transaction was based on, so record the commit again (a lie can only cause
    /// a later failure, never an accepted wrong state).
    fn repair_aborted(&mut self, pend: &[String], txid: Option<&str>) -> Result<()> {
        let mut redo = BTreeMap::new();
        for t in pend {
            let ch = &self.changes[t];
            let e = self.anchor.get(t)?;
            let ok = match &e {
                None => ch.expect_epoch.is_none(),
                Some(e) => e.pending.is_none() && Some(e.epoch) == ch.expect_epoch,
            };
            if ok {
                redo.insert(t.clone(), ch.clone());
            }
        }
        if !redo.is_empty() {
            self.anchor.begin_commit(&redo, txid)?;
            let names: Vec<String> = redo.keys().cloned().collect();
            self.anchor.finish_commit(&names, txid)?;
        }
        Ok(())
    }

    /// The transaction did not commit: discard its changes (and the pending record).
    pub fn abort(&mut self) {
        let tx = self.tx.take();
        let pend = std::mem::take(&mut self.pending);
        let Some(tx) = tx else { return };
        if !pend.is_empty() {
            let _ = self.anchor.abort(&pend, tx.txid.as_deref());
        }
        for u in tx.undo.into_iter().rev() {
            match u {
                Undo::Row { table, rid, old, root, count, nslots, droot, dcount } => {
                    if let Some(s) = self.snaps.get_mut(&table) {
                        s.root = root;
                        s.count = count;
                        s.nslots = nslots;
                        match old {
                            Some(o) => {
                                s.rows.insert(rid, o);
                            }
                            None => {
                                s.rows.remove(&rid);
                            }
                        }
                    }
                    // the transaction object is gone: the per-table deltas die with it
                    let _ = (droot, dcount);
                }
                Undo::Create { table, had_snap, .. } => match had_snap {
                    Some(s) => {
                        self.snaps.insert(table, *s);
                    }
                    None => {
                        self.snaps.remove(&table);
                    }
                },
                Undo::Drop { table, had_snap, .. } => {
                    if let Some(s) = had_snap {
                        self.snaps.insert(table, *s);
                    }
                }
            }
        }
        for t in tx.rescanned {
            self.snaps.remove(&t);
        }
    }

    /// The outcome is unknown (in doubt): leave `pending` in the anchor for the next connect to settle by scanning.
    pub fn detach(&mut self) {
        self.tx = None;
        self.pending.clear();
        self.snaps.clear();
    }
}

// ── Client integration: scan, snapshot, writes ───────────────────────────────
/// What `adopt_table` / `verify_table` report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorInfo {
    pub table: String,
    pub rows: usize,
    pub slots: usize,
    pub epoch: Option<u64>,
}

fn parse_hash(v: &Value) -> Result<Option<[u8; 32]>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {
            let mut o = [0u8; 32];
            for i in 0..32 {
                o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            Ok(Some(o))
        }
        _ => Err(integrity("malformed fhe_rows reply from the server (cell hash)")),
    }
}

impl Client {
    pub(crate) fn anchored(&self, table: &str) -> bool {
        self.amgr.is_some() && self.layout(table).is_some()
    }

    /// (plain column names, FHE column names, schema digest) of an anchored table.
    pub(crate) fn layout(&self, table: &str) -> Option<(Vec<String>, Vec<String>, [u8; 32])> {
        let d = self.schema.get(table)?;
        if !self.opts.authenticated || !d.cols.iter().any(|c| c.policy == "fhe") {
            return None;
        }
        let triples: Vec<(String, String, String)> = d.cols.iter().map(|c| (c.name.clone(), c.ty.clone(), c.policy.clone())).collect();
        Some((
            d.cols.iter().filter(|c| c.policy == "plain").map(|c| c.name.clone()).collect(),
            d.cols.iter().filter(|c| c.policy == "fhe").map(|c| c.name.clone()).collect(),
            schema_digest(table, &triples),
        ))
    }

    fn rec(&self, snap: &Snapshot, rid: i64, vals: Vec<CellIn>, fp: Vec<FhePart>) -> Result<RowRec> {
        if vals.len() != snap.plain_cols.len() || fp.len() != snap.fhe_cols.len() {
            return Err(integrity(format!("{} row {}: the server's row has the wrong shape", snap.table, rid)));
        }
        let leaf = self.fhe_key()?.anchor_leaf(&snap.table, rid, &row_material(&snap.sdig, &vals, &fp));
        Ok(RowRec { vals, fhe: fp, leaf })
    }

    fn scan(&mut self, table: &str) -> Result<Snapshot> {
        let (plain, fhe, sdig) = self.layout(table).ok_or_else(|| Error::interface(format!("{} is not an anchored table", table)))?;
        let mut snap = Snapshot::new(table, plain, fhe, sdig);
        let step = 2000.min(self.info.limits.as_ref().and_then(|l| l.fhe.as_ref()).and_then(|f| f.max_scan_rows).unwrap_or(2000));
        let max_rows = self.amgr.as_ref().unwrap().max_rows;
        let (mut start, mut root, mut count) = (0i64, BigInt::zero(), 0i64);
        let mut n;
        loop {
            let r = self.call_max("fhe_rows", json!([table, start, step]), 8 << 20)?;
            let bad = |w: &str| integrity(format!("malformed fhe_rows reply from the server ({})", w));
            n = match r["n"].as_i64() {
                Some(n) if n >= 0 => n,
                _ => return Err(bad("slot count")),
            };
            let rows = r["rows"].as_array().ok_or_else(|| bad("rows"))?;
            if n as usize > max_rows {
                return Err(Error::interface(format!(
                    "{} has {} slots: more than the anchored-mode limit of {} rows (integrity_anchor_max_rows)",
                    table, n, max_rows
                )));
            }
            if start >= n {
                break;
            }
            if rows.is_empty() || rows.len() as i64 > step as i64 {
                return Err(integrity(format!("{}: the server's scan answer does not cover the requested slots", table)));
            }
            for (k, row) in rows.iter().enumerate() {
                let row = row.as_array().ok_or_else(|| bad("row"))?;
                if row.first().and_then(|x| x.as_i64()) != Some(start + k as i64) {
                    return Err(integrity(format!("{}: the server's scan skipped or repeated a slot", table)));
                }
                let rid = start + k as i64;
                if row.get(1).and_then(|x| x.as_i64()) == Some(1) {
                    continue; // dead slot
                }
                if row.len() != 4 || row[1].as_i64() != Some(0) {
                    return Err(bad("row"));
                }
                let vals = row[2]
                    .as_array()
                    .ok_or_else(|| bad("plain"))?
                    .iter()
                    .map(|w| uwv(w).map_err(|e| bad(&e.message)))
                    .collect::<Result<Vec<CellIn>>>()?;
                let mut fp = vec![];
                for e in row[3].as_array().ok_or_else(|| bad("fhe"))? {
                    let e = e.as_array().filter(|a| a.len() == 3).ok_or_else(|| bad("fhe part"))?;
                    let nonce = match e[0].get("t").and_then(|t| t.as_str()) {
                        Some("n") => None,
                        Some("i") => Some(big(&e[0]["v"], "write nonce").map_err(|_| integrity("the server reported a malformed write nonce"))?),
                        _ => return Err(integrity("the server reported a malformed write nonce")),
                    };
                    fp.push((nonce, parse_hash(&e[1])?, parse_hash(&e[2])?));
                }
                let rec = self.rec(&snap, rid, vals, fp)?;
                root += &rec.leaf;
                count += 1;
                snap.rows.insert(rid, rec);
            }
            start += rows.len() as i64;
        }
        snap.nslots = n;
        snap.root = md(&root);
        snap.count = count;
        snap.base_root = snap.root.clone();
        snap.base_count = count;
        let m = self.amgr.as_mut().unwrap();
        m.scans += 1;
        m.scan_rows += n as u64;
        Ok(snap)
    }

    fn missing(table: &str) -> Error {
        Error::new(
            Kind::AnchorMissing,
            format!(
                "table {t} has FHE columns but the integrity anchor has no entry for it, so its row set cannot be verified. \
                 If it was created before the anchor was configured, call adopt_table({t:?}) once (trust on first use: only as \
                 honest as the server at that moment); a table created through this connection is anchored automatically",
                t = table
            ),
        )
    }

    /// Ask the server about the pending transaction of `table` (only "unknown" proves it dead).
    fn probe_in_flight(&mut self, table: &str) -> Result<()> {
        let Some(m) = &self.amgr else { return Ok(()) };
        let Some(p) = m.anchor.get(table)?.and_then(|e| e.pending) else { return Ok(()) };
        let Some(txid) = p.txid else { return Ok(()) };
        let alive = match self.call_max("tx_status", json!([txid]), 4096) {
            Ok(v) => v.as_str() != Some("unknown"),
            Err(_) => true,
        };
        self.amgr.as_mut().unwrap().in_flight.insert(txid, alive);
        Ok(())
    }

    /// Make `snaps[table]` the verified table state (cached per anchor epoch).
    pub(crate) fn a_snapshot(&mut self, table: &str, force: bool, for_write: bool) -> Result<()> {
        self.probe_in_flight(table)?;
        let m = self.amgr.as_ref().unwrap();
        let tt = m.tx.as_ref().and_then(|t| t.tables.get(table)).cloned();
        if let (Some(tt), true) = (&tt, m.snaps.contains_key(table)) {
            if tt.reset {
                return Ok(()); // created inside this transaction
            }
        }
        let a = m.anchor.get(table)?.ok_or_else(|| Self::missing(table))?;
        if !force {
            if let Some(s) = m.snaps.get(table) {
                if s.epoch == Some(a.epoch) && a.pending.is_none() && s.base_root == a.root && s.base_count == a.count as i64 {
                    return Ok(());
                }
            }
        }
        let mut fresh = self.scan(table)?;
        let (dr, dc) = tt.as_ref().map(|t| (t.droot.clone(), t.dcount)).unwrap_or((BigInt::zero(), 0));
        let got = (md(&(&fresh.root - &dr)), fresh.count - dc);
        let a = self.amgr.as_mut().unwrap().settle(table, a, &got)?;
        if let Some(tt) = &tt {
            if tt.epoch.is_some() && tt.epoch != Some(a.epoch) {
                return Err(conflict(format!(
                    "anchor: {} moved from epoch {:?} to {} during the transaction (another owner committed)",
                    table, tt.epoch, a.epoch
                )));
            }
        }
        fresh.epoch = Some(a.epoch);
        fresh.base_root = got.0;
        fresh.base_count = got.1;
        let volatile = a.pending.is_some();
        if volatile {
            fresh.epoch = None; // never cached while a commit is in flight
            if for_write {
                return Err(conflict(format!("anchor: {} has a commit in flight from another owner", table)));
            }
        }
        let m = self.amgr.as_mut().unwrap();
        m.snaps.insert(table.to_string(), fresh);
        if let Some(tx) = m.tx.as_mut() {
            if tx.tables.contains_key(table) {
                tx.rescanned.insert(table.to_string());
                if let Some(t) = tx.tables.get_mut(table) {
                    if t.epoch.is_none() && !volatile {
                        t.epoch = Some(a.epoch);
                    }
                }
            }
        }
        Ok(())
    }

    /// The verified state BEFORE a write (inside the open transaction).
    pub(crate) fn a_write_snapshot(&mut self, table: &str) -> Result<()> {
        if self.amgr.as_ref().unwrap().tx.is_none() {
            return Err(Error::interface("anchored tables are written inside a transaction"));
        }
        self.a_snapshot(table, false, true)?;
        let epoch = self.amgr.as_ref().unwrap().snaps[table].epoch;
        self.amgr.as_mut().unwrap().tt(table, epoch);
        Ok(())
    }

    pub(crate) fn a_snap(&self, table: &str) -> &Snapshot {
        &self.amgr.as_ref().unwrap().snaps[table]
    }

    /// Row ids matching `pred`, evaluated locally on the verified snapshot (SQL NULL semantics).
    pub(crate) fn a_match(&mut self, table: &str, pred: &Value) -> Result<Vec<i64>> {
        self.a_snapshot(table, false, false)?;
        let snap = self.a_snap(table);
        let ids = snap.live_ids();
        if pred.is_null() {
            return Ok(ids);
        }
        let groups = pred["or"].as_array().cloned().unwrap_or_default();
        let mut out = vec![];
        for id in ids {
            let r = &snap.rows[&id];
            let mut hit = false;
            'g: for g in &groups {
                let mut all = true;
                for a in g.as_array().cloned().unwrap_or_default() {
                    let c = a["c"].as_str().unwrap_or("");
                    let v = snap.plain_cols.iter().position(|x| x == c).map(|i| r.vals[i].clone()).unwrap_or(CellIn::Null);
                    if !atom_matches(&v, &a)? {
                        all = false;
                        break;
                    }
                }
                if all {
                    hit = true;
                    break 'g;
                }
            }
            if hit {
                out.push(id);
            }
        }
        Ok(out)
    }

    pub(crate) fn a_plain(&mut self, table: &str, col: &str, ids: &[i64]) -> Result<Vec<CellIn>> {
        self.a_snapshot(table, false, false)?;
        self.a_snap(table).plain(col, ids)
    }

    pub(crate) fn a_fhe_part(&mut self, table: &str, col: &str, ids: &[i64]) -> Result<Vec<FhePart>> {
        self.a_snapshot(table, false, false)?;
        self.a_snap(table).fhe_part(col, ids)
    }

    pub(crate) fn a_record(&mut self, table: &str, rid: i64, vals: Vec<CellIn>, fp: Vec<FhePart>, kind: u8) -> Result<()> {
        let snap = self.a_snap(table).clone_shallow();
        let new = if kind == 2 { None } else { Some(self.rec(&snap, rid, vals, fp)?) };
        let old = snap_row(self.a_snap(table), rid);
        match kind {
            0 => {
                if old.is_some() || rid < self.a_snap(table).nslots {
                    return Err(integrity(format!("{}: the server returned row id {}, which is already in use or out of order", table, rid)));
                }
            }
            _ => {
                if old.is_none() {
                    return Err(integrity(format!("row {} of {} is not part of the anchored table state", rid, table)));
                }
            }
        }
        let epoch = self.a_snap(table).epoch;
        self.amgr.as_mut().unwrap().tt(table, epoch);
        self.amgr.as_mut().unwrap().apply(table, rid, new, old);
        Ok(())
    }

    /// Trust-on-first-use: scan the server NOW and record that state in the anchor. Only as honest as the server
    /// at this moment; use it once for tables created before the anchor existed.
    pub fn adopt_table(&mut self, table: &str, replace: bool) -> Result<AnchorInfo> {
        let m = self.amgr.as_ref().ok_or_else(|| Error::interface("no integrity_anchor is configured"))?;
        if m.tx.is_some() {
            return Err(Error::interface("adopt_table: finish the transaction first"));
        }
        if !self.anchored(table) {
            return Err(Error::interface(format!("{} has no FHE columns (or the connection is not authenticated)", table)));
        }
        let a = m.anchor.get(table)?;
        if let (Some(e), false) = (&a, replace) {
            return Err(Error::interface(format!(
                "{} already has an anchor entry (epoch {}); pass replace=true to adopt the server's current state instead",
                table, e.epoch
            )));
        }
        let mut snap = self.scan(table)?;
        let m = self.amgr.as_mut().unwrap();
        if a.is_some() {
            m.anchor.remove(table, None)?;
        }
        let e = m.anchor.set(table, &snap.root, snap.count as u64, None)?;
        snap.epoch = Some(e.epoch);
        let info = AnchorInfo { table: table.into(), rows: snap.count as usize, slots: snap.nslots as usize, epoch: Some(e.epoch) };
        m.snaps.insert(table.into(), snap);
        Ok(info)
    }

    /// Force a full scan of `table` and check it against the anchor (O(rows)).
    pub fn verify_table(&mut self, table: &str) -> Result<AnchorInfo> {
        if self.amgr.is_none() {
            return Err(Error::interface("no integrity_anchor is configured"));
        }
        if !self.anchored(table) {
            return Err(Error::interface(format!("{} has no FHE columns (or the connection is not authenticated)", table)));
        }
        self.a_snapshot(table, true, false)?;
        let s = self.a_snap(table);
        Ok(AnchorInfo { table: table.into(), rows: s.count as usize, slots: s.nslots as usize, epoch: s.epoch })
    }

    /// Diagnostics: `(full scans, scanned slots)` so far (zeros without an anchor).
    pub fn anchor_stats(&self) -> (u64, u64) {
        self.amgr.as_ref().map(|m| (m.scans, m.scan_rows)).unwrap_or((0, 0))
    }

    /// On connect: settle every pending commit the anchor holds by scanning the server.
    pub(crate) fn a_settle_pending(&mut self) -> Result<()> {
        let tables = self.amgr.as_ref().unwrap().anchor.tables()?;
        let mut on_server: Option<HashSet<String>> = None;
        for t in tables {
            let Some(e) = self.amgr.as_ref().unwrap().anchor.get(&t)? else { continue };
            let Some(p) = e.pending else { continue };
            if self.schema.contains_key(&t) {
                self.a_snapshot(&t, true, false)?;
                continue;
            }
            if on_server.is_none() {
                on_server = Some(self.tables()?.into_iter().collect());
            }
            if on_server.as_ref().unwrap().contains(&t) {
                continue; // unknown schema: settled on first use
            }
            let a = &self.amgr.as_ref().unwrap().anchor;
            if p.drop {
                a.finish_commit(std::slice::from_ref(&t), p.txid.as_deref())?; // the table is gone: the drop committed
            } else if p.created {
                a.abort(std::slice::from_ref(&t), p.txid.as_deref())?; // it was never created
            } else {
                return Err(integrity(format!("table {} is gone from the server but the anchor records it (pending commit that is not a drop)", t)));
            }
        }
        Ok(())
    }
}

fn snap_row(s: &Snapshot, rid: i64) -> Option<RowRec> {
    s.rows.get(&rid).cloned()
}

impl Snapshot {
    /// Everything `rec` needs from the snapshot without borrowing the whole manager.
    fn clone_shallow(&self) -> Snapshot {
        Snapshot::new(&self.table, self.plain_cols.clone(), self.fhe_cols.clone(), self.sdig)
    }
}
