// SPDX-License-Identifier: Apache-2.0
//! No-key TorusDB client for Rust (wire protocol v2).
//!
//! Talks the no-key delegation protocol to a keyless TorusDB server: the
//! server holds no keys and only blinded scalars; this driver (the data owner)
//! holds the mask vault, blinds on insert, and unblinds + decodes results.
//! Server-side confidentiality is a one-time pad (I(M;V_S)=0).
//!
//! The crate exposes a programmatic API (no SQL parser - that lives in the
//! Python `torussql-parser`). Wire format, framing and field arithmetic match
//! the other drivers; see `../vectors.json`.
//!
//! Cargo feature `tls` (off by default) adds TLS via rustls; certificates and
//! hostnames are verified unless [`ConnectOptions::tls_insecure`] is set.

mod conn;
mod error;
mod field;

pub use error::{Error, Kind};
pub use field::{decode, encode_int, encode_rational, n, reduce, Decoded};

use conn::{Conn, TransportOpts};
use field::{md, rand_scalar};
use num_bigint::BigInt;
use num_traits::Zero;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Newest wire protocol this driver speaks.
pub const PROTOCOL_VERSION: u64 = 2;

type Result<T> = std::result::Result<T, Error>;

// ── column spec / cell values ────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub struct Column {
    pub name: String,
    pub ty: String,     // "int" | "str" | "rational"
    pub policy: String, // "plain" | "encrypted" | "paired"
}

/// A cell value, used both for input and for revealed plain/decrypted output.
#[derive(Clone, Debug, PartialEq)]
pub enum CellIn {
    Null,
    Bool(bool),
    Int(BigInt),
    Str(String),
    Rational(BigInt, BigInt),
}
/// Alias for revealed values.
pub type Cell = CellIn;

impl From<i64> for CellIn {
    fn from(v: i64) -> CellIn {
        CellIn::Int(BigInt::from(v))
    }
}
impl From<&str> for CellIn {
    fn from(v: &str) -> CellIn {
        CellIn::Str(v.to_string())
    }
}
impl From<Decoded> for CellIn {
    fn from(d: Decoded) -> CellIn {
        match d {
            Decoded::Int(a) => CellIn::Int(a),
            Decoded::Rational(a, b) => CellIn::Rational(a, b),
        }
    }
}

// ── wire value codec (mirrors proto/nokey_wire.py) ───────────────────────────
fn wv(v: &CellIn) -> Result<Value> {
    Ok(match v {
        CellIn::Null => json!({"t": "n"}),
        CellIn::Bool(b) => json!({"t": "b", "v": b}),
        CellIn::Int(i) => json!({"t": "i", "v": i.to_string()}),
        CellIn::Str(s) => json!({"t": "s", "v": s}),
        CellIn::Rational(a, b) => {
            if b.is_zero() {
                return Err(Error::interface("zero denominator"));
            }
            match reduce(a, b) {
                Decoded::Int(x) => json!({"t": "f", "n": x.to_string(), "d": "1"}),
                Decoded::Rational(x, y) => json!({"t": "f", "n": x.to_string(), "d": y.to_string()}),
            }
        }
    })
}

fn wv_int(v: &BigInt) -> Value {
    json!({"t": "i", "v": v.to_string()})
}

fn big(s: &Value, what: &str) -> Result<BigInt> {
    s.as_str()
        .and_then(|t| BigInt::parse_bytes(t.as_bytes(), 10))
        .ok_or_else(|| Error::protocol(format!("expected a decimal integer for {}", what)))
}

fn uwv(d: &Value) -> Result<CellIn> {
    let tag = d.get("t").and_then(|t| t.as_str()).unwrap_or("");
    match tag {
        "n" => Ok(CellIn::Null),
        "b" => Ok(CellIn::Bool(d["v"].as_bool().unwrap_or(false))),
        "i" => Ok(CellIn::Int(big(&d["v"], "int cell")?)),
        "s" => Ok(CellIn::Str(d["v"].as_str().unwrap_or("").to_string())),
        "f" => {
            let (a, b) = (big(&d["n"], "numerator")?, big(&d["d"], "denominator")?);
            if b.is_zero() {
                return Err(Error::protocol("zero denominator from server"));
            }
            Ok(reduce(&a, &b).into())
        }
        other => Err(Error::protocol(format!("bad wire tag {:?}", other))),
    }
}

// ── connection options ───────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// API token; required when the server runs with `--token-file`. Never
    /// logged or included in errors.
    pub token: Option<String>,
    /// Socket timeout (default 30 s; `None` = block forever).
    pub timeout: Option<Duration>,
    /// Wrap the connection in TLS (needs the `tls` cargo feature).
    pub tls: bool,
    /// PEM CA certificate(s) to trust instead of the built-in web roots.
    pub ca_pem: Option<Vec<u8>>,
    /// DANGEROUS: skip certificate verification. Local development only.
    pub tls_insecure: bool,
    /// Mask-vault file: loaded on connect if it exists; default path of
    /// `save_vault`/`load_vault`.
    pub vault_path: Option<PathBuf>,
    /// Learn tables that exist on the server but not here (schema only).
    pub sync_schema: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions {
            token: None,
            timeout: Some(Duration::from_secs(30)),
            tls: false,
            ca_pem: None,
            tls_insecure: false,
            vault_path: None,
            sync_schema: true,
        }
    }
}

/// What the server said in `hello` (protocol 1 servers: protocol = 1, no auth).
#[derive(Clone, Debug, Default)]
pub struct ServerInfo {
    pub protocol: u64,
    pub server: Option<String>,
    pub auth_required: bool,
    pub max_frame: Option<u64>,
    pub persistent: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TableInfo {
    pub rows: i64,
    pub deleted: Vec<i64>,
}

// ── joins ────────────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
}

#[derive(Clone, Debug)]
pub struct JoinStep {
    pub table: String,
    /// Alias of this instance (default: the table name).
    pub alias: Option<String>,
    /// Alias of an EARLIER instance that owns `left_col` (default: the FROM table).
    pub left_alias: Option<String>,
    /// PLAIN column of the earlier instance.
    pub left_col: String,
    /// PLAIN column of the joined table.
    pub right_col: String,
    pub kind: JoinKind,
}

impl JoinStep {
    pub fn new(table: &str, left_col: &str, right_col: &str) -> JoinStep {
        JoinStep {
            table: table.into(),
            alias: None,
            left_alias: None,
            left_col: left_col.into(),
            right_col: right_col.into(),
            kind: JoinKind::Inner,
        }
    }
    pub fn alias(mut self, a: &str) -> Self {
        self.alias = Some(a.into());
        self
    }
    pub fn left_alias(mut self, a: &str) -> Self {
        self.left_alias = Some(a.into());
        self
    }
    pub fn left(mut self) -> Self {
        self.kind = JoinKind::Left;
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct JoinOptions {
    /// Alias of the FROM table (default: its name).
    pub alias: Option<String>,
    /// WHERE predicate on the FROM table (`Value::Null` / `None` = all rows).
    pub where_: Option<Value>,
}

/// Row ids per table instance; `None` is the NULL side of a LEFT JOIN.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinResult {
    pub aliases: Vec<String>,
    pub tables: HashMap<String, String>,
    pub tuples: Vec<Vec<Option<i64>>>,
}

impl JoinResult {
    pub fn count(&self) -> usize {
        self.tuples.len()
    }
}

fn plain_key(v: &CellIn) -> Option<String> {
    match v {
        CellIn::Null => None, // NULL never matches
        CellIn::Int(i) => Some(format!("i{}", i)),
        CellIn::Bool(b) => Some(format!("i{}", *b as i32)),
        CellIn::Str(s) => Some(format!("s{}", s)),
        CellIn::Rational(a, b) => Some(format!("f{}/{}", a, b)),
    }
}

// ── the no-key client ────────────────────────────────────────────────────────
type MaskKey = (String, i64, String);
type Masks = HashMap<MaskKey, BigInt>;
type Schema = HashMap<String, Vec<Column>>;

pub struct Client {
    conn: Conn,
    masks: Masks, // (table, rowid, col) -> r
    schema: Schema,
    in_tx: bool,
    snapshot: Option<(Masks, Schema)>,
    vault_path: Option<PathBuf>,
    info: ServerInfo,
}

impl Client {
    /// Connect with default options (no auth, no TLS, 30 s timeout).
    pub fn connect(addr: &str) -> Result<Client> {
        Client::connect_with(addr, &ConnectOptions::default())
    }

    pub fn connect_with(addr: &str, o: &ConnectOptions) -> Result<Client> {
        let conn = Conn::open(
            addr,
            &TransportOpts {
                timeout: o.timeout,
                tls: o.tls,
                tls_insecure: o.tls_insecure,
                ca_pem: o.ca_pem.as_deref(),
            },
        )?;
        let mut c = Client {
            conn,
            masks: HashMap::new(),
            schema: HashMap::new(),
            in_tx: false,
            snapshot: None,
            vault_path: o.vault_path.clone(),
            info: ServerInfo { protocol: 1, ..Default::default() },
        };
        let r = (|| -> Result<()> {
            c.handshake(o.token.as_deref())?;
            if let Some(p) = &o.vault_path {
                if p.exists() {
                    c.load_vault(Some(p))?;
                }
            }
            if o.sync_schema {
                c.sync_schema()?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            c.conn.close();
            return Err(e);
        }
        Ok(c)
    }

    fn handshake(&mut self, token: Option<&str>) -> Result<()> {
        match self.call("hello", json!([])) {
            Ok(h) => {
                self.info = ServerInfo {
                    protocol: h["protocol"].as_u64().unwrap_or(1),
                    server: h["server"].as_str().map(String::from),
                    auth_required: h["auth_required"].as_bool().unwrap_or(false),
                    max_frame: h["max_frame"].as_u64(),
                    persistent: h["persistent"].as_bool(),
                };
            }
            Err(e)
                if e.kind == Kind::BadRequest
                    && (e.message.contains("unknown method") || e.message.contains("_rpc_hello")) =>
            {
                self.info = ServerInfo { protocol: 1, ..Default::default() }; // protocol-1 server
            }
            Err(e) => return Err(e),
        }
        if self.info.protocol > PROTOCOL_VERSION {
            return Err(Error::interface(format!(
                "server speaks protocol {}; this driver supports up to {} - upgrade the driver",
                self.info.protocol, PROTOCOL_VERSION
            )));
        }
        if self.info.auth_required {
            match token {
                None | Some("") => {
                    return Err(Error::new(
                        Kind::Unauthenticated,
                        "the server requires a token (set ConnectOptions::token)",
                    ))
                }
                Some(t) => {
                    self.call("auth", json!([t]))?;
                }
            }
        }
        Ok(())
    }

    fn call(&mut self, method: &str, args: Value) -> Result<Value> {
        self.conn.call(method, args)
    }

    /// What the server announced in `hello`.
    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    /// Close the connection (an open transaction is rolled back by the server).
    pub fn close(&mut self) {
        self.in_tx = false;
        self.snapshot = None;
        self.conn.close();
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    // — operations —
    pub fn ping(&mut self) -> Result<bool> {
        Ok(self.call("ping", json!([]))?.as_str() == Some("pong"))
    }
    /// Server counters (admin token when auth is on).
    pub fn stats(&mut self) -> Result<Value> {
        self.call("stats", json!([]))
    }
    pub fn checkpoint(&mut self) -> Result<i64> {
        Ok(self.call("checkpoint", json!([]))?.as_i64().unwrap_or(0))
    }
    /// Ask the server to write a checksummed backup (admin); returns its path.
    pub fn backup(&mut self) -> Result<String> {
        Ok(self.call("backup", json!([]))?.as_str().unwrap_or("").to_string())
    }
    pub fn tables(&mut self) -> Result<Vec<String>> {
        Ok(self
            .call("tables", json!([]))?
            .as_array()
            .ok_or_else(|| Error::protocol("tables: expected a list"))?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }
    pub fn table_info(&mut self, table: &str) -> Result<TableInfo> {
        let v = self.call("table_info", json!([table]))?;
        Ok(TableInfo {
            rows: v["rows"].as_i64().unwrap_or(0),
            deleted: v["deleted"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                .unwrap_or_default(),
        })
    }

    /// Learn tables that exist on the server but not here (schema only).
    pub fn sync_schema(&mut self) -> Result<Vec<String>> {
        let mut added = vec![];
        for t in self.tables()? {
            if self.schema.contains_key(&t) {
                continue;
            }
            let cols = self.call("schema", json!([t]))?;
            let cols: Vec<Column> = cols
                .as_array()
                .ok_or_else(|| Error::protocol("schema: expected a list"))?
                .iter()
                .map(|c| Column {
                    name: c[0].as_str().unwrap_or("").into(),
                    ty: c[1].as_str().unwrap_or("").into(),
                    policy: c[2].as_str().unwrap_or("").into(),
                })
                .collect();
            self.schema.insert(t.clone(), cols);
            added.push(t);
        }
        Ok(added)
    }

    // — DDL —
    pub fn create_table(&mut self, name: &str, cols: Vec<Column>) -> Result<()> {
        let wire: Vec<Value> = cols.iter().map(|c| json!([c.name, c.ty, c.policy])).collect();
        self.call("create", json!([name, wire]))?;
        self.schema.insert(name.to_string(), cols);
        Ok(())
    }

    /// Drop a table (admin). Forgets its masks.
    pub fn drop_table(&mut self, name: &str) -> Result<()> {
        self.call("drop", json!([name]))?;
        self.schema.remove(name);
        self.masks.retain(|k, _| k.0 != name);
        Ok(())
    }

    fn cols(&self, table: &str) -> Result<&Vec<Column>> {
        self.schema
            .get(table)
            .ok_or_else(|| Error::interface(format!("unknown table: {}", table)))
    }

    fn col(&self, table: &str, name: &str) -> Result<&Column> {
        self.cols(table)?
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::interface(format!("no such column: {}.{}", table, name)))
    }

    fn policy(&self, table: &str, col: &str) -> Result<String> {
        Ok(self.col(table, col)?.policy.clone())
    }

    // — blinding —
    fn encode_cell(v: &CellIn, table: &str, col: &str) -> Result<BigInt> {
        match v {
            CellIn::Null => Err(Error::interface(format!(
                "encrypted column {}.{} cannot hold NULL",
                table, col
            ))),
            CellIn::Str(_) => Err(Error::interface(format!(
                "cannot encrypt a string ({}.{})",
                table, col
            ))),
            CellIn::Bool(b) => Ok(BigInt::from(*b as i32)),
            CellIn::Int(i) => encode_int(i),
            CellIn::Rational(a, b) => encode_rational(a, b),
        }
    }

    #[allow(clippy::type_complexity)]
    fn blind_row(
        &self,
        table: &str,
        row: &[(&str, CellIn)],
    ) -> Result<(serde_json::Map<String, Value>, Vec<(String, BigInt)>)> {
        let cols = self.cols(table)?;
        let mut seen = HashSet::new();
        for (k, _) in row {
            if !cols.iter().any(|c| c.name == *k) {
                return Err(Error::interface(format!("no such column: {}.{}", table, k)));
            }
            if !seen.insert(*k) {
                return Err(Error::interface(format!("duplicate column in row: {}", k)));
            }
        }
        let mut wire = serde_json::Map::new();
        let mut pending = vec![];
        for c in cols {
            let v = row
                .iter()
                .find(|(k, _)| *k == c.name)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    Error::interface(format!("INSERT must provide column {}.{}", table, c.name))
                })?;
            if c.policy == "plain" {
                wire.insert(c.name.clone(), wv(v)?);
            } else {
                let s = Self::encode_cell(v, table, &c.name)?;
                let r = rand_scalar();
                wire.insert(c.name.clone(), wv_int(&md(&(&s + &r))));
                pending.push((c.name.clone(), r));
            }
        }
        Ok((wire, pending))
    }

    /// INSERT: blind encrypted cells, keep the masks locally. Returns the row id.
    pub fn insert(&mut self, table: &str, row: Vec<(&str, CellIn)>) -> Result<i64> {
        let (wire, pending) = self.blind_row(table, &row)?;
        let rowid = self
            .call("insert", json!([table, Value::Object(wire)]))?
            .as_i64()
            .ok_or_else(|| Error::protocol("insert: expected a row id"))?;
        for (col, r) in pending {
            self.masks.insert((table.to_string(), rowid, col), r);
        }
        Ok(rowid)
    }

    /// Bulk insert: all rows are blinded locally and sent in ONE `insert_many`
    /// RPC (all-or-nothing on the server). Returns the new row ids.
    pub fn insert_many(&mut self, table: &str, rows: Vec<Vec<(&str, CellIn)>>) -> Result<Vec<i64>> {
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let mut wires = vec![];
        let mut pendings = vec![];
        for r in &rows {
            let (w, p) = self.blind_row(table, r)?;
            wires.push(Value::Object(w));
            pendings.push(p);
        }
        let ids = self.call("insert_many", json!([table, wires]))?;
        let ids: Vec<i64> = ids
            .as_array()
            .ok_or_else(|| Error::protocol("insert_many: expected a list"))?
            .iter()
            .filter_map(|v| v.as_i64())
            .collect();
        if ids.len() != rows.len() {
            return Err(Error::protocol("insert_many returned a wrong number of row ids"));
        }
        for (rid, p) in ids.iter().zip(pendings) {
            for (col, r) in p {
                self.masks.insert((table.to_string(), *rid, col), r);
            }
        }
        Ok(ids)
    }

    /// UPDATE ... SET col = value WHERE pred. Atomic (implicit transaction when
    /// none is open). Returns the number of rows changed.
    pub fn update(&mut self, table: &str, set: Vec<(&str, CellIn)>, pred: Value) -> Result<usize> {
        for (c, _) in &set {
            self.col(table, c)?;
        }
        self.atomically(|db| {
            let idxs = db.matching(table, pred)?;
            for i in &idxs {
                for (col, v) in &set {
                    if db.policy(table, col)? == "plain" {
                        db.call("update_cell", json!([table, i, col, wv(v)?]))?;
                    } else {
                        let s = Self::encode_cell(v, table, col)?;
                        let r = rand_scalar();
                        db.call("update_cell", json!([table, i, col, wv_int(&md(&(&s + &r)))]))?;
                        db.masks.insert((table.to_string(), *i, col.to_string()), r);
                    }
                }
            }
            Ok(idxs.len())
        })
    }

    /// DELETE FROM table WHERE pred (tombstones). Returns how many rows were removed.
    pub fn delete_rows(&mut self, table: &str, pred: Value) -> Result<i64> {
        self.cols(table)?;
        let idxs = self.matching(table, pred)?;
        if idxs.is_empty() {
            return Ok(0);
        }
        Ok(self.call("delete_rows", json!([table, idxs]))?.as_i64().unwrap_or(0))
    }

    fn atomically<T>(&mut self, f: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        if self.in_tx {
            return f(self);
        }
        self.begin()?;
        match f(self) {
            Ok(v) => {
                self.commit()?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.rollback();
                Err(e)
            }
        }
    }

    // — transactions —
    pub fn in_transaction(&self) -> bool {
        self.in_tx
    }

    /// Open a transaction. The client snapshots its mask vault and schema so a
    /// rollback (or failed commit) restores them exactly.
    pub fn begin(&mut self) -> Result<()> {
        if self.in_tx {
            return Err(Error::interface("a transaction is already open"));
        }
        let snap = (self.masks.clone(), self.schema.clone());
        self.call("tx_begin", json!([]))?; // if this fails nothing changed
        self.snapshot = Some(snap);
        self.in_tx = true;
        Ok(())
    }

    fn restore(&mut self) {
        if let Some((m, s)) = self.snapshot.take() {
            self.masks = m;
            self.schema = s;
        }
        self.in_tx = false;
    }

    /// Commit. No-op outside a transaction. A failed commit restores the
    /// pre-transaction vault (the server did not commit).
    pub fn commit(&mut self) -> Result<()> {
        if !self.in_tx {
            return Ok(());
        }
        match self.call("tx_commit", json!([])) {
            Ok(_) => {
                self.snapshot = None;
                self.in_tx = false;
                Ok(())
            }
            Err(e) => {
                self.restore();
                Err(e)
            }
        }
    }

    /// Roll back server state and the local mask vault. No-op outside a transaction.
    pub fn rollback(&mut self) -> Result<()> {
        if !self.in_tx {
            return Ok(());
        }
        let r = self.call("tx_rollback", json!([]));
        self.restore(); // masks restored even if the RPC failed
        r.map(|_| ())
    }

    /// Run `f` in a transaction: commit on `Ok`, roll back on `Err`.
    pub fn transaction<T, E, F>(&mut self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut Client) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        self.begin()?;
        match f(self) {
            Ok(v) => {
                self.commit()?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.rollback();
                Err(e)
            }
        }
    }

    // — selection —
    fn matching(&mut self, table: &str, pred: Value) -> Result<Vec<i64>> {
        self.cols(table)?;
        Ok(self
            .call("matching_rowids", json!([table, pred]))?
            .as_array()
            .ok_or_else(|| Error::protocol("matching_rowids: expected a list"))?
            .iter()
            .filter_map(|v| v.as_i64())
            .collect())
    }

    fn mask(&self, table: &str, i: i64, col: &str) -> Result<&BigInt> {
        self.masks
            .get(&(table.to_string(), i, col.to_string()))
            .ok_or_else(|| {
                Error::interface(format!(
                    "no mask for {}[{}].{}: row not inserted by this vault",
                    table, i, col
                ))
            })
    }

    fn encrypted_col(&self, table: &str, col: &str) -> Result<()> {
        if self.col(table, col)?.policy == "plain" {
            return Err(Error::interface(format!(
                "{}.{} is a PLAIN column; nothing to unblind",
                table, col
            )));
        }
        Ok(())
    }

    /// Π_lin: SUM over matched rows (the server never holds a key).
    pub fn sum(&mut self, table: &str, col: &str, pred: Value) -> Result<Decoded> {
        let idxs = self.matching(table, pred)?;
        self.sum_ids(table, col, &idxs)
    }

    fn sum_ids(&mut self, table: &str, col: &str, idxs: &[i64]) -> Result<Decoded> {
        self.encrypted_col(table, col)?;
        let blinded = big(&self.call("blinded_sum", json!([table, col, idxs]))?, "blinded_sum")?;
        let mut mask = BigInt::zero();
        for i in idxs {
            mask = md(&(&mask + self.mask(table, *i, col)?));
        }
        decode(&md(&(blinded - mask)))
    }

    pub fn count(&mut self, table: &str, pred: Value) -> Result<usize> {
        Ok(self.matching(table, pred)?.len())
    }

    /// AVG = SUM / COUNT as an exact rational (`None` over zero rows).
    pub fn avg(&mut self, table: &str, col: &str, pred: Value) -> Result<Option<Decoded>> {
        let idxs = self.matching(table, pred)?;
        if idxs.is_empty() {
            return Ok(None);
        }
        let s = self.sum_ids(table, col, &idxs)?;
        let (a, b) = match s {
            Decoded::Int(a) => (a, BigInt::from(1)),
            Decoded::Rational(a, b) => (a, b),
        };
        Ok(Some(reduce(&a, &(b * BigInt::from(idxs.len())))))
    }

    /// Π_mult: encrypted inner product Σ aᵢ·bᵢ via Beaver triples.
    pub fn dot(&mut self, table: &str, left: &str, right: &str, pred: Value) -> Result<Decoded> {
        let idxs = self.matching(table, pred)?;
        self.dot_pairs(table, left, &idxs, table, right, &idxs)
    }

    fn dot_pairs(
        &mut self,
        lt: &str,
        lc: &str,
        lids: &[i64],
        rt: &str,
        rc: &str,
        rids: &[i64],
    ) -> Result<Decoded> {
        self.encrypted_col(lt, lc)?;
        self.encrypted_col(rt, rc)?;
        if lids.is_empty() {
            return Ok(Decoded::Int(BigInt::zero()));
        }
        let ls = self.unblind_cells(lt, lc, lids)?;
        let rs = self.unblind_cells(rt, rc, rids)?;
        let mut openings: Vec<Value> = vec![];
        let mut es = vec![];
        let mut triples: Vec<(BigInt, BigInt, BigInt)> = vec![];
        for k in 0..lids.len() {
            let (u, v) = (rand_scalar(), rand_scalar());
            let w = md(&(&u * &v));
            let (e, g) = (md(&(&ls[k] - &u)), md(&(&rs[k] - &v)));
            openings.push(json!([e.to_string(), g.to_string()]));
            es.push((e, g));
            triples.push((u, v, w));
        }
        let egs = self.call("mult_combine_batch", json!([openings]))?;
        let egs = egs
            .as_array()
            .filter(|a| a.len() == es.len())
            .ok_or_else(|| Error::protocol("mult_combine_batch returned a wrong number of results"))?;
        let mut acc = BigInt::zero();
        for (k, (e, g)) in es.iter().enumerate() {
            let eg = big(&egs[k], "mult_combine_batch")?;
            let (u, v, w) = &triples[k];
            acc = md(&(acc + w + e * v + g * u + eg));
        }
        decode(&acc)
    }

    /// Blinded cells minus masks = the encoded scalars (not yet decoded).
    fn unblind_cells(&mut self, table: &str, col: &str, ids: &[i64]) -> Result<Vec<BigInt>> {
        let ws = self.call("blinded_cells", json!([table, col, ids]))?;
        let ws = ws
            .as_array()
            .filter(|a| a.len() == ids.len())
            .ok_or_else(|| Error::protocol("blinded_cells: wrong number of cells"))?;
        let mut out = vec![];
        for (w, i) in ws.iter().zip(ids) {
            let b = match uwv(w)? {
                CellIn::Int(b) => b,
                _ => return Err(Error::protocol("blinded cell is not an integer")),
            };
            out.push(md(&(b - self.mask(table, *i, col)?)));
        }
        Ok(out)
    }

    /// Plain or decrypted values of `col` for the given row ids (`None` id -> Null).
    pub fn column(&mut self, table: &str, col: &str, ids: &[Option<i64>]) -> Result<Vec<CellIn>> {
        let policy = self.policy(table, col)?;
        let mut uniq: Vec<i64> = ids.iter().flatten().copied().collect();
        uniq.sort_unstable();
        uniq.dedup();
        let mut got: HashMap<i64, CellIn> = HashMap::new();
        if !uniq.is_empty() {
            if policy == "plain" {
                let ws = self.call("plain_cells", json!([table, col, uniq]))?;
                let ws = ws
                    .as_array()
                    .filter(|a| a.len() == uniq.len())
                    .ok_or_else(|| Error::protocol("plain_cells: wrong number of cells"))?;
                for (w, i) in ws.iter().zip(&uniq) {
                    got.insert(*i, uwv(w)?);
                }
            } else {
                let ss = self.unblind_cells(table, col, &uniq)?;
                for (s, i) in ss.iter().zip(&uniq) {
                    got.insert(*i, decode(s)?.into());
                }
            }
        }
        Ok(ids
            .iter()
            .map(|i| i.and_then(|i| got.get(&i).cloned()).unwrap_or(CellIn::Null))
            .collect())
    }

    /// SELECT cols FROM table WHERE pred: one `Vec<CellIn>` per row, in column order.
    pub fn select(&mut self, table: &str, columns: &[&str], pred: Value) -> Result<Vec<Vec<CellIn>>> {
        let idxs = self.matching(table, pred)?;
        let ids: Vec<Option<i64>> = idxs.iter().map(|i| Some(*i)).collect();
        let mut vecs = vec![];
        for c in columns {
            vecs.push(self.column(table, c, &ids)?);
        }
        Ok((0..idxs.len())
            .map(|k| vecs.iter().map(|v| v[k].clone()).collect())
            .collect())
    }

    // — JOIN: client-side hash join over plaintext keys —
    /// Hash join of `left` with each step in turn (like the Python engine's
    /// `_base_tuples`). Join keys must be PLAIN columns; NULL keys never match.
    pub fn join(&mut self, left: &str, steps: &[JoinStep], opts: &JoinOptions) -> Result<JoinResult> {
        self.cols(left)?;
        let first = opts.alias.clone().unwrap_or_else(|| left.to_string());
        let mut aliases = vec![first.clone()];
        let mut tables: HashMap<String, String> = HashMap::new();
        tables.insert(first.clone(), left.to_string());
        let pred = opts.where_.clone().unwrap_or(Value::Null);
        let mut tuples: Vec<Vec<Option<i64>>> =
            self.matching(left, pred)?.into_iter().map(|i| vec![Some(i)]).collect();

        for st in steps {
            let alias = st.alias.clone().unwrap_or_else(|| st.table.clone());
            if tables.contains_key(&alias) {
                return Err(Error::interface(format!("duplicate alias: {}", alias)));
            }
            let left_alias = st.left_alias.clone().unwrap_or_else(|| first.clone());
            let lt = tables
                .get(&left_alias)
                .ok_or_else(|| {
                    Error::interface(format!("unknown or later alias in ON clause: {}", left_alias))
                })?
                .clone();
            if self.col(&lt, &st.left_col)?.policy != "plain"
                || self.col(&st.table, &st.right_col)?.policy != "plain"
            {
                return Err(Error::interface("JOIN keys must be PLAIN columns"));
            }
            let right_ids = self.matching(&st.table, Value::Null)?;
            let rid_opts: Vec<Option<i64>> = right_ids.iter().map(|i| Some(*i)).collect();
            let right_keys = self.column(&st.table, &st.right_col, &rid_opts)?;
            let mut right_map: HashMap<String, Vec<i64>> = HashMap::new();
            for (rid, k) in right_ids.iter().zip(&right_keys) {
                if let Some(key) = plain_key(k) {
                    right_map.entry(key).or_default().push(*rid);
                }
            }
            let lpos = aliases.iter().position(|a| *a == left_alias).unwrap();
            let lids: Vec<Option<i64>> = tuples.iter().map(|t| t[lpos]).collect();
            let lkeys = self.column(&lt, &st.left_col, &lids)?;
            let mut stepped = vec![];
            for (t, lk) in tuples.iter().zip(&lkeys) {
                let matches = plain_key(lk).and_then(|k| right_map.get(&k));
                match matches {
                    Some(ms) if !ms.is_empty() => {
                        for m in ms {
                            let mut nt = t.clone();
                            nt.push(Some(*m));
                            stepped.push(nt);
                        }
                    }
                    _ if st.kind == JoinKind::Left => {
                        let mut nt = t.clone();
                        nt.push(None);
                        stepped.push(nt);
                    }
                    _ => {}
                }
            }
            tuples = stepped;
            aliases.push(alias.clone());
            tables.insert(alias, st.table.clone());
        }
        Ok(JoinResult { aliases, tables, tuples })
    }

    fn alias_pos(j: &JoinResult, alias: &str) -> Result<usize> {
        j.aliases
            .iter()
            .position(|a| a == alias)
            .ok_or_else(|| Error::interface(format!("unknown join alias: {}", alias)))
    }

    /// Values of alias.col for every joined row (Null on the NULL side).
    pub fn join_column(&mut self, j: &JoinResult, alias: &str, col: &str) -> Result<Vec<CellIn>> {
        let p = Self::alias_pos(j, alias)?;
        let ids: Vec<Option<i64>> = j.tuples.iter().map(|t| t[p]).collect();
        self.column(&j.tables[alias], col, &ids)
    }

    /// SUM(alias.col) over the joined rows via Π_lin; the NULL side is skipped
    /// and a row joined k times counts k times.
    pub fn join_sum(&mut self, j: &JoinResult, alias: &str, col: &str) -> Result<Decoded> {
        let p = Self::alias_pos(j, alias)?;
        let ids: Vec<i64> = j.tuples.iter().filter_map(|t| t[p]).collect();
        self.sum_ids(&j.tables[alias], col, &ids)
    }

    /// COUNT(*) of the joined rows.
    pub fn join_count(&self, j: &JoinResult) -> usize {
        j.tuples.len()
    }

    /// DOT(a.x, b.y) over joined rows where both sides are non-null (Π_mult).
    pub fn join_dot(
        &mut self,
        j: &JoinResult,
        alias_a: &str,
        col_a: &str,
        alias_b: &str,
        col_b: &str,
    ) -> Result<Decoded> {
        let (pa, pb) = (Self::alias_pos(j, alias_a)?, Self::alias_pos(j, alias_b)?);
        let mut la = vec![];
        let mut lb = vec![];
        for t in &j.tuples {
            if let (Some(a), Some(b)) = (t[pa], t[pb]) {
                la.push(a);
                lb.push(b);
            }
        }
        self.dot_pairs(&j.tables[alias_a], col_a, &la, &j.tables[alias_b], col_b, &lb)
    }

    /// Rows on the server this vault cannot decrypt (a crash between the
    /// server accepting an INSERT and the vault being saved).
    pub fn find_orphans(&mut self) -> Result<HashMap<String, Vec<i64>>> {
        let mut out = HashMap::new();
        let tables: Vec<(String, Vec<String>)> = self
            .schema
            .iter()
            .map(|(t, cols)| {
                (
                    t.clone(),
                    cols.iter().filter(|c| c.policy != "plain").map(|c| c.name.clone()).collect(),
                )
            })
            .collect();
        for (t, enc) in tables {
            if enc.is_empty() {
                continue;
            }
            let info = self.table_info(&t)?;
            let dead: HashSet<i64> = info.deleted.iter().copied().collect();
            let bad: Vec<i64> = (0..info.rows)
                .filter(|i| {
                    !dead.contains(i)
                        && enc
                            .iter()
                            .any(|c| !self.masks.contains_key(&(t.clone(), *i, c.clone())))
                })
                .collect();
            if !bad.is_empty() {
                out.insert(t, bad);
            }
        }
        Ok(out)
    }

    // — vault persistence —
    /// Write the mask vault as JSON ATOMICALLY (temp file + fsync + rename)
    /// with mode 0600 (unix). The vault is the owner's one long-lived secret.
    pub fn save_vault(&mut self, file: Option<&Path>) -> Result<()> {
        let target = file
            .map(PathBuf::from)
            .or_else(|| self.vault_path.clone())
            .ok_or_else(|| Error::interface("no vault path given"))?;
        let entries: Vec<Value> = self
            .masks
            .iter()
            .map(|((t, i, c), r)| json!([t, i, c, r.to_string()]))
            .collect();
        let body = json!({"version": 1, "masks": entries}).to_string();
        let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let tmp = dir.join(format!(
            ".{}.{}.{:08x}.tmp",
            target.file_name().and_then(|s| s.to_str()).unwrap_or("vault"),
            std::process::id(),
            rand::random::<u32>()
        ));
        let io = |e: std::io::Error| Error::interface(format!("vault write failed: {}", e));
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, &target)
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(io(e));
        }
        if self.vault_path.is_none() {
            self.vault_path = Some(target);
        }
        Ok(())
    }

    /// Replace the in-memory mask vault with the one in `file`.
    pub fn load_vault(&mut self, file: Option<&Path>) -> Result<()> {
        let src = file
            .map(PathBuf::from)
            .or_else(|| self.vault_path.clone())
            .ok_or_else(|| Error::interface("no vault path given"))?;
        let text = std::fs::read_to_string(&src)
            .map_err(|e| Error::interface(format!("cannot read vault {}: {}", src.display(), e)))?;
        let doc: Value = serde_json::from_str(&text)
            .map_err(|_| Error::interface(format!("{} is not a TorusDB vault", src.display())))?;
        let list = match (doc["version"].as_i64(), doc["masks"].as_array()) {
            (Some(1), Some(l)) => l,
            _ => return Err(Error::interface(format!("{} is not a TorusDB vault", src.display()))),
        };
        let mut m = HashMap::new();
        for e in list {
            let bad = || Error::interface("corrupt vault entry");
            let a = e.as_array().filter(|a| a.len() == 4).ok_or_else(bad)?;
            m.insert(
                (
                    a[0].as_str().ok_or_else(bad)?.to_string(),
                    a[1].as_i64().ok_or_else(bad)?,
                    a[2].as_str().ok_or_else(bad)?.to_string(),
                ),
                big(&a[3], "vault mask")?,
            );
        }
        self.masks = m;
        if self.vault_path.is_none() {
            self.vault_path = Some(src);
        }
        Ok(())
    }

    /// Number of masks currently held (diagnostics/tests).
    pub fn mask_count(&self) -> usize {
        self.masks.len()
    }
}

// ── plaintext WHERE predicates (DNF, server-evaluated on PLAIN columns) ──────
/// A plaintext equality predicate, e.g. `eq_int("dept", 5)`.
pub fn eq_int(col: &str, v: i64) -> Value {
    json!({"or": [[{"c": col, "op": "=", "v": {"t":"i","v": v.to_string()}}]]})
}

/// No predicate: all live rows.
pub fn all() -> Value {
    Value::Null
}

/// `col <op> value` with op one of `= != < <= > >=`.
pub fn cmp(col: &str, op: &str, v: &CellIn) -> Value {
    json!({"or": [[{"c": col, "op": op, "v": wv(v).unwrap_or(json!({"t": "n"}))}]]})
}
pub fn eq(col: &str, v: &CellIn) -> Value {
    cmp(col, "=", v)
}
/// `col IN (values)`.
pub fn is_in(col: &str, vs: &[CellIn]) -> Value {
    let w: Vec<Value> = vs.iter().map(|v| wv(v).unwrap_or(json!({"t": "n"}))).collect();
    json!({"or": [[{"c": col, "in": w}]]})
}
fn groups(p: &Value) -> Vec<Value> {
    p["or"].as_array().cloned().unwrap_or_default()
}
/// a AND b AND ... (distributes over OR, staying in DNF).
pub fn and(preds: &[Value]) -> Value {
    let mut acc: Vec<Vec<Value>> = vec![vec![]];
    for p in preds {
        let mut next = vec![];
        for g in &acc {
            for h in groups(p) {
                let mut ng = g.clone();
                ng.extend(h.as_array().cloned().unwrap_or_default());
                next.push(ng);
            }
        }
        acc = next;
    }
    json!({"or": acc})
}
/// a OR b OR ...
pub fn or(preds: &[Value]) -> Value {
    json!({"or": preds.iter().flat_map(groups).collect::<Vec<_>>()})
}
