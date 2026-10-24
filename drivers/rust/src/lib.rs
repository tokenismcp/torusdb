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
//! **Trust model.** The server is untrusted: every reply is validated, and the
//! server never decides which columns are encrypted - the policies this client
//! created (or loaded from its own vault) are the trust anchor. Tables whose
//! schema was merely learned from the server are read-only for plain columns
//! (see [`ConnectOptions::trust_server_schema`]).
//!
//! **FHE columns.** `policy: "fhe"` INT columns (EC-FHE on BN254, see [`FheKey`]) let the server sum
//! ciphertexts, scale them by public scalars and multiply two ciphertext columns with a pairing, with no
//! key and no per-cell state at the server: [`Client::sum`], [`Client::avg`], [`Client::scaled_sum`],
//! [`Client::dot`]/[`Client::dot_with_backend`], integrity tags via `authenticated`.
//!
//! Cargo feature `tls` (off by default) adds TLS via rustls; certificates and
//! hostnames are verified unless [`ConnectOptions::tls_insecure`] is set.

mod conn;
mod error;
mod field;
mod fhe;
mod hash;

pub use error::{Error, Kind};
pub use fhe::{
    add_sums as fhe_add_sums, cell_to_sum as fhe_cell_to_sum, mul_dots as fhe_mul_dots, sum_cells as fhe_sum_cells,
    FheBackend, FheKey, FHE_CELL_BYTES, FHE_DEFAULT_RANGE, FHE_DOT_BYTES, FHE_MAX_RANGE, FHE_SUM_BYTES,
};
#[doc(hidden)]
pub use fhe::internals as fhe_internals;
pub use field::{decode, encode_int, encode_rational, n, reduce, Decoded};

use conn::{Conn, TransportOpts, HARD_MAX_FRAME};
use field::{md, rand_scalar};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Newest wire protocol this driver speaks.
pub const PROTOCOL_VERSION: u64 = 2;
/// Longest decimal string accepted for any integer from the server.
pub const MAX_DIGITS: usize = 90;

type Result<T> = std::result::Result<T, Error>;

/// Server-side limit on list arguments is 200 000; stay well under it.
const LIST_CHUNK: usize = 100_000;
const MAC: &str = "__mac__";
const FMAC: &str = "__fmac__";
const FHE_SUM_CHUNK: usize = 2000; // ids per fhe_sum call (server cap 5000)
const FHE_DOT_CHUNK_NATIVE: usize = 2000; // server cap 6000 with the native back end
const FHE_DOT_CHUNK: usize = 50; // server cap 300 with pure Python (~0.2 s per row)
const FHE_READ_CHUNK: usize = 5000; // cells per plain_cells call (~600 bytes each)
const FHE_WRITE_CHUNK: usize = 2000; // items per update_cells call
const FHE_MAX_K: i64 = 1 << 40;
const POLICIES: [&str; 4] = ["plain", "encrypted", "paired", "fhe"];
const TYPES: [&str; 3] = ["int", "str", "rational"];

// ── column spec / cell values ────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub struct Column {
    pub name: String,
    pub ty: String,     // "int" | "str" | "rational"
    pub policy: String, // "plain" | "encrypted" | "paired" | "fhe"
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

// ── strict reply validation ──────────────────────────────────────────────────
fn proto(m: impl Into<String>) -> Error {
    Error::protocol(m)
}

fn big(s: &Value, what: &str) -> Result<BigInt> {
    let t = s.as_str().ok_or_else(|| proto(format!("bad integer in {}", what)))?;
    let digits = t.strip_prefix('-').unwrap_or(t);
    if digits.is_empty() || digits.len() > MAX_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(proto(format!("bad integer in {}", what)));
    }
    t.parse::<BigInt>().map_err(|_| proto(format!("bad integer in {}", what)))
}

const MAX_SAFE: i64 = (1 << 53) - 1;

fn row_id(v: &Value, what: &str) -> Result<i64> {
    match v.as_i64() {
        Some(i) if (0..=MAX_SAFE).contains(&i) => Ok(i),
        _ => Err(proto(format!("bad row id in {}", what))),
    }
}

fn arr<'a>(v: &'a Value, what: &str, len: Option<usize>) -> Result<&'a Vec<Value>> {
    let a = v.as_array().ok_or_else(|| proto(format!("{}: expected a list", what)))?;
    if let Some(l) = len {
        if a.len() != l {
            return Err(proto(format!("{}: expected {} items, got {}", what, l, a.len())));
        }
    }
    Ok(a)
}

fn string(v: &Value, what: &str) -> Result<String> {
    v.as_str().map(String::from).ok_or_else(|| proto(format!("{}: expected a string", what)))
}

fn ids_from(v: &Value, what: &str) -> Result<Vec<i64>> {
    arr(v, what, None)?.iter().map(|x| row_id(x, what)).collect()
}

fn norm_policy(p: &str) -> String {
    // anything we do not recognise is treated as ENCRYPTED
    if POLICIES.contains(&p) { p.to_string() } else { "encrypted".to_string() }
}
fn norm_type(t: &str) -> String {
    if TYPES.contains(&t) { t.to_string() } else { "int".to_string() }
}
fn check_name(kind: &str, n: &str) -> Result<()> {
    if n.is_empty() {
        return Err(Error::interface(format!("{} name must not be empty", kind)));
    }
    if n.starts_with("__") {
        return Err(Error::interface(format!("{} names starting with \"__\" are reserved: {}", kind, n)));
    }
    Ok(())
}

// ── wire value codec (mirrors proto/nokey_wire.py) ───────────────────────────
/// An FHE ciphertext cell as a wire value. The length is checked before anything is sent.
fn wv_cell(cell: &[u8]) -> Result<Value> {
    if cell.len() != FHE_CELL_BYTES {
        return Err(Error::interface(format!(
            "an FHE cell is exactly {} bytes, got {}",
            FHE_CELL_BYTES,
            cell.len()
        )));
    }
    Ok(json!({"t": "x", "v": fhe::b64_encode(cell)}))
}

/// A binary cell from the server: `None` for a NULL cell, else exactly `len` canonical-base64 bytes.
fn bin_cell(d: &Value, what: &str, len: usize) -> Result<Option<Vec<u8>>> {
    match d.get("t").and_then(|t| t.as_str()) {
        Some("n") => Ok(None),
        Some("x") => {
            let s = d["v"].as_str().ok_or_else(|| proto(format!("{}: expected a binary cell", what)))?;
            match fhe::b64_decode(s) {
                Some(b) if b.len() == len => Ok(Some(b)),
                _ => Err(proto(format!("{}: a binary cell must be {} bytes of canonical base64", what, len))),
            }
        }
        _ => Err(proto(format!("{}: expected a binary cell", what))),
    }
}

/// A base64 blob reply (`fhe_sum` / `fhe_dot`) of exactly `len` bytes.
fn blob(d: &Value, what: &str, len: usize) -> Result<Vec<u8>> {
    let s = d.as_str().ok_or_else(|| proto(format!("{}: expected a base64 string", what)))?;
    match fhe::b64_decode(s) {
        Some(b) if b.len() == len => Ok(b),
        _ => Err(proto(format!("{}: expected {} bytes of canonical base64", what, len))),
    }
}

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

fn uwv(d: &Value) -> Result<CellIn> {
    let tag = d.get("t").and_then(|t| t.as_str()).ok_or_else(|| proto("bad wire value"))?;
    match tag {
        "n" => Ok(CellIn::Null),
        "b" => Ok(CellIn::Bool(d["v"].as_bool().ok_or_else(|| proto("bad bool cell"))?)),
        "i" => Ok(CellIn::Int(big(&d["v"], "int cell")?)),
        "s" => Ok(CellIn::Str(string(&d["v"], "str cell")?)),
        "f" => {
            let (a, b) = (big(&d["n"], "numerator")?, big(&d["d"], "denominator")?);
            if b.is_zero() {
                return Err(proto("zero denominator from server"));
            }
            Ok(reduce(&a, &b).into())
        }
        other => Err(proto(format!("bad wire tag {:?}", other))),
    }
}

/// A blinded scalar from the server (must be an int cell), reduced mod N.
fn scalar_cell(d: &Value) -> Result<BigInt> {
    match uwv(d)? {
        CellIn::Int(b) => Ok(md(&b)),
        _ => Err(proto("blinded cell is not an integer")),
    }
}

// ── connection options ───────────────────────────────────────────────────────
#[derive(Clone)]
pub struct ConnectOptions {
    /// API token; required when the server runs with `--token-file`. Never
    /// logged, never in errors, redacted in `Debug`.
    pub token: Option<String>,
    /// Total time budget per call (default 30 s; `None` = block forever).
    /// Also bounds DNS + connect and the TLS handshake. Must not be zero.
    pub timeout: Option<Duration>,
    /// Wrap the connection in TLS (needs the `tls` cargo feature).
    pub tls: bool,
    /// PEM CA certificate(s) to trust instead of the built-in web roots. Needs `tls`.
    pub ca_pem: Option<Vec<u8>>,
    /// DANGEROUS: skip certificate verification. Local development only. Needs `tls`.
    pub tls_insecure: bool,
    /// Send the token over an UNENCRYPTED connection to a non-loopback host
    /// (refused by default: the token would travel in the clear).
    pub allow_insecure_token: bool,
    /// Mask-vault file: loaded on connect if it exists; default path of
    /// `save_vault`/`load_vault`.
    pub vault_path: Option<PathBuf>,
    /// Learn tables that exist on the server but not here (schema only).
    /// Tables learned this way are UNTRUSTED: plain reads work, writes are refused.
    pub sync_schema: bool,
    /// Allow writes to tables whose policies were learned from the server.
    /// DANGEROUS: a lying server can mark encrypted columns "plain" and make
    /// this client send them in the clear.
    pub trust_server_schema: bool,
    /// Authenticated (SPDZ MAC) mode: every encrypted cell carries a one-time-
    /// padded MAC alpha*s (hidden `__mac__<col>` cells, alpha kept in the
    /// vault) and every affine result / read is verified (`Kind::Integrity`).
    pub authenticated: bool,
    /// The owner's key for `fhe` columns (see [`FheKey`]). Needed for INSERT/UPDATE/reads/SUM/DOT on
    /// them. With `authenticated`, FHE cells also carry integrity tags in a hidden `__fmac__<col>` column.
    pub fhe_key: Option<FheKey>,
    /// How DOT on two FHE columns is computed, see [`FheDotMode`]. Default `Auto`.
    pub fhe_dot_mode: FheDotMode,
    /// Backward-compatible alias: with `authenticated` and mode `Auto`, selects `Delegated`.
    pub fhe_allow_unverified_dot: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions {
            token: None,
            timeout: Some(Duration::from_secs(30)),
            tls: false,
            ca_pem: None,
            tls_insecure: false,
            allow_insecure_token: false,
            vault_path: None,
            sync_schema: true,
            trust_server_schema: false,
            authenticated: false,
            fhe_key: None,
            fhe_dot_mode: FheDotMode::Auto,
            fhe_allow_unverified_dot: false,
        }
    }
}

impl fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("tls", &self.tls)
            .field("ca_pem", &self.ca_pem.as_ref().map(|c| format!("<{} bytes>", c.len())))
            .field("tls_insecure", &self.tls_insecure)
            .field("allow_insecure_token", &self.allow_insecure_token)
            .field("vault_path", &self.vault_path)
            .field("sync_schema", &self.sync_schema)
            .field("trust_server_schema", &self.trust_server_schema)
            .field("authenticated", &self.authenticated)
            .field("fhe_key", &self.fhe_key)
            .field("fhe_dot_mode", &self.fhe_dot_mode)
            .field("fhe_allow_unverified_dot", &self.fhe_allow_unverified_dot)
            .finish()
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
    /// Request-size limits published in `hello` (`None` on older servers: conservative defaults apply).
    pub limits: Option<ServerLimits>,
}

/// How DOT on two FHE columns is computed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FheDotMode {
    /// `Delegated` unless the connection is `authenticated`, then `Local`.
    #[default]
    Auto,
    /// The owner reads both operand columns (every cell tag-verified when `authenticated`), decrypts and
    /// multiplies/sums the plaintexts itself: verified, O(n) decryptions, no range limit on the result.
    Local,
    /// The server multiplies ciphertexts with its pairing: fast, but the result CANNOT be integrity-checked
    /// (a lying server makes you decrypt a wrong number) and must lie in the key's range.
    Delegated,
}

impl FheDotMode {
    /// Parse "auto" | "local" | "delegated"; anything else is `Kind::Interface`.
    pub fn parse(s: &str) -> Result<FheDotMode> {
        match s {
            "auto" => Ok(FheDotMode::Auto),
            "local" => Ok(FheDotMode::Local),
            "delegated" => Ok(FheDotMode::Delegated),
            other => Err(Error::interface(format!("fhe_dot_mode must be \"auto\", \"local\" or \"delegated\", got {:?}", other))),
        }
    }
}

/// Per-back-end row counts (`None` = not published).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendRows {
    pub pyecc: Option<usize>,
    pub mcl: Option<usize>,
}

impl BackendRows {
    fn get(&self, b: FheBackend) -> Option<usize> {
        match b {
            FheBackend::Pyecc => self.pyecc,
            FheBackend::Mcl => self.mcl,
        }
    }
}

/// FHE request limits from `hello.limits.fhe`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FheLimits {
    pub max_sum_rows: Option<usize>,
    pub max_dot_rows: BackendRows,
    pub recommended_dot_rows: BackendRows,
}

/// Request-size limits a server publishes in `hello`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerLimits {
    pub max_items: Option<usize>,
    pub fhe: Option<FheLimits>,
}

fn pos(v: &Value) -> Option<usize> {
    v.as_u64().filter(|n| *n >= 1 && *n <= MAX_SAFE as u64).map(|n| n as usize)
}

/// Limits are advisory sizing hints: malformed parts are ignored, never trusted blindly.
fn parse_limits(l: &Value) -> Option<ServerLimits> {
    l.as_object()?;
    let rows = |v: &Value| BackendRows { pyecc: pos(&v["pyecc"]), mcl: pos(&v["mcl"]) };
    let fhe = l.get("fhe").filter(|f| f.is_object()).map(|f| FheLimits {
        max_sum_rows: pos(&f["max_sum_rows"]),
        max_dot_rows: rows(&f["max_dot_rows"]),
        recommended_dot_rows: rows(&f["recommended_dot_rows"]),
    });
    Some(ServerLimits { max_items: pos(&l["max_items"]), fhe })
}

#[derive(Clone, Debug, PartialEq)]
pub struct TableInfo {
    pub rows: i64,
    pub deleted: Vec<i64>,
    /// Columns that have a server-side index.
    pub indexes: Vec<String>,
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
    /// WHERE predicate over PLAIN columns. Atoms on the FROM table (no alias,
    /// or its alias) are evaluated by the server's index; atoms built with
    /// [`cmp_in`] / [`is_in_of`] on another alias filter the joined rows
    /// client-side. NULL operands make an atom false, as in SQL.
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
type Undo = Vec<(MaskKey, Option<BigInt>)>;

#[derive(Clone)]
struct TableDef {
    cols: Vec<Column>,
    trusted: bool,
}
type Schema = HashMap<String, TableDef>;
/// A row ready to send: the wire cells, the masks to remember, and (authenticated FHE) the
/// `(column, plaintext)` pairs whose row-bound tags are written once the row id is known.
struct BlindedRow {
    wire: serde_json::Map<String, Value>,
    pending: Vec<(String, BigInt)>,
    tags: Vec<(String, i64)>,
}

pub struct Client {
    conn: Conn,
    masks: Masks, // (table, rowid, col) -> r   (SECRET)
    schema: Schema,
    in_tx: bool,
    txid: Option<String>,
    undo: Option<Undo>,         // mask journal of the open transaction
    tx_schema: Option<Schema>,  // schema at begin()
    in_doubt: HashMap<String, (Undo, Schema)>,
    vault_path: Option<PathBuf>,
    info: ServerInfo,
    addr: String,
    opts: ConnectOptions, // holds the token: private, redacted in Debug
    alpha: BigInt,        // SECRET MAC key
    update_cells_ok: bool, // false once the server answered "unknown method" for update_cells
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("addr", &self.addr)
            .field("closed", &self.conn.is_closed())
            .field("in_transaction", &self.in_tx)
            .field("masks", &format_args!("{} (redacted)", self.masks.len()))
            .finish()
    }
}

fn is_loopback(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => addr,
    };
    host == "localhost"
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

fn validate_opts(addr: &str, o: &ConnectOptions) -> Result<()> {
    if let Some(t) = o.timeout {
        if t.is_zero() {
            return Err(Error::interface("timeout must be positive (use None for no timeout)"));
        }
    }
    if !o.tls && (o.ca_pem.is_some() || o.tls_insecure) {
        return Err(Error::interface(
            "`ca_pem` / `tls_insecure` were given without `tls: true`; refusing to continue unencrypted",
        ));
    }
    if o.token.as_deref().map(|t| !t.is_empty()).unwrap_or(false)
        && !o.tls
        && !is_loopback(addr)
        && !o.allow_insecure_token
    {
        return Err(Error::interface(format!(
            "refusing to send the token to {} over an unencrypted connection; \
             use tls: true (or allow_insecure_token: true if you really mean it)",
            addr
        )));
    }
    Ok(())
}

/// Connect + hello + auth.
fn open_session(addr: &str, o: &ConnectOptions) -> Result<(Conn, ServerInfo)> {
    let mut conn = Conn::open(
        addr,
        &TransportOpts {
            timeout: o.timeout,
            tls: o.tls,
            tls_insecure: o.tls_insecure,
            ca_pem: o.ca_pem.as_deref(),
        },
    )?;
    let r = (|| -> Result<ServerInfo> {
        let info = match conn.call("hello", json!([]), HARD_MAX_FRAME) {
            Ok(h) => parse_hello(&h)?,
            Err(e)
                if e.kind == Kind::BadRequest
                    && (e.message.contains("unknown method") || e.message.contains("_rpc_hello")) =>
            {
                ServerInfo { protocol: 1, ..Default::default() } // protocol-1 server
            }
            Err(e) => return Err(e),
        };
        if info.protocol > PROTOCOL_VERSION {
            return Err(Error::interface(format!(
                "server speaks protocol {}; this driver supports up to {} - upgrade the driver",
                info.protocol, PROTOCOL_VERSION
            )));
        }
        let mf = info.max_frame.map(|m| m as usize).unwrap_or(HARD_MAX_FRAME);
        conn.max_read = mf.min(HARD_MAX_FRAME);
        conn.max_write = mf;
        if info.auth_required {
            match o.token.as_deref() {
                None | Some("") => {
                    return Err(Error::new(
                        Kind::Unauthenticated,
                        "the server requires a token (set ConnectOptions::token)",
                    ))
                }
                Some(t) => {
                    conn.call("auth", json!([t]), 4096)?;
                }
            }
        }
        Ok(info)
    })();
    match r {
        Ok(info) => Ok((conn, info)),
        Err(e) => {
            conn.close();
            Err(e)
        }
    }
}

fn parse_hello(h: &Value) -> Result<ServerInfo> {
    let o = h.as_object().ok_or_else(|| proto("hello: expected an object"))?;
    let protocol = o
        .get("protocol")
        .and_then(|v| v.as_u64())
        .filter(|p| *p >= 1)
        .ok_or_else(|| proto("hello.protocol: expected a positive integer"))?;
    let auth_required = o
        .get("auth_required")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| proto("hello.auth_required: expected a boolean"))?;
    let mut info = ServerInfo { protocol, auth_required, ..Default::default() };
    if let Some(s) = o.get("server") {
        info.server = Some(string(s, "hello.server")?);
    }
    if let Some(m) = o.get("max_frame") {
        let m = m.as_u64().filter(|m| *m >= 1024).ok_or_else(|| proto("hello.max_frame: bad value"))?;
        info.max_frame = Some(m);
    }
    if let Some(p) = o.get("persistent") {
        info.persistent = Some(p.as_bool().ok_or_else(|| proto("hello.persistent: expected a boolean"))?);
    }
    if let Some(l) = o.get("limits") {
        info.limits = parse_limits(l);
    }
    Ok(info)
}

fn chunks(xs: &[i64]) -> Vec<&[i64]> {
    if xs.is_empty() {
        vec![]
    } else {
        xs.chunks(LIST_CHUNK).collect()
    }
}

impl Client {
    /// Connect with default options (no auth, no TLS, 30 s timeout).
    pub fn connect(addr: &str) -> Result<Client> {
        Client::connect_with(addr, &ConnectOptions::default())
    }

    pub fn connect_with(addr: &str, o: &ConnectOptions) -> Result<Client> {
        validate_opts(addr, o)?;
        let (conn, info) = open_session(addr, o)?;
        let mut c = Client {
            conn,
            masks: HashMap::new(),
            schema: HashMap::new(),
            in_tx: false,
            txid: None,
            undo: None,
            tx_schema: None,
            in_doubt: HashMap::new(),
            vault_path: o.vault_path.clone(),
            info,
            addr: addr.to_string(),
            opts: o.clone(),
            alpha: BigInt::zero(),
            update_cells_ok: true,
        };
        if o.authenticated {
            c.alpha = BigInt::from(1) + md(&rand_scalar()).mod_floor(&(n() - 1));
        }
        let r = (|| -> Result<()> {
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

    /// What the server announced in `hello`.
    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    /// Close the connection (an open transaction is rolled back by the server).
    pub fn close(&mut self) {
        self.in_tx = false;
        self.undo = None;
        self.tx_schema = None;
        self.txid = None;
        self.conn.close();
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// One RPC with transaction-state bookkeeping.
    fn call_max(&mut self, method: &str, args: Value, max_reply: usize) -> Result<Value> {
        if self.conn.is_closed() {
            return Err(self.conn.reason());
        }
        match self.conn.call(method, args, max_reply) {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.in_tx && method != "tx_commit" && method != "tx_rollback" {
                    match e.kind {
                        // the server rolls back when the session dies
                        Kind::Connection | Kind::Timeout | Kind::Protocol => self.abort_local(),
                        // the server aborted the transaction and keeps the session
                        // aborted until ROLLBACK
                        Kind::Busy if e.message.contains("timed out") => {
                            self.abort_local();
                            let _ = self.conn.call("tx_rollback", json!([]), 4096);
                        }
                        _ => {}
                    }
                }
                Err(e)
            }
        }
    }

    fn call(&mut self, method: &str, args: Value) -> Result<Value> {
        self.call_max(method, args, HARD_MAX_FRAME)
    }

    // — operations —
    pub fn ping(&mut self) -> Result<bool> {
        Ok(self.call_max("ping", json!([]), 4096)?.as_str() == Some("pong"))
    }
    /// Server counters (admin token when auth is on).
    pub fn stats(&mut self) -> Result<Value> {
        let v = self.call("stats", json!([]))?;
        if !v.is_object() {
            return Err(proto("stats: expected an object"));
        }
        Ok(v)
    }
    pub fn checkpoint(&mut self) -> Result<i64> {
        self.call_max("checkpoint", json!([]), 4096)?
            .as_i64()
            .ok_or_else(|| proto("checkpoint: expected an integer"))
    }
    /// Ask the server to write a checksummed backup (admin); returns its path.
    pub fn backup(&mut self) -> Result<String> {
        string(&self.call_max("backup", json!([]), 1 << 16)?, "backup")
    }
    pub fn tables(&mut self) -> Result<Vec<String>> {
        let v = self.call("tables", json!([]))?;
        arr(&v, "tables", None)?.iter().map(|x| string(x, "tables item")).collect()
    }
    pub fn table_info(&mut self, table: &str) -> Result<TableInfo> {
        let v = self.call("table_info", json!([table]))?;
        let o = v.as_object().ok_or_else(|| proto("table_info: expected an object"))?;
        let rows = o
            .get("rows")
            .and_then(|r| r.as_i64())
            .filter(|r| *r >= 0)
            .ok_or_else(|| proto("table_info.rows: expected a non-negative integer"))?;
        let deleted = ids_from(o.get("deleted").unwrap_or(&Value::Null), "table_info.deleted")?;
        let indexes = match o.get("indexes") {
            None | Some(Value::Null) => vec![],
            Some(v) => arr(v, "table_info.indexes", None)?
                .iter()
                .map(|x| string(x, "table_info.indexes"))
                .collect::<Result<Vec<String>>>()?,
        };
        Ok(TableInfo { rows, deleted, indexes })
    }

    /// Learn tables that exist on the server but not here. They are UNTRUSTED
    /// (policies came from the server): plain reads work, writes are refused
    /// unless `trust_server_schema`. Never overwrites a table already known.
    pub fn sync_schema(&mut self) -> Result<Vec<String>> {
        let mut added = vec![];
        for t in self.tables()? {
            if self.schema.contains_key(&t) {
                continue;
            }
            let v = self.call("schema", json!([t]))?;
            let mut cols = vec![];
            for c in arr(&v, "schema", None)? {
                let a = arr(c, "schema column", Some(3))?;
                cols.push(Column {
                    name: string(&a[0], "column name")?,
                    ty: norm_type(&string(&a[1], "column type")?),
                    policy: norm_policy(&string(&a[2], "column policy")?),
                });
            }
            self.schema.insert(t.clone(), TableDef { cols, trusted: false });
            added.push(t);
        }
        Ok(added)
    }

    /// Mark a server-learned table as trusted for writes (you vouch for its policies).
    pub fn trust_table(&mut self, table: &str) -> Result<()> {
        let d = self
            .schema
            .get_mut(table)
            .ok_or_else(|| Error::interface(format!("unknown table: {}", table)))?;
        d.trusted = true;
        Ok(())
    }

    // — DDL —
    pub fn create_table(&mut self, name: &str, cols: Vec<Column>) -> Result<()> {
        self.create_table_impl(name, cols, false)
    }

    fn create_table_impl(&mut self, name: &str, cols: Vec<Column>, if_not_exists: bool) -> Result<()> {
        self.assert_writable()?;
        check_name("table", name)?;
        let mut seen = HashSet::new();
        for c in &cols {
            check_name("column", &c.name)?;
            if !seen.insert(c.name.clone()) {
                return Err(Error::interface(format!("duplicate column: {}", c.name)));
            }
            if !POLICIES.contains(&c.policy.as_str()) {
                return Err(Error::interface(format!("bad policy for {}: {}", c.name, c.policy)));
            }
            if !TYPES.contains(&c.ty.as_str()) {
                return Err(Error::interface(format!("bad type for {}: {}", c.name, c.ty)));
            }
            if c.policy == "fhe" && c.ty != "int" {
                return Err(Error::interface(format!("FHE columns must be INT (column {})", c.name)));
            }
        }
        let wire: Vec<Value> = cols.iter().map(|c| json!([c.name, c.ty, c.policy])).collect();
        let args = if if_not_exists { json!([name, wire, true]) } else { json!([name, wire]) };
        match self.call("create", args)? {
            // already existed: nothing changed and nothing adopted (sync_schema learns it, untrusted)
            Value::Bool(false) => return Ok(()),
            Value::Null => {}
            _ => return Err(proto("create: unexpected reply")),
        }
        self.schema.insert(name.to_string(), TableDef { cols, trusted: true });
        Ok(())
    }

    /// `CREATE TABLE IF NOT EXISTS` (atomic on the server): a no-op when the table already
    /// exists; the existing table is NOT adopted as trusted (use `sync_schema`).
    pub fn create_table_if_not_exists(&mut self, name: &str, cols: Vec<Column>) -> Result<()> {
        self.create_table_impl(name, cols, true)
    }

    /// `DROP TABLE IF EXISTS` (atomic on the server).
    pub fn drop_table_if_exists(&mut self, name: &str) -> Result<()> {
        self.drop_table_impl(name, true)
    }

    /// `CREATE INDEX ON table (col)`: PLAIN columns only (role rw+; rolled back with the transaction).
    pub fn create_index(&mut self, table: &str, col: &str) -> Result<()> {
        self.assert_writable()?;
        if self.col(table, col)?.policy != "plain" {
            return Err(Error::interface(format!("indexes are only for PLAIN columns ({}.{})", table, col)));
        }
        self.call_max("create_index", json!([table, col]), 4096)?;
        Ok(())
    }

    /// `DROP INDEX ON table (col)`.
    pub fn drop_index(&mut self, table: &str, col: &str) -> Result<()> {
        self.assert_writable()?;
        self.col(table, col)?;
        self.call_max("drop_index", json!([table, col]), 4096)?;
        Ok(())
    }

    /// Drop a table (admin). Forgets its masks. A missing table is the server's error.
    pub fn drop_table(&mut self, name: &str) -> Result<()> {
        self.drop_table_impl(name, false)
    }

    fn drop_table_impl(&mut self, name: &str, if_exists: bool) -> Result<()> {
        self.assert_writable()?;
        let args = if if_exists { json!([name, true]) } else { json!([name]) };
        match self.call("drop", args)? {
            Value::Bool(false) => return Ok(()), // did not exist: touch nothing locally
            Value::Null => {}
            _ => return Err(proto("drop: unexpected reply")),
        }
        self.schema.remove(name);
        let keys: Vec<MaskKey> = self.masks.keys().filter(|k| k.0 == name).cloned().collect();
        for k in keys {
            self.del_mask(&k);
        }
        Ok(())
    }

    fn def(&self, table: &str) -> Result<&TableDef> {
        self.schema
            .get(table)
            .ok_or_else(|| Error::interface(format!("unknown table: {}", table)))
    }

    fn cols(&self, table: &str) -> Result<&Vec<Column>> {
        Ok(&self.def(table)?.cols)
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

    fn assert_writable(&self) -> Result<()> {
        if !self.in_doubt.is_empty() {
            let mut ids: Vec<&String> = self.in_doubt.keys().collect();
            ids.sort();
            return Err(Error::interface(format!(
                "unresolved in-doubt transaction(s) {}: call resolve_transaction() before writing",
                ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )));
        }
        Ok(())
    }

    fn assert_trusted(&self, table: &str) -> Result<()> {
        if !self.def(table)?.trusted && !self.opts.trust_server_schema {
            return Err(Error::new(
                Kind::UntrustedSchema,
                format!(
                    "refusing to write to {}: its encryption policies were learned from the server, \
                     which could mislabel an encrypted column as plain. Create the table from this \
                     client / load the vault that created it, or set trust_server_schema (or trust_table()).",
                    table
                ),
            ));
        }
        Ok(())
    }

    // — mask vault with an undo journal (cheap transactions) —
    fn set_mask(&mut self, k: MaskKey, r: BigInt) {
        if let Some(u) = &mut self.undo {
            u.push((k.clone(), self.masks.get(&k).cloned()));
        }
        self.masks.insert(k, r);
    }
    fn del_mask(&mut self, k: &MaskKey) {
        if let Some(u) = &mut self.undo {
            u.push((k.clone(), self.masks.get(k).cloned()));
        }
        self.masks.remove(k);
    }
    fn apply_undo(masks: &mut Masks, u: Undo) {
        for (k, prev) in u.into_iter().rev() {
            match prev {
                Some(p) => {
                    masks.insert(k, p);
                }
                None => {
                    masks.remove(&k);
                }
            }
        }
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

    /// Blinded wire cells (value + optional MAC) and the masks to remember.
    #[allow(clippy::type_complexity)]
    fn blind_cell(
        &self,
        table: &str,
        col: &str,
        v: &CellIn,
    ) -> Result<(Vec<(String, Value)>, Vec<(String, BigInt)>)> {
        let s = Self::encode_cell(v, table, col)?;
        let r = rand_scalar();
        let mut cells = vec![(col.to_string(), wv_int(&md(&(&s + &r))))];
        let mut masks = vec![(col.to_string(), r)];
        if self.opts.authenticated {
            let r2 = rand_scalar();
            cells.push((format!("{}{}", MAC, col), wv_int(&md(&(md(&(&self.alpha * &s)) + &r2)))));
            masks.push((format!("{}{}", MAC, col), r2));
        }
        Ok((cells, masks))
    }

    // — FHE columns —
    fn fhe_key(&self) -> Result<&FheKey> {
        self.opts.fhe_key.as_ref().ok_or_else(|| {
            Error::interface("this table has FHE columns but no FHE key is loaded (set ConnectOptions::fhe_key)")
        })
    }

    /// The integer of an FHE cell: FHE columns hold integers only (no NULL, bool, string, fraction).
    fn fhe_int(v: &CellIn, table: &str, col: &str) -> Result<i64> {
        let int = match v {
            CellIn::Int(i) => Some(i.clone()),
            CellIn::Rational(a, b) if !b.is_zero() => match reduce(a, b) {
                Decoded::Int(i) => Some(i),
                _ => None,
            },
            _ => None,
        };
        match int {
            Some(i) => i64::try_from(&i).map_err(|_| {
                Error::budget(format!("value of {}.{} is outside the range of any FHE key", table, col))
            }),
            None => Err(Error::interface(format!("FHE column {}.{} holds integers only", table, col))),
        }
    }

    /// The encrypted wire cell of an FHE column plus (authenticated) its tag. `rowid` is unknown at
    /// INSERT time: a placeholder tag is sent and replaced by `fhe_write_tags` once the row id exists.
    fn fhe_cells(&self, table: &str, col: &str, x: i64, rowid: Option<i64>) -> Result<Vec<(String, Value)>> {
        let key = self.fhe_key()?;
        let mut cells = vec![(col.to_string(), wv_cell(&key.encrypt(x)?)?)];
        if self.opts.authenticated {
            let tag = match rowid {
                None => key.placeholder_cell()?,
                Some(id) => key.tag(x, table, col, id)?,
            };
            cells.push((format!("{}{}", FMAC, col), wv_cell(&tag)?));
        }
        Ok(cells)
    }

    /// Several cell writes in ONE atomic `update_cells` RPC per chunk (<= 2000 items and the server's
    /// `max_items`); the caller's transaction makes the chunks atomic together. A server that does not
    /// know `update_cells` gets repeated `update_cell` calls instead, and is not asked again.
    fn write_cells(&mut self, table: &str, items: &[(i64, String, Value)]) -> Result<()> {
        let chunk = FHE_WRITE_CHUNK.min(self.info.limits.as_ref().and_then(|l| l.max_items).unwrap_or(FHE_WRITE_CHUNK));
        for part in items.chunks(chunk) {
            if self.update_cells_ok {
                let arg: Vec<Value> = part.iter().map(|(r, c, w)| json!([r, c, w])).collect();
                match self.call_max("update_cells", json!([table, arg]), 4096) {
                    Ok(v) => {
                        if v.as_u64() != Some(part.len() as u64) {
                            return Err(proto("update_cells: implausible count"));
                        }
                        continue;
                    }
                    Err(e) if e.kind == Kind::BadRequest && e.message.contains("unknown method") => {
                        self.update_cells_ok = false;
                    }
                    Err(e) => return Err(e),
                }
            }
            for (r, c, w) in part {
                self.call_max("update_cell", json!([table, r, c, w]), 4096)?;
            }
        }
        Ok(())
    }

    fn fhe_tag_items(&self, table: &str, rowid: i64, tags: &[(String, i64)]) -> Result<Vec<(i64, String, Value)>> {
        if tags.is_empty() {
            return Ok(vec![]);
        }
        let key = self.fhe_key()?;
        tags.iter()
            .map(|(col, x)| Ok((rowid, format!("{}{}", FMAC, col), wv_cell(&key.tag(*x, table, col, rowid)?)?)))
            .collect()
    }

    fn blind_row(&self, table: &str, row: &[(&str, CellIn)]) -> Result<BlindedRow> {
        self.assert_trusted(table)?;
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
        let mut tags = vec![];
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
            } else if c.policy == "fhe" {
                let x = Self::fhe_int(v, table, &c.name)?;
                for (n, w) in self.fhe_cells(table, &c.name, x, None)? {
                    wire.insert(n, w);
                }
                if self.opts.authenticated {
                    tags.push((c.name.clone(), x));
                }
            } else {
                let (cells, masks) = self.blind_cell(table, &c.name, v)?;
                for (n, w) in cells {
                    wire.insert(n, w);
                }
                pending.extend(masks);
            }
        }
        Ok(BlindedRow { wire, pending, tags })
    }

    /// INSERT: blind encrypted cells, keep the masks locally. Returns the row id. With
    /// authenticated FHE columns the row-bound tags are written in the same transaction.
    pub fn insert(&mut self, table: &str, row: Vec<(&str, CellIn)>) -> Result<i64> {
        self.assert_writable()?;
        let b = self.blind_row(table, &row)?;
        let tagged = !b.tags.is_empty();
        let table_s = table.to_string();
        let run = move |db: &mut Client| -> Result<i64> {
            let v = db.call_max("insert", json!([table_s, Value::Object(b.wire)]), 4096)?;
            let rowid = row_id(&v, "insert")?;
            for (col, r) in b.pending {
                db.set_mask((table_s.clone(), rowid, col), r);
            }
            // the tag binds the row id, known only now - same transaction as the INSERT
            let items = db.fhe_tag_items(&table_s, rowid, &b.tags)?;
            if !items.is_empty() {
                db.write_cells(&table_s, &items)?;
            }
            Ok(rowid)
        };
        if tagged {
            self.atomically(run)
        } else {
            run(self)
        }
    }

    /// Bulk insert: all rows are blinded locally and sent in `insert_many` round
    /// trips of at most 50 000 rows (all-or-nothing: wrapped in a transaction
    /// when more than one is needed). Returns the new row ids.
    pub fn insert_many(&mut self, table: &str, rows: Vec<Vec<(&str, CellIn)>>) -> Result<Vec<i64>> {
        self.assert_writable()?;
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let mut blinded = vec![];
        for r in &rows {
            blinded.push(self.blind_row(table, r)?);
        }
        let tagged = blinded.iter().any(|b| !b.tags.is_empty());
        const PER: usize = 50_000;
        let table = table.to_string();
        let send = move |db: &mut Client, blinded: Vec<BlindedRow>| -> Result<Vec<i64>> {
            let mut all = vec![];
            let mut it = blinded.into_iter().peekable();
            while it.peek().is_some() {
                let part: Vec<_> = it.by_ref().take(PER).collect();
                let wires: Vec<Value> = part.iter().map(|b| Value::Object(b.wire.clone())).collect();
                let v = db.call_max("insert_many", json!([table, wires]), part.len() * 24 + 4096)?;
                let ids = arr(&v, "insert_many", Some(part.len()))?
                    .iter()
                    .map(|x| row_id(x, "insert_many"))
                    .collect::<Result<Vec<i64>>>()?;
                let mut items = vec![];
                for (rid, b) in ids.iter().zip(part) {
                    for (col, r) in b.pending {
                        db.set_mask((table.clone(), *rid, col), r);
                    }
                    items.extend(db.fhe_tag_items(&table, *rid, &b.tags)?);
                }
                if !items.is_empty() {
                    db.write_cells(&table, &items)?;
                }
                all.extend(ids);
            }
            Ok(all)
        };
        if blinded.len() > PER || tagged {
            self.atomically(|db| send(db, blinded))
        } else {
            send(self, blinded)
        }
    }

    /// UPDATE ... SET col = value WHERE pred. Atomic (implicit transaction when
    /// none is open). Returns the number of rows changed.
    pub fn update(&mut self, table: &str, set: Vec<(&str, CellIn)>, pred: Value) -> Result<usize> {
        self.assert_writable()?;
        self.assert_trusted(table)?;
        for (c, _) in &set {
            self.col(table, c)?;
        }
        let pred = wire_pred(&pred)?;
        self.atomically(|db| {
            let idxs = db.matching(table, pred)?;
            let mut fhe_items: Vec<(i64, String, Value)> = vec![];
            for i in &idxs {
                for (col, v) in &set {
                    let policy = db.policy(table, col)?;
                    if policy == "plain" {
                        db.call_max("update_cell", json!([table, i, col, wv(v)?]), 4096)?;
                    } else if policy == "fhe" {
                        // a fresh ciphertext (and tag) per row, never one shared cell
                        let x = Self::fhe_int(v, table, col)?;
                        for (n, w) in db.fhe_cells(table, col, x, Some(*i))? {
                            fhe_items.push((*i, n, w));
                        }
                    } else {
                        let (cells, masks) = db.blind_cell(table, col, v)?;
                        for (n, w) in cells {
                            db.call_max("update_cell", json!([table, i, n, w]), 4096)?;
                        }
                        for (n, r) in masks {
                            db.set_mask((table.to_string(), *i, n), r);
                        }
                    }
                }
            }
            if !fhe_items.is_empty() {
                db.write_cells(table, &fhe_items)?; // value + tag of every row, atomically batched
            }
            Ok(idxs.len())
        })
    }

    /// DELETE FROM table WHERE pred (tombstones). Returns how many rows were removed.
    pub fn delete_rows(&mut self, table: &str, pred: Value) -> Result<i64> {
        self.assert_writable()?;
        self.cols(table)?;
        let pred = wire_pred(&pred)?;
        let idxs = self.matching(table, pred)?;
        let mut n = 0;
        for part in chunks(&idxs) {
            let k = self
                .call_max("delete_rows", json!([table, part]), 4096)?
                .as_i64()
                .filter(|k| *k >= 0 && *k as usize <= part.len())
                .ok_or_else(|| proto("delete_rows: implausible count"))?;
            n += k;
        }
        Ok(n)
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

    /// Ids of COMMITs whose outcome is still unknown.
    pub fn in_doubt_transactions(&self) -> Vec<String> {
        let mut v: Vec<String> = self.in_doubt.keys().cloned().collect();
        v.sort();
        v
    }

    /// Open a transaction (with a fresh random id, so a lost COMMIT can be
    /// settled via `tx_status`). Every mask change is journaled so a rollback
    /// (or failed commit) restores the vault exactly.
    pub fn begin(&mut self) -> Result<()> {
        self.assert_writable()?;
        if self.in_tx {
            return Err(Error::interface("a transaction is already open"));
        }
        let mut b = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        let txid: String = b.iter().map(|x| format!("{:02x}", x)).collect();
        self.call_max("tx_begin", json!([txid]), 4096)?; // if this fails nothing changed
        self.txid = Some(txid);
        self.undo = Some(vec![]);
        self.tx_schema = Some(self.schema.clone());
        self.in_tx = true;
        Ok(())
    }

    /// The server definitely holds no transaction for us: drop the local one.
    fn abort_local(&mut self) {
        if let Some(u) = self.undo.take() {
            Self::apply_undo(&mut self.masks, u);
        }
        if let Some(s) = self.tx_schema.take() {
            self.schema = s;
        }
        self.txid = None;
        self.in_tx = false;
    }

    fn end_local(&mut self) {
        self.undo = None;
        self.tx_schema = None;
        self.txid = None;
        self.in_tx = false;
    }

    /// Commit. No-op outside a transaction. If the reply is lost the outcome is
    /// settled with `tx_status` on a fresh connection; the vault is restored ONLY
    /// when the server definitely did not commit. If that cannot be learned the
    /// result is `Kind::TransactionInDoubt` (with `txid`) and BOTH states are kept.
    pub fn commit(&mut self) -> Result<()> {
        if !self.in_tx {
            return Ok(());
        }
        let txid = self.txid.clone().unwrap_or_default();
        match self.conn.call("tx_commit", json!([]), 4096) {
            Ok(_) => {
                self.end_local();
                Ok(())
            }
            Err(e) if matches!(e.kind, Kind::Connection | Kind::Timeout | Kind::Protocol) => {
                self.settle_lost_commit(&txid, e)
            }
            Err(e) => {
                // the server ANSWERED with an error: it holds no committed transaction
                self.abort_local();
                let _ = self.conn.call("tx_rollback", json!([]), 4096);
                Err(e)
            }
        }
    }

    fn move_to_in_doubt(&mut self, txid: &str) {
        let undo = self.undo.take().unwrap_or_default();
        let schema = self.tx_schema.take().unwrap_or_else(|| self.schema.clone());
        self.in_doubt.insert(txid.to_string(), (undo, schema));
        self.end_local();
    }

    fn ask_status(txid: &str, conn: &mut Conn) -> Result<String> {
        for i in 0.. {
            let s = string(&conn.call("tx_status", json!([txid]), 4096)?, "tx_status")?;
            if s != "open" || i >= 10 {
                return Ok(s);
            }
            std::thread::sleep(Duration::from_millis(100)); // the dead session may still be unwinding
        }
        unreachable!()
    }

    fn settle_lost_commit(&mut self, txid: &str, cause: Error) -> Result<()> {
        self.conn.close(); // the old session (and its tx) must go first
        let fresh = open_session(&self.addr, &self.opts).and_then(|(mut c, info)| {
            match Self::ask_status(txid, &mut c) {
                Ok(s) => Ok((c, info, s)),
                Err(e) => {
                    c.close();
                    Err(e)
                }
            }
        });
        let (conn, info, status) = match fresh {
            Ok(x) => x,
            Err(e) => {
                self.move_to_in_doubt(txid);
                let mut err = Error::new(
                    Kind::TransactionInDoubt,
                    format!(
                        "COMMIT of transaction {} was sent but its reply was lost ({}) and the outcome \
                         could not be learned ({}). The client keeps both vault states; call \
                         reconnect() then resolve_transaction(\"{}\", None).",
                        txid, cause.message, e.message, txid
                    ),
                );
                err.txid = Some(txid.to_string());
                return Err(err);
            }
        };
        match status.as_str() {
            "committed" => {
                self.conn = conn;
                self.info = info;
                self.end_local(); // it DID commit: keep the new masks
                Ok(())
            }
            "unknown" => {
                self.conn = conn;
                self.info = info;
                self.abort_local();
                Err(Error::new(
                    cause.kind,
                    format!("COMMIT of transaction {} did not take effect ({}); rolled back", txid, cause.message),
                ))
            }
            other => {
                let mut c = conn;
                c.close();
                self.move_to_in_doubt(txid);
                let mut err = Error::new(
                    Kind::TransactionInDoubt,
                    format!("transaction {} is still {:?} on the server", txid, other),
                );
                err.txid = Some(txid.to_string());
                Err(err)
            }
        }
    }

    /// Re-open the connection (same address/credentials).
    pub fn reconnect(&mut self) -> Result<()> {
        self.conn.close();
        let (conn, info) = open_session(&self.addr, &self.opts)?;
        self.conn = conn;
        self.info = info;
        self.end_local();
        Ok(())
    }

    /// Settle an in-doubt COMMIT. With `Some(committed)` trust the caller;
    /// with `None` ask the server (`tx_status`) over the current connection.
    pub fn resolve_transaction(&mut self, txid: &str, committed: Option<bool>) -> Result<bool> {
        if !self.in_doubt.contains_key(txid) {
            return Err(Error::interface(format!("no in-doubt transaction {}", txid)));
        }
        let committed = match committed {
            Some(c) => c,
            None => {
                let status = Self::ask_status(txid, &mut self.conn)?;
                if status == "open" {
                    let mut err = Error::new(
                        Kind::TransactionInDoubt,
                        format!("transaction {} is still open on the server", txid),
                    );
                    err.txid = Some(txid.to_string());
                    return Err(err);
                }
                status == "committed"
            }
        };
        let (undo, schema) = self.in_doubt.remove(txid).unwrap();
        if !committed {
            Self::apply_undo(&mut self.masks, undo);
            self.schema = schema;
        }
        Ok(committed)
    }

    /// Roll back server state and the local mask vault. No-op outside a transaction.
    pub fn rollback(&mut self) -> Result<()> {
        if !self.in_tx {
            return Ok(());
        }
        let r = self.conn.call("tx_rollback", json!([]), 4096);
        self.abort_local(); // masks restored even if the RPC failed
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
        let cols = self.cols(table)?;
        if let Some(groups) = pred.get("or").and_then(|g| g.as_array()) {
            for atom in groups.iter().filter_map(|g| g.as_array()).flatten() {
                if let Some(name) = atom.get("c").and_then(|c| c.as_str()) {
                    if let Some(c) = cols.iter().find(|c| c.name == name) {
                        if c.policy != "plain" {
                            return Err(Error::interface(format!(
                                "predicates on encrypted column '{}' are not supported",
                                name
                            )));
                        }
                        let op = atom.get("op").and_then(|o| o.as_str()).unwrap_or("");
                        if (op == "like" || op == "not_like") && c.ty != "str" {
                            return Err(Error::interface(format!(
                                "LIKE needs a STR column ('{}' is {})",
                                name, c.ty
                            )));
                        }
                    }
                }
            }
        }
        let v = self.call("matching_rowids", json!([table, pred]))?;
        ids_from(&v, "matching_rowids")
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

    /// (Σ blinded cells − Σ masks) of one physical column, chunked.
    fn sum_one(&mut self, table: &str, c: &str, idxs: &[i64]) -> Result<BigInt> {
        let mut b = BigInt::zero();
        for part in chunks(idxs) {
            let v = self.call_max("blinded_sum", json!([table, c, part]), 4096)?;
            b = md(&(b + md(&big(&v, "blinded_sum")?)));
        }
        let mut m = BigInt::zero();
        for i in idxs {
            m = md(&(m + self.mask(table, *i, c)?));
        }
        Ok(md(&(b - m)))
    }

    /// Σ over rows, MAC-verified when authenticated.
    fn sum_scalar(&mut self, table: &str, col: &str, idxs: &[i64]) -> Result<BigInt> {
        let y = self.sum_one(table, col, idxs)?;
        if self.opts.authenticated {
            let m = self.sum_one(table, &format!("{}{}", MAC, col), idxs)?;
            if m != md(&(&self.alpha * &y)) {
                return Err(Error::new(
                    Kind::Integrity,
                    format!("MAC check failed on sum({}) - server returned a forged/incorrect aggregate", col),
                ));
            }
        }
        Ok(y)
    }

    /// Π_lin: SUM over matched rows (the server never holds a key). On an FHE column the server
    /// adds the ciphertexts (EC addition) and this client opens the result with its [`FheKey`].
    pub fn sum(&mut self, table: &str, col: &str, pred: Value) -> Result<Decoded> {
        self.encrypted_col(table, col)?;
        let pred = wire_pred(&pred)?;
        let idxs = self.matching(table, pred)?;
        if self.policy(table, col)? == "fhe" {
            return Ok(Decoded::Int(BigInt::from(self.fhe_sum(table, col, &idxs, &BigInt::one())?)));
        }
        self.sum_ids(table, col, &idxs)
    }

    /// `k * SUM(col)` over an FHE column: the SERVER multiplies the summed ciphertext by the public
    /// scalar `k` (EC scalar multiplication, not a pairing); `k * sum` must lie in the key's range.
    pub fn scaled_sum(&mut self, table: &str, col: &str, k: i64, pred: Value) -> Result<Decoded> {
        self.encrypted_col(table, col)?;
        if self.policy(table, col)? != "fhe" {
            return Err(Error::interface("scaled_sum is only supported on FHE columns"));
        }
        if k.abs() > FHE_MAX_K {
            return Err(Error::interface("the scale must be an integer with |k| <= 2^40"));
        }
        let pred = wire_pred(&pred)?;
        let idxs = self.matching(table, pred)?;
        Ok(Decoded::Int(BigInt::from(self.fhe_sum(table, col, &idxs, &BigInt::from(k))?)))
    }

    fn sum_ids(&mut self, table: &str, col: &str, idxs: &[i64]) -> Result<Decoded> {
        self.encrypted_col(table, col)?;
        if self.policy(table, col)? == "fhe" {
            return Err(Error::interface(format!("FHE column {}.{} cannot be used in a join query", table, col)));
        }
        decode(&self.sum_scalar(table, col, idxs)?)
    }

    /// SUM (times `k`) of an FHE column: chunked `fhe_sum` calls, partial blobs combined here by G1
    /// addition, then opened by the key (and, when authenticated, checked against the integrity tags).
    fn fhe_sum(&mut self, table: &str, col: &str, idxs: &[i64], k: &BigInt) -> Result<i64> {
        let key = self.fhe_key()?.clone();
        if idxs.is_empty() {
            return Ok(0);
        }
        let (mut total, mut tags): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        let sum_chunk = FHE_SUM_CHUNK.min(
            self.info.limits.as_ref().and_then(|l| l.fhe.as_ref()).and_then(|f| f.max_sum_rows).unwrap_or(FHE_SUM_CHUNK),
        );
        for part in idxs.chunks(sum_chunk) {
            let mut args = vec![json!(table), json!(col), json!(part)];
            if !k.is_one() {
                args.push(json!(k.to_i64().unwrap_or(0)));
            }
            let b = blob(&self.call_max("fhe_sum", Value::Array(args.clone()), 4096)?, "fhe_sum", FHE_SUM_BYTES)?;
            total = Some(match total {
                None => b,
                Some(t) => fhe_add_sums(&t, &b)?,
            });
            if self.opts.authenticated {
                args[1] = json!(format!("{}{}", FMAC, col));
                let r = match self.call_max("fhe_sum", Value::Array(args), 4096) {
                    Ok(v) => v,
                    Err(e) if e.message.contains("integrity tag") => {
                        return Err(Error::new(
                            Kind::Integrity,
                            format!("{}.{} has no integrity tags - it was written without authentication", table, col),
                        ))
                    }
                    Err(e) => return Err(e),
                };
                let t = blob(&r, "fhe_sum", FHE_SUM_BYTES)?;
                tags = Some(match tags {
                    None => t,
                    Some(x) => fhe_add_sums(&x, &t)?,
                });
            }
        }
        let total = total.unwrap();
        if self.opts.authenticated {
            key.decrypt_sum_verified(&total, &tags.unwrap(), table, col, idxs, k)
        } else {
            key.decrypt_sum(&total)
        }
    }

    /// Σ aᵢ·bᵢ over two FHE columns: the server multiplies ciphertexts with the pairing-based ★_ct.
    #[allow(clippy::too_many_arguments)]
    fn fhe_dot(
        &mut self,
        lt: &str,
        lc: &str,
        lids: &[i64],
        rt: &str,
        rc: &str,
        rids: &[i64],
        backend: Option<FheBackend>,
    ) -> Result<BigInt> {
        let key = self.fhe_key()?.clone();
        if lids.is_empty() {
            return Ok(BigInt::zero());
        }
        let local = match self.opts.fhe_dot_mode {
            FheDotMode::Local => true,
            FheDotMode::Delegated => false,
            FheDotMode::Auto => self.opts.authenticated && !self.opts.fhe_allow_unverified_dot,
        };
        if local {
            // verified: every operand cell is read (tag-checked when authenticated), the owner multiplies
            let a = self.fhe_reveal(lt, lc, lids)?;
            let b = self.fhe_reveal(rt, rc, rids)?;
            return Ok(a.iter().zip(&b).map(|(x, y)| BigInt::from(*x) * BigInt::from(*y)).sum());
        }
        // the server's recommended size for the requested back end (unspecified = its default is "auto":
        // be conservative and size for pyecc), never above its published cap
        let be = backend.unwrap_or(FheBackend::Pyecc);
        let lim = self.info.limits.as_ref().and_then(|l| l.fhe.as_ref());
        let fallback = if be == FheBackend::Mcl { FHE_DOT_CHUNK_NATIVE } else { FHE_DOT_CHUNK };
        let rec = lim.and_then(|f| f.recommended_dot_rows.get(be)).unwrap_or(fallback);
        let chunk = rec.min(lim.and_then(|f| f.max_dot_rows.get(be)).unwrap_or(rec)).max(1);
        let mut total: Option<Vec<u8>> = None;
        for (l, r) in lids.chunks(chunk).zip(rids.chunks(chunk)) {
            let mut args = vec![json!(lt), json!(lc), json!(l), json!(rt), json!(rc), json!(r)];
            if let Some(b) = backend {
                args.push(json!(b.as_str()));
            }
            let b = blob(&self.call_max("fhe_dot", Value::Array(args), 8192)?, "fhe_dot", FHE_DOT_BYTES)?;
            if let Some(be) = backend {
                if b[0] != be.tag() {
                    return Err(proto("fhe_dot: the back-end tag does not match the requested back end"));
                }
            }
            total = Some(match total {
                None => b,
                Some(t) => fhe_mul_dots(&t, &b)?,
            });
        }
        Ok(BigInt::from(key.decrypt_dot(&total.unwrap())?))
    }

    /// Decrypt the FHE cells of `ids` (verified against their tags when authenticated).
    fn fhe_reveal(&mut self, table: &str, col: &str, ids: &[i64]) -> Result<Vec<i64>> {
        let key = self.fhe_key()?.clone();
        let fetch = |db: &mut Client, c: &str| -> Result<Vec<Option<Vec<u8>>>> {
            let mut out = vec![];
            for part in ids.chunks(FHE_READ_CHUNK) {
                let v = db.call_max("plain_cells", json!([table, c, part]), part.len() * 700 + 4096)?;
                for w in arr(&v, "plain_cells", Some(part.len()))? {
                    out.push(bin_cell(w, "plain_cells", FHE_CELL_BYTES)?);
                }
            }
            Ok(out)
        };
        let cells = fetch(self, col)?;
        if !self.opts.authenticated {
            return cells
                .iter()
                .map(|c| match c {
                    Some(c) => key.decrypt_cell(c),
                    None => Err(proto(format!("{}.{}: the server returned an empty FHE cell", table, col))),
                })
                .collect();
        }
        let tags = fetch(self, &format!("{}{}", FMAC, col))?;
        cells
            .iter()
            .zip(&tags)
            .zip(ids)
            .map(|((c, t), id)| key.decrypt_cell_verified(c.as_deref(), t.as_deref(), table, col, *id))
            .collect()
    }

    pub fn count(&mut self, table: &str, pred: Value) -> Result<usize> {
        let pred = wire_pred(&pred)?;
        Ok(self.matching(table, pred)?.len())
    }

    /// AVG = SUM / COUNT as an exact rational (`None` over zero rows).
    pub fn avg(&mut self, table: &str, col: &str, pred: Value) -> Result<Option<Decoded>> {
        self.encrypted_col(table, col)?;
        let pred = wire_pred(&pred)?;
        let idxs = self.matching(table, pred)?;
        if idxs.is_empty() {
            return Ok(None);
        }
        let s = if self.policy(table, col)? == "fhe" {
            Decoded::Int(BigInt::from(self.fhe_sum(table, col, &idxs, &BigInt::one())?))
        } else {
            self.sum_ids(table, col, &idxs)?
        };
        let (a, b) = match s {
            Decoded::Int(a) => (a, BigInt::from(1)),
            Decoded::Rational(a, b) => (a, b),
        };
        Ok(Some(reduce(&a, &(b * BigInt::from(idxs.len())))))
    }

    /// DOT needs both columns PAIRED and INT (rational inner products collapse).
    fn check_dot(&self, table: &str, col: &str) -> Result<()> {
        let c = self.col(table, col)?;
        if c.policy != "paired" {
            return Err(Error::new(
                Kind::PlanError,
                format!("DOT requires `paired` policy on column '{}'", col),
            ));
        }
        if c.ty != "int" {
            return Err(Error::new(
                Kind::PlanError,
                format!("DOT requires INT columns (column '{}' is {})", col, c.ty),
            ));
        }
        Ok(())
    }

    /// Π_mult: encrypted inner product Σ aᵢ·bᵢ via Beaver triples (PAIRED columns) or, for two FHE
    /// columns, by the server's pairing-based ciphertext product (the server's default back end).
    pub fn dot(&mut self, table: &str, left: &str, right: &str, pred: Value) -> Result<Decoded> {
        self.dot_with_backend(table, left, right, pred, None)
    }

    /// Like [`Client::dot`] but, for FHE columns, asks the server for a specific pairing back end
    /// (`Pyecc` portable/slow, `Mcl` native/fast); `None` = the server's default. Both DOT result
    /// encodings are decoded here. Only valid for FHE columns.
    pub fn dot_with_backend(
        &mut self,
        table: &str,
        left: &str,
        right: &str,
        pred: Value,
        backend: Option<FheBackend>,
    ) -> Result<Decoded> {
        let fl = self.policy(table, left)? == "fhe";
        let fr = self.policy(table, right)? == "fhe";
        if fl || fr {
            if !(fl && fr) {
                return Err(Error::new(Kind::PlanError, "DOT cannot mix FHE and PAIRED columns"));
            }
            let pred = wire_pred(&pred)?;
            let idxs = self.matching(table, pred)?;
            let v = self.fhe_dot(table, left, &idxs, table, right, &idxs, backend)?;
            return Ok(Decoded::Int(v));
        }
        if backend.is_some() {
            return Err(Error::interface("the backend argument is only for FHE columns"));
        }
        self.check_dot(table, left)?;
        self.check_dot(table, right)?;
        let pred = wire_pred(&pred)?;
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
        self.check_dot(lt, lc)?;
        self.check_dot(rt, rc)?;
        if lids.is_empty() {
            return Ok(Decoded::Int(BigInt::zero()));
        }
        let ls = self.unblind_cells(lt, lc, lids)?;
        let rs = self.unblind_cells(rt, rc, rids)?;
        let mut es: Vec<(BigInt, BigInt)> = vec![];
        let mut triples: Vec<(BigInt, BigInt, BigInt)> = vec![];
        for k in 0..lids.len() {
            let (u, v) = (rand_scalar(), rand_scalar());
            let w = md(&(&u * &v));
            es.push((md(&(&ls[k] - &u)), md(&(&rs[k] - &v))));
            triples.push((u, v, w));
        }
        let mut egs: Vec<BigInt> = vec![];
        for part in es.chunks(LIST_CHUNK) {
            let openings: Vec<Value> = part.iter().map(|(e, g)| json!([e.to_string(), g.to_string()])).collect();
            let v = self.call_max("mult_combine_batch", json!([openings]), part.len() * (MAX_DIGITS + 8) + 4096)?;
            for x in arr(&v, "mult_combine_batch", Some(part.len()))? {
                egs.push(big(x, "mult_combine_batch")?);
            }
        }
        let mut acc = BigInt::zero();
        for (k, (e, g)) in es.iter().enumerate() {
            let (u, v, w) = &triples[k];
            if self.opts.authenticated && md(&egs[k]) != md(&(e * g)) {
                return Err(Error::new(
                    Kind::Integrity,
                    "server returned a forged product term in DOT (e*g mismatch)",
                ));
            }
            acc = md(&(acc + w + e * v + g * u + &egs[k]));
        }
        decode(&acc)
    }

    /// Blinded cells minus masks = the encoded scalars (not yet decoded);
    /// MAC-verified per cell when authenticated.
    fn unblind_cells(&mut self, table: &str, col: &str, ids: &[i64]) -> Result<Vec<BigInt>> {
        let fetch = |db: &mut Client, c: &str| -> Result<Vec<BigInt>> {
            let mut out = vec![];
            for part in chunks(ids) {
                let v = db.call_max(
                    "blinded_cells",
                    json!([table, c, part]),
                    part.len() * (MAX_DIGITS + 40) + 4096,
                )?;
                let ws = arr(&v, "blinded_cells", Some(part.len()))?;
                for (w, i) in ws.iter().zip(part) {
                    out.push(md(&(scalar_cell(w)? - db.mask(table, *i, c)?)));
                }
            }
            Ok(out)
        };
        let ss = fetch(self, col)?;
        if self.opts.authenticated {
            let ms = fetch(self, &format!("{}{}", MAC, col))?;
            for (k, (s, m)) in ss.iter().zip(&ms).enumerate() {
                if *m != md(&(&self.alpha * s)) {
                    return Err(Error::new(
                        Kind::Integrity,
                        format!(
                            "MAC check failed reading {} (row {}) - the stored encrypted value was tampered with",
                            col, ids[k]
                        ),
                    ));
                }
            }
        }
        Ok(ss)
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
                for part in chunks(&uniq) {
                    let v = self.call_max(
                        "plain_cells",
                        json!([table, col, part]),
                        part.len() * (MAX_DIGITS * 2 + 60) + 4096,
                    )?;
                    let ws = arr(&v, "plain_cells", Some(part.len()))?;
                    for (w, i) in ws.iter().zip(part) {
                        got.insert(*i, uwv(w)?);
                    }
                }
            } else if policy == "fhe" {
                let vs = self.fhe_reveal(table, col, &uniq)?;
                for (v, i) in vs.iter().zip(&uniq) {
                    got.insert(*i, CellIn::Int(BigInt::from(*v)));
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
        let pred = wire_pred(&pred)?;
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

    /// SELECT ... OFFSET `offset` LIMIT `limit` (rows are in row-id order; the server selects,
    /// the client slices). `limit: None` = no limit.
    pub fn select_range(
        &mut self,
        table: &str,
        columns: &[&str],
        pred: Value,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<Vec<Vec<CellIn>>> {
        let pred = wire_pred(&pred)?;
        let all_ids = self.matching(table, pred)?;
        let end = limit.map(|l| offset.saturating_add(l)).unwrap_or(usize::MAX);
        let idxs: Vec<i64> = all_ids.into_iter().skip(offset).take(end.saturating_sub(offset)).collect();
        let ids: Vec<Option<i64>> = idxs.iter().map(|i| Some(*i)).collect();
        let mut vecs = vec![];
        for c in columns {
            vecs.push(self.column(table, c, &ids)?);
        }
        Ok((0..idxs.len()).map(|k| vecs.iter().map(|v| v[k].clone()).collect()).collect())
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

        // split WHERE: FROM-table atoms go to the server, others filter the joined rows
        let mut push = Value::Null;
        let mut post: Option<Value> = None;
        if let Some(w) = &opts.where_ {
            if !w.is_null() {
                let all_first = atoms_of(w)?
                    .iter()
                    .all(|a| a.get("a").and_then(|x| x.as_str()).map(|x| x == first).unwrap_or(true));
                if all_first {
                    push = strip_alias(w);
                } else {
                    post = Some(w.clone());
                }
            }
        }
        let mut tuples: Vec<Vec<Option<i64>>> =
            self.matching(left, push)?.into_iter().map(|i| vec![Some(i)]).collect();

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

        if let Some(w) = post {
            // fetch the PLAIN columns the predicate needs, then evaluate with SQL NULL semantics
            let mut need: Vec<(String, String)> = vec![];
            let atoms = atoms_of(&w)?;
            for a in &atoms {
                let al = a.get("a").and_then(|x| x.as_str()).unwrap_or(&first).to_string();
                let c = a.get("c").and_then(|x| x.as_str()).ok_or_else(|| Error::interface("predicate atom without a column"))?.to_string();
                let table = tables
                    .get(&al)
                    .ok_or_else(|| Error::interface(format!("unknown alias in WHERE: {}", al)))?
                    .clone();
                if self.col(&table, &c)?.policy != "plain" {
                    return Err(Error::interface("WHERE may only reference PLAIN columns"));
                }
                if !need.contains(&(al.clone(), c.clone())) {
                    need.push((al, c));
                }
            }
            let mut vals: HashMap<(String, String), Vec<CellIn>> = HashMap::new();
            for (al, c) in need {
                let p = aliases.iter().position(|a| *a == al).unwrap();
                let ids: Vec<Option<i64>> = tuples.iter().map(|t| t[p]).collect();
                let v = self.column(&tables[&al], &c, &ids)?;
                vals.insert((al, c), v);
            }
            let groups = w["or"].as_array().cloned().unwrap_or_default();
            let mut keep = vec![];
            for (i, t) in tuples.into_iter().enumerate() {
                let mut ok = false;
                'g: for g in &groups {
                    let mut all = true;
                    for a in g.as_array().cloned().unwrap_or_default() {
                        let al = a.get("a").and_then(|x| x.as_str()).unwrap_or(&first).to_string();
                        let c = a["c"].as_str().unwrap_or("").to_string();
                        if !atom_matches(&vals[&(al, c)][i], &a)? {
                            all = false;
                            break;
                        }
                    }
                    if all {
                        ok = true;
                        break 'g;
                    }
                }
                if ok {
                    keep.push(t);
                }
            }
            tuples = keep;
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
        if self.policy(&j.tables[alias], col)? == "fhe" {
            return Err(Error::interface(format!(
                "FHE column {}.{} cannot be used in a join query",
                j.tables[alias], col
            )));
        }
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

    /// Live rows on the server this vault cannot decrypt (a crash between the
    /// server accepting an INSERT and the vault being saved). Driven by the live
    /// row ids the server returns, never by a server-claimed row count.
    pub fn find_orphans(&mut self) -> Result<HashMap<String, Vec<i64>>> {
        let mut out = HashMap::new();
        let tables: Vec<(String, Vec<String>)> = self
            .schema
            .iter()
            .map(|(t, d)| {
                (
                    t.clone(),
                    // FHE columns need no mask: any client holding the key reads them
                    d.cols.iter().filter(|c| c.policy != "plain" && c.policy != "fhe").map(|c| c.name.clone()).collect(),
                )
            })
            .collect();
        for (t, enc) in tables {
            if enc.is_empty() {
                continue;
            }
            let live = self.matching(&t, Value::Null)?;
            let bad: Vec<i64> = live
                .into_iter()
                .filter(|i| enc.iter().any(|c| !self.masks.contains_key(&(t.clone(), *i, c.clone()))))
                .collect();
            if !bad.is_empty() {
                out.insert(t, bad);
            }
        }
        Ok(out)
    }

    // — vault persistence —
    /// Write the mask vault (masks, the schema policies you created, and the
    /// MAC key) as JSON ATOMICALLY (temp file + fsync + rename + directory
    /// fsync) with mode 0600 (unix). Missing parent directories are created.
    /// Refused while a COMMIT is in doubt or a transaction is open.
    pub fn save_vault(&mut self, file: Option<&Path>) -> Result<()> {
        let target = file
            .map(PathBuf::from)
            .or_else(|| self.vault_path.clone())
            .ok_or_else(|| Error::interface("no vault path given"))?;
        if !self.in_doubt.is_empty() {
            return Err(Error::interface(
                "cannot save the vault while a COMMIT is in doubt; resolve_transaction() first",
            ));
        }
        if self.in_tx {
            return Err(Error::interface("cannot save the vault inside an open transaction"));
        }
        let entries: Vec<Value> = self
            .masks
            .iter()
            .map(|((t, i, c), r)| json!([t, i, c, r.to_string()]))
            .collect();
        let mut schema = serde_json::Map::new();
        for (t, d) in &self.schema {
            if d.trusted {
                let cols: Vec<Value> = d.cols.iter().map(|c| json!([c.name, c.ty, c.policy])).collect();
                schema.insert(t.clone(), Value::Array(cols));
            }
        }
        let mut doc = json!({"version": 2, "masks": entries, "schema": schema,
                              "authenticated": self.opts.authenticated});
        if self.opts.authenticated {
            doc["alpha"] = json!(self.alpha.to_string());
        }
        let body = doc.to_string();
        let dir = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let io = |e: std::io::Error| Error::interface(format!("vault write failed: {}", e));
        std::fs::create_dir_all(&dir).map_err(io)?;
        let tmp = dir.join(format!(
            ".{}.{}.{:08x}.tmp",
            target.file_name().and_then(|s| s.to_str()).unwrap_or("vault"),
            std::process::id(),
            rand::random::<u32>()
        ));
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
            std::fs::rename(&tmp, &target)?;
            // make the rename itself durable
            if let Ok(d) = std::fs::File::open(&dir) {
                let _ = d.sync_all();
            }
            Ok(())
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

    /// Replace the in-memory mask vault (and trusted schema) with the one in `file`.
    pub fn load_vault(&mut self, file: Option<&Path>) -> Result<()> {
        let src = file
            .map(PathBuf::from)
            .or_else(|| self.vault_path.clone())
            .ok_or_else(|| Error::interface("no vault path given"))?;
        if self.in_tx {
            return Err(Error::interface("cannot load a vault inside an open transaction"));
        }
        let bad = |m: &str| Error::interface(format!("{} is not a valid TorusDB vault: {}", src.display(), m));
        let text = std::fs::read_to_string(&src)
            .map_err(|e| Error::interface(format!("cannot read vault {}: {}", src.display(), e)))?;
        let doc: Value = serde_json::from_str(&text).map_err(|_| bad("not JSON"))?;
        let version = doc["version"].as_i64();
        let list = match (version, doc["masks"].as_array()) {
            (Some(1), Some(l)) | (Some(2), Some(l)) => l,
            _ => return Err(bad("wrong version/shape")),
        };
        let mask_re = |s: &str| !s.is_empty() && s.len() <= MAX_DIGITS && s.bytes().all(|b| b.is_ascii_digit());
        let mut m: Masks = HashMap::new();
        for e in list {
            let a = e.as_array().filter(|a| a.len() == 4).ok_or_else(|| bad("corrupt mask entry"))?;
            let t = a[0].as_str().ok_or_else(|| bad("corrupt mask entry"))?;
            let i = a[1].as_i64().filter(|i| (0..=MAX_SAFE).contains(i)).ok_or_else(|| bad("bad row id"))?;
            let c = a[2].as_str().ok_or_else(|| bad("corrupt mask entry"))?;
            let r = a[3].as_str().filter(|s| mask_re(s)).ok_or_else(|| bad("bad mask"))?;
            let rv: BigInt = r.parse().map_err(|_| bad("bad mask"))?;
            if rv >= *n() {
                return Err(bad("mask out of range"));
            }
            m.insert((t.to_string(), i, c.to_string()), rv);
        }
        let mut sch: Schema = HashMap::new();
        if version == Some(2) {
            if let Some(s) = doc.get("schema").filter(|s| !s.is_null()) {
                let s = s.as_object().ok_or_else(|| bad("bad schema"))?;
                for (t, cols) in s {
                    let mut cs = vec![];
                    for c in cols.as_array().ok_or_else(|| bad("bad schema"))? {
                        let a = c.as_array().filter(|a| a.len() == 3).ok_or_else(|| bad("bad schema column"))?;
                        let nm = a[0].as_str().ok_or_else(|| bad("bad schema column"))?;
                        cs.push(Column {
                            name: nm.to_string(),
                            ty: norm_type(a[1].as_str().unwrap_or("")),
                            policy: norm_policy(a[2].as_str().unwrap_or("")),
                        });
                    }
                    sch.insert(t.clone(), TableDef { cols: cs, trusted: true });
                }
            }
        }
        let auth = doc["authenticated"].as_bool().unwrap_or(false);
        let mut alpha = None;
        if auth {
            let a = doc["alpha"]
                .as_str()
                .filter(|s| mask_re(s))
                .and_then(|s| s.parse::<BigInt>().ok())
                .filter(|a| !a.is_zero() && a < n())
                .ok_or_else(|| bad("bad MAC key"))?;
            if !self.opts.authenticated {
                return Err(Error::interface(format!(
                    "{} was created in authenticated (MAC) mode; connect with authenticated: true",
                    src.display()
                )));
            }
            alpha = Some(a);
        } else if self.opts.authenticated && !m.is_empty() {
            return Err(Error::interface(format!(
                "{} was created without MACs; refusing to run authenticated mode on it",
                src.display()
            )));
        }
        self.masks = m;
        for (t, d) in sch {
            self.schema.insert(t, d); // vault policies are the trust anchor
        }
        if let Some(a) = alpha {
            self.alpha = a;
        }
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

const OPS: [&str; 7] = ["=", "!=", "<>", "<", "<=", ">", ">="];


/// `col <op> value` with op one of `= != <> < <= > >=`. Invalid values
/// (zero denominator, unknown operator) are rejected, never silently altered.
pub fn cmp(col: &str, op: &str, v: &CellIn) -> Result<Value> {
    if !OPS.contains(&op) {
        return Err(Error::interface(format!("bad operator: {}", op)));
    }
    Ok(json!({"or": [[{"c": col, "op": op, "v": wv(v)?}]]}))
}
/// Like [`cmp`] for a joined table instance: only valid in [`JoinOptions::where_`].
pub fn cmp_in(alias: &str, col: &str, op: &str, v: &CellIn) -> Result<Value> {
    let mut p = cmp(col, op, v)?;
    p["or"][0][0]["a"] = json!(alias);
    Ok(p)
}
pub fn eq(col: &str, v: &CellIn) -> Result<Value> {
    cmp(col, "=", v)
}
/// `col IN (values)`.
pub fn is_in(col: &str, vs: &[CellIn]) -> Result<Value> {
    let w = vs.iter().map(wv).collect::<Result<Vec<Value>>>()?;
    Ok(json!({"or": [[{"c": col, "in": w}]]}))
}
/// Like [`is_in`] for a joined table instance.
pub fn is_in_of(alias: &str, col: &str, vs: &[CellIn]) -> Result<Value> {
    let mut p = is_in(col, vs)?;
    p["or"][0][0]["a"] = json!(alias);
    Ok(p)
}
fn atom1(col: &str, op: &str, v: Value) -> Value {
    json!({"or": [[{"c": col, "op": op, "v": v}]]})
}
/// `col IS NULL` (the only atom that matches NULL cells; true on the NULL side of a LEFT JOIN).
pub fn is_null(col: &str) -> Value {
    atom1(col, "is_null", json!({"t": "n"}))
}
/// `col IS NOT NULL`.
pub fn not_null(col: &str) -> Value {
    atom1(col, "not_null", json!({"t": "n"}))
}
/// `col LIKE pattern` (STR columns only; % = any run, _ = one char, case-sensitive, no ESCAPE).
pub fn like(col: &str, pattern: &str) -> Value {
    atom1(col, "like", json!({"t": "s", "v": pattern}))
}
/// `col NOT LIKE pattern` (NULL cells match neither LIKE nor NOT LIKE).
pub fn not_like(col: &str, pattern: &str) -> Value {
    atom1(col, "not_like", json!({"t": "s", "v": pattern}))
}
/// `col BETWEEN lo AND hi`, sent as (col >= lo) AND (col <= hi).
pub fn between(col: &str, lo: &CellIn, hi: &CellIn) -> Result<Value> {
    Ok(and(&[cmp(col, ">=", lo)?, cmp(col, "<=", hi)?]))
}
/// `col NOT IN (values)`, sent as an AND of `!=` atoms (NULL cells never match).
pub fn not_in(col: &str, vs: &[CellIn]) -> Result<Value> {
    if vs.is_empty() {
        return Err(Error::interface("NOT IN needs at least one value"));
    }
    let atoms = vs.iter().map(|v| cmp(col, "!=", v)).collect::<Result<Vec<Value>>>()?;
    Ok(and(&atoms))
}
/// Qualify every atom of `pred` with a table alias (for [`JoinOptions::where_`]).
pub fn on_alias(alias: &str, pred: Value) -> Value {
    let mut p = pred;
    if let Some(gs) = p.get_mut("or").and_then(|g| g.as_array_mut()) {
        for g in gs {
            if let Some(atoms) = g.as_array_mut() {
                for a in atoms {
                    a["a"] = json!(alias);
                }
            }
        }
    }
    p
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

fn atoms_of(p: &Value) -> Result<Vec<Value>> {
    let g = p.get("or").and_then(|g| g.as_array()).ok_or_else(|| Error::interface("malformed predicate"))?;
    let mut out = vec![];
    for grp in g {
        for a in grp.as_array().ok_or_else(|| Error::interface("malformed predicate"))? {
            out.push(a.clone());
        }
    }
    Ok(out)
}

fn strip_alias(p: &Value) -> Value {
    let mut q = p.clone();
    if let Some(gs) = q.get_mut("or").and_then(|g| g.as_array_mut()) {
        for g in gs {
            if let Some(atoms) = g.as_array_mut() {
                for a in atoms {
                    if let Some(o) = a.as_object_mut() {
                        o.remove("a");
                    }
                }
            }
        }
    }
    q
}

/// Predicate as sent to a single-table RPC: alias-qualified atoms are refused.
fn wire_pred(p: &Value) -> Result<Value> {
    if p.is_null() {
        return Ok(Value::Null);
    }
    for a in atoms_of(p)? {
        if a.get("a").is_some() {
            return Err(Error::interface("alias-qualified predicates are only valid in JoinOptions::where_"));
        }
    }
    Ok(p.clone())
}

fn cmp_cells(a: &CellIn, b: &CellIn) -> Option<std::cmp::Ordering> {
    fn num(v: &CellIn) -> Option<(BigInt, BigInt)> {
        match v {
            CellIn::Int(i) => Some((i.clone(), BigInt::from(1))),
            CellIn::Bool(b) => Some((BigInt::from(*b as i32), BigInt::from(1))),
            CellIn::Rational(a, b) => Some((a.clone(), b.clone())),
            _ => None,
        }
    }
    if let (Some((an, ad)), Some((bn, bd))) = (num(a), num(b)) {
        if ad.is_positive() && bd.is_positive() {
            return Some((an * &bd).cmp(&(bn * &ad)));
        }
    }
    if let (CellIn::Str(x), CellIn::Str(y)) = (a, b) {
        return Some(x.cmp(y));
    }
    None
}

/// SQL LIKE: `%` any run, `_` one character, case-sensitive, no escape.
fn like_match(text: &str, pat: &str) -> bool {
    let (t, p): (Vec<char>, Vec<char>) = (text.chars().collect(), pat.chars().collect());
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '%' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && (p[pi] == '_' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            mark += 1;
            ti = mark;
            pi = s + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

fn atom_matches(val: &CellIn, a: &Value) -> Result<bool> {
    use std::cmp::Ordering::*;
    match a["op"].as_str() {
        Some("is_null") => return Ok(*val == CellIn::Null),
        Some("not_null") => return Ok(*val != CellIn::Null),
        _ => {}
    }
    if *val == CellIn::Null {
        return Ok(false); // SQL: a NULL operand makes the atom false
    }
    if let Some(op @ ("like" | "not_like")) = a["op"].as_str() {
        let CellIn::Str(text) = val else { return Ok(false) };
        let CellIn::Str(pat) = uwv(&a["v"])? else {
            return Err(Error::interface("LIKE needs a string pattern"));
        };
        return Ok(like_match(text, &pat) == (op == "like"));
    }
    if let Some(list) = a.get("in").and_then(|l| l.as_array()) {
        for w in list {
            if cmp_cells(val, &uwv(w)?) == Some(Equal) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let rhs = uwv(&a["v"])?;
    let c = cmp_cells(val, &rhs);
    let op = a["op"].as_str().unwrap_or("");
    Ok(match (op, c) {
        ("!=", None) | ("<>", None) => true,
        (_, None) => false,
        ("=", Some(o)) => o == Equal,
        ("!=", Some(o)) | ("<>", Some(o)) => o != Equal,
        ("<", Some(o)) => o == Less,
        (">", Some(o)) => o == Greater,
        ("<=", Some(o)) => o != Greater,
        (">=", Some(o)) => o != Less,
        _ => return Err(Error::interface(format!("bad operator: {}", op))),
    })
}
