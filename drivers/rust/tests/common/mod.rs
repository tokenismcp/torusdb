// SPDX-License-Identifier: Apache-2.0
//! Test support: start a REAL keyless TorusDB server (Python) as a subprocess.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
pub mod fake;
use torusdb::Column;

pub const ADMIN: &str = "admin-token-0123456789";
pub const RW: &str = "rw-token-0123456789abc";
pub const RO: &str = "ro-token-0123456789abc";

/// Repository root (this crate lives at <root>/drivers/rust). `TORUSDB_PY_ROOT` points the Python side
/// (server, core, parser, python driver) at another checkout (e.g. a pristine release snapshot).
pub fn repo() -> PathBuf {
    match std::env::var("TORUSDB_PY_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p).canonicalize().unwrap(),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap(),
    }
}

/// Integration tests must not silently skip where a server is mandatory (CI).
pub fn require_integration() -> bool {
    std::env::var("TORUSDB_REQUIRE_INTEGRATION").is_ok()
}

pub fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors.json")
}

/// Cross-language expression vectors generated from the Python reference (drivers/gen_expr_vectors.py).
pub fn expr_vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../expr_vectors.json")
}

fn python() -> Option<String> {
    let mut cands: Vec<String> = vec![];
    if let Ok(p) = std::env::var("TORUSDB_PYTHON") {
        cands.push(p);
    } else {
        cands.push(repo().join(".venv/bin/python").to_string_lossy().into());
        cands.push(repo().join("../.venv/bin/python").to_string_lossy().into()); // monorepo dev layout
        cands.push("python3".into());
    }
    let server = repo().join("server/nokey_server.py");
    if !server.exists() {
        return None;
    }
    for c in cands {
        let ok = Command::new(&c)
            .arg(&server)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(c);
        }
    }
    None
}

pub struct Server {
    child: Child,
    pub addr: String,
    pub port: u16,
}

impl Server {
    /// `None` (with a SKIP note on stderr) when no interpreter/server is found.
    pub fn start(extra: &[&str]) -> Option<Server> {
        Server::start_env(extra, &[])
    }

    /// Like `start`, with extra environment variables for the server process (e.g. PYTHONPATH
    /// pointing at a directory with the native `mclbn256` package).
    pub fn start_env(extra: &[&str], env: &[(&str, &str)]) -> Option<Server> {
        let py = match python() {
            Some(p) => p,
            None => {
                if require_integration() {
                    panic!("TORUSDB_REQUIRE_INTEGRATION is set but no usable \
                            Python interpreter/server was found (set TORUSDB_PYTHON)");
                }
                eprintln!("SKIP: no usable Python interpreter/server (set TORUSDB_PYTHON)");
                return None;
            }
        };
        let mut child = Command::new(py)
            .arg(repo().join("server/nokey_server.py"))
            .args(["--host", "127.0.0.1", "--port", "0", "--log-level", "WARNING"])
            .args(extra)
            .env("PYTHONUNBUFFERED", "1")
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
        let mut line = String::new();
        let mut rd = BufReader::new(child.stdout.take().unwrap());
        rd.read_line(&mut line).expect("server banner");
        // "no-key TorusDB server 0.5.0 (HOLDS NO KEYS) on 127.0.0.1:PORT ..."
        let hp = line
            .split(" on ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or_else(|| panic!("cannot parse server banner: {:?}", line))
            .to_string();
        let port: u16 = hp.rsplit(':').next().unwrap().parse().unwrap();
        // keep draining stdout so the server never blocks on a full pipe
        std::thread::spawn(move || {
            let mut s = String::new();
            while rd.read_line(&mut s).map(|n| n > 0).unwrap_or(false) {
                s.clear();
            }
        });
        Some(Server { child, addr: hp, port })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("torusdb-rs-{}-{}-{}", tag, std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn col(name: &str, ty: &str, policy: &str) -> Column {
    Column { name: name.into(), ty: ty.into(), policy: policy.into() }
}

pub fn emp_cols() -> Vec<Column> {
    vec![
        col("id", "int", "plain"),
        col("dept", "int", "plain"),
        col("salary", "rational", "encrypted"),
        col("rate", "int", "paired"),
        col("hours", "int", "paired"),
    ]
}

pub fn kv_cols() -> Vec<Column> {
    vec![col("k", "int", "plain"), col("v", "int", "encrypted")]
}

/// Directory with the native `mclbn256` package (optional): when TORUSDB_MCL_PATH is set the
/// server gets it on PYTHONPATH, so FHE DOT runs on the fast native back end.
pub fn mcl_path() -> Option<String> {
    std::env::var("TORUSDB_MCL_PATH").ok().filter(|p| Path::new(p).exists())
}

/// Run the Python peer (tests/fhe_peer.py): it connects with the Python driver and runs SQL.
/// Returns its JSON output.
pub fn run_peer(host: &str, port: u16, spec: &serde_json::Value) -> serde_json::Value {
    let py = python().expect("a Python interpreter is needed for the cross-implementation tests");
    let root = repo();
    let sep = ":";
    let pp = ["core", "parser", "drivers/python"].iter().map(|d| root.join(d).to_string_lossy().to_string()).collect::<Vec<_>>().join(sep);
    let out = Command::new(py)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fhe_peer.py"))
        .arg(host)
        .arg(port.to_string())
        .arg(spec.to_string())
        .env("PYTHONPATH", pp)
        .output()
        .expect("run fhe_peer");
    assert!(out.status.success(), "fhe_peer failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("peer output")
}

// ── raw access (what a hostile server operator or a buggy client can do) ─────
use std::io::{Read, Write};
use std::net::TcpStream;

pub fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).ok()?;
    let mut b = vec![0u8; u32::from_be_bytes(h) as usize];
    s.read_exact(&mut b).ok()?;
    Some(b)
}
pub fn write_frame(s: &mut TcpStream, b: &[u8]) -> bool {
    s.write_all(&(b.len() as u32).to_be_bytes()).is_ok() && s.write_all(b).is_ok()
}
/// One raw RPC on its own connection.
pub fn raw_rpc(addr: &str, method: &str, args: serde_json::Value) -> serde_json::Value {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(120))).unwrap();
    write_frame(&mut s, serde_json::json!({"m": method, "a": args}).to_string().as_bytes());
    serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap()
}

/// Run the Python expression peer (drivers/expr_peer.py): the Python engine evaluates the same expressions
/// against the same server (its own owner, its own copy of the tables). Returns its JSON output.
pub fn run_expr_peer(host: &str, port: u16, spec: &serde_json::Value) -> serde_json::Value {
    let py = python().expect("a Python interpreter is needed for the cross-implementation tests");
    let root = repo();
    let pp = ["core", "parser", "drivers/python"].iter().map(|d| root.join(d).to_string_lossy().to_string()).collect::<Vec<_>>().join(":");
    let out = Command::new(py)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../expr_peer.py"))
        .arg(host)
        .arg(port.to_string())
        .arg(spec.to_string())
        .env("PYTHONPATH", pp)
        .output()
        .expect("run expr_peer");
    assert!(out.status.success(), "expr_peer failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("peer output")
}
