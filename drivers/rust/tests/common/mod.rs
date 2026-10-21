// SPDX-License-Identifier: Apache-2.0
//! Test support: start a REAL keyless TorusDB server (Python) as a subprocess.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use torusdb::Column;

pub const ADMIN: &str = "admin-token-0123456789";
pub const RW: &str = "rw-token-0123456789abc";
pub const RO: &str = "ro-token-0123456789abc";

/// Repository root (this crate lives at <root>/drivers/rust).
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Integration tests must not silently skip where a server is mandatory (CI).
pub fn require_integration() -> bool {
    std::env::var("TORUSDB_REQUIRE_INTEGRATION").is_ok()
}

pub fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors.json")
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
