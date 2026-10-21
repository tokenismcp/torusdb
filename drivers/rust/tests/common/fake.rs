//! Scriptable hostile fake server + a lossy TCP proxy for regression tests.
#![allow(dead_code)]
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum Reply {
    Json(Value),
    Raw(Vec<u8>),
    Frames(Vec<Value>),
    /// only a (lying) length header, then silence
    Hdr(u32),
    /// a length header, then one byte every `ms`
    Drip(u32, u64),
    Drop,
    Hang,
}

pub type Handler = dyn Fn(&str, &Value, usize) -> Reply + Send + Sync;

pub struct Fake {
    pub addr: String,
    pub seen: Arc<Mutex<Vec<String>>>,
    pub bodies: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<TcpStream>>>,
}

impl Fake {
    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
    pub fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
    pub fn saw(&self, m: &str) -> bool {
        self.seen().iter().any(|x| x == m)
    }
    /// push unsolicited bytes to every connected client
    pub fn push(&self, b: &[u8]) {
        for c in self.conns.lock().unwrap().iter_mut() {
            let _ = c.write_all(b);
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for c in self.conns.lock().unwrap().iter() {
            let _ = c.shutdown(Shutdown::Both);
        }
        let _ = TcpStream::connect(&self.addr); // wake the accept loop
    }
}

fn frame(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

pub fn hello() -> Value {
    json!({"ok": {"protocol": 2, "server": "fake", "auth_required": false, "max_frame": 33554432, "persistent": false}})
}

/// Defaults for a handshake-only server; `over` takes precedence.
pub fn base(over: impl Fn(&str, &Value, usize) -> Option<Reply> + Send + Sync + 'static) -> Arc<Handler> {
    Arc::new(move |m, a, n| {
        if let Some(r) = over(m, a, n) {
            return r;
        }
        match m {
            "hello" => Reply::Json(hello()),
            "tables" => Reply::Json(json!({"ok": []})),
            "ping" => Reply::Json(json!({"ok": "pong"})),
            _ => Reply::Json(json!({"ok": null})),
        }
    })
}

pub fn fake(h: Arc<Handler>) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(vec![]));
    let bodies = Arc::new(Mutex::new(vec![]));
    let stop = Arc::new(AtomicBool::new(false));
    let conns = Arc::new(Mutex::new(vec![]));
    let counts = Arc::new(Mutex::new(std::collections::HashMap::<String, usize>::new()));
    let (s2, b2, st2, c2) = (seen.clone(), bodies.clone(), stop.clone(), conns.clone());
    std::thread::spawn(move || {
        for sock in l.incoming() {
            if st2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut sock) = sock else { break };
            c2.lock().unwrap().push(sock.try_clone().unwrap());
            let (h, s, b, counts) = (h.clone(), s2.clone(), b2.clone(), counts.clone());
            std::thread::spawn(move || loop {
                let mut hdr = [0u8; 4];
                if sock.read_exact(&mut hdr).is_err() {
                    return;
                }
                let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
                if sock.read_exact(&mut buf).is_err() {
                    return;
                }
                let body = String::from_utf8_lossy(&buf).to_string();
                let req: Value = serde_json::from_slice(&buf).unwrap();
                let m = req["m"].as_str().unwrap().to_string();
                s.lock().unwrap().push(m.clone());
                b.lock().unwrap().push(body);
                let n = {
                    let mut c = counts.lock().unwrap();
                    let e = c.entry(m.clone()).or_insert(0);
                    *e += 1;
                    *e
                };
                match h(&m, &req["a"], n) {
                    Reply::Drop => return,
                    Reply::Hang => std::thread::sleep(Duration::from_secs(8)),
                    Reply::Hdr(x) => {
                        let _ = sock.write_all(&x.to_be_bytes());
                        std::thread::sleep(Duration::from_secs(8));
                    }
                    Reply::Drip(x, ms) => {
                        let _ = sock.write_all(&x.to_be_bytes());
                        for _ in 0..200 {
                            if sock.write_all(b"x").is_err() {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(ms));
                        }
                    }
                    Reply::Raw(r) => {
                        let _ = sock.write_all(&frame(&r));
                    }
                    Reply::Frames(fs) => {
                        let mut all = vec![];
                        for f in fs {
                            all.extend(frame(f.to_string().as_bytes()));
                        }
                        let _ = sock.write_all(&all);
                    }
                    Reply::Json(v) => {
                        let _ = sock.write_all(&frame(v.to_string().as_bytes()));
                    }
                }
            });
        }
    });
    Fake { addr, seen, bodies, stop, conns }
}

// ── lossy proxy in front of a real server ────────────────────────────────────
#[derive(Clone)]
struct Rule {
    method: String,
    /// true: forward the request, swallow the reply and cut the client;
    /// false: cut the client without forwarding
    forward: bool,
    /// refuse every later connection
    down: bool,
}

pub struct Proxy {
    pub addr: String,
    rule: Arc<Mutex<Option<Rule>>>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    /// One-shot rule for the next matching request.
    pub fn lose(&self, method: &str, forward: bool, down: bool) {
        *self.rule.lock().unwrap() = Some(Rule { method: method.into(), forward, down });
    }
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
    }
}

fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).ok()?;
    let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
    s.read_exact(&mut buf).ok()?;
    Some(buf)
}

pub fn proxy(target: &str) -> Proxy {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let rule: Arc<Mutex<Option<Rule>>> = Arc::new(Mutex::new(None));
    let paused = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, p2, s2, t) = (rule.clone(), paused.clone(), stop.clone(), target.to_string());
    std::thread::spawn(move || {
        for c in l.incoming() {
            if s2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(client) = c else { break };
            if p2.load(Ordering::SeqCst) {
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }
            let Ok(up) = TcpStream::connect(&t) else { continue };
            let swallow = Arc::new(AtomicBool::new(false));
            let down_after = Arc::new(AtomicBool::new(false));
            // client -> upstream
            {
                let (mut c_in, mut u_out) = (client.try_clone().unwrap(), up.try_clone().unwrap());
                let (c_kill, u_kill) = (client.try_clone().unwrap(), up.try_clone().unwrap());
                let (rule, swallow, down_after) = (r2.clone(), swallow.clone(), down_after.clone());
                std::thread::spawn(move || {
                    while let Some(fr) = read_frame(&mut c_in) {
                        let m = serde_json::from_slice::<Value>(&fr).ok().and_then(|v| v["m"].as_str().map(String::from));
                        let hit = {
                            let mut r = rule.lock().unwrap();
                            match (&*r, &m) {
                                (Some(x), Some(m)) if x.method == *m => r.take(),
                                _ => None,
                            }
                        };
                        if let Some(x) = hit {
                            if !x.forward {
                                let _ = c_kill.shutdown(Shutdown::Both);
                                let _ = u_kill.shutdown(Shutdown::Both);
                                return;
                            }
                            swallow.store(true, Ordering::SeqCst);
                            down_after.store(x.down, Ordering::SeqCst);
                        }
                        let mut out = (fr.len() as u32).to_be_bytes().to_vec();
                        out.extend(fr);
                        if u_out.write_all(&out).is_err() {
                            return;
                        }
                    }
                    let _ = u_kill.shutdown(Shutdown::Both);
                });
            }
            // upstream -> client
            {
                let (mut u_in, mut c_out) = (up.try_clone().unwrap(), client.try_clone().unwrap());
                let (c_kill, u_kill) = (client.try_clone().unwrap(), up.try_clone().unwrap());
                let p3 = p2.clone();
                std::thread::spawn(move || {
                    while let Some(fr) = read_frame(&mut u_in) {
                        if swallow.load(Ordering::SeqCst) {
                            let _ = c_kill.shutdown(Shutdown::Both);
                            let _ = u_kill.shutdown(Shutdown::Both);
                            if down_after.load(Ordering::SeqCst) {
                                p3.store(true, Ordering::SeqCst);
                            }
                            return;
                        }
                        let mut out = (fr.len() as u32).to_be_bytes().to_vec();
                        out.extend(fr);
                        if c_out.write_all(&out).is_err() {
                            return;
                        }
                    }
                    let _ = c_kill.shutdown(Shutdown::Both);
                });
            }
        }
    });
    Proxy { addr, rule, paused, stop }
}

/// One raw RPC to a real server (acts as the "lying server" / another client).
pub fn raw_rpc(addr: &str, method: &str, args: Value) -> Value {
    let mut s = TcpStream::connect(addr).unwrap();
    let body = json!({"m": method, "a": args}).to_string();
    s.write_all(&frame(body.as_bytes())).unwrap();
    serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap()
}
