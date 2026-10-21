//! Length-prefixed JSON-RPC transport over TCP (optionally TLS), with TOTAL
//! deadlines, frame caps and unsolicited-data detection.

use crate::error::{Error, Kind};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Never accept a bigger reply.
pub(crate) const HARD_MAX_FRAME: usize = 64 * 1024 * 1024;
/// Until `hello` says otherwise.
pub(crate) const HELLO_MAX_FRAME: usize = 1024 * 1024;

pub(crate) enum Stream {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn sock(&self) -> &TcpStream {
        match self {
            Stream::Tcp(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => &s.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

pub(crate) struct Conn {
    stream: Option<Stream>,
    timeout: Option<Duration>,
    /// Largest reply frame accepted.
    pub max_read: usize,
    /// Largest request frame the server accepts.
    pub max_write: usize,
    reason: Option<Error>,
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct TransportOpts<'a> {
    pub timeout: Option<Duration>,
    pub tls: bool,
    pub tls_insecure: bool,
    pub ca_pem: Option<&'a [u8]>,
}

fn split_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => addr,
    }
}

/// Time left until `deadline`; `None` deadline = unlimited.
fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>, Error> {
    match deadline {
        None => Ok(None),
        Some(d) => {
            let now = Instant::now();
            if now >= d {
                Err(Error::new(Kind::Timeout, "timed out (total deadline reached)"))
            } else {
                Ok(Some(d - now))
            }
        }
    }
}

fn set_timeouts(s: &TcpStream, left: Option<Duration>) -> Result<(), Error> {
    s.set_read_timeout(left)?;
    s.set_write_timeout(left)?;
    Ok(())
}

impl Conn {
    pub fn open(addr: &str, o: &TransportOpts) -> Result<Conn, Error> {
        let deadline = o.timeout.map(|t| Instant::now() + t);
        // DNS can block for a long time and std cannot bound it: resolve on a thread.
        let addrs: Vec<SocketAddr> = {
            let (tx, rx) = std::sync::mpsc::channel();
            let a = addr.to_string();
            std::thread::spawn(move || {
                let _ = tx.send(a.to_socket_addrs().map(|i| i.collect::<Vec<_>>()));
            });
            let got = match remaining(deadline)? {
                Some(t) => rx
                    .recv_timeout(t)
                    .map_err(|_| Error::new(Kind::Timeout, format!("resolving {} timed out", addr)))?,
                None => rx
                    .recv()
                    .map_err(|_| Error::connection(format!("cannot resolve {}", addr)))?,
            };
            got.map_err(|e| Error::connection(format!("cannot resolve {}: {}", addr, e)))?
        };
        let mut last: Option<std::io::Error> = None;
        let mut tcp = None;
        for a in addrs {
            let r = match remaining(deadline)? {
                Some(t) => TcpStream::connect_timeout(&a, t),
                None => TcpStream::connect(a),
            };
            match r {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let tcp = match tcp {
            Some(t) => t,
            None => {
                let e = last.map(|e| e.to_string()).unwrap_or_else(|| "no address".into());
                return Err(Error::connection(format!("cannot connect to {}: {}", addr, e)));
            }
        };
        let _ = tcp.set_nodelay(true);
        let stream = if o.tls {
            Self::wrap_tls(tcp, split_host(addr), o, deadline)?
        } else {
            Stream::Tcp(tcp)
        };
        Ok(Conn {
            stream: Some(stream),
            timeout: o.timeout,
            max_read: HELLO_MAX_FRAME,
            max_write: HELLO_MAX_FRAME,
            reason: None,
        })
    }

    #[cfg(not(feature = "tls"))]
    fn wrap_tls(_t: TcpStream, _h: &str, _o: &TransportOpts, _d: Option<Instant>) -> Result<Stream, Error> {
        Err(Error::interface(
            "TLS requested but this build has no TLS support (enable the `tls` cargo feature)",
        ))
    }

    #[cfg(feature = "tls")]
    fn wrap_tls(mut tcp: TcpStream, host: &str, o: &TransportOpts, deadline: Option<Instant>) -> Result<Stream, Error> {
        use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
        use std::sync::Arc;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::connection(format!("TLS config: {}", e)))?;
        let config = if o.tls_insecure {
            // explicit opt-in only: encrypted but UNAUTHENTICATED peer
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match o.ca_pem {
                Some(pem) => {
                    let mut any = false;
                    for c in CertificateDer::pem_slice_iter(pem) {
                        let c = c.map_err(|e| Error::interface(format!("bad CA PEM: {}", e)))?;
                        roots
                            .add(c)
                            .map_err(|e| Error::interface(format!("bad CA certificate: {}", e)))?;
                        any = true;
                    }
                    if !any {
                        return Err(Error::interface("no certificate found in the CA PEM"));
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| Error::interface(format!("bad TLS server name {:?}: {}", host, e)))?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|e| Error::connection(format!("TLS: {}", e)))?;
        while conn.is_handshaking() {
            // total deadline for the whole handshake: shrink the socket timeout every round
            set_timeouts(&tcp, remaining(deadline)?)?;
            conn.complete_io(&mut tcp).map_err(|e| {
                if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
                    Error::new(Kind::Timeout, "TLS handshake timed out")
                } else {
                    Error::connection(format!("TLS handshake failed: {}", e))
                }
            })?;
        }
        Ok(Stream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))))
    }

    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
    }

    /// Why the connection died (the original error), or a plain "closed".
    pub fn reason(&self) -> Error {
        self.reason.clone().unwrap_or_else(|| Error::interface("connection is closed"))
    }

    pub fn close(&mut self) {
        if let Some(Stream::Tcp(s)) = &self.stream {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        #[cfg(feature = "tls")]
        if let Some(Stream::Tls(s)) = &mut self.stream {
            s.conn.send_close_notify();
            let _ = s.flush();
            let _ = s.sock.shutdown(std::net::Shutdown::Both);
        }
        self.stream = None;
    }

    /// True when bytes nobody asked for are waiting (a desynchronized or hostile peer).
    fn unsolicited(s: &mut Stream) -> bool {
        match s {
            Stream::Tcp(t) => {
                if t.set_nonblocking(true).is_err() {
                    return false;
                }
                let mut b = [0u8; 1];
                let r = matches!(t.peek(&mut b), Ok(n) if n > 0);
                let _ = t.set_nonblocking(false);
                r
            }
            #[cfg(feature = "tls")]
            Stream::Tls(t) => {
                // decrypted application data already buffered beyond the reply
                let mut b = [0u8; 1];
                matches!(t.conn.reader().read(&mut b), Ok(n) if n > 0)
            }
        }
    }

    fn io(&mut self, method: &str, args: &Value, max_reply: usize) -> Result<Vec<u8>, Error> {
        let timeout = self.timeout;
        let (max_write, cap) = (self.max_write, self.max_read.min(max_reply));
        let s = self.stream.as_mut().ok_or_else(|| self.reason.clone().unwrap_or_else(|| Error::interface("connection is closed")))?;
        let req = json!({"m": method, "a": args}).to_string();
        if req.len() > max_write {
            return Err(Error::interface(format!(
                "request of {} bytes exceeds the server's max_frame ({})",
                req.len(),
                max_write
            )));
        }
        let len = u32::try_from(req.len()).map_err(|_| Error::interface("request too large"))?;
        if Conn::unsolicited(s) {
            return Err(Error::protocol("unsolicited data from server"));
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut frame = Vec::with_capacity(4 + req.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(req.as_bytes());
        let mut off = 0;
        while off < frame.len() {
            set_timeouts(s.sock(), remaining(deadline)?)?;
            match s.write(&frame[off..]) {
                Ok(0) => return Err(Error::connection("connection lost: write returned 0")),
                Ok(n) => off += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::from(e)),
            }
        }
        set_timeouts(s.sock(), remaining(deadline)?)?;
        s.flush()?;
        let mut hdr = [0u8; 4];
        read_exact(s, &mut hdr, deadline)?;
        let n = u32::from_be_bytes(hdr) as usize;
        if n > cap {
            return Err(Error::protocol(format!("declared reply frame too large: {} bytes (limit {})", n, cap)));
        }
        // grow as bytes ARRIVE: a lying header must not allocate its claim up front
        let mut buf: Vec<u8> = Vec::with_capacity(n.min(64 * 1024));
        let mut chunk = vec![0u8; 64 * 1024];
        while buf.len() < n {
            let want = (n - buf.len()).min(chunk.len());
            read_exact(s, &mut chunk[..want], deadline)?;
            buf.extend_from_slice(&chunk[..want]);
        }
        if Conn::unsolicited(s) {
            return Err(Error::protocol("unsolicited data from server"));
        }
        Ok(buf)
    }

    /// One request/response. Any transport failure (including a timeout, after
    /// which a late reply could desynchronize the stream) closes the connection.
    /// `max_reply` bounds the reply frame for this call.
    pub fn call(&mut self, method: &str, args: Value, max_reply: usize) -> Result<Value, Error> {
        let buf = match self.io(method, &args, max_reply) {
            Ok(b) => b,
            Err(e) => {
                // a request refused locally leaves the stream untouched
                let local = e.kind == Kind::Interface;
                if !local {
                    self.reason = Some(e.clone());
                    self.close();
                }
                return Err(e);
            }
        };
        let resp: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => {
                let e = Error::protocol("server sent malformed JSON");
                self.reason = Some(e.clone());
                self.close();
                return Err(e);
            }
        };
        if let Some(err) = resp.get("err") {
            return Err(Error::from_server(err.as_str().unwrap_or("malformed error")));
        }
        match resp.get("ok") {
            Some(v) => Ok(v.clone()),
            None => Err(Error::protocol("reply has neither ok nor err")),
        }
    }
}

/// Fill `buf`, shrinking the socket timeout on every read so the call has ONE
/// total deadline (a peer dripping a byte at a time cannot extend it).
fn read_exact(s: &mut Stream, buf: &mut [u8], deadline: Option<Instant>) -> Result<(), Error> {
    let mut got = 0;
    while got < buf.len() {
        set_timeouts(s.sock(), remaining(deadline)?)?;
        match s.read(&mut buf[got..]) {
            Ok(0) => return Err(Error::connection("connection lost: server closed the connection")),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::from(e)),
        }
    }
    Ok(())
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct NoVerify(std::sync::Arc<rustls::crypto::CryptoProvider>);

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
