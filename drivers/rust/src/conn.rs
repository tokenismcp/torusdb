// SPDX-License-Identifier: Apache-2.0
//! Length-prefixed JSON-RPC transport over TCP (optionally TLS).

use crate::error::{Error, Kind};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_FRAME_IN: usize = 256 * 1024 * 1024;

pub(crate) enum Stream {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
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

impl Conn {
    pub fn open(addr: &str, o: &TransportOpts) -> Result<Conn, Error> {
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .map_err(|e| Error::connection(format!("cannot resolve {}: {}", addr, e)))?
            .collect();
        let mut last = None;
        let mut tcp = None;
        for a in addrs {
            let r = match o.timeout {
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
        tcp.set_read_timeout(o.timeout)?;
        tcp.set_write_timeout(o.timeout)?;
        let stream = if o.tls {
            Self::wrap_tls(tcp, split_host(addr), o)?
        } else {
            Stream::Tcp(tcp)
        };
        Ok(Conn { stream: Some(stream) })
    }

    #[cfg(not(feature = "tls"))]
    fn wrap_tls(_tcp: TcpStream, _host: &str, _o: &TransportOpts) -> Result<Stream, Error> {
        Err(Error::interface(
            "TLS requested but this build has no TLS support (enable the `tls` cargo feature)",
        ))
    }

    #[cfg(feature = "tls")]
    fn wrap_tls(mut tcp: TcpStream, host: &str, o: &TransportOpts) -> Result<Stream, Error> {
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
            conn.complete_io(&mut tcp)
                .map_err(|e| Error::connection(format!("TLS handshake failed: {}", e)))?;
        }
        Ok(Stream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))))
    }

    pub fn is_closed(&self) -> bool {
        self.stream.is_none()
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

    fn io(&mut self, method: &str, args: &Value) -> Result<Vec<u8>, Error> {
        let s = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::interface("connection is closed"))?;
        let req = json!({"m": method, "a": args}).to_string();
        let mut frame = Vec::with_capacity(4 + req.len());
        frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
        frame.extend_from_slice(req.as_bytes());
        s.write_all(&frame)?;
        s.flush()?;
        let mut hdr = [0u8; 4];
        read_exact(s, &mut hdr)?;
        let n = u32::from_be_bytes(hdr) as usize;
        if n > MAX_FRAME_IN {
            return Err(Error::protocol(format!("declared reply frame too large: {} bytes", n)));
        }
        let mut buf = vec![0u8; n];
        read_exact(s, &mut buf)?;
        Ok(buf)
    }

    /// One request/response. Any transport failure (including a timeout, after
    /// which a late reply could desynchronize the stream) closes the connection.
    pub fn call(&mut self, method: &str, args: Value) -> Result<Value, Error> {
        let buf = match self.io(method, &args) {
            Ok(b) => b,
            Err(e) => {
                if e.kind != Kind::Interface {
                    self.close();
                }
                return Err(match e.kind {
                    Kind::Timeout => Error::new(
                        Kind::Timeout,
                        "no reply within the timeout; connection dropped",
                    ),
                    _ => e,
                });
            }
        };
        let resp: Value = serde_json::from_slice(&buf)
            .map_err(|_| Error::protocol("server sent malformed JSON"))?;
        if let Some(err) = resp.get("err") {
            return Err(Error::from_server(err.as_str().unwrap_or("error")));
        }
        match resp.get("ok") {
            Some(v) => Ok(v.clone()),
            None => Err(Error::protocol("reply has neither ok nor err")),
        }
    }
}

fn read_exact(s: &mut Stream, buf: &mut [u8]) -> Result<(), Error> {
    match s.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(Error::connection("connection lost: server closed the connection"))
        }
        Err(e) => Err(Error::from(e)),
    }
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
