// SPDX-License-Identifier: Apache-2.0
//! Typed errors. Server errors arrive as `"Kind: message"` strings; the kind
//! is parsed out so callers can match on it.

use std::fmt;

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Server: missing/invalid token (also raised locally when the server
    /// requires a token and none was given).
    Unauthenticated,
    /// Server: the token's role may not call this RPC (e.g. `ro` writing).
    Forbidden,
    /// Server: busy (connection cap, lock held by another transaction).
    Busy,
    /// Server: malformed or invalid request.
    BadRequest,
    /// Server: internal error (details are only in the server log).
    InternalError,
    /// Server: planner error.
    PlanError,
    /// Any other server error class (the text before the first `": "`).
    Server(String),
    /// Cannot connect / connection lost / TLS failure.
    Connection,
    /// No reply within the timeout (the connection is dropped).
    Timeout,
    /// The peer sent something malformed or unsupported.
    Protocol,
    /// Dialect v0.6: the expression text is not valid syntax (the engine's `ParseError`).
    Parse,
    /// Dialect v0.6: the expression needs more sequential ciphertext x ciphertext product levels (owner
    /// rounds) than `max_mult_depth` allows; raised before any request. (A plan error in the Python engine.)
    DepthLimitExceeded,
    /// Dialect v0.6: a denominator evaluated to zero (raised after the protocol ran to its last round).
    DivisionByZero,
    /// Client misuse: unknown table/column, closed client, bad join, ...
    Interface,
    /// A value or aggregate outside the exactly representable range.
    OutOfBudget,
    /// A MAC check failed: the server lied (authenticated mode).
    Integrity,
    /// Write to a table whose encryption policies were only learned from the server.
    UntrustedSchema,
    /// A COMMIT whose outcome could not be determined (see `Error::txid`).
    TransactionInDoubt,
    /// Anchored mode: the server presents an OLDER table state than the anchor records (a lagging
    /// replica, or a rollback). Never accepted silently.
    StaleServer,
    /// The anchor file is unusable (symlink, lax permissions, corrupt, unknown version).
    AnchorFile,
    /// A compare-and-swap on the anchor failed: another owner advanced the epoch, or a commit is pending.
    AnchorConflict,
    /// The table has FHE columns but the anchor has no entry for it (see `Client::adopt_table`).
    AnchorMissing,
}

/// The error type of every fallible call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
    /// Set for `Kind::TransactionInDoubt`: pass it to `Client::resolve_transaction`.
    pub txid: Option<String>,
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Error {
        Error { kind, message: message.into(), txid: None }
    }
    pub(crate) fn interface(m: impl Into<String>) -> Error {
        Error::new(Kind::Interface, m)
    }
    pub(crate) fn protocol(m: impl Into<String>) -> Error {
        Error::new(Kind::Protocol, m)
    }
    pub(crate) fn connection(m: impl Into<String>) -> Error {
        Error::new(Kind::Connection, m)
    }
    pub(crate) fn budget(m: impl Into<String>) -> Error {
        Error::new(Kind::OutOfBudget, m)
    }

    /// Parse a server error string such as `"Forbidden: role 'ro' may not call 'insert'"`.
    pub fn from_server(text: &str) -> Error {
        if let Some((head, rest)) = text.split_once(": ") {
            if !head.is_empty()
                && head.chars().next().unwrap().is_ascii_alphabetic()
                && head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                let kind = match head {
                    "Unauthenticated" => Kind::Unauthenticated,
                    "Forbidden" => Kind::Forbidden,
                    "Busy" => Kind::Busy,
                    "BadRequest" => Kind::BadRequest,
                    "InternalError" => Kind::InternalError,
                    "PlanError" => Kind::PlanError,
                    other => Kind::Server(other.to_string()),
                };
                return Error::new(kind, rest);
            }
        }
        Error::new(Kind::Server("ServerError".into()), text)
    }

    /// The server-side class name, or a local kind name.
    pub fn kind_name(&self) -> String {
        match &self.kind {
            Kind::Unauthenticated => "Unauthenticated".into(),
            Kind::Forbidden => "Forbidden".into(),
            Kind::Busy => "Busy".into(),
            Kind::BadRequest => "BadRequest".into(),
            Kind::InternalError => "InternalError".into(),
            Kind::PlanError => "PlanError".into(),
            Kind::Server(s) => s.clone(),
            Kind::Connection => "ConnectionError".into(),
            Kind::Timeout => "TimeoutError".into(),
            Kind::Protocol => "ProtocolError".into(),
            Kind::Parse => "ParseError".into(),
            Kind::DepthLimitExceeded => "DepthLimitExceeded".into(),
            Kind::DivisionByZero => "DivisionByZero".into(),
            Kind::Interface => "InterfaceError".into(),
            Kind::OutOfBudget => "OutOfBudget".into(),
            Kind::Integrity => "IntegrityError".into(),
            Kind::UntrustedSchema => "UntrustedSchema".into(),
            Kind::TransactionInDoubt => "TransactionInDoubt".into(),
            Kind::StaleServer => "StaleServerError".into(),
            Kind::AnchorFile => "AnchorFileError".into(),
            Kind::AnchorConflict => "AnchorConflict".into(),
            Kind::AnchorMissing => "AnchorMissingError".into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind_name(), self.message)
    }
}

impl std::error::Error for Error {}

/// Lets old `Result<_, String>` code keep using `?` on string errors.
impl From<String> for Error {
    fn from(s: String) -> Error {
        Error::new(Kind::Interface, s)
    }
}
impl From<&str> for Error {
    fn from(s: &str) -> Error {
        Error::new(Kind::Interface, s)
    }
}
/// Lets old `fn main() -> Result<(), String>` code keep using `?` on driver calls.
impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        use std::io::ErrorKind::{TimedOut, WouldBlock};
        match e.kind() {
            TimedOut | WouldBlock => Error::new(Kind::Timeout, e.to_string()),
            _ => Error::connection(e.to_string()),
        }
    }
}
