# torusdb (Rust) - v0.5.0

No-key TorusDB client (wire protocol v2). Connects to a **keyless** server,
holds the mask vault locally, blinds on insert and unblinds results - the
server never holds a key and never decrypts. Programmatic API (no SQL parser;
that lives in the Python `torussql-parser`); exact mod-n arithmetic via
`num-bigint`; wire format and framing match the other drivers.

```rust
use torusdb::{Client, Column, CellIn, eq_int, all};

let mut db = Client::connect("127.0.0.1:8533")?;
db.create_table("emp", vec![
    Column{ name:"id".into(),     ty:"int".into(),      policy:"plain".into() },
    Column{ name:"salary".into(), ty:"rational".into(), policy:"encrypted".into() },
    Column{ name:"rate".into(),   ty:"int".into(),      policy:"paired".into() },
    Column{ name:"hours".into(),  ty:"int".into(),      policy:"paired".into() },
])?;
db.insert("emp", vec![
    ("id", CellIn::Int(1.into())),
    ("salary", CellIn::Rational(8000.into(), 1.into())),
    ("rate", CellIn::Int(50.into())),
    ("hours", CellIn::Int(40.into())),
])?;

db.sum("emp", "salary", all())?;            // Decoded::Int(8000) - computed on blinded scalars
db.avg("emp", "salary", all())?;            // Some(exact rational), None when empty
db.dot("emp", "rate", "hours", all())?;     // Beaver-triple Pi_mult
db.count("emp", eq_int("dept", 5))?;
```

## Connecting: auth, TLS, timeouts

```rust
let db = Client::connect_with("db.example.com:8533", &ConnectOptions {
    token: Some(std::env::var("TORUSDB_TOKEN")?),  // needed if the server uses --token-file
    tls: true,                                      // needs `--features tls`
    ca_pem: Some(std::fs::read("ca.pem")?),         // optional private CA (else webpki roots)
    timeout: Some(Duration::from_secs(30)),         // default 30 s; None = block
    vault_path: Some("vault.json".into()),          // loaded on connect if it exists
    ..Default::default()
})?;
```

* `hello` negotiates the protocol (up to 2; a v1 server that does not know
  `hello` is treated as protocol 1 without auth; a newer one is refused).
  `db.server_info()` returns the reply.
* If the server needs auth and no token is given, `connect` fails with
  `Kind::Unauthenticated` before sending anything. Tokens never appear in
  errors or logs.
* **TLS** is behind the cargo feature `tls` (off by default), built on
  `rustls` + `ring` + `webpki-roots` (the `ring` crate needs a C compiler to
  build). Certificate **and** hostname are verified; the only way to skip
  verification is the explicit `tls_insecure: true` (encrypted but
  unauthenticated - local development only). Requesting `tls: true` in a build
  without the feature is an error, never a silent downgrade. No client
  certificates (mutual TLS) yet.
* A missing reply within the timeout gives `Kind::Timeout` and the connection
  is dropped (a late reply would desynchronize it). Lost connections give
  `Kind::Connection`. The timeout applies to each read/write.

## Errors

Every call returns `Result<_, Error>`; `Error { kind: Kind, message }`
implements `Display` + `std::error::Error`. `Kind` is `Unauthenticated`,
`Forbidden`, `Busy`, `BadRequest`, `InternalError`, `PlanError`,
`Server(String)` (other server classes), or local: `Connection`, `Timeout`,
`Protocol`, `Interface` (misuse, unknown table/column, closed client, bad
join), `OutOfBudget` (see below).

Source compatibility: `From<String> for Error` and `From<Error> for String`
exist, so old `fn main() -> Result<(), String>` code with `?` keeps compiling.
Breaking changes vs 0.4: `connect` returns `Result<_, Error>` (was
`io::Result`), `encode_int`/`encode_rational`/`decode` return `Result`
(they can now report `OutOfBudget`), `CellIn` gained `Null` and `Bool`.

**Exact range.** Matching the Python reference: ints must satisfy
`|v| <= ~2^126`; fractions `|num|, den <= ~2^126` and `|num|*den < ~2^189`;
decoding is strict, so an aggregate that overflowed raises `OutOfBudget`
instead of returning a wrong number.

## Transactions

```rust
db.transaction(|db| {                 // commit on Ok, roll back on Err
    db.insert("emp", row)?;
    db.update("emp", vec![("salary", CellIn::Int(1.into()))], eq_int("id", 1))?;
    Ok::<_, torusdb::Error>(())
})?;
// or manually: db.begin()?; ... db.commit()? / db.rollback()?
```

The client snapshots its mask vault and schema at `begin()`; `rollback()` (and
a failed `commit()`) restore them, so masks of rolled-back inserts disappear
exactly as the server's rows do. `update()` uses an implicit transaction when
none is open. A dropped connection rolls back on the server. One transaction
is open server-wide at a time (others wait, then get `Busy`).

## Bulk insert, update, delete, select

`insert_many(table, rows)` blinds every row locally and sends ONE
`insert_many` RPC (all-or-nothing). Also `update`, `delete_rows` (tombstones),
`select(table, &cols, pred)`, `column(...)`. Predicates run on the server
against **plain** columns: `eq_int`, `eq`, `cmp(col, op, &v)`, `is_in`,
`and(&[..])`, `or(&[..])`, `all()`.

## JOIN

A client-side hash join over PLAIN key columns (like the Python engine's
`_base_tuples`); NULL keys never match; self-joins via aliases.

```rust
let steps = [
    JoinStep::new("dept", "did", "did").alias("d").left_alias("e"),
    JoinStep::new("proj", "did", "did").alias("p").left_alias("d").left(), // LEFT JOIN
];
let j = db.join("emp", &steps, &JoinOptions { alias: Some("e".into()), where_: Some(eq_int("eid", 1)) })?;
j.tuples;                              // Vec<Vec<Option<i64>>>: rowid per alias, None = NULL side
db.join_column(&j, "d", "dname")?;     // plain / decrypted values
db.join_sum(&j, "p", "budget")?;       // Pi_lin over the non-null rowids
db.join_count(&j);
db.join_dot(&j, "e", "x", "p", "y")?;  // Pi_mult across tables
```

## Vault

`save_vault(Some(path))` writes the masks as JSON atomically (temp file,
fsync, rename) with mode `0600` (unix); `load_vault` restores them.
`find_orphans()` lists server rows this vault cannot decrypt. The vault is the
owner's one long-lived secret: lose it and the data is gone, leak it and
confidentiality is gone.

## Admin

`ping`, `tables`, `table_info`, `stats`, `checkpoint`, `backup`, `drop_table`
(the last four need an `admin` token when auth is on).

## Differences from the Python driver

* No SQL / PEP 249 cursor; no GROUP BY, ORDER BY, MIN/MAX, scalar-mul.
* Vault is a plain JSON snapshot written on demand - not the Python driver's
  append-only checksummed log, no passphrase, no save after every statement.
* No authenticated (SPDZ MAC) mode.
* TLS only with `--features tls`; no mutual TLS.

## Build & test

```bash
cargo build                 # add --features tls for TLS
cargo test                  # vectors + transport (fake server) + integration
cargo test --features tls   # also the TLS tests (need `openssl` on PATH)
cargo run --example demo    # against a running server
```

Integration tests start a real server subprocess (`$TORUSDB_PYTHON`, else
`<repo>/.venv/bin/python`, else `python3`, running
`torussql/server/nokey_server.py --port 0`). When none is found they print
`SKIP` and return (they show as passed - check stderr). The vector tests read
`../vectors.json`, so they only run from a checkout of the repository.
