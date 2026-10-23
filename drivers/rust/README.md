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
  `Kind::Connection`. The timeout is a total budget per call.

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
against **plain** columns: `eq_int`, `eq`, `cmp(col, op, &v)`, `is_in` (the last three return `Result`),
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

## Trust model: the server is untrusted

* **Schema.** Tables you create (or load from your own vault - it stores the
  policies) are *trusted*; tables only learned via `sync_schema()` are
  *untrusted*: plain reads work, writes fail with `Kind::UntrustedSchema`
  (otherwise a lying server could relabel an encrypted column "plain" and
  receive it in the clear). Opt in with `trust_server_schema: true` or
  `trust_table(name)`. Unknown policy strings are treated as encrypted.
* **Replies** are validated: types, array lengths against the request, no
  silent `filter_map` of bad items, <= 90 digits per integer, frames capped at
  `min(hello.max_frame, 64 MiB)` (and per call), unsolicited bytes rejected.
  Anything else is `Kind::Protocol`.
* **Deadlines.** `timeout` is a TOTAL budget per call (and for DNS+connect and
  the TLS handshake): a peer that drips bytes cannot extend it.
* **Authenticated (MAC) mode.** `ConnectOptions { authenticated: true, .. }`
  adds hidden one-time-padded MAC cells (`__mac__<col>`, alpha kept in the
  vault, same layout as the Python driver) and verifies SUM/AVG/DOT/reads: a
  server that edits stored values or lies about aggregates is caught
  (`Kind::Integrity`). Without it these drivers do **not** detect a lying server.
* **Secrets.** `Debug` for `ConnectOptions` and `Client` redacts the token,
  CA bytes, masks and MAC key. The token is refused on an unencrypted
  non-loopback connection unless `allow_insecure_token`.

## SQL conveniences (predicates, indexes, OFFSET, IF [NOT] EXISTS)

```rust
db.count("t", between("age", &20.into(), &50.into())?)?;   // (age >= 20) AND (age <= 50)
db.count("t", not_in("id", &[1.into(), 2.into()])?)?;      // AND of != atoms: NULL cells never match
db.select("t", &["id"], is_null("age"))?;                  // is_null / not_null: the only atoms that match NULL
db.select("t", &["id"], like("name", "ali%"))?;            // STR columns; % run, _ one char, case-sensitive, no ESCAPE
db.select_range("t", &["id"], all(), 10, Some(5))?;        // OFFSET 10 LIMIT 5 (row-id order, sliced client-side)
db.create_index("t", "age")?; db.drop_index("t", "age")?;  // PLAIN columns, role rw+, transactional
db.table_info("t")?.indexes;
db.create_table_if_not_exists("t", cols)?;  db.drop_table_if_exists("t")?;
```

A NULL operand makes every atom false except `is_null`/`not_null`, so `not_in`,
`not_like` and `!=` never match NULL cells. LIKE needs a STR column; predicates on
encrypted columns are refused. In `JoinOptions::where_` qualify atoms with
`on_alias("b", is_null("w"))`: on the NULL side of a LEFT JOIN `is_null` is true,
every other atom false. `drop_table` of a missing table is an error (the server's
`drop` RPC alone accepts it silently).

## Lost COMMIT replies

`begin()` sends a random transaction id. If a COMMIT's reply is lost the
client reconnects and asks `tx_status(txid)`: `committed` keeps the new masks;
`unknown` restores the vault and returns the error; if the status cannot be
obtained you get `Kind::TransactionInDoubt` with `err.txid`, and BOTH vault
states are kept. Writes are refused until `reconnect()` and
`resolve_transaction(&txid, None)` (asks the server) or
`resolve_transaction(&txid, Some(true|false))`. The vault is restored only on a
definite server answer; `Busy ... timed out` inside a transaction drops the
local transaction at once.

## Differences from the Python driver

* No SQL / PEP 249 cursor; no GROUP BY, ORDER BY, MIN/MAX, scalar-mul. Join
  WHERE over joined tables is a client-side post-filter on PLAIN columns
  (`cmp_in("d", "dname", "=", &v)`).
* Vault is a plain JSON snapshot written on demand (atomic, 0600, directory
  fsync) - not the Python driver's append-only checksummed log, no passphrase;
  an in-doubt COMMIT is held in memory only (`save_vault` refuses while one is
  unresolved).
* TLS only with `--features tls`; no mutual TLS.
* Predicate builders `cmp`/`eq`/`is_in` are fallible (`Result`) so invalid
  values are rejected instead of altered.
* Integers from the server are limited to 90 digits; long id lists are chunked
  (the server rejects lists over 200 000).

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
`../vectors.json`, so they only run from a checkout of the repository; the published crate ships no tests (`include` omits `tests/`). Set `TORUSDB_REQUIRE_INTEGRATION=1` to fail instead of skip.
