<p align="center"><img src="https://raw.githubusercontent.com/tokenismcp/torusdb/main/assets/logo-128.png" alt="TorusDB" width="96"></p>

# torusdb (Rust) - v0.5.0

No-key TorusDB client (wire protocol v2). Connects to a **keyless** server,
holds the mask vault locally, blinds on insert and unblinds results - the
server never holds a key and never decrypts. Programmatic API (full statement parsing
lives in the Python `torussql-parser`; the one piece of SQL this crate parses is the v0.6
*arithmetic expression*, `db.expr("emp", "rate * hours / 2", all())`); exact mod-n arithmetic via
`num-bigint`; wire format and framing match the other drivers.

> **Dialect v0.6 is supported**: arithmetic expressions `+ - * /` with products of arbitrary multiplicative
> depth, division by public and by encrypted values, `SUM(expr)` / `AVG(expr)` - see
> [Arithmetic expressions](#arithmetic-expressions-dialect-v06) and
> [`spec/TorusSQL-Spec-v0.6.md`](../../spec/TorusSQL-Spec-v0.6.md). Statements in this README about "one
> multiplicative level" describe the FHE (pairing) columns and the depth-1 `dot`.

## Install and first run

You need a running server (Python >= 3.11): from the repository root
`pip install ./parser ./core ./drivers/python ./server && torusdb-server`
([`docs/GETTING_STARTED.md`](../../docs/GETTING_STARTED.md)). Then add the crate:

```bash
cargo add torusdb                     # once published
# from a checkout, today (Cargo.toml):  torusdb = { path = "/path/to/torussql/drivers/rust" }
cd drivers/rust && cargo run --example demo     # bundled example against 127.0.0.1:8533 (fresh server each run)
```

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

## Arithmetic expressions (dialect v0.6)

`db.expr(table, text, pred)` evaluates ONE SELECT-list expression over the selected rows;
`db.join_expr(&join_result, text)` does the same over the rows of a `join()` (columns `alias.col`).
The text is parsed here with exactly the grammar, precedence, constant folding and policy rules of the
Python parser/engine (`src/expr.rs` is a port of `torussql_parser/expr.py`; the two are checked against each
other on `../expr_vectors.json`, ~400 accept/reject cases, and on a live Python peer):

```rust
let mut db = Client::connect_with(addr, &ConnectOptions { authenticated: true, max_mult_depth: 8, ..Default::default() })?;
// emp(dept PLAIN, rate PAIRED, hours PAIRED, tax RATIONAL PAIRED, bonus RATIONAL ENC)
db.expr("emp", "rate * hours * (1 - tax) + bonus / 2", all())?;            // ExprValue::Rows: one entry per row (None where an operand is NULL)
db.expr("emp", "SUM(rate * hours * (1 - tax)) / COUNT(*)", eq_int("dept", 5))?; // ExprValue::Scalar(Some(Decoded)): exact
db.expr("emp", "AVG(rate + hours)", all())?;                               // Scalar(None) over zero rows
db.expr("emp", "100 / rate", all())?;                                      // exact rational, never truncated
db.analyze_expr("emp", "rate * hours * rate")?;                            // ExprInfo { kind: "row", depth: 2, ct_muls: 2, .. } - sends nothing
db.last_expr_cost();                                                       // Some(ExprCost { depth, mult_rounds, products, inversions, linear_sums, mode, openings, wires, requests, reveals })
// ConnectOptions { expression_mode: ExprMode::Shared (default: server-held secret-shared wires) | ExprMode::Owner (any v2 server), .. }
```

* **Grammar** (spec section 5.1): `+ - * /`, unary minus, parentheses, integer and `FRAC(n, d)` literals, `SUM(expr)`,
  `AVG(expr)`, `COUNT(*)`, columns `col` / `alias.col`; `*` `/` bind tighter than `+` `-`, all left-associative; `-5` in
  operator position is a subtraction (`a-1`), `--` starts a comment (write `a - -1`); tree height <= 100. `MIN`, `MAX`, `DOT` are
  whole projections, not expressions (use `dot()` / `join_dot()`); strings, `%`, functions and a trailing `;` are `Parse` errors.
* **Policy rules** (checked before any request, identical to the Python validator and engine): `PLAIN` columns and
  literals are public operands; `ENC`/`PAIRED` columns may appear in any linear position (`+ -`, public scalar multiples,
  division by a public value); a product of two encrypted operands and a division by an encrypted denominator need every
  encrypted column involved to be `PAIRED`; `STR` and `FHE` columns are rejected (an `FHE` column keeps `sum`, `avg`,
  `scaled_sum`, `dot` - the error names FHE); a per-row expression needs an `ENC`/`PAIRED` column; per-row columns and aggregates
  cannot be mixed; constants fold exactly and a constant zero denominator or a constant beyond 2^126 is a `PlanError`.
* **Transport: `expression_mode`.** `ExprMode::Shared` (the default, exactly as in the Python driver) or `ExprMode::Owner`
  (`ConnectOptions::expression_mode`, `Client::set_expression_mode`). In shared mode every wire of the circuit is a two-party additive sharing and a server with the
  `wire_exec` / `wire_free` RPCs (wire protocol 2.1, advertised in `hello.limits.wires`) is required; against an older server the
  query fails with `Kind::Server("ExecError")` before any wire request and the message names `ExprMode::Owner`, which evaluates
  expressions the v0.6 way (the owner unmasks the operand cells; works with any v2 server). Both modes return identical results.
* **Depth and rounds.** The depth of an expression is its number of sequential ciphertext x ciphertext products
  (`a*b*c*d` is 3, `(a*b)*(c*d)` is 2). In shared mode a division by an **encrypted** value costs one more level (the product
  `rho*y` that is opened, then `x * (1/y)`), and the driver sends one `wire_exec` request per level plus one (the last also reveals
  the result and frees every wire): `last_expr_cost().mult_rounds == depth` and `.requests == depth + 1` (more when the
  caps in `hello.limits.wires` split a level into several requests). In owner mode it is ONE batched `mult_combine_batch` round
  trip per level (chunked to the server's `max_items`) and a division costs no extra level. `max_mult_depth` (`ConnectOptions::max_mult_depth` or
  `set_max_mult_depth`, default 8) caps it, counted in the active mode: a deeper expression fails with
  `Kind::DepthLimitExceeded` **before any request**. `analyze_expr` reports the dialect depth (without the extra division level). In
  `expr()` a plain `a*b` is an expression like any other, so it counts toward the cap (the Python engine keeps its v0.5 `a*b`
  form outside it).
* **Division** is exact: `7/2` is `Decoded::Rational(7, 2)`. By a public value it is a multiplication by the inverse (no round).
  By an encrypted value in shared mode **nobody decrypts the denominator**: a fresh uniform non-zero `rho` is dealt as a sharing,
  `t = rho*y` is formed by a Beaver product and opened (uniform on non-zero values whatever `y` is; MAC-checked first when
  authenticated), and `1/y = t^-1 * rho` is a local public-scalar multiplication (in owner mode the owner unmasks the denominator
  and inverts it). A denominator that is 0 in any selected row returns `Kind::DivisionByZero` - but only **after the protocol ran to its
  last request**: a zero `t` is replaced by a fresh random non-zero dummy before anything goes back to the server, so neither the
  request sequence nor its content reveals that a zero occurred (no abort oracle). A result outside the exactness contract
  (|num|, den <= 2^126, |num|*den < 2^189) is `Kind::OutOfBudget`, never a wrong number; a transient intermediate outside it is harmless
  when the final result is back inside.
* **Who computes what** (spec section 5.10; [review packet](../../docs/crypto-review-packet.md) section 3.3). *Shared mode.* Every
  wire X is `X = X_S + X_O (mod n)`; a stored cell is `x~ = x + r`, so a loaded column is `X_S = x~` (the server's own value) and
  `X_O = -r` (the mask the owner already holds). The **server** applies every linear gate to its share (add, subtract, public
  scalar / vector multiply, public add, `SUM`, broadcast), computes its share of every Beaver product (including its `e*g` term)
  and keeps the result as a NEW server-resident wire in a session-scoped, capped store, and finally sends its share of the result
  wire(s); it never receives a key, mask, MAC key or anything derived from a plaintext except uniform shares and openings, never
  decodes, and never learns a product, quotient or the result. The **owner** (this process) applies the same linear gates to its
  shares, deals one fresh uniform triple per product ELEMENT (the server gets only its shares), computes its share of each
  product, and at the end adds the server's revealed share to its own and decodes. It reads no operand cell and unmasks no operand
  or intermediate; a linear `SUM(a + 2*b)` is still a server-side sum of stored cells (`loadsum`, one per column). **Honest
  limits:** the owner does O(rows) local ring arithmetic and bandwidth per level (inherent to unconditionally secure two-party
  computation), and, being the *dealer*, could derive operands from its own openings (this code never does; only the server is
  blind). New RPCs `wire_exec`, `wire_free` only; the wire audit tests assert that nothing else is used and that no mask, MAC
  key, encoded plaintext, intermediate or inverse reaches the server, that openings and `t^-1` are uniform and that no triple
  is reused (with controls proving the audit can fail; `../mutation_check_expr_shared.py` breaks the evaluator on purpose and
  requires the tests to fail). *Owner mode* (kept): the server holds blinded cells and only sums stored cells for linear sums and
  multiplies the two openings `e*g` of each Beaver product; products and quotients are not offloaded (the owner unmasks both
  operands of every product and every encrypted denominator); intermediates reach the server only inside the next level's opening
  `e = x - u` with a fresh uniform `u` (RPCs `blinded_cells`, `blinded_sum`, `mult_combine_batch`).
* **Integrity.** With `authenticated`, in shared mode every wire carries a share of its SPDZ tag (`alpha * X`, `alpha` known
  only to the owner), every opening and the revealed result are MAC-checked (`Kind::Integrity`), the opened `t = rho*y` before the
  zero test (so tampering with a denominator is a `Kind::Integrity` error, never a zero oracle), and so is every stored cell read
  into a wire (a tampered, swapped or replayed cell or tag). A reply with the wrong number of results, a short vector or a ring
  element >= n is a `Kind::Integrity` error, a non-numeric element a `Kind::Protocol` error. **Without `authenticated` the shared mode is
  secure against a semi-honest server only**: an active server can shift a result by a delta of its choosing and, by shifting a
  denominator's share, learn whether that denominator equals a guess (pinned by tests). In owner mode every cell and blinded
  sum is checked and the server's `e*g` of every product (an intermediate has no MAC; it never leaves the owner).
* **Wire lifecycle.** The wires a query creates are dropped by the last request on success and, on any other exit path (an error
  or abort in the middle of the protocol), by an explicit `wire_free`; the server also frees them at `COMMIT` / `ROLLBACK`,
  after a transaction timeout, when an unused wire's TTL expires and when the connection ends. Caps (`WireError`, i.e. `Kind::Server("WireError")`: live wires,
  elements per session, a server-wide element cap, ops and elements per request) are enforced by the server and sized by the
  client from `hello.limits.wires`.
* **Cost.** `db.last_expr_cost()` = `ExprCost { depth, mult_rounds, products, inversions, linear_sums, mode, openings, wires, requests,
  reveals }`; the last four count the shared-mode transport (`openings`: ring elements opened, `wires`: created on the server,
  `requests`: `wire_exec` calls, `reveals`) and are 0 in owner mode (`mode` is `ExprMode::Owner`).
* **Trust.** Expressions refuse a table whose policies were only learned from the server (`Kind::UntrustedSchema`, unlike a
  plain read): a lying server could label an encrypted column "plain" and have a blinded value used as a public operand.
  Transactions work as for everything else (an open transaction sees its own writes; rollback restores).

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
join), `OutOfBudget` (see below), and for v0.6 expressions `Parse` (syntax),
`PlanError` (illegal under the policy / type / scope rules), `DepthLimitExceeded`
(a plan error in the Python engine: more product levels than `max_mult_depth`) and
`DivisionByZero`. `Kind` gained these three variants in this release (it is not
`#[non_exhaustive]`: an exhaustive `match` on it needs a new arm).

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

## FHE columns (EC-FHE on BN254)

`policy: "fhe"` columns (INT only) are the complementary mode to `encrypted`/`paired`: the server itself adds
ciphertexts (EC point addition), scales them by a public scalar (EC scalar multiplication) and multiplies two
ciphertext columns with a **pairing** (the ciphertext product ★_ct, *not* a scalar multiplication). It never
holds a key or a mask and there is **no vault** state: any client with the key reads and writes. This is
elliptic-curve FHE, not lattice FHE (no noise, no bootstrapping, one multiplicative level). Normative spec:
`proto/fhe-wire.md`; behaviour: `docs/fhe-columns.md`.

```rust
use torusdb::{Client, ConnectOptions, FheBackend, FheKey, all, eq_int, CellIn};

let key = FheKey::load(Path::new("fhe.key"), Some(&std::env::var("FHE_PASS")?))?;   // sealed file from Python fhe.save_key / key.save()
// or FheKey::generate(1_000_000)?, FheKey::from_hex("<64 hex>", range)?, FheKey::from_secret_bytes(&[u8; 32], range)?
let mut db = Client::connect_with("127.0.0.1:8533", &ConnectOptions {
    fhe_key: Some(key),
    authenticated: true,                                 // integrity tags (see below)
    timeout: Some(Duration::from_secs(120)),
    ..Default::default()
})?;
db.create_table("emp", vec![/* ... */ Column { name: "rate".into(), ty: "int".into(), policy: "fhe".into() }])?;
db.insert("emp", vec![("id", CellIn::Int(1.into())), ("rate", CellIn::Int(40.into())), /* ... */])?;
db.select("emp", &["id", "rate"], eq_int("id", 1))?;     // cells are decrypted (and tag-verified) here
db.sum("emp", "rate", all())?;                           // SUM: the server adds ciphertexts -> Decoded::Int
db.avg("emp", "rate", all())?;                           // exact rational, None when empty
db.scaled_sum("emp", "rate", 3, all())?;                 // 3 * SUM(rate), public scalar |k| <= 2^40
db.update("emp", vec![("rate", CellIn::Int(45.into()))], eq_int("id", 1))?;   // fresh ciphertext + tag per row
db.dot_with_backend("emp", "rate", "hours", all(), Some(FheBackend::Pyecc))?; // sum(rate_i * hours_i) by pairings
```

* **Key** (`FheKey`, cheap to clone, `Debug` redacted): `range` bounds every plaintext AND every result
  (`[-range, range]`, default 10^6, at most 2^40); out of range is `Kind::OutOfBudget`, never a wrapped value.
  Key files are `TORUSFHEKEY1 sealed <salt>` (scrypt + encrypt-then-MAC, byte-compatible with Python
  `fhe.save_key`/`load_key`, label `fhe-key`) or `TORUSFHEKEY1 plain` (tests only); `key.save(path, pass)` writes
  either, mode `0600`. SHA-256/512, HMAC and scrypt are implemented inside the crate (no new dependency).
* **Encryption** uses independent random `r1`, `r2` from `rand::thread_rng()` (a CSPRNG) for the G1 and G2 halves
  (mandatory: a shared `r` gives anyone with the public key a value oracle). A cell is 384 bytes
  (`C1 || C2 || D1 || D2`), sent as `{"t":"x"}`; its length is checked before sending.
* **Reads:** `select`/`column` decrypt with a bounded discrete log (baby-step/giant-step; about `sqrt(2*range)`
  table entries, built once per process and range). `sum`/`avg`/`scaled_sum` call `fhe_sum` in chunks of 2000 ids
  and add the partial blobs here.
* **DOT**: `db.dot(...)` uses the server's default pairing back end; `db.dot_with_backend(..., Some(FheBackend::Pyecc))`
  (pure Python, about 0.2 s per row, chunks of 50 rows) or `Some(FheBackend::Mcl)` (native, about 1 ms per row,
  chunks of 2000) asks for one explicitly (`None` = server default, chunks of 50). Both result encodings (tag
  `0x01` py_ecc, `0x02` mcl) are decoded here without any native library (GT arithmetic in the py_ecc
  polynomial basis `w^12 = 18w^6 - 82`). Both columns must be FHE (mixing with PAIRED is `Kind::PlanError`).
  Give the connection a generous `timeout` for pure-Python servers.
* **Integrity** (`authenticated: true`): every FHE cell gets a tag `Enc(alpha*v + gamma)` in the hidden column
  `__fmac__<col>`, written right after the INSERT (the row id is only known then) inside one transaction.
  Cell reads, `sum`, `avg` and `scaled_sum` verify `tag-sum == alpha * value-sum + k * (sum gamma) * G1` in
  the exponent and fail with `Kind::Integrity` for a changed value, a dropped/duplicated/swapped row, a scaled
  answer or untagged data. Not covered: replay of an older version of a cell.
* **DOT modes** (`fhe_dot_mode`: `auto` | `local` | `delegated`; invalid values are an interface error). `delegated`: the server multiplies ciphertexts with its pairing (fast) but the result can NOT be integrity-checked - a lying server makes you decrypt a wrong number - and it must lie in the key's range. `local`: the owner reads both operand columns (each cell tag-verified when `authenticated`), decrypts and multiplies/sums the plaintexts itself: verified, O(n) decryptions, no range limit on the result (10^6 * 10^6 works). `auto` (default) = `delegated` unless `authenticated`, then `local`. `fhe_allow_unverified_dot` remains as an alias selecting `delegated` on an authenticated connection.
* **Atomic tagged INSERT.** With `authenticated`, an INSERT/INSERT-many into a table with FHE columns runs in its own
  transaction (INSERT, then the row-bound tags), so a failure leaves no untagged row. Inside a transaction you opened
  yourself the error is returned and the half-written row stays in YOUR transaction: roll it back.
* **Batched writes and server limits.** Tag writes after an authenticated INSERT and the value+tag writes of an FHE UPDATE go out in one atomic `update_cells` RPC per <= 2000 items (inside the same transaction); a server without it answers "unknown method" and the driver falls back to `update_cell` once and remembers. `fhe_sum` / `fhe_dot` / `update_cells` chunk sizes follow `hello.limits` (`max_sum_rows`, `recommended_dot_rows` of the requested back end - pyecc when unspecified - capped by `max_dot_rows`, `max_items`); older servers get the conservative defaults.
* **Second secret `s2`.** `Q = s*G1` but `Q2 = s2*G2` with `s2 = SHA-512("torussql/fhe/v2/g2-secret\0" || s)` reduced to `[1, n-1]` (derived, so key files still hold only `s`). `Q2 = s*G2` would let anyone with the public key confirm a guessed value via `e(G2, C2 - v*G1) == e(Q2, C1)`. DOT decryption is `M = c11 * c01^-s2 * c10^-s * c00^(s*s2)`; `c00`, `c01`, `c10` are group-checked first.
* **Write nonces.** With `authenticated`, every write (INSERT and each UPDATE of a row) draws a fresh random nonce (1 <= n < 2^120) stored in the plain hidden column `__fnonce__<col>`, and the tag tweak is `gamma = PRF("gamma", table, col, rowid, nonce)`. Without it a server could serve an affine mix `lambda*old + (1-lambda)*new` of two versions of a row (cells and tags) and have any integer accepted. INSERT sends the nonce with the row, then writes the real tag via `update_cells`; UPDATE writes value + tag + nonce in one `update_cells`. Reads, SUM, AVG and `k*SUM` fetch the nonces with `plain_cells` and fail with an integrity error if one is missing or not an integer.
* **Constant-time-ish search.** The giant-step discrete-log walk starts at a random index and wraps around, so decryption time does not depend on the plaintext (a fixed start leaks it linearly). Key `range` is capped at 2^40, key files included.
* **Backend is a hint.** `FheBackend` in DOT is a REQUEST: the server may use its own pairing library; the tag of the returned blob (0x01 py_ecc, 0x02 mcl) says which, and both are decrypted with the matching generator. The server rejects duplicate ids in `fhe_sum`/`fhe_dot`; the driver never sends any.
* **Hostile DOT answers.** Before the secret is used as an exponent, `c00`, `c01` and `c10` of a DOT blob are checked
  to lie in the target group (order n); otherwise a hostile server could probe `s` modulo small prime factors of
  `p^12 - 1` through the success or failure of decryption.
* **Not supported (rejected like the Python engine):** predicates / ORDER / GROUP / MIN / MAX / indexes / JOIN on
  FHE columns, per-row `k*col`, non-integer or NULL values, booleans, strings. Tables learned from the server
  stay read-only unless trusted (`trust_table`).
* **Performance** (release or `cargo test`, Apple silicon): 100 encryptions about 0.25-0.35 s after a ~50-80 ms
  table build, about 7-11 ms per cell decryption, DOT-result decryption about 60-90 ms (range 10^6, including a
  one-off GT table). Arithmetic is on `num-bigint` and is **not constant-time**. The crate's `[profile.dev]` is
  optimised (`opt-level = 1`, dependencies 3) so `cargo test` stays fast.

## Anchored table-state integrity (`integrity_anchor`)

Tags make a changed *value* detectable; they cannot tell you **which rows exist** or **whether the table is current**
(both are facts only the server states), and a server can replay an old consistent state. The anchor is a small
owner-trusted record per table, `{epoch, root, count, pending}`, where `root = sum of PRF(K_anchor, table, rowid, canonical
row) mod n` over the live rows (`K_anchor` derives from the key like alpha/gamma; the server never sees a leaf). Configure
`ConnectOptions { integrity_anchor: Some("/secure/anchor.json".into()), .. }` (or `AnchorSpec::Custom(Arc<dyn Anchor>)`) together with `authenticated` and `fhe_key`:

* Reads/WHERE/COUNT/AVG denominators and PLAIN values are answered from a **snapshot** built by scanning the server (`fhe_rows`)
  and checked against the anchor (sum of leaves and row count); cell and tag bytes fetched later must hash to what the scan
  reported. The snapshot is cached per anchor epoch (rescanned when another owner advanced it) and updated in place by your
  own writes (`db.anchor_stats()` counts scans). A server that hides, adds, resurrects, swaps or replays rows, hides a delete, or serves
  another cell after the scan raises an integrity error; a state equal to an *older* epoch is `Kind::StaleServer` ("the server is behind
  the anchor": a lagging replica or a rollback; never accepted silently).
* Every write to an anchored table runs in a transaction: the new `(root, count)` is recorded as `pending` in the anchor
  BEFORE `tx_commit` (compare-and-swap on the epoch, all touched tables in one atomic anchor write), then finished or aborted. A
  crash or lost COMMIT reply leaves `pending`; the next connect (or `tx_status`) settles it by scanning the server.
* A table created through this connection is anchored from the first byte; a table that existed earlier is refused
  (`AnchorMissing`) until `db.adopt_table(t, replace)` / `db.verify_table(t)`: **trust on first use**, only as honest as the server at that moment. `verifyTable` forces a
  full rescan. `integrity_anchor_max_rows` (default 1 000 000 slots) bounds the owner's memory (~0.5 KB per row).
* `FileAnchor` is **format-compatible with the Python implementation** (`torusdb_core.fhe_anchor.FileAnchor`): JSON, mode 0600,
  temp file + fsync + rename, epoch CAS, `pending` with txid, last 8 roots; refuses symlinks, other owners, lax permissions,
  corrupt files and unknown versions. Python, TypeScript and Rust owners can alternate on one anchor file and one key.
* **Locking.** `FileAnchor` takes `flock(<path>.lock)` (declared via `extern "C"`, no new dependency; unix only), the very lock Python takes; TypeScript takes it on macOS/BSD (`O_EXLOCK`) but not on Linux (no `flock` in Node), where concurrent writers of different languages must not overlap.
* Keep the anchor where the server cannot write, back it up like the FHE key (losing it loses row-set integrity). Not covered:
  an anchor shared by owners running concurrently on a network file system; a custodian-quorum anchor is the same `Anchor` trait/interface (not provided).

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

* No SQL / PEP 249 cursor; no GROUP BY, ORDER BY, MIN/MAX (`scaled_sum` exists for FHE columns only). v0.6 expressions are
  evaluated one per call (`expr` / `join_expr`) rather than as a SELECT list; `MIN`/`MAX`/`DOT` are not expression operands in
  either driver, and `FHE` columns are rejected inside an expression (the Python engine's `SUM(f)` / `DOT(f, g)` forms are the
  `sum()` / `dot()` methods here). Join
  WHERE over joined tables is a client-side post-filter on PLAIN columns
  (`cmp_in("d", "dname", "=", &v)`).
* Vault is a plain JSON snapshot written on demand (atomic, 0600, directory
  fsync) - not the Python driver's append-only checksummed log, no passphrase (FHE key files ARE sealed);
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
`server/nokey_server.py --port 0`; it must be Python >= 3.11 with `py_ecc`, so on a machine whose
`python3` is older set `TORUSDB_PYTHON=/path/to/python3.12`). When none is found they print
`SKIP` and return (they show as passed - check stderr). The vector tests read
`../vectors.json`, `../expr_vectors.json` and `../../proto/fhe-vectors.json`, so they only run from a checkout of the repository; the published crate ships no tests (`include` omits `tests/`). Set `TORUSDB_REQUIRE_INTEGRATION=1` to fail instead of skip.

`TORUSDB_PY_ROOT=/path/to/checkout` runs the Python side (server, core, parser, python driver) from another checkout.
The v0.6 expression tests (`tests/expr*.rs`) are driven by `../expr_vectors.json` (regenerate with `PYTHONPATH=core:parser
python drivers/gen_expr_vectors.py > drivers/expr_vectors.json`) and a live Python peer (`../expr_peer.py`: the same random
expressions through the Python engine and this crate against one server; seed via `TORUSDB_PEER_SEED`).

The FHE tests also run the Python reference as a cross-implementation peer (`tests/fhe_peer.py`, with
`PYTHONPATH=<repo>/core:<repo>/parser:<repo>/drivers/python`); set `TORUSDB_MCL_PATH=<dir containing mclbn256>`
to additionally run DOT against a server with the native pairing library.
