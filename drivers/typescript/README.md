# @torusdb/driver (TypeScript / Node) - v0.5.0

No-key TorusDB client. Connects to a **keyless** server (wire protocol v2),
holds the mask vault locally, blinds on insert and unblinds results - the
server never holds a key and never decrypts.

The driver exposes a **programmatic API** (not raw SQL - SQL parsing lives in
the Python `torussql-parser`). Field arithmetic uses native `BigInt` (exact
mod-n); wire format and framing match the Python driver and `../../proto/`.

```ts
import { Client, eq } from "@torusdb/driver";

const db = await Client.connect("127.0.0.1", 8533);
await db.createTable("emp", [
  { name: "id", type: "int", policy: "plain" },
  { name: "dept", type: "int", policy: "plain" },
  { name: "salary", type: "rational", policy: "encrypted" },
  { name: "rate", type: "int", policy: "paired" },
  { name: "hours", type: "int", policy: "paired" },
]);
await db.insert("emp", { id: 1, dept: 5, salary: { num: 8000n, den: 1n }, rate: 50, hours: 40 });

await db.sum("emp", "salary");                 // 8000n  (Pi_lin on blinded scalars)
await db.sum("emp", "salary", eq("dept", 5));
await db.avg("emp", "salary");                 // exact rational, or null when empty
await db.dot("emp", "rate", "hours");          // 2000n  (Beaver-triple Pi_mult)
await db.count("emp", eq("dept", 5));
db.close();
```

Results are `bigint` for integers and `{ num, den }` (lowest terms) for
non-integers. Integers may be passed as `number` (safe integers) or `bigint`.

## Connecting: auth, TLS, timeouts

```ts
const db = await Client.connect("db.example.com", 8533, {
  token: process.env.TORUSDB_TOKEN,   // required if the server runs with --token-file
  tls: true,                          // certificate AND hostname verified
  ca: fs.readFileSync("ca.pem"),      // optional: trust a private CA
  timeoutMs: 30_000,                  // per request; default 30000, 0 = none
  vaultPath: "./vault.json",          // loaded on connect if it exists
});
```

* `hello` negotiates the protocol (the driver speaks up to 2; a v1 server that
  does not know `hello` is treated as protocol 1 without auth; a newer server
  is refused). `db.serverInfo` holds the reply.
* If the server needs auth and no `token` is given, `connect` fails with
  `kind: "Unauthenticated"` before sending anything. Tokens are never put in
  error messages or logs.
* TLS is verified by default. The only way to skip verification is the
  explicit `tlsInsecure: true` (encrypted but unauthenticated - local
  development only).
* A reply that does not arrive within `timeoutMs` rejects with `TimeoutError`
  and the connection is dropped (a late reply would desynchronize it). Lost
  connections reject with `ConnectionError`; no call is ever left pending.
  Calls on one connection are serialized.

## Errors

Everything throws `TorusError` with a `.kind`:

* server kinds (text before the first `": "`): `Unauthenticated`, `Forbidden`
  (e.g. `ro` token writing), `Busy`, `BadRequest`, `InternalError`,
  `PlanError`, ...
* local kinds: `ConnectionError`, `TimeoutError`, `ProtocolError`,
  `InterfaceError` (misuse, unknown table/column, closed client, bad join),
  `OutOfBudget` (value or aggregate outside the exactly representable range -
  ints must satisfy `|v| <= ~2^126`, and decoding refuses results that do not
  reconstruct exactly instead of returning a wrong number).

## Transactions

```ts
await db.transaction(async () => {          // commit on success, rollback on throw
  await db.insert("emp", {...});
  await db.update("emp", { salary: 1 }, eq("id", 1));
});
// or manually: await db.begin(); ... await db.commit() / await db.rollback()
```

The client snapshots its mask vault and schema at `begin()`; `rollback()` (and
a failed `commit()`) restores them, so masks of rolled-back inserts/updates
disappear exactly as the server's rows do. `update()` is wrapped in an
implicit transaction when none is open. A dropped connection rolls back on the
server. Only one transaction is open server-wide at a time (others wait, then
get `Busy`).

## Bulk insert, update, delete

```ts
const ids = await db.insertMany("emp", rows);   // blinded locally, ONE insert_many RPC
await db.update("emp", { salary: 9n }, eq("id", 1));
await db.deleteRows("emp", eq("id", 2));        // tombstone
await db.select("emp", ["id", "salary"], eq("dept", 5));   // reveals values
```

Predicates (`eq ne lt le gt ge isIn and or`) run on the server against
**plain** columns only.

## JOIN

No SQL parser here, so joins are an RPC-level client-side hash join (like the
Python engine's `_base_tuples`). Join keys must be PLAIN columns; NULL keys
never match.

```ts
const j = await db.join("emp", [
  { table: "dept", alias: "d", leftAlias: "e", leftCol: "did", rightCol: "did" },
  { table: "proj", alias: "p", leftAlias: "d", leftCol: "did", rightCol: "did", kind: "left" },
], { alias: "e", where: eq("eid", 1) });      // where applies to the left table
j.tuples;                                     // rowid per alias; null = NULL side of a LEFT JOIN
await db.joinColumn(j, "d", "dname");         // plain / decrypted values
await db.joinSum(j, "p", "budget");           // Pi_lin over the non-null rowids
await db.joinCount(j);
await db.joinDot(j, "e", "x", "p", "y");      // Pi_mult across tables
```

A self-join just aliases the same table twice.

## Vault

`db.saveVault(file?)` writes the masks as JSON atomically (temp file, fsync,
rename) with mode `0600`; `db.loadVault(file?)` restores them. The vault is
the owner's one long-lived secret: lose it and the data is gone, leak it and
confidentiality is gone. `findOrphans()` lists server rows this vault cannot
decrypt (crash between an INSERT and a save). Save after writes you cannot
afford to lose.

## Admin / introspection

`ping()`, `tables()`, `tableInfo(t)`, `stats()`, `checkpoint()`, `backup()`,
`dropTable()` (the last four need an `admin` token when auth is on).

## Trust model: the server is untrusted

* **Schema.** The server never decides which columns are encrypted. Tables you
  create here (or load from your own vault - the vault stores the policies) are
  *trusted*. Tables only learned from the server via `syncSchema()` are
  *untrusted*: plain reads work, but `insert`/`insertMany`/`update` throw
  `UntrustedSchema` (a lying server could otherwise label an encrypted column
  "plain" and receive it in the clear). Opt in with `trustServerSchema: true`
  or `db.trustTable(name)`. Unknown policy strings are treated as encrypted.
* **Replies** are validated (types, array lengths against the request, safe
  integers, <= 90 digits per integer, frames capped at
  `min(hello.max_frame, 64 MiB)`); anything else is a `ProtocolError`, never a
  raw `TypeError`. Unsolicited bytes from the server kill the connection.
* **Authenticated (MAC) mode.** `Client.connect(h, p, { authenticated: true })`
  writes a hidden one-time-padded MAC `alpha*s` next to every encrypted cell
  (`__mac__<col>`, same layout as the Python driver; alpha lives in the vault)
  and verifies it on every SUM/AVG/DOT/read: a server that edits stored values
  or lies about aggregates is caught (`IntegrityError`). Without it these
  drivers do **not** detect a lying server. Use the same mode the table was
  written in; the vault records it. Mixing modes on one table is refused only
  when the vault says so - the server does not expose `__mac__` columns.
* **Secrets.** Masks, the MAC key and the token are `#private` and redacted
  from `util.inspect` / `JSON.stringify`. The token is refused on an
  unencrypted non-loopback connection unless `allowInsecureToken: true`.

## SQL conveniences (predicates, indexes, OFFSET, IF [NOT] EXISTS)

```ts
import { between, notIn, isNull, isNotNull, like, notLike } from "@torusdb/driver";
await db.count("t", between("age", 20, 50));          // (age >= 20) AND (age <= 50)
await db.count("t", notIn("id", [1, 2, 3]));          // AND of != atoms: NULL cells never match
await db.select("t", ["id"], isNull("age"));          // the only atoms that match NULL
await db.select("t", ["id"], like("name", "ali%"));   // STR columns, % = run, _ = one char, case-sensitive, no ESCAPE
await db.select("t", ["id"], null, { offset: 10, limit: 5 });   // rows in row-id order, sliced client-side
await db.createIndex("t", "age");  await db.dropIndex("t", "age");   // PLAIN columns, role rw+, transactional
(await db.tableInfo("t")).indexes;                    // ["age", ...]
await db.createTable("t", cols, { ifNotExists: true });
await db.dropTable("t", { ifExists: true });          // without ifExists a missing table is an error
```

A NULL operand makes every atom false except `isNull`/`isNotNull`, so `notIn`,
`notLike` and `ne` never match NULL cells. LIKE needs a STR column and a string
pattern; predicates on encrypted columns are refused. In `join()` options pass an
alias as the last argument (`isNull("w", "b")`): on the NULL side of a LEFT JOIN
`isNull` is true and every other atom is false. OFFSET/LIMIT apply to `select`
only (there are no per-row encrypted expressions in this driver).

## Lost COMMIT replies

`begin()` sends a random transaction id. If a COMMIT's reply is lost (timeout,
dropped connection) the driver reconnects and asks `tx_status(txid)`:
`committed` keeps the new masks; `unknown` restores the vault and throws;
if the status cannot be obtained it throws `TransactionInDoubt` (`.txid`),
keeping BOTH vault states. Writes are refused until you `await db.reconnect()`
and `await db.resolveTransaction(txid)` (asks the server) or
`resolveTransaction(txid, true|false)` (you know the answer). The vault is
restored only on a definite server answer. A `Busy ... timed out` reply inside
a transaction drops the local transaction immediately.

## Concurrency

Every public operation (including `begin`/`commit`/`rollback` and a whole
`transaction(fn)`) is serialized on the client, so concurrent callers cannot
interleave inside a transaction. Calls made *inside* `transaction(fn)` re-enter.

## Differences from the Python driver

* No SQL, no PEP 249 cursor: use the methods above.
* Vault persistence is a plain JSON snapshot written on demand (atomic, 0600,
  directory fsync) - not the Python driver's append-only checksummed log, no
  passphrase sealing, no automatic save after every statement, and an in-doubt
  COMMIT is held in memory only (`saveVault` refuses while one is unresolved).
* ORDER BY / GROUP BY / MIN / MAX / scalar-mul are not provided (JOIN, SUM,
  AVG, COUNT, DOT are). Join WHERE over joined tables is a client-side
  post-filter on PLAIN columns (`eq("dname", "Eng", "d")`).
* No client certificates (mutual TLS) option yet.
* Integers from the server are limited to 90 digits; sums over > 100 000 rows
  are chunked (the server rejects longer lists).

## Build, test

```bash
npm install
npm run build        # dist/torusdb.js + .d.ts
npm test             # compiles to build-test/ and runs node:test
```

Integration tests start a real server subprocess:
`$TORUSDB_PYTHON` (or `<repo>/.venv/bin/python`, then `python3`)
`torussql/server/nokey_server.py --port 0`. If no working interpreter/server
is found they are **skipped**, not failed. The vector tests need no server.
TLS tests need `openssl`.
