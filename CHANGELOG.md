# TorusSQL Changelog

All notable changes are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Versioning Policy](docs/versioning.md).

---

## [0.5.0] — 2026-10-21

Hardening release: SQL joins completed, server and drivers made operable, a
cryptographic self-audit, and the open repository made self-contained.

### Added — replication, snapshot reads, pooling (late 0.5.0)

- **Replication** (`docs/replication.md`): asynchronous WAL shipping, read-only
  hot standbys (`--replica-of`), snapshot bootstrap, `repl_status`, manual
  `promote` with timelines and cluster ids.
- **Snapshot reads:** readers no longer wait for (or see) another session's open
  write transaction; they read the last committed state.
- **Thread-safe `Connection`** (DB-API threadsafety 2) and `torussql.pool.ConnectionPool`.

### Added — disk storage engine and indexes (late 0.5.0)

- `--storage disk`: rows in checksummed append-only heap files with an LRU row
  cache; data sets larger than RAM; crash-safe with the existing journal;
  automatic compaction. Details: `docs/storage.md`.
- `CREATE INDEX ON t (col)` / `DROP INDEX ON t (col)` on PLAIN columns (parser,
  validator, planner, server RPCs `create_index` / `drop_index`, `table_info.indexes`).
- `tests/test_storage.py`, `bench/storage_bench.py`.

### Changed — fully open source (late 0.5.0)

- **`torusdb-core`** (`core/`, Apache-2.0): the keyless engine (planner, blinding
  client, keyless store, no-key protocol primitives) now lives in this repository.
  The driver and server no longer depend on any proprietary package;
  `pip install torusdb-server torussql` works on a clean machine (verified from
  built wheels in a fresh virtualenv).
- New **`torussql` shell** (psql-style: `-c`, `-f`, `\dt`, `\d`, `\timing`, token/TLS/vault
  flags) replaces the old `torusctl` demo REPL.
- CI, Dockerfile and docs no longer reference a private engine repository.

### Added — threshold masks and full audit (late 0.5.0)

- **Threshold mask custody** (`docs/masks.md`): per-cell masks shared k-of-n
  among custodians; aggregates unblinded from partial sums; stateless owner;
  `mask-init/status/gc/repair/reshare` operator tools.
- **Schema trust anchor:** tables learned from the server are read-only unless
  `trust_server_schema=True` (a hostile server could relabel an encrypted
  column as plain).
- Unified `RecordLog` (journal/vault/mask stores): failed appends truncated,
  torn tail vs corruption distinguished, sequence-numbered, header-bound AAD.
- Transaction ids, `tx_status`, vault tx markers: a lost COMMIT reply no longer
  loses masks (`TransactionInDoubt` when it cannot be resolved).
- Server/SQL fixes from five independent audits (differential fuzz vs SQLite,
  validator/planner fuzz, tx fuzz, protocol attacks, claims verification):
  NULL-safe predicates, AVG on PLAIN, scalar bound, DDL parity, `__` reserved
  names, row-id validation, parameter-scanner `%%`, CI artifact leak, and more.

### Added — SQL dialect v0.5 (`spec/TorusSQL-Spec-v0.5.md`)

- Table **aliases** (`FROM emp e`), **self-joins**, **any number of joins**,
  **`LEFT [OUTER] JOIN`** (NULL semantics: NULL keys never match; aggregates skip
  the null side; `COUNT(*)` counts it).
- `GROUP BY` / `HAVING` over joins; `WHERE` on any joined table; `DOT` and `a*b`
  across tables; qualified names on single-table queries.
- `ORDER BY` an unselected column; NULLs sort last ascending / first descending.
- **Literal type checking** on INSERT / UPDATE / WHERE in both the open validator
  and the planner (previously `'abc'` could be stored in an INT column and
  `FRAC(1,2)` in an INT ENC column; NULL/strings in encrypted columns crashed
  with a raw `TypeError`).

### Added — server (`torusdb-server`, wire protocol v2: `proto/torussql-wire-v2.md`)

- Token **authentication with roles** (`ro`/`rw`/`admin`), constant-time compare,
  digest storage, failed-auth lockout; non-loopback bind refuses to start without it.
- **Transactions** (serializable by exclusion) with undo log; dropped connection,
  timeout or failed journal write rolls back. Multi-row UPDATE is atomic.
- **Crash-safe durability**: checksummed snapshot + write-ahead journal with
  torn-write recovery, generation numbers, periodic checkpoints, advisory lock.
- Online **backup** + `--restore-from`; `stats` RPC; Prometheus `/metrics` and
  `/healthz`; structured logging; graceful SIGTERM; connection cap, idle timeout,
  frame cap, bounded TLS handshake; request validation; internal errors never
  leak details (opaque `ref`).
- New RPCs: `hello`, `auth`, `tables`, `table_info`, `blinded_cells`,
  `insert_many`, `tx_*`, `stats`, `checkpoint`, `backup`, `ping`.
- Predicates on encrypted columns are rejected at the RPC layer too.

### Added — threshold key custody (`torussql.custody`, z-MPC style)

- **Dealerless DKG** over Laurent-series sharing (secret = residue): Feldman
  commitments + Schnorr proofs of knowledge; aborts and names the culprit.
- **k-of-n key use without reassembly**: ECIES-style envelope, one verifiable
  message per custodian (Chaum–Pedersen DLEQ proof), aggregator-free combine.
- **Proactive refresh and membership change** (reshare to any new k, n; public key
  unchanged). Signed/encrypted file-based ceremony; custodian daemon with tokens,
  TLS, rate limit, policy hook and audit log; `python -m torussql.custody` CLI.
- **Vault integration**: `connect(vault_custody=…)`, `rotate_vault_key()`,
  `reseal_vault()` (passphrase ⇄ threshold ⇄ new key). Curves: secp256k1, BN254.
- Custodian hosts need only `torussql` + `py_ecc`; the driver now imports lazily.
- Honest limits (docs/custody.md §3–4): computational (ECDLP, not post-quantum),
  Feldman-style DKG, an open vault lives in owner memory. ~100 new tests.

### Added — drivers

- **Python**: transactions (`begin/commit/rollback`, `with conn.transaction()`),
  token auth, **durable append-only mask-vault log** (0600, per-record checksum,
  sequence numbers, optional passphrase sealing), orphan detection/repair,
  one-round-trip `executemany` bulk INSERT, schema sync, `server_stats/backup`.
- **TypeScript** and **Rust**: rewritten to protocol v2 with typed errors, verified
  TLS (Rust behind `tls` feature), transactions, auth, `insertMany`, client-side
  hash joins (aliases, self-join, LEFT), vault save/load, strict decode budget —
  with **78 and 50 integration tests** against a real server (previously none; the
  Rust crate did not compile).

### Changed — security defaults

- `tls=True` now **verifies** certificate and hostname; skipping requires the
  explicit `tls_insecure=True`. Default socket timeout is 30 s (was unbounded).
- **Exactness contract**: `encode` rejects values that can never decode, and
  `decode` raises `OutOfBudget` instead of returning a wrong number when an
  aggregate overflows (previously silent corruption — audit F-1/F-2).
- Fixed: DROP TABLE left stale client schema and masks; a non-grouped column under
  GROUP BY returned a list instead of an error; the TPC-H Q1 query was invalid.

### Packaging / repository

- Wire codec and framing moved into the driver package (a pip-installed driver
  is now self-contained); `torusdb-server` and the engine's `torussql-parser`
  dependency are declared; all open packages share version 0.5.0 (test-enforced).
- Full Apache-2.0 `LICENSE` text (the file previously held only a short notice),
  `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`; hardened multi-stage Docker image
  (non-root, healthcheck) verified by build + run.
- Standalone repository with its own CI (`.github/workflows/ci.yml`).

### Documentation

- Rewritten ops guide (with measured performance), updated threat model, wire v2
  spec, dialect spec v0.5, quickstart (its code is executed by the test suite),
  and a **cryptographic review packet** with 12 internal-audit findings and the
  questions for an external reviewer. **No external audit has been done.**

### Tests

Python suite 264 → 600+ (`test_join_v05`, `test_ops`, `test_crypto_audit`,
`test_literal_types`, `test_vault_audit`, …); plus 78 TypeScript and 50 Rust.

## [0.4.0] — 2026-06-22

### Added — SQL dialect v0.4

- **`[INNER] JOIN t2 ON t1.col = t2.col`** — single INNER JOIN on a PLAIN
  equality condition. Client-side hash join. Both ON columns must be PLAIN.
  Projections use `table.col` qualified refs or auto-resolve when unambiguous
  across joined tables. Aggregates (SUM/AVG/COUNT/MIN/MAX) work over the
  joined result. WHERE applies to the primary (left) table.
  22 engine tests + 10 conformance tests (open/closed agreement verified).

- **Qualified column names** — `table.col` syntax in projections, WHERE,
  GROUP BY, ORDER BY, and aggregate functions; the tokenizer now accepts `.`
  as a symbol and the parser handles it in all relevant positions.

### Added — Benchmarks

- **TPC-H subset** (`bench/tpch.py`): Q1-like (GROUP BY + 3-col encrypted
  SUM/COUNT), Q3-like (INNER JOIN + encrypted SUM), Q6-like (filter + SUM).
  One-command run; `--json` flag for CI-storable results.

### Added — Security

- **Cryptographic review packet** (`docs/crypto-review-packet.md`):
  theorem statements, implementation pointers, test vector recipes, and
  specific review questions for each security property. Ready for external
  academic or professional cryptographic review.

### Added — Packaging

- **npm publish config** (`drivers/typescript/package.json` v0.4.0):
  `files`, `prepublishOnly` build, `publishConfig`, author + repository
  metadata. CI step gates `npm publish` to `refs/tags/v*`.
- **cargo publish config** (`drivers/rust/Cargo.toml` v0.4.0):
  `keywords`, `categories`, `include`, full crates.io metadata. CI step
  gates `cargo publish` to `refs/tags/v*`.

---

## [0.3.0] — 2026-06-22

### Added — SQL dialect v0.3

- `SELECT DISTINCT` — deduplicates output rows on plaintext columns.
- `GROUP BY plain_col` — one output row per group; aggregates per group.
  GROUP BY on encrypted columns raises `ProgrammingError`.
- `HAVING COUNT(*) op n` — group filter (requires GROUP BY).
- `UPDATE t SET col=val [WHERE pred]` — re-blinds encrypted columns with
  fresh masks; tombstone rowids stay stable.
- `DELETE FROM t [WHERE pred]` — tombstone delete; rowids are stable so
  mask vault keys `(table, rowid, col)` never shift.

### Added — DB-API 2.0 (PEP 249) Python driver

- `torussql.apilevel = "2.0"`, `threadsafety = 1`, `paramstyle = "format"`.
- Full exception hierarchy: `Warning`, `Error`, `InterfaceError`,
  `DatabaseError`, `DataError`, `OperationalError`, `IntegrityError`,
  `InternalError`, `ProgrammingError`, `NotSupportedError`.
- `Connection.cursor()` → `Cursor` with `description`, `rowcount`,
  `arraysize`, `execute`, `executemany`, `fetchone`, `fetchmany`, `fetchall`,
  `close`, and iteration protocol.
- `%s` parameter substitution with SQL-safe literal rendering.

### Added — TLS transport

- Server: `--tls --cert <pem> [--key <pem>] [--cafile <ca>]` CLI flags.
  Full TLS with CA verification; mutual TLS with `--cafile`.
- Driver: `connect(..., tls=True, cafile=..., certfile=..., keyfile=...)`.
  Dev mode (no cafile) and verified mode.

### Added — Phase 6: Security & compliance

- **Threat model** (`docs/threat-model.md`): formal description of what the
  server sees (I(M;V_S)=0), what an attacker learns, side channels, and
  custody adversary model.
- **Fuzz / robustness suite** (`fuzz/test_fuzz_parser.py`): 1000-mutation
  parser fuzz, wire codec fuzz (truncated frames, random bytes, huge payloads),
  live server fuzz (200 random JSON-RPC payloads). Server must survive all.
- **Driver package** (`drivers/python/pyproject.toml`): pip-installable
  `torussql` with correct classifiers and zero runtime deps.

### Added — Phase 7: Productization

- **Dockerfile** (`server/Dockerfile`): minimal Python 3.12-slim image with
  non-root user, `/data` volume, `EXPOSE 8533`, TLS-ready entrypoint.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): matrix (Python 3.11,
  3.12), engine/query/parser/conformance/e2e/fuzz suites, parser package
  check, driver import check, Docker build + smoke test, bench smoke (100 rows).
- **Quickstart** (`docs/quickstart.md`): 10-minute tutorial, full SQL surface.
- **Ops guide** (`docs/ops-guide.md`): production deployment, TLS, mTLS,
  backup/restore, disaster recovery, performance baselines.
- **Versioning policy** (`docs/versioning.md`): two public surfaces (dialect
  + wire), MINOR/MAJOR bump rules, pre-1.0 policy.
- **CHANGELOG** (this file).

### Fixed

- `blinded_cell` RPC previously serialized as `str()` and the driver cast to
  `int()`. Broke `SELECT col FROM t` on `STR PLAIN` columns over the wire.
  Fixed by using `w.wv`/`w.uwv` typed codec on both sides.

### Tests

272 tests total (241 → 272): +27 DB-API, +4 TLS, +fuzz suite.

---

## [0.2.0] — 2026 (earlier session)

### Added

- No-key delegation engine (`ecfhe/nokey.py`): I(M;V_S)=0, Π_lin + Π_mult.
- No-key SQL engine (`ecfhe_query/nokey_engine.py`): full dialect over blinded scalars.
- Networked no-key server (`server/nokey_server.py`) + Python driver (`drivers/python/`).
- LSS key custody (`ecfhe/lss.py`, `ecfhe_query/keymgmt.py`, `chain.py`).
- Malicious-server integrity MAC (SPDZ-style, §IX, authenticated mode).
- Binary framing (`proto/framing.py`): 4-byte length-prefixed frames.
- TypeScript driver (`drivers/typescript/`), Rust driver (`drivers/rust/`).
- Cross-language conformance vectors (`drivers/vectors.json`).
- Benchmark harness (`bench/bench.py`).
- Retired trusted-evaluator (server no longer holds any key).

---

## [0.1.0] — 2026 (earlier session)

### Added

- TorusSQL dialect spec (`spec/TorusSQL-Spec-v0.1.md`).
- Executable conformance suite (`spec/conformance/`).
- Wire protocol (`proto/torussql.proto`, `proto/wire.py`).
- Open parser + validator (`parser/torussql_parser/`).
- `torusctl` REPL.
- Phase 2 SQL: COUNT(*), compound WHERE (AND/OR/IN), ORDER BY, LIMIT, AVG, MIN/MAX, per-row scalar mul, aliases.
