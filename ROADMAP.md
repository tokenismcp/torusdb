# TorusSQL Roadmap

Legend: ✅ shipped · 🚧 partial · ⬜ planned · 🔬 research (no honest construction yet).
This file states what is *not* done as plainly as what is.

## Shipped (through v0.5, plus the unreleased v0.6 dialect)

| Area | Status |
|---|---|
| Dialect: DDL/DML, SUM/AVG/MIN/MAX/COUNT, `k*col`, `a*b`, `DOT`, WHERE (AND/OR/IN), GROUP BY/HAVING, ORDER BY/LIMIT/DISTINCT, aliases | ✅ spec v0.5 + executable conformance |
| **Dialect v0.6 (unreleased)**: arithmetic expressions `+ - * /`, products of arbitrary depth (one batched round per level, default max depth 8), division by public and by encrypted values, `SUM(expr)`/`AVG(expr)` | ✅ Python driver/engine + conformance, now with **secret-shared wires** (wire protocol 2.1: the server holds its share of every intermediate, nothing is unmasked at the owner; F-18 addressed). Residuals: the owner is the Beaver dealer and so *can* derive operands (F-22), shared mode needs `authenticated=True` against a malicious server (F-23). The TypeScript and Rust drivers still use the owner-computed transport (`mult_combine_batch`), same grammar/results/costs of that mode, cross-checked against the Python engine's `expr_mode="owner"` |
| **Wire protocol 2.1**: `wire_exec` / `wire_free` (session-scoped secret-shared wire store, caps, TTL) | ✅ server + Python driver; ⬜ TypeScript and Rust drivers |
| Joins: INNER/LEFT, aliases, self-joins, multi-join, grouping over joins | ✅ (hash join at the owner on PLAIN keys) |
| Exactness contract with loud overflow errors | ✅ |
| Open parser + validator, engine-agreement tests | ✅ |
| Keyless server: auth/roles, TLS, WAL + checkpoints, backup/restore, transactions, metrics, Docker | ✅ single node |
| Drivers: Python (DB-API 2.0), TypeScript, Rust | ✅ (MAC integrity and FHE columns in all three; vault log/passphrase sealing and custody: Python only) |
| Replication (async + sync WAL shipping, manual promotion), disk storage engine, secondary indexes, pooling | ✅ ([`docs/replication.md`](docs/replication.md), [`docs/storage.md`](docs/storage.md)) |
| Durable, sealed, tamper-evident mask-vault log | ✅ Python driver |
| **Threshold key custody**: dealerless DKG, k-of-n verifiable key use, refresh/reshare, daemon, CLI | ✅ Python (`torussql.custody`) |
| Internal cryptographic audit + review packet | ✅ (findings F-1…F-12) |
| Benchmarks: micro, network, TPC-H-style | ✅ |

## Next — required before calling it 1.0

1. ⬜ **Independent cryptographic review** of the review packet; resolve findings
   F-3 (Π_mult offload for `DOT` / `a * b`), F-22 (owner-blind triple generation), F-25 (shared-wire
   proof sketches), F-4 (make authenticated mode the default?), F-10 (standard AEAD for the vault).
2. ⬜ **CI evidence**: the workflow is committed but has not yet run on a hosted
   runner; first green run + required checks on `main`.
3. ⬜ **Vault log with passphrase sealing in the TypeScript and Rust drivers** (their MAC mode exists; their vault
   is a JSON snapshot saved on demand).
4. ⬜ **Automatic fail-over** (replication and manual promotion exist: `docs/replication.md`).
5. ⬜ Publish packages (PyPI: parser, core, driver, server; npm; crates.io) — needs registry tokens (the
   engine is in-repo, so the wheels are self-contained). Until then install from a checkout
   ([`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)).

## Later

* ⬜ **Threshold unblinding** — secret-share the *masks* themselves so that unblinding is also a
  quorum operation and no single process ever holds the vault (linear, so it fits the same
  sharing). Larger change: n× mask storage and online custodians on every query.
* ⬜ Custody in the TypeScript / Rust drivers; Pedersen/GJKR DKG; P-256 and Ed25519 groups;
  a post-quantum-safe threshold-use option.

* ⬜ Multi-column `ORDER BY`, `HAVING` on aggregates other than COUNT (`IS NULL` shipped).
* ⬜ Non-equi and `RIGHT`/`FULL` joins; subqueries.
* ⬜ Streaming result cursors (today results are fully materialised at the owner).
* ⬜ Multi-owner deployments (needs MPC triple preprocessing).
* ⬜ Schema migration tooling (ALTER TABLE).
* 🔬 Encrypted predicates / ordering (needs an FHE comparison circuit).
* 🔬 Sub-linear owner work for products (shared wires keep the intermediates at the server, but the owner still does O(rows) share arithmetic per level), and an owner that is *blind* to intermediates (needs a third non-colluding dealer or computational OT/HE triple generation; F-22).
* ⬜ Shared-wire expressions in the TypeScript and Rust drivers (wire protocol 2.1).
* ✅ Expressions in the TypeScript and Rust drivers (owner-computed mode; `drivers/expr_vectors.json`, live Python peer).
* 🔬 Expressions over `FHE` columns (the pairing scheme has one multiplicative level).
* 🔬 Access-pattern hiding (ORAM-style) — the largest remaining leakage.

## Explicit non-goals

Server-side key storage or decrypt-then-re-encrypt designs, anywhere, ever. The
server holds no key and no mask; this is the product's defining constraint.
