# TorusSQL Roadmap

Legend: ✅ shipped · 🚧 partial · ⬜ planned · 🔬 research (no honest construction yet).
This file states what is *not* done as plainly as what is.

## Shipped (through v0.5)

| Area | Status |
|---|---|
| Dialect: DDL/DML, SUM/AVG/MIN/MAX/COUNT, `k*col`, `a*b`, `DOT`, WHERE (AND/OR/IN), GROUP BY/HAVING, ORDER BY/LIMIT/DISTINCT, aliases | ✅ spec v0.5 + executable conformance |
| Joins: INNER/LEFT, aliases, self-joins, multi-join, grouping over joins | ✅ (hash join at the owner on PLAIN keys) |
| Exactness contract with loud overflow errors | ✅ |
| Open parser + validator, engine-agreement tests | ✅ |
| Keyless server: auth/roles, TLS, WAL + checkpoints, backup/restore, transactions, metrics, Docker | ✅ single node |
| Drivers: Python (DB-API 2.0), TypeScript, Rust | ✅ (MAC integrity, vault log/sealing: Python only) |
| Durable, sealed, tamper-evident mask-vault log | ✅ Python driver |
| **Threshold key custody**: dealerless DKG, k-of-n verifiable key use, refresh/reshare, daemon, CLI | ✅ Python (`torussql.custody`) |
| Internal cryptographic audit + review packet | ✅ (findings F-1…F-12) |
| Benchmarks: micro, network, TPC-H-style | ✅ |

## Next — required before calling it 1.0

1. ⬜ **Independent cryptographic review** of the review packet; resolve findings
   F-3 (Π_mult offload), F-4 (make authenticated mode the default?), F-10 (standard AEAD for the vault).
2. ⬜ **CI evidence**: the workflow is committed but has not yet run on a hosted
   runner; first green run + required checks on `main`.
3. ⬜ **Authenticated (MAC) mode and vault log in the TypeScript and Rust drivers.**
4. ⬜ **Replication / hot standby** for the server (today: restore from backup).
5. ⬜ Publish packages (PyPI parser; npm; crates.io) — needs registry tokens and a
   decision on distributing the proprietary engine wheels.
6. ⬜ Connection pooling and a thread-safe connection in the Python driver.

## Later

* ⬜ **Threshold unblinding** — secret-share the *masks* themselves so that unblinding is also a
  quorum operation and no single process ever holds the vault (linear, so it fits the same
  sharing). Larger change: n× mask storage and online custodians on every query.
* ⬜ Custody in the TypeScript / Rust drivers; Pedersen/GJKR DKG; P-256 and Ed25519 groups;
  a post-quantum-safe threshold-use option.

* ⬜ Multi-column `ORDER BY`, `IS NULL`, `HAVING` on aggregates other than COUNT.
* ⬜ Non-equi and `RIGHT`/`FULL` joins; subqueries.
* ⬜ Streaming result cursors (today results are fully materialised at the owner).
* ⬜ Secondary indexes on PLAIN columns (server scans today).
* ⬜ Multi-owner deployments (needs MPC triple preprocessing).
* ⬜ Schema migration tooling (ALTER TABLE).
* 🔬 Encrypted predicates / ordering (needs an FHE comparison circuit).
* 🔬 Multiplication depth > 1.
* 🔬 Access-pattern hiding (ORAM-style) — the largest remaining leakage.

## Explicit non-goals

Server-side key storage or decrypt-then-re-encrypt designs, anywhere, ever. The
server holds no key and no mask; this is the product's defining constraint.
