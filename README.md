# TorusSQL

**The open developer surface of [TorusDB](https://torusdb.io)** — a SQL dialect,
drivers and a keyless server for data that stays encrypted end to end.

You write ordinary-looking SQL. The server computes over **blinded** data and
**never holds a key and never decrypts**; results unblind only in your own
client. It runs the *no-key delegation protocol* (Lee, J1729 Labs): the server
sees a one-time pad of each encrypted value, so a breach of the server reveals
nothing about encrypted columns (`I(M; V_S) = 0`, unconditional).

```
┌──────────────── owner / client (trusted) ────────────────┐
│  driver · mask vault · blind / unblind · planner          │
└──────────────────────────┬───────────────────────────────┘
           blinded scalars │  Π_lin (affine) · Π_mult (Beaver)
┌──────────────────────────▼───── server (untrusted) ──────┐
│  NO keys · NO masks · NO decryption                       │
└───────────────────────────────────────────────────────────┘
```

> **Be precise about the guarantee.** It covers the *values* of `ENC`/`PAIRED`
> columns. The server still sees `PLAIN` columns, the schema, row counts, access
> patterns and join keys, and — unless you enable `authenticated=True` — can lie
> about results undetected. No independent cryptographic audit has been done
> (internal audit: [`docs/crypto-review-packet.md`](docs/crypto-review-packet.md) §11).
> Read [`docs/threat-model.md`](docs/threat-model.md) before relying on it.

## What it does (dialect v0.5)

```sql
CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED);

SELECT SUM(salary), AVG(salary) FROM emp WHERE dept = 5;           -- encrypted aggregation
SELECT DOT(rate, hours) FROM emp;                                  -- encrypted × encrypted (depth 1)
SELECT d.dname, COUNT(*), SUM(e.salary)                            -- joins + grouping + encrypted SUM
  FROM emp e LEFT JOIN dept d ON e.dept = d.dept
 GROUP BY d.dname HAVING COUNT(*) > 1 ORDER BY d.dname LIMIT 10;
SELECT e.name, m.name FROM emp e JOIN emp m ON e.mgr = m.id;       -- self-join
UPDATE emp SET salary = FRAC(9500,1) WHERE id = 2;  DELETE FROM emp WHERE dept = 9;
```

`INSERT/UPDATE/DELETE`, `SUM AVG MIN MAX COUNT`, `k*col`, `a*b`, `DOT`,
`WHERE` (AND/OR/IN) on `PLAIN` columns, `GROUP BY/HAVING`, `ORDER BY/LIMIT/DISTINCT`,
aliases, `INNER`/`LEFT` joins (any number, self-joins), transactions. Full
reference and the list of what is *not* supported:
[`spec/TorusSQL-Spec-v0.5.md`](spec/TorusSQL-Spec-v0.5.md).

## Repository layout

| Path | What |
|---|---|
| `spec/` | Dialect specification + executable conformance suite |
| `parser/` | `torussql-parser` — engine-free parser and static validator (zero deps) |
| `drivers/python/` | `torussql` — PEP 249 driver (TLS, tokens, transactions, durable sealed vault, bulk load) |
| `drivers/typescript/`, `drivers/rust/` | `@torusdb/driver`, `torusdb` — same protocol, joins, transactions, vault |
| `server/` | `torusdb-server` — keyless server: auth/roles, WAL durability, backups, metrics, Docker |
| `proto/` | Wire protocol v2 spec |
| `torusctl/` | Interactive shell |
| `bench/` | Micro-, network and TPC-H-style benchmarks |
| `fuzz/`, `tests/` | Fuzz/robustness and end-to-end suites |
| `docs/` | Quickstart, ops guide, threat model, crypto review packet, versioning |

The homomorphic engine (`ec-fhe-engine`, `ec-fhe-query`) is a separately licensed
dependency of the Python driver and server — see [`NOTICE`](NOTICE).

## Try it

```bash
# wheels from the release page / your package index; the engine wheels come with your TorusDB licence
pip install torusdb-server torussql
torusdb-server --db ./demo.db &                       # loopback; see docs/ops-guide.md for production
python - <<'PY'
import torussql
c = torussql.connect("127.0.0.1", 8533, vault_path="./demo.vault")
c.execute("CREATE TABLE t (id INT PLAIN, v INT ENC)")
c.cursor().executemany("INSERT INTO t (id, v) VALUES (%s, %s)", [(1, 10), (2, 32)])
print(c.execute("SELECT SUM(v) FROM t").rows)         # [[42]] — computed on blinded data
PY
```

## Operating it

Durable (snapshot + WAL), authenticated (roles), TLS-verifying by default,
transactional, with backups, metrics and a hardened container image — see
[`docs/ops-guide.md`](docs/ops-guide.md), including a runbook and the honest
list of limitations (single node, no replication, in-memory dataset).

## Development

```bash
pytest parser/tests                         # engine-free
TORUSDB_ENGINE_DIR=/path/to/engine pytest   # everything (engine = ec_fhe_engine + ec_fhe_query dirs)
(cd drivers/typescript && npm ci && npm test)
(cd drivers/rust && cargo test)
```

Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) · Security reports:
[`SECURITY.md`](SECURITY.md) · Changes: [`CHANGELOG.md`](CHANGELOG.md) · Plan:
[`ROADMAP.md`](ROADMAP.md) · License: Apache-2.0 ([`LICENSE`](LICENSE)).
