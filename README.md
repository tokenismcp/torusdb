<p align="center">
  <img src="assets/logo.png" alt="TorusDB" width="140">
</p>

# TorusSQL

<p align="center">
  <a href="https://github.com/tokenismcp/torusdb/actions/workflows/ci.yml"><img src="https://github.com/tokenismcp/torusdb/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
  <img src="https://img.shields.io/badge/status-experimental%20(pre--audit)-orange" alt="experimental, pre-audit">
</p>

> **Status: experimental (v0.x), not independently audited.** Do not put data you
> cannot afford to lose or leak into it yet. The cryptography has had internal
> reviews only, no external one. `FHE` columns use BN254 (≈100-bit security, not
> 128), and the pure-Python pairing path is about 150× slower than the optional
> native one. The code, tests and docs were developed with substantial AI
> assistance (see [Status and provenance](#status-and-provenance)). Known limits
> are listed in [`docs/threat-model.md`](docs/threat-model.md).

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

**New here? Start with [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)** (10 minutes,
install to a restart-safe encrypted `SUM`). **Requires Python 3.11 or newer** for the
Python packages, shell and server (`python3 --version`; macOS and older Linux often ship
3.9/3.10, and `pip` then fails with "requires a different Python").

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
`WHERE` (AND/OR/IN/NOT IN/BETWEEN/IS NULL/LIKE) on `PLAIN` columns, `GROUP BY/HAVING`, `ORDER BY/LIMIT/DISTINCT`,
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
| `drivers/python/torussql/custody/` | **Threshold key custody** (z-MPC-style Laurent sharing): dealerless DKG, k-of-n verifiable key use, refresh/reshare, custodian daemon, CLI — see [`docs/custody.md`](docs/custody.md) |
| `server/` | `torusdb-server` — keyless server: auth/roles, WAL durability, backups, metrics, Docker |
| `proto/` | Wire protocol v2 spec |
| `drivers/python/torussql/cli.py` | `torussql` — interactive shell (`psql` for TorusDB) |
| `docs/audit-scope.md` | Brief for an independent security reviewer |
| `docs/fhe-review-log.md` | Internal review findings of the FHE columns (fixed / residual) |
| `docs/fhe-columns.md` | `FHE` columns: server-side SUM/DOT on ciphertexts, no key at the server |
| `docs/ec-fhe-and-no-key.md` | Why the server never evaluates under a key |
| `docs/replication.md` | Hot standbys, promotion |
| `docs/storage.md` | Disk storage engine (`--storage disk`) and `CREATE INDEX` |
| `core/` | `torusdb-core` — keyless engine: planner, blinding client, keyless store (Apache-2.0) |
| `bench/` | Micro-, network and TPC-H-style benchmarks |
| `fuzz/`, `tests/` | Fuzz/robustness and end-to-end suites |
| `docs/` | **[Getting started](docs/GETTING_STARTED.md)**, [quickstart](docs/quickstart.md), ops guide, threat model, crypto review packet, versioning |

Everything here is Apache-2.0 and self-contained: no proprietary package is needed
to build, run or test any of it.

## Try it

The packages are not on PyPI yet; until they are, install from a checkout (run in the
directory that contains this README, inside a Python >= 3.11 virtualenv):

```bash
python3.12 -m venv .venv && source .venv/bin/activate        # any Python >= 3.11
pip install ./parser ./core ./drivers/python ./server        # once published: pip install torusdb-server torussql
torusdb-server --db ./demo.db &                       # loopback; see docs/ops-guide.md for production
torussql --vault ./demo.vault                         # interactive shell, like psql
```

```
torussql> CREATE TABLE t (id INT PLAIN, v INT ENC);
torussql> INSERT INTO t (id, v) VALUES (1, 10);
torussql> INSERT INTO t (id, v) VALUES (2, 32);
torussql> SELECT SUM(v) FROM t;                       -- computed by the server on blinded data
```

or from code (use another table name, or another server/vault, if you already ran the shell
above: `table 't' already exists`):

```python
import torussql
c = torussql.connect("127.0.0.1", 8533, vault_path="./demo.vault")
c.execute("CREATE TABLE t2 (id INT PLAIN, v INT ENC)")
c.cursor().executemany("INSERT INTO t2 (id, v) VALUES (%s, %s)", [(1, 10), (2, 32)])
print(c.execute("SELECT SUM(v) FROM t2").rows)        # [[42]]
```

Docker: `docker build -f server/Dockerfile -t torusdb-server .` (see the Dockerfile header).
`FHE` columns and threshold custody need an optional dependency: `pip install "py_ecc>=6,<9"`
(plus `mclbn256` for native speed) — see [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) §5.

## Threshold key custody

The owner's mask vault can be sealed under a key that **no one ever holds**: it is
generated dealer-free by `n` custodians and used by any `k` of them through one
verifiable message each — the key is never reassembled (`python -m torussql.custody`,
[`docs/custody.md`](docs/custody.md)). Needs `pip install "py_ecc>=6,<9"` (extra `torussql[custody]`);
custodian hosts need neither the server nor the engine core.

## Postgres-style operation

* **Disk storage** (`--storage disk`): data larger than RAM, crash-safe, auto-compacting — [`docs/storage.md`](docs/storage.md)
* **Indexes** on plain columns: `CREATE INDEX ON t (col)`
* **Replication**: read-only hot standbys, promotion — [`docs/replication.md`](docs/replication.md)
* **Snapshot reads**: readers never block on another session's transaction
* **Pooling / threads**: thread-safe connections, `torussql.pool.ConnectionPool`
* **Shell**: `torussql` (`psql`-like)

## Operating it

Durable (snapshot + WAL), authenticated (roles), TLS-verifying by default,
transactional, with backups, metrics, a disk storage engine, asynchronous/synchronous
replication with manual promotion and a hardened container image — see
[`docs/ops-guide.md`](docs/ops-guide.md), including a runbook and the honest list of
limitations (single writer node, no automatic fail-over, one open transaction at a time).

## Development

```bash
pip install pytest "py_ecc>=6,<9"           # Python >= 3.11; the tests import the source tree directly
pytest                                      # everything (pure Python; py_ecc for the FHE/custody tests)
pytest spec/conformance                     # just the dialect conformance suite
(cd drivers/typescript && npm ci && npm test)    # Node >= 18
(cd drivers/rust && cargo test)
```

## Status and provenance

* **Maturity:** v0.x, experimental. Measured in tests, not in production years: there is no
  long-running deployment, no large-scale load experience and no independent security audit.
* **Security review so far:** internal and AI-assisted review rounds with proof-of-concept
  attacks, every confirmed finding fixed and covered by a regression test
  ([`docs/fhe-review-log.md`](docs/fhe-review-log.md)). That is not a substitute for an external
  audit; a brief for one is in [`docs/audit-scope.md`](docs/audit-scope.md).
* **How it was built:** the author designed the protocols and the product; the implementation,
  tests and documentation were produced with substantial help from AI coding assistants and
  reviewed by running the test suites and attack scripts, not by line-by-line human review of
  every file. Treat the code accordingly and read it before you rely on it.
* **Not in this repository:** the EC-FHE engine used by the full TorusDB product is closed source;
  this repository is the key-less server layer, drivers and spec, and works without it.

Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) · Security reports:
[`SECURITY.md`](SECURITY.md) · Changes: [`CHANGELOG.md`](CHANGELOG.md) · Plan:
[`ROADMAP.md`](ROADMAP.md) · License: Apache-2.0 ([`LICENSE`](LICENSE)).
