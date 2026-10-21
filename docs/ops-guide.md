# TorusDB Operations Guide

**Version:** 0.5 · applies to `torusdb-server` 0.5 and driver `torussql` 0.5

This guide covers running the keyless server in production. Two facts shape
everything below:

1. **The server holds no key and no mask.** Stealing its disk, memory or
   backups reveals nothing about encrypted columns. It does hold your PLAIN
   columns, schema, row counts and access patterns — see `threat-model.md`.
2. **The owner's *mask vault* is the only thing that can read your encrypted
   data.** Lose it and the encrypted columns are gone for good; leak it and
   confidentiality is gone. Operations are therefore about two assets:
   *server state* (recoverable, low secrecy) and *the vault* (irreplaceable,
   high secrecy).

---

## 1. Installing

```bash
pip install torusdb-server          # pulls torussql + the engine package
# or, container:
docker build --build-context engine=/path/to/engine-parent \
             -f server/Dockerfile -t torusdb-server:0.5.0 .
```

The engine packages (`ec-fhe-engine`, `ec-fhe-query`) are licensed separately
and are not in the public repository — the image and wheels need them at
build/install time.

## 2. Starting the server

```bash
torusdb-server --host 0.0.0.0 --port 8533 \
    --db /var/lib/torusdb/main.db \
    --token-file /etc/torusdb/tokens \
    --tls --cert /etc/torusdb/server.crt --key /etc/torusdb/server.key \
    --backup-dir /var/backups/torusdb --metrics-port 9433 --log-json
```

A **non-loopback bind refuses to start without `--token-file`** (override only
for throw-away testing with `--insecure-no-auth`). Without `--tls` on a
non-loopback address it logs a warning: tokens and PLAIN data would travel in
the clear.

| Flag | Default | Meaning |
|---|---|---|
| `--db PATH` | in-memory | Enable durability (snapshot + journal + lock file) |
| `--fsync always\|never` | `always` | fsync each commit. `never` is faster and loses the last commits on power failure |
| `--checkpoint-every N` | 5000 | Fold the journal into a new snapshot every N commits |
| `--token-file F` | none | Enable authentication (see §3) |
| `--tls --cert C [--key K] [--cafile CA]` | off | TLS ≥1.2; `--cafile` requires client certificates (mutual TLS) |
| `--max-connections N` | 256 | Extra connections get `Busy` |
| `--idle-timeout S` | 300 | Drop connections silent for S seconds |
| `--max-frame-mb M` | 32 | Largest accepted request/response |
| `--backup-dir D`, `--backup-keep K` | off, 7 | Where the admin `backup` RPC writes; retention |
| `--metrics-port P`, `--metrics-host H` | off, 127.0.0.1 | Prometheus `/metrics` + `/healthz` |
| `--log-level`, `--log-json` | INFO, off | Logging |
| `--restore-from FILE` | — | Restore `--db` from a backup file and exit |

`SIGTERM`/`SIGINT` stop accepting connections, write a final checkpoint and
release the lock. Requests still running at that instant are cut off (their
clients see a lost connection; nothing half-applied is journaled).

## 3. Authentication and roles

Token file — one `role:token` per line, `#` comments, tokens ≥16 characters,
or `role:sha256:<hex>` to avoid storing the raw token:

```
admin:Zk1b…32+ random chars…
rw:9Qe3…
ro:Ff7a…
```

Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

| Role | May call |
|---|---|
| `ro` | reads: schema, tables, row selection, blinded reads and aggregates |
| `rw` | `ro` + CREATE, INSERT, UPDATE, DELETE, transactions |
| `admin` | `rw` + DROP TABLE, `stats`, `checkpoint`, `backup` |

Clients pass `connect(..., token="…")`. Restrict the file (`chmod 600`) and
rotate by adding the new token, deploying clients, then removing the old one
and restarting (tokens are read at start-up). After 5 failed attempts from an
address, that address is locked out for 30 s. Use TLS: tokens are bearer
secrets.

> A token is *access control*, not *confidentiality*: a `ro` token can read the
> blinded store, which is useless without the owner's vault.

## 4. TLS

```bash
# internal CA + server cert (example; use your PKI in production)
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -keyout ca.key -out ca.crt -subj "/CN=torusdb-ca"
openssl req -newkey rsa:3072 -nodes -keyout server.key -out server.csr -subj "/CN=db.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
        -extfile <(printf "subjectAltName=DNS:db.example.com") -out server.crt
```

Clients **verify the certificate and hostname by default**:
`connect("db.example.com", 8533, tls=True, cafile="ca.crt", token=…)`. For mutual
TLS add `--cafile ca.crt` to the server and `certfile=`/`keyfile=` to the client.
`tls_insecure=True` (encrypt but do not authenticate the server) exists for
local development only.

## 5. Durability and crash recovery

With `--db PATH` the server keeps three files:

| File | Purpose |
|---|---|
| `PATH` | Snapshot, JSON, SHA-256 checked, carries a *generation* number |
| `PATH.journal` | Write-ahead log; one checksummed line per committed statement/transaction |
| `PATH.lock` | Advisory lock — a second server on the same database refuses to start |

* Every acknowledged commit is in the journal (fsync'd under `--fsync always`).
* On start-up the server loads the snapshot, replays journal records of the
  same generation, and discards a torn final record. A crash *between* writing
  a new snapshot and truncating the journal is harmless — stale-generation
  records are ignored.
* A snapshot whose checksum fails stops the server with an instruction to
  restore from backup; it never starts on silently corrupt data.
* The journal is journaled **after** the operation succeeds in memory and
  **before** the client is acknowledged; if the journal write fails (disk full)
  the operation is undone and the client gets an error.

Snapshot and journal contain only blinded scalars and PLAIN data — they may be
copied, replicated and archived with ordinary tools. They are **not** useful
without the vault, and the vault is not useful without them: back up both.

## 6. Backup and restore

```python
conn = torussql.connect(..., token=ADMIN_TOKEN)
path = conn.backup()          # checksummed snapshot in --backup-dir (server-side)
```

Schedule it (cron, k8s CronJob) and copy the files off-host. Retention is
`--backup-keep`. To restore, stop the server and run:

```bash
torusdb-server --db /var/lib/torusdb/main.db --restore-from /var/backups/torusdb/main.db.20261021T0300.g7.1.bak
torusdb-server --db /var/lib/torusdb/main.db ...        # start normally
```

The restore verifies the backup checksum first. **A restored server and a vault
that was saved later disagree**: rows written after the backup are gone from the
server, while their masks remain in the vault (harmless — unused masks). The
opposite — a vault older than the server — leaves rows without masks (see
`find_orphans` in §7). Take vault and server backups together.

## 7. Vault custody (read this)

```python
conn = torussql.connect(..., vault_path="/secure/disk/owner.vault",
                        vault_passphrase="long passphrase")
```

* The vault is an **append-only, per-record checksummed log**, created `0600`,
  fsync'd after every statement (every commit inside a transaction). A crash can
  tear only the last record, which is dropped on load; a damaged record anywhere
  else makes load **refuse** rather than guess. A wrong passphrase never
  modifies the file.
* With `vault_passphrase` every record is sealed (scrypt-derived key,
  encrypt-then-MAC). Without it the file is plaintext — rely on full-disk
  encryption and file permissions.
* **Back it up** like a private key: copy `owner.vault` after significant
  changes and keep copies in at least two places. For organisational custody
  use the LSS export (`ecfhe_query.keymgmt.export_custody`): the vault is sealed
  and the key split t-of-n among custodians.
* **Orphans.** A crash after the server accepted an INSERT but before the mask
  reached the vault leaves a row this vault cannot decrypt. `conn.find_orphans()`
  lists them and `conn.repair_orphans()` tombstones them. Run it after any
  unclean client shutdown.
* Never share one vault file between concurrent writers; each owner process has
  its own vault, and a second reader needs the owner's vault to decrypt.
* Leaving `vault_path` unset keeps the vault in memory only — fine for tests,
  fatal for real data.
* **Threshold custody.** For production, seal the vault under a `k`-of-`n`
  threshold key instead of a passphrase: `connect(…, vault_custody=ThresholdCustody(pub, quorum))`.
  The key is generated without a dealer, held by `n` custodian daemons on separate
  hosts, and *used* (never reassembled) by any `k` of them. Ceremony, daemons,
  refresh, replacement and compromise response: [`custody.md`](custody.md).
  Existing vaults migrate with `conn.reseal_vault(custody=…)`.

## 8. Transactions

Default is **autocommit**: each statement is atomic; a multi-row `UPDATE` runs
in an implicit transaction so it can never half-apply. For multiple statements:

```python
with conn.transaction():         # commit on success, rollback on exception
    cur.execute("UPDATE …"); cur.execute("INSERT …")
```

* A rollback restores the server (undo log) **and** the client's masks.
* Isolation is **serializable by exclusion**: one transaction at a time. Other
  connections' requests wait up to 10 s (`Busy` afterwards). A transaction open
  longer than 60 s is aborted the moment someone is waiting, and its owner gets
  `ServerBusyError: transaction timed out`. A dropped connection rolls back.
* Checkpoints wait for open transactions.
* Keep transactions short; this is a deliberate simplicity/safety trade-off,
  not a high-concurrency write path.

## 9. Observability

`conn.server_stats()` (admin) and, with `--metrics-port`, Prometheus text at
`/metrics` and `200 ok` at `/healthz` (bind to localhost or protect it — it has
no authentication).

| Metric | Alert suggestion |
|---|---|
| `torusdb_up` | page if absent |
| `torusdb_connections_active` vs `--max-connections` | warn at 80% |
| `torusdb_connections_rejected_total` | any increase |
| `torusdb_auth_failures_total` | rate spike = brute force |
| `torusdb_errors_total{type=…}` | `InternalError` > 0 → inspect log `ref=` |
| `torusdb_request_seconds_total / torusdb_requests_total` | latency regression |
| `torusdb_journal_records` | stuck high ⇒ checkpoints failing |
| `torusdb_tx_rollbacks_total` | many ⇒ clients dropping/timeouts |
| `torusdb_table_rows{table}` | capacity planning |

Logs carry connects/disconnects, auth failures, slow requests (>1 s), timed-out
transactions and internal errors with a reference id; **request payloads are
never logged**.

## 10. Capacity and performance

Single process, Python, all data in memory, one mutex around the data (reads
serialize too). Measured on an Apple-silicon laptop over loopback TCP, 20 000
rows, 5 columns (1 ENC, 2 PAIRED), `bench/net_bench.py`:

| Operation | Result |
|---|---|
| INSERT, one statement per round trip | ~8 000 rows/s |
| INSERT, `executemany` (one round trip) | ~31 000 rows/s (24 000 authenticated) |
| `SUM(enc)` over 20 000 rows | ~7 ms (20 ms authenticated) |
| filtered `SUM` / `COUNT` | 8–9 ms |
| `GROUP BY` + `COUNT` + `SUM(enc)`, 50 groups | ~32 ms |
| `JOIN` + `GROUP BY` + `SUM(enc)` | ~35 ms |
| `DOT(a,b)` over 2 000 rows | ~26 ms |
| `SELECT` 1 000 rows incl. an encrypted column | ~13 ms |

Memory: ≈ **1.1 KB/row** (plain mode) or **2.2 KB/row** (authenticated) for a
row with one ENC and two PAIRED columns, split between server and owner vault;
the on-disk snapshot is ≈ 370 / 700 bytes/row and the vault ≈ 300 / 600 bytes/row.
Plan RAM at roughly 3× the snapshot size. Reproduce with
`python bench/net_bench.py --rows 20000 [--auth]` and `python bench/tpch.py`.

Exceeding these sizes needs sharding by table across servers; there is no
built-in replication or clustering (see §13).

## 11. Upgrades and compatibility

* Wire protocol **v2** (this release) adds `hello`, auth, transactions, bulk
  and batch RPCs. A v2 driver talks to a v1 server (no auth/transactions); a v1
  driver talks to a v2 server only with authentication disabled.
* Snapshots written by 0.4 and earlier (no checksum) load fine and are rewritten
  in the checksummed v2 format at the first checkpoint. Downgrading after that
  requires `--restore-from` a pre-upgrade backup.
* Stop the server with `SIGTERM` for upgrades (final checkpoint). Take a backup
  first.

## 12. Runbook

| Symptom | Action |
|---|---|
| `database is in use by another process` | Another server holds the lock; stop it. A stale lock file is harmless — the lock is released when the process dies. |
| `snapshot checksum mismatch` | Disk corruption or tampering. Restore from the newest `--backup-dir` file. |
| Clients get `InternalError (ref=ab12cd34)` | `grep ab12cd34` the server log for the traceback. |
| Clients get `Busy: database is locked by another transaction` | A client holds a transaction; it is aborted after 60 s. Find the leaking client. |
| `vault has no mask for … row N` | The server has rows this vault never wrote: run `conn.find_orphans()`; if the *whole table* is unreadable you are using the wrong vault. |
| `OutOfBudget` | A value or aggregate exceeded the exact-arithmetic range (|num|,den ≤ 2^126, |num|·den < 2^189). Scale to integers, aggregate in groups, or reduce magnitude. |
| `IntegrityError` (authenticated mode) | The server returned or stored altered data. Treat as an incident: restore from backup, rotate infrastructure. |
| Disk full | Writes fail with an error and are rolled back; free space, then optionally `conn.checkpoint()`. |
| Lost token file | Create a new one and restart; tokens carry no data. |
| **Lost vault** | Unrecoverable for encrypted columns unless you have a vault backup or a custody quorum. PLAIN columns remain readable. |

## 13. Known limitations (be honest with your auditors)

* No replication, clustering or hot standby — recovery is restore-from-backup.
* One in-memory dataset per server; one open transaction at a time.
* Integrity (`authenticated=True`) is **opt-in**; without it a malicious server
  can return wrong answers undetected.
* Joins run at the owner on plaintext keys; encrypted-key joins, encrypted
  predicates, and multiplication depth >1 are not supported.
* Metadata (schema, row counts, access patterns, join keys, timing) is visible
  to the server.
* No external cryptographic audit has been completed.
