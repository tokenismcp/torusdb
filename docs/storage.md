# Storage engines

`torusdb-server --db PATH` keeps a snapshot (`PATH`) and a write-ahead journal
(`PATH.journal`). *Where the rows live* is chosen with `--storage`:

| | `memory` (default) | `disk` |
|---|---|---|
| rows | RAM; whole database is rewritten into each snapshot | heap files in `PATH.data/`; RAM holds 9 bytes per row + a row cache |
| data set limit | RAM | disk (plus ~9 bytes/row of RAM for slot tables) |
| checkpoint | writes every row | flushes heaps, writes slot tables, small manifest |
| start-up | parse snapshot | load slot tables (O(rows) bytes), rebuild indexes by scan |

```bash
torusdb-server --db /var/lib/torusdb/main.db --storage disk --cache-rows 100000
```

A memory-mode database opens in disk mode (rows are imported) and vice versa
is *not* supported in place — restore a logical backup instead. Both modes serve
the identical wire protocol and SQL.

## How the disk engine works

* **Heap file** `t<id>.<epoch>.heap`: append-only records `[len][crc32][row]`.
  An UPDATE appends a new row version and repoints the slot; a rollback restores
  the previous pointer and truncates the file back.
* **Slot table** `t<id>.<generation>.slots`: record offset and dead flag per row
  id, CRC-protected, written atomically at each checkpoint.
* **Manifest** (the snapshot file): schema, per-table file names, slot counts and
  the heap length at the checkpoint, index columns. Replacing it atomically is the
  commit point of a checkpoint.
* **Recovery:** load the manifest, truncate every heap to its checkpointed length
  (bytes written after it are discarded), then replay the journal — the journal is
  the only durability mechanism for commits, exactly as in memory mode. Files not
  named by the manifest (crash leftovers, older generations) are deleted.
* **Compaction:** when superseded versions exceed half of a heap, the checkpoint
  rewrites it (new epoch) with only current versions. Row ids never change.
* **Integrity:** every record and slot table is checksummed; damage is reported as
  a corrupt database (the server refuses to start; restore from backup).

## Indexes

```sql
CREATE INDEX ON emp (dept);        -- PLAIN columns only
DROP INDEX ON emp (dept);
```

Indexes accelerate `=`, `<`, `<=`, `>`, `>=` and `IN` (any combination in AND/OR
predicates where every OR branch has an indexable atom); anything else scans.
Encrypted columns cannot be indexed (the server cannot compare them). Index
definitions are durable; the index contents live in RAM and are rebuilt at start.

## Limits (be aware)

* **Concurrency model:** one write transaction at a time, served first-come-first-served
  (`BEGIN` waits up to `--tx-wait`, then `Busy`); a transaction idle for `--tx-idle-timeout`
  seconds (default 30) or older than `tx_timeout` is aborted so it cannot hold the lock
  forever. Readers never wait: they see the last committed state. Row ids and the owner's
  masks are assigned at write time, which rules out optimistic multi-writer transactions —
  scale reads with replicas (`docs/replication.md`), keep write transactions short.
* Backups (`backup` RPC), memory-mode checkpoints and replica bootstrap snapshots are
  *logical* and **streamed** to disk with a running checksum, so the server never holds
  a second copy. *Reading* one back (restore, replica bootstrap) still parses the whole
  file in memory.
* Dead rows keep their data until a future vacuum; deleted values stay on disk
  (they are blinded scalars/plaintext columns the server could already see).
* Heap data is not fsynced per commit (the journal is); it is fsynced at checkpoint.
