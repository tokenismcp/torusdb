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

* One writer at a time (a global lock); readers wait for it.
* Backups (`backup` RPC) are *logical* and are assembled in memory — for very
  large databases take a filesystem copy of a stopped server instead.
* Dead rows keep their data until a future vacuum; deleted values stay on disk
  (they are blinded scalars/plaintext columns the server could already see).
* Heap data is not fsynced per commit (the journal is); it is fsynced at checkpoint.
