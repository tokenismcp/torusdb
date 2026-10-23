# Replication and fail-over

`torusdb-server` supports **asynchronous WAL-shipping replication** with
read-only hot standbys and manual promotion.

```bash
# primary (as usual; needs --db and an admin token for the replica)
torusdb-server --db /data/main.db --token-file tokens --tls --cert c.crt --key c.key

# replica: first start downloads a consistent snapshot, then streams the WAL
export REPL_TOKEN=<admin token of the primary>
torusdb-server --db /data/replica.db --token-file tokens \
    --replica-of primary.example:8533 --repl-token-env REPL_TOKEN --repl-tls --repl-cafile ca.pem
```

* Clients can read from a replica (SELECT, `table_info`, …); any write answers
  *"this server is a read-only replica"*. Encrypted data needs the owner's vault or
  mask cluster exactly as on the primary — replicas hold no keys and no masks either.
* `repl_status` (admin) shows role, WAL position, lag and the last error;
  `stats` carries the role/timeline.
* **Promotion:** `conn._wire.call("promote", [])` (admin) stops following, bumps the
  **timeline** and makes the node writable. Fence the old primary first — the
  software cannot do it for you. Other replicas of the old primary must be
  re-bootstrapped from the new one (empty `--db`, same flags); they refuse to
  follow across timelines and say so.
* In-doubt transactions (`tx_status`) resolve correctly after a promotion: the
  committed-transaction ids are replicated with the commits.

## How it works

The primary appends every commit to its journal, then makes it visible in an
in-memory ring (`--repl-ring`, default 200 000 commits). A replica long-polls
`repl_fetch(position)`; positions are `(generation, seq)` of the primary's
journal. Applying a commit goes through the same mutation path as the primary's,
and is journaled locally together with the primary position, so a replica restarts
exactly where it stopped (crash or clean). A replica that fell out of the ring (or
points at a different `cluster_id`/timeline) stops with a clear error instead of
guessing; re-bootstrap it. Bootstrap streams a checksummed snapshot file in
512 KiB chunks (`repl_snapshot_*`); producing it pauses the primary's writers
for the time it takes to serialise the database.

## Guarantees and limits

* **Asynchronous:** commits acknowledged to clients may be lost on a primary crash if
  the replica had not fetched them yet. There is no synchronous mode yet.
* A replica only ever sees commits that were durable in the primary's journal.
* No automatic fail-over, no cascading replicas, no multi-primary.
* The bootstrap snapshot is assembled in memory on the primary (like `backup`).
* Replication traffic carries only blinded scalars and plaintext columns — but use
  TLS: it is the same data the server stores, and the admin token travels with it.
