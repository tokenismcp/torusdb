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
for the time it takes to write the snapshot.

## Synchronous replication

```bash
torusdb-server ... --sync-replicas 1 --sync-timeout 10 [--sync-strict]
```

With `--sync-replicas N` a commit is acknowledged to the client only after N live
replicas have confirmed it (a replica confirms a commit by asking for the *next* one,
i.e. after it applied and journaled it). Without enough replicas for `--sync-timeout`
seconds the primary either **degrades to asynchronous** (default; logged and counted in
`stats.sync_timeouts`) or, with `--sync-strict`, answers *Busy* — the commit is still
durable on the primary, so the client must check `tx_status` before retrying (the
drivers already do this for lost replies). Confirmation is not automatic fail-over: you
still promote by hand, and a lagging or disconnected replica is simply not counted.

## Guarantees and limits

* **Asynchronous by default:** commits acknowledged to clients may be lost on a primary
  crash if the replica had not fetched them yet; use `--sync-replicas` to close that
  window (at the price of commit latency).
* A replica only ever sees commits that were durable in the primary's journal.
* No automatic fail-over, no cascading replicas, no multi-primary.
* The bootstrap snapshot is streamed to disk on the primary (writers are paused while
  it is produced); the replica parses the downloaded file in memory.
* Replication traffic carries only blinded scalars and plaintext columns — but use
  TLS: it is the same data the server stores, and the admin token travels with it.
