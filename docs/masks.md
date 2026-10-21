# Threshold masks (`torussql.custody.masks`)

By default the owner holds the **mask vault** — the one-time pads that turn the
server's blinded scalars back into numbers. Whoever opens that vault can read the
data, so its custody matters as much as the key's. With a **mask cluster** the
masks are never held by one party: each cell's mask `r` is secret-shared k-of-n
among independent *custodians* (the same Laurent-series sharing as the key
custody, see `custody.md`). The owner process becomes **stateless**.

```
owner (stateless) ──blinded scalars──▶ DB server (no keys, no masks)
      │ ▲
      │ └─ partial sums of masks ◀─ ≥ k custodians (each holds one share per cell)
      ▼
   n custodians
```

## What changes

* **Aggregates** (`SUM`, `COUNT`, `AVG`, …): each custodian returns the *sum of
  its shares* over the row set; the owner interpolates `k` partial sums into
  `Σ r` and unblinds. **No individual mask is revealed** by an aggregate.
* **Reading a cell** (a projected encrypted column, a `DOT` operand) reveals that
  one cell's mask to the owner. Custodians can rate-limit this per caller
  (`--reveal-quota`) and require a minimum aggregate size
  (`--min-aggregate-rows`).
* **Writes** are *mask-first*: shares are staged on the custodians before the
  server cell is written. A crash leaves at worst an orphan mask (harmless;
  `mask-gc` removes it), never a server cell without a mask.
* Each cell group has a random id (`__cid__`) and each cell a random version
  (`__mv__<col>`) stored as hidden plaintext columns on the server. They are
  random, carry no information, and make rollbacks idempotent.
* **Lying custodians** are detected by robust reconstruction (majority over
  `k`-subsets) when more than `k` answer; `< k` honest answers fail closed.

## Setup

```bash
# 1. each custodian host
python -m torussql.custody serve --mask-store /var/lib/tdb/masks.log \
    --listen 0.0.0.0:8601 --token-file tokens --tls --cert c.crt --key c.key
# 2. cluster.json: {"k":3,"nodes":[{"host":..,"port":..,"x":1},…],"tls":{...}}
python -m torussql.custody mask-init --cluster cluster.json --token-env OWNER_TOKEN
# 3. connect (stateless; no vault file)
conn = torussql.connect(host, token=..., mask_cluster=ThresholdMaskStore(nodes, k),
                        trust_server_schema=True)
```

A stateless owner has no vault to remember the schema in, so it learns it from
the server — see *Schema trust* below.

## Operations

| Command | Purpose |
|---|---|
| `mask-status` | per-custodian counters |
| `mask-gc` | delete masks of cells that no longer exist on the server (`--dry-run`, `--min-age`) |
| `mask-repair` | re-share cells a lagging custodian is missing; refuses if >50 % look orphaned |
| `mask-reshare` | move to a new (k, n) / membership; the old generation is frozen, then dropped with `mask_drop_gen` |

## Schema trust

A table whose column policies were *learned from the server* is read-only for the
client unless `trust_server_schema=True`: a malicious server could otherwise
relabel an encrypted column `plain` and receive plaintext on INSERT/UPDATE.
Tables created through (or restored from) the client's own vault are trusted.
A stateless owner must therefore either opt in after checking the schema, or
pin it out of band.

## Limits (read these)

* Fewer than `k` mask shares reveal nothing about `r` (information-theoretic, the
  shares are Shamir-style over the BN254 scalar field). But `k` colluding custodians learn every mask and
  hence all data they can match to server cells. Choose custodians in independent
  administrative domains.
* The **owner process** sees the masks of whatever it reads, and the plaintext of
  results. Compromising a running owner leaks what it reads *during* the compromise;
  it does not leak the rest of the database.
* Latency: every encrypted read/aggregate is a quorum round trip (k parallel RPCs).
* Availability needs ≥ `k` reachable custodians, writes need `write_quorum`.
* **Not externally audited.** This is an internal design and test effort only.
