# FHE columns — EC-FHE: the server computes on ciphertexts, with no key

> **This is elliptic-curve FHE (EC-FHE), not lattice-based FHE.** Ciphertexts are points on the
> BN254 pairing curve (G1/G2). There is no noise budget and no bootstrapping.
>
> Two different operations — do not confuse them:
> * **ciphertext × ciphertext** (`DOT`) is the pairing-based tensor product **★_ct**
>   (Weil/optimal-ate pairing of ciphertext points, landing in the target group GT; one level
>   deep). It is *not* a scalar multiplication.
> * **public scalar × ciphertext** (`k * SUM(col)`) is plain EC scalar multiplication of the
>   ciphertext points — cheap, and a different operation.

`ENC`/`PAIRED` columns use the *no-key delegation* protocol: the server stores one-time
pads and the owner finishes every computation. **`FHE` columns** are the other, complementary
mode: the server itself adds ciphertexts (EC point addition), scales them by public scalars
(EC scalar multiplication) and multiplies two ciphertext columns (★_ct pairing). It never holds a
secret key, a bootstrap key or any mask; only the owner's `FheKey` can decrypt.

```sql
CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE, hours INT FHE);
INSERT INTO emp (id, dept, rate, hours) VALUES (1, 5, 40, 160);
SELECT SUM(rate), AVG(rate), COUNT(*) FROM emp WHERE dept = 5;   -- server adds ciphertexts (EC addition)
SELECT 3 * SUM(rate) FROM emp;                                   -- ... times a PUBLIC scalar (EC scalar mult)
SELECT DOT(rate, hours) FROM emp;                                -- ct × ct (★_ct pairing) summed: Σ rateᵢ·hoursᵢ
SELECT id, rate FROM emp WHERE id = 1;                           -- cells are decrypted by the owner
UPDATE emp SET rate = 45 WHERE id = 1;                           -- fresh ciphertext, no mask bookkeeping
```

```bash
torussql --fhe-keygen ./fhe.key --fhe-pass-env FHE_PASS --fhe-range 1000000   # once
torussql --fhe-key ./fhe.key --fhe-pass-env FHE_PASS -p 8533                   # then use FHE columns
```
```python
import os, torussql
from torusdb_core import fhe
key = fhe.load_key("fhe.key", os.environ["FHE_PASS"])
conn = torussql.connect("127.0.0.1", 8533, fhe_key=key, authenticated=True)   # authenticated: integrity tags
```

Needs `pip install "py_ecc>=6,<9"` (or `"torusdb-core[fhe-native]"` for the ~150x faster native back end);
without it the tools stop with that instruction. Step by step: [`GETTING_STARTED.md`](GETTING_STARTED.md) §5.
A table with `FHE` columns can be created without a key, but reading or writing its FHE cells
without `--fhe-key` / `fhe_key=` fails with "no FHE key is loaded".

## What you get compared with `ENC` / `PAIRED`

| | `ENC`/`PAIRED` (no-key delegation) | `FHE` |
|---|---|---|
| server learns about a cell | nothing (one-time pad, information-theoretic) | nothing computationally (SXDH on BN254, ≈100-bit) |
| owner state | **mask vault** per cell (or a mask cluster) | **only the key**; no per-cell state, any number of clients with the key read/write |
| `SUM` / `AVG` / `k*SUM` | owner sums masks | server adds ciphertext points (and scales them by public k); owner decrypts one point |
| `DOT` / `a*b` | owner needs the plaintext operands (O(n) at the owner) | **server** multiplies ciphertexts with the ★_ct pairing; owner decrypts one value |
| UPDATE/DELETE/crash/orphans | mask-first ordering, gc, repair | nothing to repair |
| speed | fast | native back end: encrypt 0.3 ms/cell, `SUM` 0.4 ms/row, `DOT` 1.4 ms/row; pure Python: 33 ms, 0.1 ms, 200 ms |
| result range | ≈ ±2^126 exact rationals | integers only, results within the key's range (default ±10^6) |
| integrity vs a lying server | optional SPDZ MACs | optional tags for cells / `SUM` / `k*SUM`; with `integrity_anchor=` also the row set and freshness (see below); `DOT` is verified by recomputing at the owner (`fhe_dot_mode="local"`, the default when authenticated), **none for delegated `DOT`** |

## Scheme (EC-FHE on the BN254 pairing groups; implemented in `torusdb_core/fhe.py`)

Two secrets `s` and `s2` (a local key derives `s2` from `s`; a threshold key shares it separately);
public `Q = sP`, `Q2 = s2·G2`. Encrypting `v`: G1 half `(r₁P, vP + r₁Q)` and G2
half `(r₂G2, vG2 + r₂Q2)` with **independent** `r₁, r₂`. SUM adds the G1 halves; DOT pairs the
G2 half of one cell with the G1 half of the other and multiplies the four pairings over all
rows (Miller loops are multiplied before one final exponentiation). The owner recovers
`Σv` or `Σab` with a baby-step/giant-step discrete log bounded by the key's range.

*Why independent randomness and a second secret:* a layout that shares `r` between the halves lets
anyone with the public key test whether a cell encrypts a guessed value
(`e(C₂ − vP, G2) = e(Q, D₁)`), i.e. a dictionary attack. Independent randomness alone is *not*
enough: with `Q = sP` and `Q2 = s·G2` both public, `e(G2, C₂ − vP) = e(Q2, C₁)` still confirms a
guess. Using an independent `s2` for the G2 half closes both. `tests/test_fhe.py` tries every
pairing identity between a cell and the public keys, with a positive control showing the weak
variants are broken.

## Limits — read before relying on it

* **Integrity is partial** (`authenticated=True`) — and with an **integrity anchor** (next section) the two
  biggest gaps below, *row-set lies* and *replay/rollback*, are closed. Without an anchor there is NO row-set
  integrity and NO freshness. Each FHE cell gets a second ciphertext, a
  *tag* `Enc(α·v + γ(table, column, row id))` where `α` and the per-cell tweak `γ` are PRF
  outputs of the owner's secret. For any set of rows the owner checks, in the exponent and
  without a discrete log, `tag-sum = α·value-sum + k·Σγ`. This catches a changed value, a
  dropped, duplicated or swapped row, a result scaled by the server, and cells written without
  tags (soundness ≈ 1/n per attempt). **Not covered:** replay of an older version of the same
  cell or of a whole table, the **set of rows** (WHERE results, COUNT/AVG denominators, deleted/dead rows —
  all come from the server), and **delegated `DOT`** — a ciphertext product cannot be tag-checked, so an
  authenticated connection by default (`fhe_dot_mode="auto"`) verifies `DOT` locally instead (the owner reads
  both operand columns, each cell verified by its tag, and multiplies the plaintexts: O(n) decryptions);
  `fhe_dot_mode="delegated"` (legacy spelling `fhe_allow_unverified_dot=True`) lets the server multiply
  and the result is NOT integrity-checked. Without
  `authenticated=True` a malicious server can return a wrong ciphertext and the owner decrypts
  a wrong number (or fails with *out of range*); use `ENC` + `authenticated=True` when
  you need verified products.
* **Malleability.** The server can compute any sum/product of your ciphertexts — that is the
  feature. It also means access control of who may *ask* the server matters.
* **What the server still sees:** plaintext columns, the schema, row counts, which rows each
  query touches, and the fact that two cells are equal *only* if you tell it (it cannot test).
* **No WHERE/ORDER/GROUP BY/MIN/MAX/JOIN on FHE columns; no `k*col`, `a*b` per row, rational
  values.** Rejected loudly by the validator and the planner.
* **Range:** every plaintext and every result must lie in `[-range, range]`; larger sums raise
  an error rather than wrap. Decryption keeps a table of ≈ √(2·range) entries (range 10^9 ≈
  45 k entries, a few seconds the first time per process).
* **Performance:** install the native back end (`pip install "torusdb-core[fhe-native]"`,
  i.e. `mclbn256`/herumi mcl) and everything is ≈150× faster — measured on an Apple-silicon
  laptop: 500-row `DOT` in 0.7 s, 1 000-cell `SUM` in 0.4 s, 1 000 encryptions in 0.3 s. Without
  it the pure-Python `py_ecc` fallback is used automatically (a 1 000-row `DOT` takes ≈3 minutes
  of server CPU; the server computes outside the database lock, in chunks of 100 rows per
  request). Force a back end with `TORUSDB_FHE_BACKEND=pyecc|mcl`.
* **Back ends are interoperable for cells and SUMs, not for DOT results.** Cells are plain
  curve points, so a cell written with one back end is read by the other. A `DOT` result is a
  target-group element whose encoding depends on the library's pairing; it carries a one-byte
  tag and is decoded by the back end that made it. A client without the native library
  automatically asks the server for the pure-Python one (slower).
* The native back end switches the `mcl` library's process-wide curve to `alt_bn128`
  (`BN_SNARK1`), validates every point **including subgroup membership**, and self-tests
  against `py_ecc` at start-up. Do not mix it with other `mcl` users in the same process.
* **Key custody:** by default the key is a file (sealed with a passphrase); losing it loses the
  data. For no single-holder of `s` use **threshold custody** (next section).
* **Cryptographic review:** this construction is new in this codebase and has had no
  independent review. Treat it as experimental.
* Python, TypeScript and Rust drivers support FHE columns (same wire format; known-answer vectors
  in `proto/fhe-vectors.json` and cross-language tests).

## Anchored table-state integrity (`integrity_anchor=`)

Tags (above) make a changed *value* detectable. They cannot tell the owner **which rows exist** or **whether the
table is current**, because both are facts only the server states. Closing them needs a small piece of
owner-trusted state. That state is the **anchor**: per table `{epoch, root, count, pending}`.

```python
conn = torussql.connect(host, fhe_key=key, authenticated=True,
                        integrity_anchor="/secure/place/anchor.json")     # or an Anchor object
conn.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE)")   # anchored from the first byte
conn.adopt_table("old_table")     # one-off, for a table that existed before the anchor (trust on first use)
conn.verify_table("emp")          # explicit audit: full rescan against the anchor
```
```bash
torussql --authenticated --fhe-key fhe.key --integrity-anchor anchor.json [--adopt-table emp] ...
```

**What it protects (conditions in the last paragraph of this list).** With the anchor configured, a server that
lies about
* the **set of rows** — adds, drops or resurrects rows, flips dead/live flags, hides a DELETE, or tampers with a
  PLAIN column (the data a WHERE runs on) — is detected (F3 of the review log);
* **time** — serves a whole table rolled back to an older, internally consistent state, replays one old version of
  a row (value + tag + nonce together), or swaps rows — is detected (the "known residual limit" of the review log);
* **COUNT / AVG denominators and DELETE/UPDATE target sets** cannot be lied about: the owner evaluates the WHERE
  itself on the verified table state and never asks the server which rows match.

**How it works.**
* `leaf(row) = PRF(K_anchor, table, rowid, canonical(row))  mod n`. `K_anchor` derives from the MAC secret exactly
  like α/γ, under its own domain label (`anchor-leaf`). The canonical row is the schema digest, every PLAIN column
  value with a type tag, and for each FHE column the write nonce, SHA-256(cell) and SHA-256(tag).
* `root = Σ_{live rows} leaf (mod n)`, `count = #live rows`. Dead rows contribute nothing. The root is additive:
  INSERT adds a leaf, DELETE subtracts one, UPDATE does both — the owner keeps the root current **at statement
  time** without rescanning.
* New read RPC `fhe_rows(table, start, count)` (≤ 2000 slots per call; see `proto/fhe-wire.md`) returns, per slot,
  dead/live, the PLAIN values and, per FHE column, nonce and the two hashes. **The server computes the hashes — it is
  untrusted and its hashes are used only through the root check.**
* `verify`: the owner scans all slots, recomputes every leaf, requires `Σ leaf == anchor.root` (plus the open
  transaction's uncommitted delta) and the same count; on success it keeps the verified snapshot
  `{rowid → plain values, nonces, hashes}`. Anything else raises `IntegrityError("table state … does not match the
  anchor …")`; a state equal to an *older* epoch raises `StaleServerError` ("the server is behind the anchor": a lagging
  replica or a rollback — never a silent pass).
* While the snapshot is valid for the anchor epoch the owner answers WHERE, COUNT, AVG denominators, PLAIN-column
  reads, DELETE/UPDATE targets **from the snapshot**; the nonces of the tag check come from the snapshot; the cell and
  tag bytes fetched for a read must hash to the snapshot's SHA-256 values. The tag check stays as the second layer
  (`SUM`/`k*SUM` cannot be hash-checked cell by cell — the server adds them — but they are bound to the anchored
  nonces, so only the current version of every cell can satisfy the tag equation).
* The snapshot is cached per anchor epoch, updated in place by the owner's own writes, and rescanned when another
  owner advanced the epoch (or a commit by another owner is pending).

**Soundness argument.** Let `S` be the anchored live set and `S' ≠ S` what a server presents. The two sums differ by
`Σ ± leaf(x)` over the symmetric difference, where every `x = (table, rowid, material)` is a distinct PRF input.
The server never sees `K_anchor` or any leaf; the leaves of distinct inputs are indistinguishable from independent
uniform elements of Z_n; so a non-empty ±combination vanishes with probability ≈ 1/n (≈ 2^-254) plus the PRF
advantage. Hence a presented state whose leaves sum to `R` is exactly the anchored one: same rows at the same slots
(the rowid is part of the leaf and the scan must be gap-free), same PLAIN values, same nonces, same cell/tag hashes.
The owner's accept/reject is an equality oracle for *whole states* only (a changed state is rejected regardless of
K), so it leaks nothing about the leaves. Cell and tag bytes fetched later must hash to the verified SHA-256 values
(collision resistance, 2^-128). Nonces and hashes are taken from the verified snapshot, never from the server's
later answers. Schema (names, types, policies) is part of every leaf, so a server cannot relabel a column.

**Commit protocol (atomic with the server transaction).** Statement time: leaf deltas accumulate per table. At
COMMIT the owner first records `pending = {root_new, count_new, epoch+1, txid}` in the anchor (compare-and-swap on
the epoch; all touched tables in one atomic anchor write), **then** sends `tx_commit`, then `finish_commit` (answer
"committed") or `abort` (rolled back / error). Lost reply: the existing `tx_status` resolution decides. Crash with a
`pending` in the anchor: on the next connect the owner scans the server and settles it by what it finds — state
sum == `root_new` → finish, == old root → abort, neither → `IntegrityError`. A reader that meets another owner's pending
commit settles it the same way (it never aborts a commit that `tx_status` says is still on its way). Autocommit
statements that were not transactional before (UPDATE, DELETE, DDL on FHE tables) run in an implicit transaction in
this mode. ROLLBACK discards the delta. Tables created through the connection start at root 0 / count 0; DROP removes
the entry (so does a re-CREATE). A table that exists but has no anchor entry is refused for authenticated FHE reads
and writes with a message pointing at `adopt_table`.

**Operating it.**
* The anchor is the owner's trust root. **Keep it where the server cannot write**, with the FHE key's care. A single
  file is a single point of failure (lose or roll it back and the mode is void) — use a **`QuorumAnchor`** (next
  bullet) when that matters. `FileAnchor`
  writes a `0600` JSON file (versioned, atomic rename + fsync, advisory `flock` between owner processes) and refuses
  symlinks, files that are not ours, lax permissions, corrupt content and unknown versions. It holds no key and no
  plaintext (roots are PRF sums), but whoever can *roll it back* defeats it.
* `adopt_table(t)` is **trust on first use**: it records whatever the server shows at that moment, lies included.
* Several owner processes may share one anchor file on a local file system (several `FileAnchor` objects, one file);
  if another owner advances the epoch while you hold a snapshot you rescan; a transaction whose base epoch moved is
  rolled back with an explicit error. The `Anchor` interface (`get`, `begin_commit`, `finish_commit`, `abort`, `set`,
  `remove`; CAS on the epoch) is what `QuorumAnchor` implements.
* **`QuorumAnchor` (no single store).** `connect(..., integrity_anchor=QuorumAnchor(nodes, threshold=k))` keeps the
  very same anchor document on `n` custodians (the daemon of `docs/custody.md`, started with `--anchor-store`; the owner's
  token needs the new `anchor` permission, readers `anchor_read` — separate from key-share and mask permissions).
  Each custodian holds one versioned compare-and-swap register per anchor id (RecordLog: append-only, checksummed,
  fsync per write, optional passphrase sealing, survives restarts). **Read:** ask all; the value is the highest version
  that at least `k` custodians report identically — a liar, a lagging or a rolled-back custodian is outvoted while fewer
  than `k` do the same, and lagging copies are repaired (version only moves forward). **Write:** the CAS goes to all and
  counts only if `write_quorum` (default `max(k, n-k+1)`; constraint `n - W < k`) accept; otherwise the owner does
  not commit (fails closed; if the write nevertheless landed, the normal pending-settlement aborts it by scanning).
  Racing owners are serialised by the per-custodian CAS. Pending/finish/abort/settlement are the same code as with
  `FileAnchor`. CLI: `torussql --anchor-custodian HOST:PORT ... --anchor-token-env VAR --anchor-threshold K
  [--anchor-write-quorum W] [--anchor-id NAME]`. **Exact condition:** at least `k` custodians are honest, reachable and
  hold the latest value, and at most `k-1` lie, are rolled back or are compromised. With `k` colluding/rolled-back
  custodians the old or forged state wins (tested as the stated limit); with fewer than `k` reachable the owner gets
  `AnchorQuorumError` and nothing is accepted or committed. Residual: a *partial* write by a crashed owner can briefly
  lower availability (copies at a version that is not vouched for) until the next successful write repairs them; an
  operator who loses more than `n-k` custodians' disks loses the anchor.
* **Periodic re-verification.** `integrity_recheck_seconds=S` (CLI `--integrity-recheck-seconds`, default off) re-scans a
  cached snapshot older than `S` seconds before the next query, so a silent server rollback or tampering of data the
  owner does not read is noticed within `S` seconds (cost: one O(rows) scan per period).
* Replicas and standbys serve the same reads (`fhe_rows` is a read RPC). A replica that lags the anchor is refused
  with the "behind the anchor" error until it catches up.

**Cost (measured, Apple-silicon laptop under load, native back end).** O(rows) once per anchor epoch and per
process: a full scan is ≈ **0.2 s per 10 000 rows** at the owner (leaf PRF + hashing; the server side adds ≈ 20 ms
per 2000-slot call); the verified snapshot costs ≈ **0.6 KB of owner memory per row** (≈ 1.1 KB peak while scanning);
default cap `integrity_anchor_max_rows=1_000_000` (≈ 0.6 GB). A local WHERE over the snapshot is a Python loop
(≈ 13 ms per 10 000 rows). Writes cost one extra hash and PRF per row and the anchor file is rewritten (with fsyncs) once per COMMIT;
measured bulk INSERT of 2000 rows: 8.9 s without vs 9.3 s with the anchor (within noise on a loaded machine; the
native encryption dominates).

**What it still does NOT cover.**
* An **owner who loses the anchor** (or restores an older copy of it) with a `FileAnchor`: the anchor is then itself
  subject to rollback, and without it the table can only be re-adopted on trust. A `QuorumAnchor` removes that single
  point of failure *only under its condition* (≥ k honest, reachable custodians holding the latest value; ≤ k-1 faulty
  or colluding — k colluding custodians, or the anchor store sharing a host with the server, defeat it).
* **Trust on first use** (`adopt_table`) and everything before the anchor existed.
* Only tables with at least one FHE column are anchored, and only their **PLAIN and FHE** columns: `ENC`/`PAIRED`
  columns of the same table keep their own SPDZ MAC/mask-version protection and are not part of the leaf.
* **Delegated `DOT`** (`fhe_dot_mode="delegated"`) is still unverified (the default `local` mode verifies operands).
* **Availability and metadata**: the server can still refuse service, make a connection fail with `IntegrityError` at
  will, and see row counts, access patterns and PLAIN data. Writers that bypass the anchor are detected (the next
  scan fails), not tolerated.
* **Freshness between rescans**: between epoch changes the owner answers from its cached snapshot. A server that
  silently rolls back *data the owner does not read* is noticed on the next fetch of that data, on `verify_table()`,
  when another owner (or a restart) triggers a rescan, or — if you set `integrity_recheck_seconds` — within that period.
* `FileAnchor` is implemented in the Python, TypeScript and Rust drivers (one file format); the replicated
  `QuorumAnchor` is Python only. The O(rows) scan and per-row memory do not suit very large tables.

## Threshold custody of the FHE key (`ThresholdFheKey`)

> **Security notice (fixed in bundle version 3).** Earlier threshold bundles (v2) published
> `X2 = s2*G1`; anyone holding `X2` and a cell recovers the plaintext (`e(G1, D2) / e(X2, D1) = g^v`) with no secret
> at all. Such bundles are now **rejected** ("VULNERABLE - regenerate"); data encrypted under them must be
> re-encrypted under a new key (and treat the old `public2.json` as having compromised those cells). Local
> (non-threshold) keys were never affected.

The FHE secrets can live **only** as k-of-n sharings among custodians (the Laurent-series sharing of
`torussql.custody`, dealerless DKG). No server, custodian or owner process holds `s` or `s2`, and neither
is ever reassembled (the tests run every operation with `laurent.reconstruct` patched to raise). The scheme has
**two independent secrets in two different groups**:

* `s`, custody group `bn254` (G1): `Q = s*G1` is the public key of the G1 half and cell/SUM decryption.
* `s2`, custody group **`bn254g2`** (G2): the DKG itself runs in G2, so its public key **is** `Q2 = s2*G2`. Feldman
  commitments, verification keys `Y_i = y_i*G2`, proofs of knowledge, DLEQ/GT proofs are all G2 objects. **No G1
  image of `s2` (`s2*G1`, `y_i*G1`, a G1 commitment vector) is ever created or published** - not in `public2.json`,
  the bundle, RPC answers or the audit log. `Q2 = s*G2` is forbidden as well (dictionary oracle).

A local `FheKey` derives `s2` from `s`; a threshold key cannot (nobody knows `s`), hence the second DKG on the same
custodian hosts. The *identity* keys of a file ceremony stay in their own group (`secp256k1` or `bn254`); only the
key group differs (`dkg-start/finish --key-group bn254g2`; broadcasts are signed in the identity group but carry
128-byte G2 commitments). The custodian daemon refuses G1-style decryption (`partial`, `partial_batch`) on a G2 key:
`s2` is only ever applied to GT elements.

```bash
# 1. TWO dealerless DKGs (docs/custody.md section 2.1): key 1 -> s (--key-group bn254), key 2 -> s2 (--key-group bn254g2);
#    run the daemons for both (e.g. host1:8601 serves s, host1:8602 serves s2)
#    (or ONE daemon per host holding both shares: `serve --share s.json --share s2.json`, and omit --custodian2)
# 2. one owner-side step: a sealed MAC secret and ONE public bundle (Q2 = key 2's public key); it PRINTS the
#    BUNDLE FINGERPRINT: compare it out of band and pin it wherever the bundle is loaded
python -m torussql.custody fhe-keygen-threshold --public public.json --public2 public2.json --token-env CT \
    --custodian host1:8601 --custodian host2:8601 --custodian host3:8601 \
    --out fhe-bundle.json        # add --custodian2 ... only if s2 is served elsewhere
python -m torussql.custody fhe-open-test ... --bundle fhe-bundle.json --expect-bundle-fingerprint FP
torussql --fhe-threshold fhe-bundle.json --custody-public public.json --custody-public2 public2.json \
         --custodian host1:8601 ... --custodian2 host1:8602 ... --custody-token-env CT --expect-bundle-fingerprint FP -p 8533
```
```python
from torusdb_core.fhe_threshold import ThresholdFheKey
key = ThresholdFheKey.load("fhe-bundle.json", PublicKey.load("public.json"), custodians1,
                           PublicKey.load("public2.json"), custodians2,
                           expect_fingerprint=FP)       # without it the load WARNS
conn = torussql.connect(host, fhe_key=key, authenticated=True)     # the same surface as FheKey
```
Bundle format version 3: `v, kind, key_id, key_id2, range, Q (= X1), Q2 (= key 2's public key), mac`. There is no
`X2`. Versions 1 and 2 are rejected with explicit errors. A key may be loaded without `custodians2` (only the
public keys): it encrypts and reads cells/SUMs, but `DOT` raises "needs the second secret".

**Bundle integrity.** The bundle is public but not harmless to edit: replacing the sealed MAC envelope by one
wrapped to the PUBLIC key with an attacker-chosen secret would let a lying server forge integrity tags. The
**bundle fingerprint** (SHA-256 over `key_id`, `key_id2`, `range`, `Q`, `Q2` and the whole MAC envelope) is printed by
`fhe-keygen-threshold`; pin it with `--expect-bundle-fingerprint` / `expect_fingerprint=` (a mismatch is refused,
loading without a pin warns). The value range is enforced to be in `[1, 2^40]` when a bundle is loaded (the discrete-log
table is O(sqrt(range))).

| owner operation | without `s`, `s2` |
|---|---|
| encrypt | needs only `Q = X1` (key 1's public key) and `Q2` (key 2's public key, a non-identity G2 subgroup point that must not be the G2 image of `Q`). No custodian is contacted. |
| decrypt a cell / `SUM` / `k*SUM` | the existing threshold decryption on key 1: the owner sends `E = C1`, each custodian answers `y_i*E` with a DLEQ proof, the client combines `s*C1 = sum(lambda_i * y_i*E)`. Batched: a `SELECT` of n cells is one round. |
| decrypt `DOT` | `M = c11 * c01^-s2 * c10^-s * c00^(s*s2)` by **threshold exponentiation in GT**: custodian i returns `c^(y_i)` with a Chaum-Pedersen proof, the client combines `c^s = prod(D_i^lambda_i)`. Round 1 (key 1): `c00^s`, `c10^s`. Round 2 (key 2): `c01^s2` and `(c00^s)^s2`. `s*s2` is never computed — the second round's input is `c00^s`. |
| integrity tags | see the MAC trade-off below. |

**Soundness of the GT proof** (`torussql/custody/gt.py`). Statement: `Y_i = y_i*B` (`B = G1` for `s`, `G2` for `s2`) is custodian i's public
verification key and `D = c^(y_i)`. G1 and the order-q subgroup mu_q of GT have the same prime order q, so the
standard Chaum-Pedersen protocol runs across them: `R1 = k*B`, `R2 = c^k`, `h = H(ctx, G1, Y_i, c, D, R1, R2)`,
`z = k + h*y_i`; verify `z*B = R1 + h*Y_i` and `c^z = R2 * D^h`. Special soundness: two accepting transcripts with
the same commitments extract `y = (z-z')/(h-h')` with `Y_i = y*B` and `D^(h-h') = c^((h-h')*y)`; because `c` and `D`
lie in mu_q and `gcd(h-h', q) = 1`, `u -> u^(h-h')` is injective there, so `D = c^y` — the same `y` as the
verification key. **Both `c` and `D` are tested for `u^q = 1`**: without that a hostile server could hand the
owner a GT element carrying a small-order component, and a custodian that exponentiated it would leak `y_i`
modulo small primes, and a lying custodian could add such a factor to `D`. Custodians refuse such elements
(`malformed request`); the owner refuses them before asking. A lying custodian is excluded (and listed in
`quorum.last_problems`); if fewer than k honest answers remain the call fails — it never returns a wrong value.
The challenge also binds the key id, epoch and a per-use context, so a transcript cannot be replayed elsewhere.
Exponentiation by the secret `y_i` is split-scalar blinded like the G1 code, which is *not* constant-time.

**What the custodians learn.** A custodian sees the ciphertext elements it is asked to exponentiate
(`E`, `c`) and, for `DOT`, the intermediate `c00^s` (sent to the s2 custodians) — exactly the information the data owner would
have, no more; it does not see other custodians' shares, plaintexts or results beyond that. Like the vault envelope
this is a **decryption oracle for whoever holds a caller token**: any token holder can have *any* ciphertext opened
(it cannot be tied to "this column"). Inputs are validated (canonical encoding, on-curve / subgroup membership,
identity refused), the `approve(caller, E_hex, ctx)` hook is called for every item with its canonical encoding
(GT elements as `"gt:" + hex`), and the **rate limit is charged per item**, so a batch is not a way around it.
A read of n cells is **one request of n items**: the per-request limit (`--rate`, default 30/min) is unchanged
and a separate COST-WEIGHTED item budget (`--item-budget`, default 30000 units/min per caller and key; a G1 point costs 1, a G2 point 2, a GT element 100 - a GT item is ~100x the CPU) bounds the throughput (about 30000 cells or 300 GT elements = 60 `DOT` decryptions per minute);
`--max-batch` (default 2000) caps one request. Treat tokens as decryption capabilities.

**Integrity tags and the MAC secret (trade-off).** Tags need `alpha` and per-cell `gamma`, which for a plain
`FheKey` are PRFs of `s`. With a threshold key nobody holds `s`, so a **separate random 32-byte MAC secret** is generated
at `fhe-keygen-threshold`, sealed under key 1's threshold envelope (`wrap_key`/`unwrap_key`, authenticated, bound to the key id
and purpose) and stored in the public bundle. It is opened by a quorum **lazily and only when `authenticated=True` is
used**; the owner process then holds it in memory. Consequence: that process (and anyone who compromises it) can
forge tags — i.e. defeat integrity checking against a lying server — but **can not decrypt anything**, because the
MAC secret is unrelated to `s`. Without `authenticated=True` the MAC secret is never opened. The process that ran
`fhe-keygen-threshold` also saw it once. `--no-mac` creates a key with no MAC secret (authenticated mode then fails with a
clear error). Rotating the MAC secret means re-tagging the data.

**Limits.** Every threshold read/decryption needs a live quorum (that is the point); latency is network round trips
plus pure-Python proof checking (a `DOT` decryption takes ~2 s: two sequential GT rounds, one per key). Constant-time multiplication is only a **partial mitigation**: with `mclbn256` the secret-scalar G1/G2 multiplications (`s*C1`, encryption randomness, shares, nonces) use `mulCT`; GT exponentiation (DOT decryption, the custodians' `c^(y_i)`) has no constant-time primitive and keeps exponent-split randomisation, and the pure-Python path is variable-time. A delegated `DOT` (server-side ★_ct) has no integrity protection; an authenticated connection verifies `DOT` locally (`fhe_dot_mode`).
Refresh/reshare of either key's shares keeps `Q`, `Q2` and the bundle valid (key ids are unchanged).
`secp256k1` custody keys cannot be used (the pairing groups are BN254).

## Wire / storage format

A cell is 384 bytes: `C1 ‖ C2` (G1, 64 bytes each, big-endian affine, all-zero = ∞) then
`D1 ‖ D2` (G2, 128 bytes each). RPCs `fhe_sum(table, col, ids)` and
`fhe_dot(ltable, lcol, lids, rtable, rcol, rids)` return base64 blobs (128 bytes / 4×384 bytes).
`fhe_rows(table, start, count)` (anchored mode) returns per-slot dead/live flags, PLAIN values, write nonces and
SHA-256 hashes of cells and tags — see `proto/fhe-wire.md`.
The server validates length and curve membership of every stored cell and rejects plaintext
or binary values in other columns.
