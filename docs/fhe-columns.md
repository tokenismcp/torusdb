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
from torusdb_core import fhe
key = fhe.load_key("fhe.key", passphrase)
conn = torussql.connect(host, fhe_key=key, authenticated=True)   # authenticated: integrity tags
```

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
| integrity vs a lying server | optional SPDZ MACs | optional tags for cells / `SUM` / `k*SUM` (see below); **none for `DOT`** |

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

* **Integrity is partial** (`authenticated=True`). Each FHE cell gets a second ciphertext, a
  *tag* `Enc(α·v + γ(table, column, row id))` where `α` and the per-cell tweak `γ` are PRF
  outputs of the owner's secret. For any set of rows the owner checks, in the exponent and
  without a discrete log, `tag-sum = α·value-sum + k·Σγ`. This catches a changed value, a
  dropped, duplicated or swapped row, a result scaled by the server, and cells written without
  tags (soundness ≈ 1/n per attempt). **Not covered:** replay of an older version of the same
  cell, and **`DOT`** — a ciphertext product cannot be tag-checked, so an authenticated
  connection refuses `DOT` unless you pass `fhe_allow_unverified_dot=True`. Without
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
The server validates length and curve membership of every stored cell and rejects plaintext
or binary values in other columns.
