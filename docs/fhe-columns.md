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

`s` secret; public `Q = sP`, `Q2 = sG2`. Encrypting `v`: G1 half `(r₁P, vP + r₁Q)` and G2
half `(r₂G2, vG2 + r₂Q2)` with **independent** `r₁, r₂`. SUM adds the G1 halves; DOT pairs the
G2 half of one cell with the G1 half of the other and multiplies the four pairings over all
rows (Miller loops are multiplied before one final exponentiation). The owner recovers
`Σv` or `Σab` with a baby-step/giant-step discrete log bounded by the key's range.

*Why independent randomness:* a layout that shares `r` between the halves lets anyone with the
public key test whether a cell encrypts a guessed value (`e(C₂ − vP, G2) = e(Q, D₁)`), i.e. a
dictionary attack by the server. We reproduced that test against a shared-randomness paired
ciphertext and verified it finds nothing here (`tests/test_fhe.py`).

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
* **Key custody:** the key is a file (sealed with a passphrase). Threshold custody of the FHE
  key is not wired up yet. Losing the key loses the data.
* **Cryptographic review:** this construction is new in this codebase and has had no
  independent review. Treat it as experimental.
* Only the Python driver supports FHE columns so far.

## Wire / storage format

A cell is 384 bytes: `C1 ‖ C2` (G1, 64 bytes each, big-endian affine, all-zero = ∞) then
`D1 ‖ D2` (G2, 128 bytes each). RPCs `fhe_sum(table, col, ids)` and
`fhe_dot(ltable, lcol, lids, rtable, rcol, rids)` return base64 blobs (128 bytes / 4×384 bytes).
The server validates length and curve membership of every stored cell and rejects plaintext
or binary values in other columns.
