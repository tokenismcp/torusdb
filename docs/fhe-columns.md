# FHE columns — the server computes on ciphertexts, with no key

`ENC`/`PAIRED` columns use the *no-key delegation* protocol: the server stores one-time
pads and the owner finishes every computation. **`FHE` columns** are the other, complementary
mode: the server itself adds and multiplies **ciphertexts** using public data only. It never
holds a secret key, a bootstrap key or any mask; only the owner's `FheKey` can decrypt.

```sql
CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, rate INT FHE, hours INT FHE);
INSERT INTO emp (id, dept, rate, hours) VALUES (1, 5, 40, 160);
SELECT SUM(rate), AVG(rate), COUNT(*) FROM emp WHERE dept = 5;   -- server adds ciphertexts
SELECT DOT(rate, hours) FROM emp;                                -- server multiplies + sums: Σ rateᵢ·hoursᵢ
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
conn = torussql.connect(host, fhe_key=key)
```

## What you get compared with `ENC` / `PAIRED`

| | `ENC`/`PAIRED` (no-key delegation) | `FHE` |
|---|---|---|
| server learns about a cell | nothing (one-time pad, information-theoretic) | nothing computationally (SXDH on BN254, ≈100-bit) |
| owner state | **mask vault** per cell (or a mask cluster) | **only the key**; no per-cell state, any number of clients with the key read/write |
| `SUM` / `AVG` | owner sums masks | server adds ciphertexts, owner decrypts one point |
| `DOT` / `a*b` | owner needs the plaintext operands (O(n) at the owner) | **server** multiplies ciphertexts with pairings; owner decrypts one value |
| UPDATE/DELETE/crash/orphans | mask-first ordering, gc, repair | nothing to repair |
| speed | fast | `SUM` fast; `DOT` ≈ 0.2 s per row in pure Python; encrypt ≈ 35 ms per cell |
| result range | ≈ ±2^126 exact rationals | integers only, results within the key's range (default ±10^6) |
| integrity vs a lying server | optional SPDZ MACs | **none yet** |

## Scheme (BGN-style, BN254 pairing groups; implemented in `torusdb_core/fhe.py`)

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

* **No integrity.** A malicious server can return a wrong ciphertext; the owner decrypts a
  wrong number (or fails with *out of range*). Use `ENC` + `authenticated=True` when you need
  to detect that. FHE MACs are future work.
* **Malleability.** The server can compute any sum/product of your ciphertexts — that is the
  feature. It also means access control of who may *ask* the server matters.
* **What the server still sees:** plaintext columns, the schema, row counts, which rows each
  query touches, and the fact that two cells are equal *only* if you tell it (it cannot test).
* **No WHERE/ORDER/GROUP BY/MIN/MAX/JOIN on FHE columns; no `k*col`, `a*b` per row, rational
  values.** Rejected loudly by the validator and the planner.
* **Range:** every plaintext and every result must lie in `[-range, range]`; larger sums raise
  an error rather than wrap. Decryption keeps a table of ≈ √(2·range) entries (range 10^9 ≈
  45 k entries, a few seconds the first time per process).
* **Performance:** pure-Python pairings. A `DOT` over 1 000 rows takes minutes of server CPU
  (outside the database lock, in chunks of 100 rows per request). A native pairing library is
  the obvious next step; the ciphertext format is backend-independent.
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
