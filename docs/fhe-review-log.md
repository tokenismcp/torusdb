# FHE columns — review log

Findings of reviews done **inside this project** (AI-assisted red team; reproduced with scripts).
This is **not** an independent human audit — see `audit-scope.md` for the brief to commission one.

## Round 1 — red-team of the first implementation (all items reproduced, then fixed)

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | **Critical** (threshold mode only) | The second key's public point `X2 = s2·G1` was published; anyone holding it recovers every plaintext with `e(G1, D2)/e(X2, D1) = g^v`. | **Fixed**: key 2 runs in G2 (`bn254g2` custody group); no G1 image of `s2` exists. v2 bundles are refused ("VULNERABLE"). Cells encrypted under a v2 threshold key must be treated as public and re-encrypted. Regression: PoC kept as a test with a positive control. |
| F2 | High | γ depended only on (table, column, row id): the server could mix an old and a new version of a row, `λ·old + (1−λ)·new`, and have any integer accepted. | **Fixed**: γ includes a per-write random nonce stored next to the cell. Pure replay of a complete old version (value, tag, nonce) is undetected without an anchor — **FIXED in anchor mode** (see F3 and below). |
| F3 | Medium | The set of row ids comes from the server (WHERE on plain columns has no integrity), so a lying server can add/drop rows by lying about the predicate; COUNT/AVG inherit it. | **FIXED in anchor mode** (`integrity_anchor=`, see `fhe-columns.md`): the owner verifies the table's row set against an owner-held root and evaluates WHERE/COUNT/AVG/DELETE/UPDATE targets itself. Conditions: `authenticated=True` + FHE key + anchor; the table was created through the anchored connection or adopted (trust on first use); anchor store not rolled back and not colluding with the server; only PLAIN and FHE columns are covered. **Without an anchor still open** (documented; aggregate over ids you enumerated yourself). Tests: `tests/test_fhe_table_integrity.py` (PoC 5 as regression, with a negative control without anchor). |
| F4 | Medium | The threshold bundle had no integrity (MAC envelope swap); `range` unbounded (DoS). | **Fixed**: bundle fingerprint (pin it with `--expect-bundle-fingerprint`; loading without a pin warns), range capped to [1, 2^40] everywhere. |
| F5 | Medium | DoS levers for token holders: global lock held while validating cells; client-chosen slow pairing back end; duplicate ids; GT items cost 100× a G1 item at the custodian. | **Fixed**: validation runs before the lock, the server picks the pairing back end, ids must be distinct, custodian budgets are cost-weighted (G1=1, G2=2, GT=100). |
| F6 | Low–Medium | `decrypt_dot` checked `c00` and the *product* `c01·c10` for subgroup membership; small-order elements could leak bits of `s − s2` (native back end's GT pow is not a real exponentiation outside the subgroup). | **Fixed**: each of `c00, c01, c10` is checked individually with an exact Fp12 test. |
| F7 | Low | Discrete-log search time was linear in the plaintext (timing leak). | **Fixed**: the walk starts at a random index and wraps. |
| F8 | Low | Pure-Python server did not prove G2 subgroup membership. | **Fixed** at write time (≈0.1 s per cell in pure Python; native: ≈1 ms). |
| F9 | Low | Lazy native-backend initialisation was not thread-safe. | **Fixed** (lock). |
| F10 | Info | `hello` lists back ends; internal exception text in some errors; key-file range unchecked; scrypt interactive-grade. | Range check **fixed**; the rest documented. |

## Round 2 — anchored table state (F3 and replay)

Both remaining server lies need owner-held state to detect, so the fix is a small owner-trusted anchor per table
(`{epoch, root, count, pending}`; `root = Σ PRF-keyed row leaves`; design and soundness argument in
`fhe-columns.md`). Review notes from building and testing it (all covered by tests):

* A reader that finds another owner's `pending` commit and sees the OLD state must not abort it when the commit is
  merely on its way (it would corrupt the anchor); only `tx_status == unknown` proves it dead. A reader that sees the
  NEW state finishes it, and the committer's own `finish` accepts that.
* A scan that reports the previous epoch's state is classified as "server is behind the anchor" (replica lag or
  rollback) from the last 8 roots the anchor keeps; it is still an `IntegrityError`.
* The `fhe_sum` result cannot be hash-checked cell by cell; it is bound to the current version through the anchored
  nonces in the tag check (an old version has an old nonce).
* A server that refuses (out-of-range ids, missing cells) rows the verified snapshot contains is reported as an
  integrity failure, not a user error.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F11 | Info | `ENC`/`PAIRED` columns, delegated `DOT`, metadata and availability are outside the anchor. | Documented. |
| F12 | Info | The anchor is itself a rollback target; `adopt_table` is trust-on-first-use; an anchor store that colludes with the server defeats the mode. | **Single-store case FIXED by `QuorumAnchor`** (k-of-n custodian-replicated, highest version with k identical answers, read-repair, CAS writes needing W acks). Condition: ≥ k honest, reachable custodians holding the latest value and ≤ k-1 faulty/rolled-back/colluding; k colluding custodians (or anchor store on the server's host) still defeat it. `adopt_table` stays trust on first use. Tests: `tests/test_fhe_quorum_anchor.py`. |
| F13 | Info | A cached snapshot could keep answering while the server silently rolled back data the owner never reads. | Mitigated by the optional `integrity_recheck_seconds` (bounded by the period; default off). |

## Round 3 — products of integer-linear forms (v0.6.1; self-review, not independent)

Added: server-side `fhe_mul` (depth-1 products of public integer combinations of cells, aggregated), see
`fhe-columns.md` "Expressions over FHE columns". The design question was how far products can go *without* a key at the server and
*without* the owner decrypting-and-re-encrypting an intermediate (rejected on principle). Answer: exactly one pairing level, with
operands that are integer-linear in cells; nothing deeper. Findings and review questions from building it (tests in
`tests/test_fhe_expr.py` unless noted):

| ID | Severity | Finding / question | Status |
|---|---|---|---|
| F14 | Info | Does a per-row integer combination with PUBLIC coefficients create a value oracle? A combination is a function of public data the server could already compute (pair any G2 half with any G1 half); the value-oracle pairing identities between a *combined* operand and the public keys `Q`, `Q2` are tested, with the weak-`Q2 = s·G2` positive control. | Tested; no new public key-dependent value exists. |
| F15 | Info | Constants inside an operand (`(a+1)*b`) are added as a trivial ciphertext (`c·G1` on `C2`, `c·G2` on `D2`, randomness 0). | Sound: the randomised part (`C1`/`D1`, `Σk·r`) is unchanged; a cancelled combination (`a-a`) is the public constant, built from nothing. |
| F16 | Info | Randomness independence (`r1 != r2`) after combining: halves are combined separately, so `Σk·r1` and `Σk·r2` stay independent; the same-cell product `a*a` pairs `D` and `C` of one cell (independent randomness). | Tested (`test_randomness_of_the_two_halves...`). |
| F17 | Medium (owner side) | A hostile server could send a GT blob made of small-order elements. | Unchanged: `decrypt_dot` checks `c00, c01, c10` individually; chunk blobs are multiplied with `mul_dots` and the PRODUCT is checked before any exponentiation. |
| F18 | Medium | Ranges: a result outside `[-range, range]` must raise, never wrap. Operand coefficients, constants (`<= 2^40`), width (16) and expression size bound every true product below `2^232`, far under `n/2`. A hostile writer could store a cell outside the key range; unauthenticated delegated mode cannot detect that (no integrity at all there); authenticated mode opens each cell with a range-checked dlog. | Both modes raise on an out-of-range term (tested, boundary included); `5*SUM(a*b)` may leave the range after decryption by design. |
| F19 | Medium | Integrity of a product. Tags are linear in the value; `Σ TagL_i ★ R_i = α·ΣL_iR_i + Σγ_iR_i` needs `Σγ_iR_i`, which the owner can form only from the plaintexts `R_i` (or by revealing `γ_i` to the server, which destroys the tag). A probabilistic check of the pairing result without the operands does not exist in this scheme. | **Not solved; mitigated honestly**: authenticated `auto` = `local` (verified operands, owner multiplies); delegated + authenticated only by explicit opt-in. No silent weakening. |
| F20 | Low | DoS: a product multiplies the per-row curve work by the number of terms. | Server caps rows, row×terms (`fhe_max_mul_work`), terms (16), operand rows for aggregates (`fhe_max_mul_agg_rows_native`); published in `hello.limits.fhe`. `AL*AR` over `m` chunks costs `m²` requests. |
| F21 | Info | The owner uploads nothing: no ciphertext, no tag, no scalar derived from data. The wire audit enumerates every string/integer the server receives and is validated against sabotaged traffic and a sabotaged client. | Tested (`test_wire_audit...`, `test_the_audit_has_teeth`, `test_a_sabotaged_owner...`). |
| F22 | Info | `AVG` introduces `1/n`: `n` is public (the server knows the row count), applied at the owner after decryption. | By design. |

Open review questions for an external reviewer: (Q1) is there any distinguisher between `Enc(L)` built from `m` stored cells with
public coefficients and a fresh encryption of `L`, other than via the individual cells (multi-challenge SXDH with linear
relations among challenges)? (Q2) Does the dependence `s2 = H(s)` matter once the adversary can pair arbitrary half-pairs? (Q3) Is the
statement "the GT result reveals only the owner-opened value" tight when many products over overlapping rows are decrypted by the
same owner and the application leaks the plaintexts to a party who also controls the server? (Q4) Is there a sound way to verify a
GT result with `O(1)` owner work (e.g. a second GT tag with an owner-computable correction)? We found none.

## Known residual limits (inherent to the design)

* **Rollback / replay of a complete old version** of a cell or table (value + tag + nonce together) is not
  detectable *without owner-held state*. **FIXED in anchor mode** (`integrity_anchor=`); without it, keep your own
  counters.
* **Row-set integrity** (F3): without an anchor, plain columns and the row-id lists the server returns are not
  authenticated. **FIXED in anchor mode**, for tables with FHE columns, PLAIN and FHE columns only.
* **The anchor itself**: with a `FileAnchor`, loss, rollback or collusion with the server defeats anchor mode. A
  `QuorumAnchor` tolerates up to `k-1` faulty custodians and `n-k` unavailable ones (conditions in `fhe-columns.md`);
  `adopt_table` is trust on first use.
* **Delegated `DOT` and delegated FHE expressions** (`SUM(a*b)`, `SUM(a)*SUM(b)`, ...) have no integrity check; `local` mode (default when authenticated) verifies operands instead.
* **Not constant time** in pure Python, and GT exponentiation is never constant time (only split-randomised).
* **Security level** ≈ 100 bit (BN254), SXDH assumed. **No independent human review yet.**

## How to re-run the checks

`pytest torussql/tests/test_fhe.py torussql/tests/test_fhe_redteam.py torussql/tests/test_fhe_threshold.py
torussql/tests/test_fhe_table_integrity.py torussql/tests/test_fhe_expr.py torussql/parser/tests/test_fhe_expr_analysis.py` (with and without `PYTHONPATH=…/mclbn256` for the native back end).
