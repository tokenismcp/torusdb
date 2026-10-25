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

## Known residual limits (inherent to the design)

* **Rollback / replay of a complete old version** of a cell or table (value + tag + nonce together) is not
  detectable *without owner-held state*. **FIXED in anchor mode** (`integrity_anchor=`); without it, keep your own
  counters.
* **Row-set integrity** (F3): without an anchor, plain columns and the row-id lists the server returns are not
  authenticated. **FIXED in anchor mode**, for tables with FHE columns, PLAIN and FHE columns only.
* **The anchor itself**: with a `FileAnchor`, loss, rollback or collusion with the server defeats anchor mode. A
  `QuorumAnchor` tolerates up to `k-1` faulty custodians and `n-k` unavailable ones (conditions in `fhe-columns.md`);
  `adopt_table` is trust on first use.
* **Delegated `DOT`** has no integrity check; `local` mode (default when authenticated) verifies operands instead.
* **Not constant time** in pure Python, and GT exponentiation is never constant time (only split-randomised).
* **Security level** ≈ 100 bit (BN254), SXDH assumed. **No independent human review yet.**

## How to re-run the checks

`pytest torussql/tests/test_fhe.py torussql/tests/test_fhe_redteam.py torussql/tests/test_fhe_threshold.py
torussql/tests/test_fhe_table_integrity.py` (with and without `PYTHONPATH=…/mclbn256` for the native back end).
