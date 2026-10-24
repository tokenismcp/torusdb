# FHE columns — review log

Findings of reviews done **inside this project** (AI-assisted red team; reproduced with scripts).
This is **not** an independent human audit — see `audit-scope.md` for the brief to commission one.

## Round 1 — red-team of the first implementation (all items reproduced, then fixed)

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | **Critical** (threshold mode only) | The second key's public point `X2 = s2·G1` was published; anyone holding it recovers every plaintext with `e(G1, D2)/e(X2, D1) = g^v`. | **Fixed**: key 2 runs in G2 (`bn254g2` custody group); no G1 image of `s2` exists. v2 bundles are refused ("VULNERABLE"). Cells encrypted under a v2 threshold key must be treated as public and re-encrypted. Regression: PoC kept as a test with a positive control. |
| F2 | High | γ depended only on (table, column, row id): the server could mix an old and a new version of a row, `λ·old + (1−λ)·new`, and have any integer accepted. | **Fixed**: γ includes a per-write random nonce stored next to the cell. Pure replay of a complete old version (value, tag, nonce) is still undetected — see below. |
| F3 | Medium | The set of row ids comes from the server (WHERE on plain columns has no integrity), so a lying server can add/drop rows by lying about the predicate; COUNT/AVG inherit it. | **Documented, not fixable in this design**: plain columns are not authenticated. Mitigation: aggregate over ids you enumerated yourself (primary-key list). |
| F4 | Medium | The threshold bundle had no integrity (MAC envelope swap); `range` unbounded (DoS). | **Fixed**: bundle fingerprint (pin it with `--expect-bundle-fingerprint`; loading without a pin warns), range capped to [1, 2^40] everywhere. |
| F5 | Medium | DoS levers for token holders: global lock held while validating cells; client-chosen slow pairing back end; duplicate ids; GT items cost 100× a G1 item at the custodian. | **Fixed**: validation runs before the lock, the server picks the pairing back end, ids must be distinct, custodian budgets are cost-weighted (G1=1, G2=2, GT=100). |
| F6 | Low–Medium | `decrypt_dot` checked `c00` and the *product* `c01·c10` for subgroup membership; small-order elements could leak bits of `s − s2` (native back end's GT pow is not a real exponentiation outside the subgroup). | **Fixed**: each of `c00, c01, c10` is checked individually with an exact Fp12 test. |
| F7 | Low | Discrete-log search time was linear in the plaintext (timing leak). | **Fixed**: the walk starts at a random index and wraps. |
| F8 | Low | Pure-Python server did not prove G2 subgroup membership. | **Fixed** at write time (≈0.1 s per cell in pure Python; native: ≈1 ms). |
| F9 | Low | Lazy native-backend initialisation was not thread-safe. | **Fixed** (lock). |
| F10 | Info | `hello` lists back ends; internal exception text in some errors; key-file range unchecked; scrypt interactive-grade. | Range check **fixed**; the rest documented. |

## Known residual limits (inherent to the design)

* **Rollback / replay of a complete old version** of a cell (value + tag + nonce together) is not detectable
  without owner-held state. Keep owner-side counters if you need freshness.
* **Row-set integrity** (F3): plain columns and the row-id lists the server returns are not authenticated.
* **Delegated `DOT`** has no integrity check; `local` mode (default when authenticated) verifies operands instead.
* **Not constant time** in pure Python, and GT exponentiation is never constant time (only split-randomised).
* **Security level** ≈ 100 bit (BN254), SXDH assumed. **No independent human review yet.**

## How to re-run the checks

`pytest torussql/tests/test_fhe.py torussql/tests/test_fhe_redteam.py torussql/tests/test_fhe_threshold.py` (with and
without `PYTHONPATH=…/mclbn256` for the native back end).
