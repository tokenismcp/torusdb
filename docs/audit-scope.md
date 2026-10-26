# External security review — scope and brief

This document is for an independent reviewer. It states what we want examined, in what
order, what we already know, and how to build and attack the system. **No independent
review has been done yet**; everything below the "internal work" heading is our own.

## 1. What the system claims

1. **Server confidentiality.** The server stores plaintext columns and, for `ENC`/`PAIRED`
   columns, scalars blinded by a uniformly random one-time pad in Z/nZ (n = BN254 order).
   Claim: the server's view of an encrypted cell is independent of its plaintext
   (`I(M; V_S) = 0`, unconditional). The server holds no key, bootstrap key or mask.
2. **Correct delegated computation.** `SUM/AVG/k·col` (affine, `Π_lin`) and `DOT`/`a*b`
   (Beaver triples, `Π_mult`) return exact results inside a stated range
   (|num|,den ≤ 2^126, |num|·den < n/2^64) and raise `OutOfBudget` outside it —
   never a plausible wrong number.
3. **Optional integrity** (`authenticated=True`): SPDZ-style MACs detect a lying server
   except with probability ~1/n per forgery attempt.
4. **Key custody without a holder.** The vault key is generated dealer-free by n
   custodians and used by any k through verifiable partial decryptions; it is never
   reassembled (`torussql.custody`).
5. **Threshold masks.** Optionally the one-time-pad masks themselves are Shamir-/Laurent-
   shared among custodians; aggregates are unblinded from partial sums.
6. **Durability and replication** do not weaken 1–5 (storage and replication traffic carry
   only what the server may already see).

## 2. Priority tiers

| Tier | Component | Path | ~LOC (Python) |
|---|---|---|---|
| 1 | Encoding, `Π_lin`, `Π_mult`, MAC | `core/torusdb_core/protocol.py`, `nokey_engine.py` (client side: `_blind_row`, `_update`, aggregates, MAC checks), `expr_eval.py` (v0.6 multi-level products and division; review packet 3.3) | ~2.8k |
| 1 | Server request handling, auth, limits | `server/nokey_server.py`, `server/durability.py`, `parser/torussql_parser` | ~3.4k |
| 1 | Threshold key custody (DKG, partial decryption, reshare) | `drivers/python/torussql/custody/{group,laurent,shares,dkg,reshare,threshold,proofs,identity,keys}.py` | ~3.1k |
| 2 | Threshold masks, custodian network service | `custody/{masks,net,quorum}.py` | (incl. above) |
| 2 | Vault / record log sealing | `drivers/python/torussql/{vault,recordlog,seal}.py` | ~1.2k |
| 2 | Storage engine and replication | `core/torusdb_core/store.py`, `server/replication.py` | ~1.2k |
| 3 | TypeScript and Rust drivers | `drivers/typescript/src`, `drivers/rust/src` | ~4.6k |

Specific questions we want answered are in `crypto-review-packet.md` §10 (rational
reconstruction bound, subset secrecy of the Laurent sharing, MAC soundness under
aggregate-level attacks) and below.

## 3. Adversary models (see `threat-model.md`)

* **Honest-but-curious or fully malicious server** (reads/changes anything it stores, sees
  all traffic after TLS, may lie about results, may relabel schema, may replay old
  state). It is *assumed* to see PLAIN columns, schema, row counts, access patterns, and
  join keys; those leaks are in scope for *documentation accuracy*, not as defects.
* **Network attacker** (without TLS).
* **Up to k−1 colluding or compromised custodians**, and active ones that lie.
* **Abusive but authenticated client** (role `ro`/`rw`) trying to exceed its role, DoS the
  server, or extract more than its role allows from a custodian.
* **Compromised owner process** is out of scope for confidentiality of what it can read,
  but in scope for "compromise reveals no more than what the process could read".

## 4. Out of scope

Side channels beyond those listed in `threat-model.md` §5, post-quantum security (the
custody layer is ECDLP-based), the proprietary legacy engine (not in this repository),
denial of service by an attacker who controls the network path.

## 5. Build and attack it

```bash
git clone <repo> && cd torussql
python -m venv .venv && . .venv/bin/activate          # Python >= 3.11
pip install pytest "py_ecc>=6,<9" -e parser -e core -e drivers/python -e server
pytest                                                # ~900 tests, ~4–6 min
torusdb-server --port 8533 --insecure-no-auth &        # loopback; see docs/ops-guide.md
torussql -c "CREATE TABLE t (id INT PLAIN, v INT ENC)" -c "INSERT INTO t (id, v) VALUES (1, 42)"
```

Useful harnesses: `core/tests/test_crypto_audit.py` (records everything the server ever
receives and asserts it is uniform / mask-free), `fuzz/` (parser and wire fuzzing),
`spec/conformance/` (validator-vs-engine parity), `bench/`. The TypeScript driver
(`npm ci && npm test`) and Rust driver (`cargo test`) run against the Python server.

## 6. Internal work already done

* Internal line-by-line review (`crypto-review-packet.md` §11, findings F-1…F-17).
* Five independent AI-assisted audits of server/durability, SQL layer, custody, drivers and
  documentation claims, plus differential fuzzing against SQLite (≈228 k queries) and
  validator/planner fuzzing (≈240 k); every confirmed finding was fixed with a regression
  test or documented. These are **not** a substitute for your review.

## 7. Known open items (we know; please still confirm severity)

*FHE columns have a detailed internal review log with fixed and residual findings: `fhe-review-log.md`. Please start there.*


* `Π_mult` for `DOT` / `a * b` offers no server offload and needs owner-held plaintext operands (F-3). Expressions use secret-shared wires, but the owner is the triple dealer and can derive operands (F-22); the shared-wire proofs are sketches (F-25); unauthenticated mode is semi-honest only (F-23).
* Integrity is opt-in and does not cover the *set* of rows (a server can omit/duplicate
  rows of a MAC-authenticated table consistently with the row-id list it returns) (F-4).
* Beaver triples come from the single owner; multi-owner needs MPC preprocessing (F-9).
* Vault sealing is an HMAC-SHA256 stream + encrypt-then-MAC, not a standard AEAD (F-10).
* Pure-Python big-int arithmetic is not constant time; scalar splitting only decorrelates.
* Active-server oracle: a server that chooses which rows/ids to open can learn a bounded
  amount via adaptive queries when the client reveals individual cells.
* DKG is Feldman-style (biasable public key, abort on any fault) (F-14/F-15).
* Replication is asynchronous unless `--sync-replicas` is used; no automatic fail-over.
* The hosted artefacts have never been published; reproducible builds are not yet set up.

## 8. What we would like back

A written report with severity-ranked findings, a clear statement of which claims in §1
you tried to break and how, test vectors or PoCs for each finding, and your opinion on
whether the `OutOfBudget` range and the MAC soundness bound are tight. We will publish
the report (redacting only unfixed critical details) and credit the reviewer. Report
privately first: see `SECURITY.md`.
