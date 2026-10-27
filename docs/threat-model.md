# TorusSQL Threat Model

**Version:** 0.5 · **Date:** 2026-10-21 · **Author:** J1729 Labs

---

## 1. System overview

```
┌──────────────── Owner / Client (trusted boundary) ───────────────────┐
│  torussql shell · Python/TS/Rust driver · mask vault · encode / unblind     │
│  LSS custody: vault-key K split (t-of-n) among custodians             │
└───────────────────────────────┬──────────────────────────────────────┘
              blinded scalars only │  Π_lin · Π_mult (one round, Beaver)
┌─────────────────────────────────▼──── Server (untrusted, online) ────┐
│  NO keys · NO masks · schema + one-time-padded blinded store           │
│  AnchorLedger (hash-chained commitments — optional chain backend)      │
└────────────────────────────────────────────────────────────────────────┘
```

The **trust boundary** is the owner process (and its custodians). Everything
outside it — the server, the network, the database file, even a compromised
server process — is adversarial.

---

## 2. Adversary model

### 2.1 Server adversary (primary)

| Property | Guarantee |
|---|---|
| What the server stores | One-time-padded blinded scalars x̃ = x + r (mod n), plaintext column values, schema |
| What the server learns | **Nothing** about encrypted values: I(M; V_S) = 0 (unconditional, Thm 30/31) |
| Adversary assumed to be | **Semi-honest** (follows the protocol, records all traffic) |
| Honest-but-curious breach | Stolen server database = one-time pad. Zero information. |
| Malicious server | Cannot forge results undetected in **authenticated mode** except w.p. 1/n (information-theoretic, no computational assumption). For shared-wire expressions this covers every stored cell, share, opening and the result (w.p. ≤ (depth+1)·checks/n, sketch: review packet §3.3). **Unauthenticated mode is secure against a semi-honest server only**: a lying server can shift results by a chosen amount and, by shifting a denominator's share, learn whether it equals a guess |
| Complexity | Post-quantum safe: the one-time-pad guarantee is unconditional, requires no computational hardness assumption |

The server cannot be an "honest evaluator" because it holds no key. It is
structurally incapable of decryption — `Server` has no key field by
construction (verified in tests).

### 2.2 Network adversary

| Threat | Mitigation |
|---|---|
| Passive eavesdropper | *Encrypted* cells in transit are blinded scalars (one-time pads) — safe even without TLS. **But** PLAIN columns, schema, query shapes, row ids **and API tokens** travel in the clear without TLS. **Use TLS.** |
| Active MITM | **TLS 1.2+ with certificate and hostname verification (default since v0.5)** prevents injection. Without TLS a MITM can substitute blinded scalars (authenticated mode catches it except w.p. 1/n) and can steal tokens. |
| Replay of old blinded data | A replayed *response* is rejected in authenticated mode (stale masks no longer unblind: see audit F-5/`test_replaying_a_stale_cell_after_update_is_detected`). Without authenticated mode staleness is not detected. |

### 2.3 Custodian adversary (key management)

| Threat | Mitigation |
|---|---|
| Single custodian compromise | **LSS t-of-n**: any single stolen share reveals nothing about K |
| t-1 custodians collude | Secret still protected: requires t shares |
| t custodians collude | Full compromise — the vault-key K is reconstructable. Protect by choosing honest custodians. |
| Rollback attack (old share) | **AnchorLedger + verify_current**: superseded pre-refresh anchors rejected |
| Tampered share | **Hiding commitments in Anchor**: each presented share is verified against the public anchor before recovery accepts it |

### 2.3b Unauthorized or abusive client (v0.5)

| Threat | Mitigation |
|---|---|
| Anonymous access | Token authentication with roles `ro` < `rw` < `admin` (`--token-file`); a non-loopback bind **refuses to start** without tokens. Tokens are compared in constant time and stored/accepted as SHA-256 digests. |
| Token brute force | Constant-delay + per-IP lockout after repeated failures. Tokens must be ≥16 characters. |
| Privilege escalation | Every RPC is checked against the session role; `drop`, `stats`, `checkpoint`, `backup` are admin-only. |
| Resource exhaustion | Connection cap, idle timeout, maximum frame size (checked before any payload is buffered), TLS handshake bounded and performed off the accept loop, transaction wait/timeout so one stuck client cannot hold the database. |
| Malformed input / data corruption | Strict request validation (types, row-id ranges, exact column sets on INSERT); internal errors return only an opaque reference — stack traces go to the server log, never the client. |
| A read-only token reads data | It receives only what the server already holds (blinded cells and plaintext columns); it cannot decrypt without the owner's vault. |

### 2.3c Threshold custody (v0.5, optional)

With `vault_custody=ThresholdCustody(...)` the vault key is held by `n` custodians
under a `k`-of-`n` Laurent-series sharing and **used without being reassembled**
(`custody.md`). Adversary model:

| Adversary | Outcome |
|---|---|
| Steals the vault file | Sealed; needs `k` custodians (separate hosts/admins) |
| Compromises < `k` custodians | Learns nothing about the key (perfect secrecy of the sharing); can at most refuse service |
| Malicious custodian | Its partial result carries a DLEQ proof; a wrong one is detected and excluded |
| Network attacker | Tokens + TLS (verified by default); ceremony files are signed/encrypted |
| Compromises ≥ `k` custodians (same epoch) | Key compromised — reseal onto a new key |
| Quantum attacker holding vault file + public key | Can recover the key (ECDLP). Use passphrase/info-theoretic custody if this matters |
| Compromises the owner process while the vault is open | Sees the masks — threshold protects at rest and the authority to open, not an open session |

### 2.3d Threshold masks (optional)

With `mask_cluster`, no single party holds the masks. Server + fewer than `k`
custodians learn nothing beyond the baseline (shares are information-theoretic).
`k` colluding custodians recover masks; an active custodian that lies is detected
when more than `k` answer (fail-closed otherwise). Reading a cell reveals its mask
to the owner process; aggregates reveal only the sum. A malicious DB server can
relabel schema policies — mitigated by the read-only rule for server-learned
tables (`trust_server_schema`). Details and limits: `masks.md`.

### 2.3f Shared-wire expressions (v0.6 expressions, wire protocol 2.1)

Expressions run on secret-shared wires (spec §5.10, review packet §3.3). The server holds one
additive share of every intermediate in a per-session store, so a *breach of the server* yields
shares, stored cells and triple shares that are uniform and independent of every value (including
every intermediate and the result - the result is never sent to the server). Adversary outcomes:

| Adversary | Outcome |
|---|---|
| Passive server / stolen server memory or snapshot | Uniform shares only; I(M; V_S) = 0, unconditional, post-quantum. Wire stores are ephemeral (freed at query end, transaction end, TTL, disconnect). |
| Server that follows the protocol but records everything | Same. It learns the query shape (levels, products per level, rows, request sizes) - F-21 - and, for a zero denominator, nothing (the opened `t` is replaced by a dummy). |
| Malicious server, `authenticated=True` | Any tampering with a stored cell, share, opening or reply is detected (`IntegrityError`) except w.p. ≤ (depth+1)·checks/n. Plain data (`WHERE` results, join keys, row existence) is not authenticated. Denial of service remains possible. |
| Malicious server, **unauthenticated** (default) | Not covered: it can shift any result by an amount of its choice and test a denominator against a guess (the owner's `DivisionByZero` is the oracle). Use `authenticated=True` on any host not trusted to follow the protocol. |
| Client that tries to exhaust server memory with wires | Per-session and server-wide element caps, a wire-count cap, request-size/op caps and a TTL (`--wire-max-elements`, `--wire-max-total-elements`, `--wire-max-wires`, `--wire-ttl`); a violation is a named `WireError`. Wires are private to a session and are read-only (`ro` role may use them). |
| The owner process itself | Holds the masks and, as the Beaver dealer, can derive operands and intermediates from the public openings (F-22). Not a boundary this design defends; the owner is the data owner. |

### 2.3e FHE columns (optional, experimental)

For `FHE` columns the server holds ciphertexts and public parameters only; it can compute
sums and inner products of them (that is the feature) but cannot decrypt, and it cannot test
guessed values (independent halves; SXDH). **Integrity is opt-in and partial:** with
`authenticated=True` cells, `SUM`/`AVG`/`k*SUM` carry row-bound tags and `DOT` is verified by
re-multiplying at the owner (`fhe_dot_mode="local"`, the default there; a *delegated* `DOT` is
unverified); with an `integrity_anchor` the row set and freshness are verified too. Without
`authenticated=True` a lying server can return a wrong ciphertext undetected. Not covered
either way: malleability (any sum/product of stored cells), and the construction itself has had
no independent review. Details: `fhe-columns.md`.

**FHE expressions (v0.6.1, v0.6.2).** Depth-1 products of integer-linear forms (`SUM((a+2*b)*(c-d))`, `SUM(a)*SUM(b)`, public
scale/add/divide afterwards), aggregated OR per row (v0.6.2: `SELECT L*R FROM t`, one ciphertext per row — same operand shapes,
same caps, same wire shape as the aggregate case) are computed by the server from stored cells and the query's integer
literals and opened only by the owner (one GT element per row, for the per-row shape). The server receives no ciphertext, tag,
mask, key or plaintext-derived number (wire audit in the tests) and holds no key; per-row combinations with public
coefficients are functions of data it can already compute, so they add no oracle. It sees the query shape and access pattern.
Integrity: none for a delegated product, aggregated or per row (as `DOT`) — review log round 4 looked specifically for a
sound, owner-cheap integrity check (a second pairing-based tag) and found none, for a structural reason (any bilinear pairing
of affine tags leaves a cross term linear in a plaintext the owner never read); an authenticated connection verifies by
recomputing from verified cells at the owner (`fhe_dot_mode`, default there), unchanged. Nothing is ever decrypted or
re-encrypted between levels because there is only one level; deeper shapes (aggregated or per row) are rejected. Review log
rounds 3–4.

### 2.4 Owner-process adversary

If the owner process is compromised, the mask vault is exposed. Mask vault
security reduces to:
- Process isolation (OS-level)
- Vault-key K custody (threshold LSS)
- Secure passphrase-derived share encryption (PBKDF2-HMAC)

The server database is still safe: a compromised owner cannot retroactively
learn what the server stored before the owner's mask vault existed.

---

## 3. What the server sees (detailed)

For each encrypted column `col` of row `i`, the server stores:

```
x̃[i][col] = x[i][col] + r[i][col]  (mod n)
```

where `n` is the group order of BN254 (~2^254), and `r[i][col]` is a
uniformly random mask known only to the owner. The server sees **only** x̃,
which is uniformly distributed in Z/nZ independent of x. This is the one-time
pad (OTP) property.

For plaintex columns, the server stores the raw value (INT, STR, RATIONAL).
This is by design — plaintext columns can be used in WHERE/ORDER/GROUP BY.

**Access pattern**: the server sees which row indices are queried and which
WHERE predicates select them (for plaintext columns). This is a **metadata
leak** and is out of scope for the current threat model.

**Joins (v0.4+)** are evaluated at the owner on *plaintext* key columns, so the
server additionally learns that the owner fetched the key column of the joined
tables (all rows of the right table, the matching rows of the left) — never an
encrypted value. Aggregates over a join reveal, via the row-id sets sent to
Π_lin, exactly which row combinations were aggregated.

**Expressions (v0.6).** For `a*b*c + s/2`-style queries the server receives the ids of the rows
read (as for any query), the blinded cells it already stores, and per multiplicative level a batch
of openings `(e, g) = (x − u, y − v)` with fresh uniform `u, v` (never reused; tested for
uniformity and for the absence of any mask, encoded plaintext, intermediate, inverse or quotient in
everything it receives: `core/tests/test_crypto_audit.py`, `tests/test_expr_e2e.py`). It also sees
the **shape** of the expression: the number of levels (rounds), the number of products per level
and the number of rows involved. A zero encrypted denominator does not change what the server sees
— the owner finishes the remaining rounds with a dummy value and raises the error afterwards — so
a division by zero is not an oracle for the server. The owner learns every operand it reads
(denominators included); that is the data owner's own data.

**Transactions and the journal** contain the same blinded/plaintext data the
server already stores; they add timing (when rows were written) but no new
plaintext.

**Scope of "I(M;V_S)=0".** The theorem is about the *value* of an encrypted
cell given the server's view of that cell. It is not a claim about metadata
(this section), plaintext columns, or integrity.

---

## 4. What an attacker learns from the ciphertext store

Assume a full breach of the server (read all data, past and present):

- **Encrypted columns**: nothing. The blinded scalars are a one-time pad.
- **Plaintext columns**: full exposure. Design choice — if a column needs
  confidentiality, it must be `ENC` or `PAIRED`.
- **Schema**: the table structure (column names, types, policies). Visible.
- **Row count**: visible (the server stores all rows, including tombstones).
- **Access patterns**: visible (which rowids are queried, in what order).

**Recommendation**: treat plaintext columns as public metadata. Put sensitive
values in `ENC` or `PAIRED` columns.

---

## 5. Side channels

| Channel | Status |
|---|---|
| **Timing** | Not mitigated. Modular arithmetic timing can leak row counts and index access patterns. |
| **Memory access patterns** | Not mitigated. An attacker with local hardware access could measure memory access. |
| **Network traffic volume** | Π_mult is one batched round; traffic volume leaks that multiplication happened and the operand count. |
| **Row count** | Visible from server storage size. |

These are **out of scope** for the v0.3 threat model. Mitigations (ORAM,
constant-time ops, traffic shaping) are a future research item.

---

## 6. Integrity guarantees (authenticated mode)

With `connect(..., authenticated=True)` (or `NoKeyClient(..., authenticated=True)`):

- Each encrypted cell `s` carries a parallel one-time-padded MAC column:
  `m = α·s (mod n)`, where α is secret to the owner.
- Every affine result (SUM, AVG, scaled-SUM, per-row) has its MAC verified
  before decoding. A forged affine result is caught except w.p. 1/n.
- Every encrypted cell read for DOT/× has its MAC verified before the Beaver
  protocol proceeds. A tampered stored ciphertext is caught before it is used.
- The server's product term `e·g` in Π_mult is independently re-checked.
- **No computational assumption**: the security is information-theoretic over
  Z/nZ, not computational.

**Without authenticated mode** (the default): a malicious server can forge any
result undetected (pinned by a test). Authenticated mode is strongly
recommended for any server you do not fully control. Decode additionally
refuses to return a value that overflowed the exact-representation budget
(`OutOfBudget`) in every mode.

---

## 7. Out-of-scope threats

The following are explicitly **not** in scope for this version:

- **Oblivious RAM / access-pattern hiding**: the server sees which rows are
  accessed. This requires ORAM, which is a future research item.
- **Encrypted predicate evaluation**: WHERE/GROUP BY/ORDER BY on encrypted
  columns is impossible without revealing the server's plaintext comparison
  capability. This is a fundamental FHE limitation.
- **An owner that is blind to intermediates / multi-owner expressions**: dialect v0.6 evaluates products
  of any depth (up to `max_mult_depth`, default 8) and division on *secret-shared wires*: the server
  holds its share of every intermediate and never learns a product, quotient or result (unconditional),
  and the owner's code fetches no operand and unmasks nothing. But the owner is the dealer of the Beaver
  triples and of the division mask, so the public openings determine every operand and intermediate for
  an owner that chose to compute them (it is the data owner, so in the single-owner model this reveals
  nothing it does not already hold). It still does O(rows) share arithmetic per level. A deployment with
  several mutually distrusting owners, or one that must keep intermediates from the owner, needs triples
  nobody knows (a third non-colluding dealer, or OT/HE-based generation) - not implemented (review packet
  F-22, F-9). `FHE` columns still have a single multiplicative level (no expressions over them).
- **Traffic analysis**: volume/timing of network exchanges can leak query
  structure.
- **Physical side channels**: power analysis, cache-timing, etc.
- **Social engineering / supply-chain attacks** on custodians.

---

## 8. Security properties summary

| Property | Guarantee | Assumption |
|---|---|---|
| Server confidentiality | I(M; V_S) = 0 | Unconditional (OTP) |
| Post-quantum safety | Yes | OTP requires no computational assumption |
| Result integrity | Forgery caught w.p. 1 - 1/n | Information-theoretic (auth mode) |
| Key custody | t-of-n threshold recovery | LSS threshold + honest custodian majority |
| Anti-rollback | Old anchors rejected | AnchorLedger chain integrity |
| Transport security | TLS 1.2+, certificate verified by default | Standard PKI / CA trust |
| Access control | Token + role per RPC, lockout, quotas | Token secrecy (use TLS) |
| Crash safety | Checksummed snapshot + WAL, torn-write recovery, atomic transactions | Storage honours fsync |
| Owner-vault durability | Append-only checksummed log, optional sealing, 0600 | Passphrase strength, disk not shared |
| Arithmetic soundness | Out-of-budget results raise instead of returning wrong values | — |

---

## 9. Recommendations for production deployments

1. **Use authenticated mode** (`authenticated=True`) to detect a malicious server.
2. **Use TLS** with a CA-verified certificate in production.
3. **Export vault custody** to at least 3 custodians with a 2-of-3 quorum.
4. **Rotate shares** (custody refresh) after any suspected custodian
   compromise.
5. **Mark all sensitive columns as `ENC` or `PAIRED`**. Plaintext columns are
   visible to the server.
6. **Do not store secrets in plaintext columns**, even if they "look random" —
   they are exposed in a breach.
7. **Monitor AnchorLedger** for unexpected epoch transitions.
8. **Run server in an isolated environment** (container, minimal OS) to reduce
   physical side-channel exposure.

---

## 10. Cryptographic review status

**Current**: internal review and internal audit only (J1729 Labs) — findings
F-1…F-12 are listed with status in `crypto-review-packet.md` §11 and are covered
by `core/tests/test_crypto_audit.py`. **No independent external review
has been completed.** Do not describe the system as externally audited.
**Planned**: KISA submission + academic peer review.

The formal proofs (Thm 30/31 for confidentiality; §IX for integrity) are in:
- Lee, *"No-Key Delegation of Elliptic-Curve FHE"*, J1729 Labs (no-key-ecfhe.pdf)
- Shim & Lee, *"Laurent Series Secret Sharing"*, J1729 Labs (LSSS paper)

External reviewers should start from these documents and verify against the
implementations in `core/torusdb_core/protocol.py` and
`drivers/python/torussql/custody/`.
