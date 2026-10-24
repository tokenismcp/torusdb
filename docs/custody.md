# Threshold Key Custody (z-MPC style)

**Version:** 0.5 · package `torussql.custody` · tests `tests/test_custody*.py`

The owner's mask vault is the one secret that can read the data. This module
generates its **protection key without a dealer** and lets it be **used without
ever being reassembled**, by any `k` of `n` custodians.

> **Threshold *storage* vs threshold *use*.** The older closed-engine `keymgmt`
> custody splits a key and *reconstructs it* on one machine at recovery time —
> that machine briefly holds the whole key. Here the key `x` is never
> assembled, not at generation, not at use, not at refresh. Each custodian
> answers one verifiable message; the opener combines the answers.

## 1. How it works

```
 custodian 1 ─ D₁ = y₁·E, π₁ ─┐
 custodian 2 ─ D₂ = y₂·E, π₂ ─┼─►  opener (any participant):  verify each πᵢ,
 custodian 3 ─ D₃ = y₃·E, π₃ ─┘     S = Σ λᵢ·Dᵢ = x·E   →   K = KDF(S ‖ E ‖ X ‖ ctx)
        (k of n suffice; the key x appears nowhere)               │
                                                                  ▼
                              seals / opens the owner's mask-vault log
```

* **Wrap (anyone, no quorum):** pick `e`, `E = e·G`, `K = KDF(e·X ‖ E ‖ X ‖ ctx)`.
  Writing or rotating a vault key needs only the *public* key `X`.
* **Open (quorum):** `K` needs `x·E`. Custodian `i` returns `Dᵢ = yᵢ·E` with a
  Chaum–Pedersen proof that it used the same `yᵢ` as its public verification key
  `Yᵢ = yᵢ·G`. A wrong or malicious answer fails its proof and is **excluded**
  instead of silently corrupting the key.
* **Aggregator-free, one round:** every custodian is asked once, in parallel;
  whoever is opening the vault combines. There is no coordinator service.
* **Sharing = Laurent series.** `f(z) = a₀ + b₁z⁻¹ + … + b_t z⁻ᵗ` over `F_q`
  (`q` = group order), `t = k−1`; the secret is the **residue** `b₁`, a
  custodian at point `xᵢ` holds `yᵢ = f(xᵢ)`, and reconstruction from any quorum
  `S` is the fixed linear functional `b₁ = Σ λᵢ yᵢ` with
  `λᵢ = −xᵢ^{k−1}·(Σ_{j≠i} xⱼ) / Π_{j≠i}(xᵢ − xⱼ)`. That linearity is what makes
  *using* the key under threshold possible.
* **Dealerless DKG.** Every custodian deals a sharing of its own random residue
  with Feldman commitments and a Schnorr proof of knowledge; the key is the sum of
  the residues, so nobody knows it. Verification weights tie each share to the
  commitments: `y·G = Σₘ xⱼ⁻ᵐ·Cₘ`.
* **Proactive refresh / membership change (reshare).** A quorum re-shares its
  Lagrange-weighted shares `λᵢ·yᵢ` to a new committee (any new `k′, n′`); receivers
  check the dealer re-shared its *true* share (`C′ᵢ₁ = λᵢ·Yᵢ`, public) and that the
  public key `X` is unchanged. Use it on a schedule, to replace a lost or
  compromised custodian, or to change the quorum.

### Relation to z-MPC

| z-MPC feature | Here |
|---|---|
| Laurent-series secret sharing, secret as residue | **Yes** — same structure as the older closed-engine LSS, with linear reconstruction coefficients |
| Aggregator-free, one-round | **Yes** — one message per custodian to use the key; DKG and reshare are one broadcast round |
| Zero-knowledge proofs | **Yes** — Schnorr proof of knowledge (DKG, signatures), Chaum–Pedersen DLEQ (every partial result) |
| Multiple curves | secp256k1 (default), BN254 G1. *Not* P-256 / Ed25519 yet |
| Pedersen commitments (hiding) | **No** — Feldman commitments (computationally hiding). `X` is public anyway; see §4 |
| "O(t)" reconstruction | Not claimed: coefficients cost O(k²) field operations, irrelevant for k ≤ 32 |

This is an **independent implementation of the mathematics** (the repository's
own Laurent LSS), not a port of z-MPC code. The z-MPC reference implementation is
published under **AGPL-3.0 with a separate commercial licence**; none of its code
is used here, so this module stays Apache-2.0. If you decide to depend on their
code or CLI, review their licence first.

## 2. Operating it

Custodian hosts need only `torussql` and `py_ecc` — **not** the TorusDB engine.

### 2.1 Key ceremony (production: one participant per host)

```bash
export PW='…'    # passphrase for local identity/share files; never on the command line
python -m torussql.custody identity-new --index 1 --out id1.json --passphrase-env PW   # each host
python -m torussql.custody ids-merge id1.pub.json id2.pub.json id3.pub.json --out ids.json
#   ▲ everyone compares the printed fingerprints OUT OF BAND — this is the trust root
S=$(python -m torussql.custody new-session)            # one host; share the value with all
python -m torussql.custody dkg-start  --identity id1.json --ids ids.json --k 2 --n 3 --session $S --out box --passphrase-env PW
#   send box/broadcast_1.json to everyone, box/share_1_to_J.json to participant J only
#   (private shares are already encrypted to J; broadcasts are signed)
python -m torussql.custody dkg-finish --identity id1.json --ids ids.json --k 2 --n 3 --session $S \
        --inbox box --out share1.json --public-out public.json --passphrase-env PW
#   everyone compares the printed transcript hash and public key; keep public.json
```

Every broadcast is signed together with the ceremony specification (group, k, n,
digest of `ids.json`; for a reshare also old key_id/epoch/public-key digest, dealing
quorum and new k/n), the signer and expected sender index; the transcript hash
covers the same specification. Every private share file is encrypted to its
recipient **and signed by its dealer** (session, i, j, ciphertext): a substituted
or forged file is rejected as such, without blaming the honest dealer. (Reshare does
not bind the *new* committee's identity list into the signed specification; new
holders are bound only by the shares being encrypted to their keys.) File formats
are versioned (`TORUSSHARE2`, `TORUSID2`, `torussql-share/2`); v1 files are refused.
Identity, share and vault files are sealed under separate passphrase-derivation
labels with the header as authenticated data, so one file type cannot be accepted
as another. Each participant has ONE identity key used for both signing and
share-decryption DH — an accepted, domain-separated design (distinct signature
context prefixes and a labelled KDF), not split into two keys.

The ceremony **aborts and names the culprit** on a bad share, bad commitment, a
missing/forged proof, a bad signature or swapped files, and must then be restarted
without them. *Dev/test only:* `keygen-local` runs the whole ceremony in one
process (it prints a warning — that process sees every share).

### 2.2 Running a custodian

```bash
python -m torussql.custody serve --share share1.json --listen 0.0.0.0:8601 \
    --token-file tokens --tls --cert c.crt --key c.key --audit /var/log/custodian.audit --passphrase-env PW
```

`tokens` holds `caller:token` lines (≥16 chars, at least 8 distinct characters and
~64 bits of estimated entropy — a sanity check only; generate tokens with
`secrets.token_urlsafe(32)`). The daemon refuses a non-loopback listen without
`--tls`, rate-limits each caller (default 30/min; malformed requests count against
the limit *before* anything is written to the audit log), refuses malformed or
off-curve points, and appends a JSON audit line for every authenticated decision
(caller, key epoch, a hash of the canonical request — never a share).
**Failed and unauthenticated attempts are audited too** (failed auth, lockout,
unauthenticated requests, malformed pre-auth frames), but rate-limited per source IP
and globally, with a one-line "suppressed N events" summary, so a flood cannot fill
the log; the file is created `0600` (`O_NOFOLLOW`) and rotated once at 64 MiB. Auth
failures lock out the source *IP* (not the connection) for 30 s after 5 failures.
Connections are capped globally and per IP, pre-authentication reads have a hard
10 s total deadline and a 16-frame budget, idle authenticated connections are
dropped after 30 s. `hello`/`ping` are unauthenticated and disclose key_id, epoch,
index, k, n (public metadata). `SIGHUP` reloads a refreshed share; the daemon only
accepts a share of the **same key and same custodian index with a strictly newer
epoch** (a replaced or rolled-back file is refused).

`approve(caller, E, context)` is an optional in-code hook, called for every
key-service request with the *canonical* hex of `E` (the request is parsed to a
group element and re-encoded first, so case/whitespace tricks cannot bypass a
deny-list; `LocalCustodian` uses the same signature with `caller="local"`). It is a
**service-level rate or human decision** ("should this custodian answer now?"), not
a per-vault policy: the custodian is a decryption oracle on points, `E` carries no
vault identity and can be blinded by the caller (`E+rG`, `−E`), and **`context` is
informational — it is chosen by the caller, only enters the proof hash, and
authorizes nothing**. Do not build per-ciphertext or per-context access control on
it.

Clients: `RemoteCustodian` refuses plaintext TCP to a non-loopback host unless
`tls=True` (or `allow_insecure=True` on a fully trusted network). `open-test` takes
the token only from `--token-env` (never argv) and accepts `HOST:PORT` or
`[IPv6]:PORT`.

### 2.3 Using it from the driver

```python
from torussql.custody import PublicKey, Quorum, ThresholdCustody
from torussql.custody.net import RemoteCustodian

pub = PublicKey.load("public.json")
quorum = Quorum(pub, [RemoteCustodian(h, p, token, group=pub.g, tls=True, cafile="ca.pem")
                      for h, p in custodian_addresses], timeout=20)
conn = torussql.connect(host, port, token=db_token, vault_path="owner.vault",
                        vault_custody=ThresholdCustody(pub, quorum))
```

* First use creates the vault sealed under a fresh envelope (public key only).
* Opening an existing vault asks the custodians; `VaultLocked` if fewer than `k` answer validly.
* `conn.rotate_vault_key()` re-seals under a fresh envelope — **no quorum needed**.
* `conn.reseal_vault(custody=new)` migrates between modes (passphrase → threshold,
  or onto a brand-new threshold key). The old file stays valid until the new one is
  fully written.

### 2.4 Lifecycle

| Event | Action |
|---|---|
| Scheduled hygiene (e.g. monthly) | `reshare-start/finish` with the same `k, n` → fresh shares, same public key; `SIGHUP` the daemons |
| A custodian is lost (≥ k remain) | reshare among the survivors to a committee with a replacement |
| A custodian is *suspected* compromised (< k compromised) | reshare immediately; old-epoch shares no longer combine |
| **k or more** shares compromised | the key is compromised. New ceremony, then `reseal_vault(custody=new)`; treat vault ciphertexts that were exposed as readable |
| Change quorum (e.g. 2-of-3 → 3-of-5) | `reshare-*` with new `--new-k/--new-n` |

### 2.5 FHE columns on a threshold key

Two custody keys can be the secrets of `FHE` columns (`docs/fhe-columns.md`, "Threshold custody of the FHE
key"): `s` in group `bn254` and an independent `s2` in group **`bn254g2`** (run its DKG with
`dkg-start/dkg-finish --key-group bn254g2`, or `keygen-local --group bn254g2` for development). The G2 key's public
key is the G2 point `Q2`; no G1 image of `s2` is ever produced (it would decrypt every cell publicly). Custodians gain
two key-service methods under the existing `key` permission and the same `approve` / rate-limit / audit machinery:
`partial_batch` (many G1 points per request; refused on a G2 key) and `gt_partial_batch` (GT exponentiation with a
Chaum-Pedersen proof in the key's group, for `DOT`). `python -m torussql.custody fhe-keygen-threshold` /
`fhe-open-test` are the ceremony and check commands (the bundle has its own fingerprint, see fhe-columns.md).

**One daemon, several keys.** `serve --share A.json --share B.json` makes one daemon hold the shares of
several different keys (typically `s` and `s2`). Every request then names its `key_id`
(`RemoteCustodian.for_key(public)` does this); a request without one is refused on a multi-key daemon, a
request naming a key the daemon does not hold is refused, and a key-1 request is never answered with the key-2
share (the proof is also bound to the key id and epoch, so a swapped answer fails verification). A single-share
daemon still accepts legacy requests without a `key_id`. `--key-access KEY_ID:caller,caller` restricts a key to
named tokens; `approve` may be a `{key_id: callable}` map; request and item limits are counted per (caller, key).
The audit log records the `key_id` of every key-service decision.

**Limits (all per caller and key, all with a clear error):**

| flag | default | meaning |
|---|---|---|
| `--rate` | 30 | REQUESTS per minute; a batch is one request |
| `--item-budget` | 30000 | COST UNITS answered per minute: G1 point = 1, G2 point = 2, GT element = 100 (GT is ~100x the CPU); `0` = unlimited |
| `--max-batch` | 2000 | items in one batch request (GT batches are further capped at 64 by their cost) |

Reading n FHE cells is one request of n items, so the default budget allows ~30000 cells (or 300 GT elements = 60 DOT decryptions) per minute per caller
while the request limit and the audit-log/DoS protections stay as they were (malformed requests also cost budget).

**Audit log rotation.** `--audit-max-mb` (default 64) rotates `audit.log` to `.1`, `.2`, ... and `--audit-keep N`
(default 7) is the number of rotated files kept (the oldest is deleted; `0` discards the full log). Rotated files
stay `0600`.

**Constant-time arithmetic: partial mitigation.** With `mclbn256` importable (and `TORUSSQL_CUSTODY_NATIVE`
not `0`), every secret-scalar multiplication on the `bn254` group (shares, nonces, private keys, G2 shares)
uses mcl's constant-time ladder (`mclBnG1_mulCT` / `mclBnG2_mulCT`); the FHE owner side does the same for
`s*C1`, encryption randomness, plaintexts and public-key derivation. This is **not** complete: (a) the pure-Python
paths (`py_ecc`, and `secp256k1` always) are variable-time big-int arithmetic; (b) GT exponentiation (the custodian's
`c^(y_i)` and the owner's DOT decryption) has no constant-time primitive in mcl and keeps the split-exponent
randomisation (`c^(k-r)*c^r` with fresh `r`), which only decorrelates repeated measurements; (c) point
conversions and Python itself are not constant time; (d) the bounded discrete logarithm works on plaintexts.
Run custodians on isolated hosts.

**Public-key trust anchor.** `public.json` carries every verification key, so a swapped file defeats DLEQ
verification. `public-show` prints a **fingerprint** (SHA-256 over group, k, n, epoch and all commitments);
procedure: (1) after the DKG every custodian runs `public-show` and the fingerprints are compared out of band;
(2) every client and operator command that reads the file takes `--expect-fingerprint FP` (`open-test`,
`fhe-keygen-threshold`, `fhe-open-test` also `--expect-fingerprint2`, `reshare-start/finish`, `public-show`;
`torussql --custody-expect-fingerprint[2]`) and refuses a mismatch before contacting anyone; (3) re-pin after a
refresh/reshare, which changes the epoch and commitments (the `key_id` does not change).

**Ceremony hardening.** A DKG/reshare dealing whose constant-term or residue commitment is the identity
(a "contribution-less" dealing) is rejected; this cannot reject an honest dealer (a random coefficient is 0 with
probability 1/q). `reshare-start` now needs `--old-ids` and `--new-ids` and `reshare-finish` needs `--new-ids`:
the digests of both committees' identity lists are signed into every reshare broadcast, so a dealing cannot be
replayed to a different set of recipients; broadcasts in the old format are refused with an explicit message.

## 3. What it protects — and what it does not

**Protects**
* The vault file at rest, and the *authority to open it*: it takes `k` custodians
  (separate hosts, separate admins) to produce the opening key.
* No single custodian, and no coalition below `k`, learns anything about the
  *shares-as-a-sharing*: the Laurent sharing itself is perfectly hiding for the
  evaluation points used (tested for every `(k−1)`-subset up to n=10). But the
  Feldman commitments make `X` and every `Yᵢ` public, so secrecy of `x` is
  **computational** (ECDLP), not information-theoretic.
* A faulty custodian cannot corrupt an opening undetected (DLEQ). Callers are
  authenticated by bearer tokens; **TLS/mTLS is optional on the daemon and must be
  enabled on any untrusted network** (the client refuses plaintext to non-loopback
  hosts unless told otherwise). Authenticated decisions and failed attempts are
  audited (the latter rate-limited and bounded).
* By design the code never reassembles the key: no function does, and the tests
  monkeypatch `laurent.reconstruct` to fail during generation, use, refresh and
  reshare. That test is evidence for the shipped code paths, not a proof — it
  cannot rule out a different code path recomputing the key.

**Does not protect**
* **An opened vault lives in the owner process's memory.** To unblind results the
  owner needs the masks. Whoever compromises that process while the vault is open
  sees them. Making the *masks themselves* threshold-shared is available as a separate
  mode — see `masks.md`.
* The opener learns the envelope's derived key `K` for that vault (not `x`).
* `k` colluding custodians reconstruct `x`; nothing can stop them.
* **Post-quantum:** this mode rests on ECDLP in secp256k1 / BN254. A quantum
  attacker holding the vault file *and* the public key can recover `x`. The older
  `keymgmt` custody (information-theoretic shares + symmetric sealing) is
  PQ-safe but reassembles the key at recovery. Choose per threat model; the
  server-side confidentiality of the database (one-time pad) is unaffected.
* Availability: fewer than `k` reachable custodians means the vault cannot be opened.

## 4. Known limitations (also in the review packet)

* Feldman-style DKG: an adversary speaking last can bias the *distribution* of `X`.
  Harmless for an encryption key; do not reuse this DKG where uniformity matters.
* The DKG needs all `n` participants; any failure restarts the ceremony.
* Transport of ceremony files is only as trustworthy as the fingerprint comparison.
* Pure Python: **arithmetic is NOT constant-time** (`py_ecc` uses variable-time
  big-int double-and-add; run time depends on the scalar's Hamming weight). Every
  multiplication by a secret scalar (key shares, identity keys, proof nonces,
  dealing coefficients) is computed as `k·P = (k−r)·P + r·P` with a fresh random
  `r`; this only *decorrelates* repeated measurements from `k` and does not make
  the arithmetic constant time or defeat a local/co-resident observer. A caller
  with a token chooses `E`, so `yᵢ·E` timing is observable by a networked
  attacker to the extent the rate limit allows. For high-value deployments use a
  constant-time library (libsecp256k1 / coincurve) and isolated hosts.
* Secret dataclass fields (`KeyShare.y`, `Identity.secret`) are excluded from
  `repr` and refuse pickling/copying; this is hygiene, not memory protection.
* `PublicKey.key_id` covers only the group and `X` (stable across refresh and
  reshare, on purpose). `PublicKey.digest` additionally covers k, n, epoch and all
  commitments and is checked when a public-key file is loaded; `public.json` is
  still an unauthenticated trust anchor — pin its `key_id`/`digest` out of band.
* Sealed-file freshness/rollback is not protected at the custody layer; see the
  vault notes.
* Nothing can force a custodian to **erase** an old share after a reshare.
* Sealing uses the stdlib HMAC-keystream construction (finding F-10).
* No independent audit has been done.

## 5. Performance (Apple-silicon laptop, pure Python)

| group | k-of-n | DKG (all parties, 1 process) | open (local) | reshare |
|---|---|---|---|---|
| secp256k1 | 2-of-3 | 59 ms | 36 ms | 35 ms |
| secp256k1 | 3-of-5 | 180 ms | 67 ms | 121 ms |
| secp256k1 | 5-of-9 | 776 ms | 164 ms | 596 ms |
| bn254 | 3-of-5 | 510 ms | 196 ms | 321 ms |

Opening a 3-of-5 vault over TCP loopback: ~74 ms. In a real deployment network
latency dominates; the vault is opened once per session.
