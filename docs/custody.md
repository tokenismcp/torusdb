# Threshold Key Custody (z-MPC style)

**Version:** 0.5 · package `torussql.custody` · tests `tests/test_custody*.py`

The owner's mask vault is the one secret that can read the data. This module
generates its **protection key without a dealer** and lets it be **used without
ever being reassembled**, by any `k` of `n` custodians.

> **Threshold *storage* vs threshold *use*.** The older `ecfhe_query.keymgmt`
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
| Laurent-series secret sharing, secret as residue | **Yes** — same structure as `ecfhe/lss.py`, with linear reconstruction coefficients |
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

The ceremony **aborts and names the culprit** on a bad share, bad commitment, a
missing/forged proof, a bad signature or swapped files, and must then be restarted
without them. *Dev/test only:* `keygen-local` runs the whole ceremony in one
process (it prints a warning — that process sees every share).

### 2.2 Running a custodian

```bash
python -m torussql.custody serve --share share1.json --listen 0.0.0.0:8601 \
    --token-file tokens --tls --cert c.crt --key c.key --audit /var/log/custodian.audit --passphrase-env PW
```

`tokens` holds `caller:token` lines (≥16 chars). The daemon refuses a non-loopback
listen without `--tls`, rate-limits each caller (default 30/min), refuses malformed
or off-curve points, and appends a JSON audit line for every decision (caller, key
epoch, a hash of the request — never a share). `SIGHUP` reloads a refreshed share.
A custodian can also be given an `approve(caller, E, context)` callback in code to
require human or policy approval.

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

## 3. What it protects — and what it does not

**Protects**
* The vault file at rest, and the *authority to open it*: it takes `k` custodians
  (separate hosts, separate admins) to produce the opening key.
* No single custodian, and no coalition below `k`, learns anything about `x` —
  perfect secrecy of the sharing for the evaluation points used (tested for every
  `(k−1)`-subset up to n=10).
* A faulty custodian cannot corrupt an opening undetected (DLEQ), cannot be
  impersonated (tokens/TLS), and its decisions are auditable.
* The key is never reassembled by generation, use, refresh or reshare — the test
  suite runs those paths with the reconstruction function disabled.

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
* Pure Python: arithmetic is not constant-time. The scalar is randomised
  (`k + r·q`) to blunt timing correlation; run custodians on isolated hosts.
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
