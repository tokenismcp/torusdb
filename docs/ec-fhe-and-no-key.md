# EC-FHE and the no-key server

TorusDB's cryptography comes from the EC-FHE line of work. The open server
implements the **no-key delegation protocol** of that line: the server stores
one-time-padded scalars (and plaintext columns), evaluates affine functions on
them (`Π_lin`) and combines owner-opened Beaver openings (`Π_mult`), and holds **no
key, no bootstrap key and no mask**. Everything that decrypts happens in the data
owner's process.

## Why there is no server-side EC-FHE evaluation mode

We looked at adding a per-column "evaluate on EC-FHE ciphertexts at the server"
back end. In the EC-FHE reference engine the two evaluation paths are:

| path | what the evaluator needs | consequence |
|---|---|---|
| `bootstrap_assisted` (default) | the bootstrap key; every operation partially decrypts, computes on the rational, re-encrypts | exactly the *decrypt-then-re-encrypt at the server* structure this project forbids |
| `ct_native` (pairing ★_ct) | "a secret-key holder co-located with the evaluator"; the ★_ct adapter is not yet implemented | a secret key at the server |

Homomorphic *addition* alone stays in G1 without a key — but sums are already served
by `Π_lin`, with unconditional (information-theoretic) hiding and no elliptic-curve
work at the server. So under the rule "the server never holds key material" an
EC-FHE evaluation back end would add no capability, and with the rule relaxed it would
re-introduce the very trust assumption the no-key protocol removes. For that reason
it is **not built**; this is a design decision, not an omission.

## What an "EC-FHE DBMS" means here

* the data model, SQL and wire protocol are the product;
* the cryptographic core is `torusdb_core.protocol` (encode/decode, `Π_lin`, `Π_mult`);
* confidentiality of encrypted columns holds against the server unconditionally
  (`I(M; V_S) = 0`), with the leakage listed in `threat-model.md` (plaintext columns,
  schema, row counts, access patterns);
* integrity against a lying server is opt-in (`authenticated=True`, SPDZ-style MACs).

## If you want server-side evaluation anyway

It must be a separate, clearly labelled mode with its own threat model: the server
(or a TEE / separate evaluator service) would hold evaluation key material, and a
compromise of it would break confidentiality of those columns. It would need a column
policy distinct from `ENC`/`PAIRED`, a planner extension, new RPCs and an explicit
opt-in at table creation. Nothing in the open tree prevents that, but it should be
a deliberate product decision rather than a default.
