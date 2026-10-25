# EC-FHE and the no-key server

TorusDB's cryptography comes from the EC-FHE line of work. The open server
implements the **no-key delegation protocol** of that line: the server stores
one-time-padded scalars (and plaintext columns), evaluates affine functions on
them (`Π_lin`) and combines owner-opened Beaver openings (`Π_mult`), and holds **no
key, no bootstrap key and no mask**. Everything that decrypts happens in the data
owner's process.

## Server-side evaluation: `FHE` columns

An earlier version of this page said a server-side evaluation mode would add nothing without
server-held keys. That was wrong for the *pairing* path. The reference engine's default
evaluator (`bootstrap_assisted`) does need a bootstrap key at the evaluator, and its
`ct_native` path assumes a co-located secret-key holder — both rejected here. But the
pairing step itself (`★_ct`, the pairing-based ciphertext×ciphertext product) uses **only public ciphertext data**, so the server
can add and multiply ciphertexts and the owner decrypts the aggregate. That is implemented
as the `FHE` column policy — see [`fhe-columns.md`](fhe-columns.md) — with a layout that fixes a
weakness we found in shared-randomness paired ciphertexts (a public-key value oracle).

Which mode to use: `ENC`/`PAIRED` for information-theoretic confidentiality, MAC integrity and
speed, at the price of a mask vault and owner-side multiplication; `FHE` when you need the
server to compute products/inner products without owner state, accepting computational
security, opt-in (tag-based, partial) integrity rather than information-theoretic MACs, and
slower pairings (`docs/fhe-columns.md`, "Limits").

## What an "EC-FHE DBMS" means here

* the data model, SQL and wire protocol are the product;
* the cryptographic core is `torusdb_core.protocol` (encode/decode, `Π_lin`, `Π_mult`);
* confidentiality of encrypted columns holds against the server unconditionally
  (`I(M; V_S) = 0`), with the leakage listed in `threat-model.md` (plaintext columns,
  schema, row counts, access patterns);
* integrity against a lying server is opt-in (`authenticated=True`, SPDZ-style MACs).
