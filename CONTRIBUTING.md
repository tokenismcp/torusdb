# Contributing

Thanks for helping. A few ground rules keep the project safe to depend on.

## Setup

```bash
git clone <repo> && cd torussql
pip install pytest "py_ecc>=6,<9"
pytest                                           # everything; pure Python, no proprietary parts
(cd drivers/typescript && npm ci && npm test)
(cd drivers/rust && cargo test && cargo clippy --all-targets -- -D warnings)
```

## Rules

1. **Spec first.** A dialect change starts as an edit to `spec/TorusSQL-Spec-*.md`
   plus conformance cases in `spec/conformance/` — the open validator and the engine
   must accept/reject identically (`tests/test_join_v05.py` shows the pattern).
2. **The server must never hold a key or a mask**, nor receive one: nothing may be
   added to an RPC argument that derives from a mask, an encoded plaintext of an
   encrypted cell, or the MAC key. `core/tests/test_crypto_audit.py` records
   every value a server receives and enforces this — keep it passing.
3. **No silent wrong answers.** Prefer a loud error (`OutOfBudget`, `IntegrityError`,
   `PlanError`) to a plausible-looking incorrect result.
4. **Tests accompany every change**, including the failure path. Security-relevant
   behaviour (auth, limits, durability) is tested in `tests/test_ops.py`.
5. **Compatibility.** Wire and dialect changes follow `docs/versioning.md`; bump all
   open packages together (`tests/test_versions.py`) and update `CHANGELOG.md`.
6. Keep the three drivers consistent: a protocol change lands in Python, TypeScript
   and Rust together, with `drivers/vectors.json` extended for any codec change.
7. Do not add runtime dependencies to the parser or TypeScript driver without
   discussion; the Python driver and server are stdlib-only apart from the engine.

## Pull requests

Describe the behaviour change and its tests. CI must be green. By contributing you
agree your work is licensed under Apache-2.0 (see `LICENSE`).
