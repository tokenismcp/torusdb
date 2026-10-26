# Releasing

All open packages share one version (`tests/test_versions.py` enforces it):
`parser`, `core`, `drivers/python`, `server`, `drivers/typescript`, `drivers/rust`.

1. Update the version everywhere (the test lists the places) and add a
   `## [X.Y.Z]` section to `CHANGELOG.md`.
2. `pytest` · `(cd drivers/typescript && npm ci && npm test)` ·
   `(cd drivers/rust && cargo test && cargo test --features tls && cargo clippy --all-targets -- -D warnings)`
   · `docker build -f server/Dockerfile -t torusdb-server:X.Y.Z .`
3. Tag `vX.Y.Z` and push. CI builds the wheels, smoke-tests an installed server
   in a clean virtualenv, then publishes (PyPI trusted publishing for the four
   Python packages one at a time in dependency order, npm, crates.io). One-time setup:
   PyPI trusted-publisher entries, `NPM_TOKEN`, `CARGO_REGISTRY_TOKEN` and the GitHub
   environments `pypi`, `pypi-parser`, `pypi-driver`, `pypi-server`, `npm`, `crates`.
   PyPI allows one pending publisher per repo/workflow/environment and at most three
   pending at a time: register `torussql-parser` (`pypi-parser`), `torusdb-core` (`pypi`)
   and `torussql` (`pypi-driver`) first. After the first release creates them, register
   `torusdb-server` (`pypi-server`) and use "Re-run failed jobs" on the tag's run; the
   same version is then uploaded, no new number needed.
4. Push the Docker image to your registry (the CI job only verifies the build).

Never publish from a dirty tree; never reuse a version number.
