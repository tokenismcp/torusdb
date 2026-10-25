# TorusSQL Versioning Policy

**Applies from v0.1 · Owner: J1729 Labs**

---

## Two public surfaces, versioned independently

TorusSQL has exactly **two public surfaces** with compatibility guarantees.
Everything else — the engine internals, the blinded-scalar math, the mask
vault layout — is internal and may change in any release.

### Surface 1: The dialect (`spec/TorusSQL-Spec-v*.md`)

**What it covers**: SQL syntax, statement semantics, exact result types,
accepted/rejected statements, and the open validator (`torussql-parser`).

**Stability rule**: once a capability ships in §4 of the spec, its syntax and
exact result do not change incompatibly within a major version. A statement
that was legal and produced result R will always be legal and produce R.

**Version scheme**: `DIALECT_MAJOR.MINOR`

| Bump | When |
|---|---|
| `MINOR` | New statement or projection added (backward-compatible) |
| `MAJOR` | A legal statement changes semantics or becomes illegal |

Current: **0.5** (`spec/TorusSQL-Spec-v0.5.md`; v0.1 kept for history).

### Surface 2: The wire protocol (`proto/torussql-wire-v*.md`)

**What it covers**: the binary framing (4-byte length prefix), the JSON RPC
envelope (`{"m": ..., "a": [...]}` / `{"ok": ...}` / `{"err": ...}`), and
the no-key RPC set (`proto/torussql-wire-v2.md`).

**Stability rule**: a client built against wire version N will interoperate
with any server that speaks N, regardless of engine internals.

**Version scheme**: `WIRE_MAJOR.MINOR`

| Bump | When |
|---|---|
| `MINOR` | New RPC method added (old clients ignore unknown responses) |
| `MAJOR` | Existing method renamed, argument schema changed, or framing format changed |

Current: **protocol 2** (`proto/torussql-wire-v2.md`; 4-byte **big-endian** length prefix + JSON envelope). Protocol 1 is the pre-0.5 server (no `hello`, auth or transactions); v2 drivers interoperate with it.

---

## Package versions

The Python packages follow [Semantic Versioning 2.0](https://semver.org/).

| Package | Current | Tracks |
|---|---|---|
| `torussql` (Python driver) | 0.5.0 | Wire + dialect surface |
| `torusdb-server` | 0.5.0 | Wire surface + operational flags |
| `torussql-parser` | 0.5.0 | Dialect surface only |
| `@torusdb/driver` (npm), `torusdb` (crate) | 0.5.0 | Wire surface |
| `torusdb-core` | 0.5.0 | Internal engine API (not a public interface) |

**All open packages (parser, drivers, server) share one version number and are released together (enforced by `tests/test_versions.py`). The driver and parser packages are the public API.** `torusdb-core`
is an implementation detail — do not depend on their interfaces directly.

---

## Pre-1.0 policy (current)

Until the packages reach 1.0, MINOR bumps **may** introduce breaking changes
in the dialect or wire, with a deprecation notice in the CHANGELOG and at
least one release of dual-support where feasible.

After 1.0:
- `MAJOR` bumps: breaking changes allowed.
- `MINOR` bumps: backward-compatible additions only.
- `PATCH` bumps: bug fixes, no API changes.

---

## What is NOT versioned / guaranteed

- Engine internals (mask encoding, blinded-scalar representation, persistence format)
- `torussql` shell meta-commands (`\dt`, `\d`, `\timing`) — may change in any release
- Internal RPC methods not documented in `torussql-wire-v*.md`
- The conformance suite itself (tests may be added; existing tests never weakened)

---

## Conformance

A third-party engine is **conformant** if `spec/conformance/test_conformance.py`
passes against it. This suite is the binding contract. Run it from a checkout
(Python >= 3.11, `pip install pytest`):

```bash
pytest spec/conformance          # runs against the bundled keyless engine
```

To test another engine, change only the `EngineSeam` adapter in `spec/conformance/conftest.py`. The ROADMAP is the
route; the spec and suite are the destination.

Conformance tests are versioned with the dialect: adding a test is a MINOR
dialect bump; weakening or removing a test is a MAJOR bump.

---

## CHANGELOG

See [`CHANGELOG.md`](../CHANGELOG.md) for the full release history.
