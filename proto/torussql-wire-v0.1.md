# TorusSQL Wire Protocol — v0.1

The contract between an **open** TorusSQL client and the **closed** TorusDB
engine. Defines how statements, client-encrypted parameters, and results
cross the boundary — and nothing about how the engine evaluates them.

- Normative typed/binary schema: [`torussql.proto`](torussql.proto).
- Equivalent **canonical JSON** encoding: this document.
- Reference codec (JSON): [`wire.py`](wire.py).

## 1. Principles

1. **Client-side keys.** The client holds the secret key. It encrypts every
   value bound to an `ENC`/`PAIRED` column and decrypts every encrypted
   result cell. The engine never receives a key and never holds the
   plaintext of an encrypted value.
2. **Opaque ciphertext.** A ciphertext is `{scheme, body}` where `body` is
   engine-defined octets. The protocol — and therefore every open driver —
   treats it as an opaque blob. No curve, pairing, or noise field is ever on
   the wire.
3. **Parameters, not inlined secrets.** Encrypted values are sent as
   positional parameters bound to `?` placeholders, never as text inside the
   SQL string. This keeps plaintext out of the statement and makes the
   client the only party that ever sees it.
4. **Typed errors only.** Failures map to the fixed `ErrorKind` set, the same
   set the dialect spec §7 requires for conformance.

## 2. Session lifecycle

```
client                         engine
  │   Connect(Hello) ───────────▶│
  │◀─────────── Welcome           │   negotiate version, scheme, decode ranges
  │                               │
  │   Execute(ExecuteRequest) ───▶│   per statement
  │◀─────────── ExecuteResponse   │
  │            ...                │
```

`Welcome` carries the **decode-range contract** (spec §5):
`decode_range_additive` bounds `SUM`/scalar-mul result magnitude;
`decode_range_product` bounds `*`/`DOT` result magnitude. A client that
issues a query whose result would exceed these gets an `ErrorKind=RANGE`
response, never a silently wrapped value.

## 3. Parameter binding

The `sql` field uses `?` as a positional placeholder. `params` are bound
left-to-right. A value destined for an encrypted column MUST be a
`Ciphertext` the client produced; a value for a `PLAIN` column may be
plaintext or inlined directly in the text.

```
sql    = "INSERT INTO payroll (id, rate, hours) VALUES (?, ?, ?)"
params = [ {int: 1}, {cipher: <opaque>}, {cipher: <opaque>} ]
```

> In v0.1 the local demo engine (`torusctl`) inlines `FRAC(...)` literals and
> encrypts server-side for convenience. The wire contract above is the target
> hosted architecture; a driver speaking this protocol encrypts client-side.

## 4. Canonical JSON encoding

For debuggability and zero-codegen drivers, v0.1 defines a canonical JSON
form equivalent to the protobuf messages. Field names are the proto field
names. `bytes` are base64 (standard, padded). `oneof` is encoded as exactly
one present key.

### Value

```json
{ "int_val": 42 }
{ "str_val": "alice" }
{ "rat_val": { "num": 2, "den": 3 } }
{ "cipher":  { "scheme": 1, "body": "<base64>" } }
{ "is_null": true }
```

### Hello / Welcome

```json
{ "client_name": "torusctl", "max_dialect_version": 1 }
```
```json
{ "dialect_version": 1, "scheme": 1,
  "decode_range_additive": 10000000, "decode_range_product": 1000000,
  "capabilities": ["sum", "scalar_mul", "ct_mul", "dot"] }
```

### ExecuteRequest / ExecuteResponse

```json
{ "sql": "SELECT DOT(x, y) FROM t", "params": [] }
```
```json
{ "result": { "columns": ["dot(x,y)"],
              "rows": [ { "cells": [ { "cipher": { "scheme": 1, "body": "..." } } ] } ] } }
```
```json
{ "affected": 1 }
```
```json
{ "error": { "kind": "RANGE", "message": "product exceeds decode range" } }
```

## 5. Error kinds

| `kind`        | When                                                      |
|---------------|-----------------------------------------------------------|
| `PARSE`       | statement does not parse under the dialect grammar        |
| `POLICY`      | operation illegal for a column's policy or type (e.g. `DOT` on `RATIONAL`, `WHERE` on encrypted) |
| `UNSUPPORTED` | capability not in the negotiated dialect version          |
| `RANGE`       | result magnitude exceeds the negotiated decode range      |
| `INTERNAL`    | engine fault; MUST NOT leak any plaintext                 |

## 6. Versioning

`dialect_version` is the negotiated TorusSQL version (`1` for v0.1). The
`scheme` tag versions the opaque ciphertext format independently, so the
engine can evolve its internals without a dialect bump. A client MUST treat
a ciphertext with an unfamiliar `scheme` as opaque and round-trip it
unchanged.

---

*Open protocol, opaque payload: every byte of structure on the wire is
public; every byte of `Ciphertext.body` is the engine's business.*
