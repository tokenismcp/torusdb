# TorusDB No-Key Wire Protocol — v2

Authoritative description of the protocol spoken between a data-owner driver and
the keyless server. (`torussql-wire-v0.1.md` described the retired
trusted-evaluator design and is kept for history only.)

## 1. Framing

A **frame** is a 4-byte **big-endian** unsigned length followed by that many
bytes of payload. Servers reject a declared length above their limit
(default 32 MiB) *before* reading the payload. A frame of length 0 is legal.
The payload is a UTF-8 JSON object. Reference: `torussql/framing.py`.

## 2. Envelope

```
request   {"m": "<method>", "a": [ …positional args… ]}
success   {"ok": <result>}
failure   {"err": "<ErrorType>: <message>"}
```

One response per request, in order, on the same connection. Connections are
stateful (authentication role, open transaction).

## 3. Values

| Wire form | Meaning |
|---|---|
| `{"t":"i","v":"123"}` | integer (decimal string — exact for big ints) |
| `{"t":"s","v":"text"}` | string |
| `{"t":"f","n":"1","d":"3"}` | exact fraction |
| `{"t":"b","v":true}` / `{"t":"n"}` | boolean / NULL |

Blinded scalars, sums and Beaver openings travel as decimal strings in
`[0, n)`, n = BN254 group order. A **predicate** is
`{"or": [[atom, …], …]}` with `atom = {"c": col, "op": "=", "v": value}` or
`{"c": col, "in": [value, …]}`; only PLAIN columns may be tested.
Row ids are non-negative integers, never reused.

## 4. Session

1. `hello []` (no authentication required; since 0.5 the reply also carries `persistent` and `limits` =
   `{max_items, fhe: {max_sum_rows, max_dot_rows{pyecc,mcl}, recommended_dot_rows{pyecc,mcl}, backends[], default_backend}}`
   so clients can size their requests; absent on older servers) → `{protocol, server, auth_required,
   max_frame, persistent}`. A client must refuse `protocol` greater than it
   knows. A v1 server answers `hello` with an "unknown method"/`_rpc_hello`
   error; treat as protocol 1 (no auth, no transactions, no batch RPCs).
2. If `auth_required`: `auth [token]` → `{role}`. Until then every other method
   except `hello`/`ping` fails with `Unauthenticated`.

## 5. Methods

| Method | Args | Result | Role |
|---|---|---|---|
| `hello`, `ping`, `auth` | — / — / `[token]` | see §4 / `"pong"` / `{role}` | public |
| `tables` | `[]` | `[name…]` | ro |
| `schema` | `[table]` | `[[col,type,policy]…]` | ro |
| `table_info` | `[table]` | `{rows, deleted:[ids]}` | ro |
| `matching_rowids` | `[table, predicate\|null]` | `[rowid…]` (live rows) | ro |
| `plain_cells` | `[table, col, [ids]]` | `[value…]` | ro |
| `blinded_cell` / `blinded_cells` | `[table,col,id]` / `[table,col,[ids]]` | value / `[value…]` | ro |
| `blinded_sum` | `[table,col,[ids]]` | `"Σ mod n"` | ro |
| `blinded_scaled_sum` | `[table,col,[ids],k]` | `"k·Σ mod n"` | ro |
| `blinded_per_row_scaled` | `[table,col,[ids],k]` | `["k·x mod n"…]` | ro |
| `mult_combine_batch` | `[[[e,g]…]]` | `["e·g mod n"…]` | ro |
| `create` | `[table, [[col,type,policy]…]]` | `null` | rw |
| `insert` | `[table, {col: value…}]` | rowid | rw |
| `insert_many` | `[table, [{col: value…}…]]` | `[rowid…]` (atomic) | rw |
| `update_cell` | `[table, id, col, value]` | `null` | rw |
| `update_cells` | `[table, [[id, col, value], …]]` (≤ `limits.max_items`) | applied count; **atomic** — one bad item rolls the whole batch back | rw |
| `delete_rows` | `[table, [ids]]` | count | rw |
| `tx_begin` / `tx_commit` / `tx_rollback` | `[]` | `null` | rw |
| `drop` | `[table]` | `null` | admin |
| `stats` / `checkpoint` / `backup` | `[]` | object / generation / path | admin |

`insert` rows must contain exactly the table's columns (plus, in authenticated
mode, a `__mac__<col>` for each encrypted column).

## 6. Transactions

`tx_begin` takes the database's single transaction slot (waiting up to the
server's `tx_wait`, then `Busy`). Until commit/rollback, other connections'
requests wait. `tx_commit` journals the whole transaction as one atomic unit;
`tx_rollback`, a dropped connection, or exceeding `tx_timeout` while someone
waits undoes it. The *client* must also restore its mask vault on rollback.

## 7. Errors

`Type: message` where Type ∈ `Unauthenticated` (no/invalid token),
`Forbidden` (role, lockout), `Busy` (connection cap, transaction lock, timed-out
transaction), `BadRequest` (malformed request, bad row id/column, predicate on an
encrypted column, oversized frame), `PlanError`/`ParseError`/`ExecError`,
`InternalError … (ref=xxxxxxxx)` (details only in the server log). Unknown
methods fail with `BadRequest: unknown method`.

## 8. Compatibility

Adding a method or a result field is a MINOR change; renaming/removing a method,
changing an argument shape, or changing framing is MAJOR. Clients ignore unknown
result fields. Current: **protocol 2**; the dialect is versioned separately
(`spec/TorusSQL-Spec-v0.5.md`).
