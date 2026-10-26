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
| `wire_exec` | `[[op…]]` (§9) | `[result…]`, one per op | ro |
| `wire_free` | `[[wire id…] \| null]` | count freed | ro |
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

## 9. Shared wires (expressions; wire protocol 2.1)

`wire_exec` / `wire_free` carry the **server half of the paper's circuit composition Π_C** for
dialect v0.6 expressions. Every wire of the circuit is an additive sharing `X = X_S + X_O (mod n)`;
the server keeps `X_S` in a **session-scoped store** (ids are chosen by the client, ≤ 64 characters,
private to the connection), the owner keeps `X_O`. Nothing here is a key, mask, MAC key or plaintext:
everything the client sends is a uniform share, a fresh Beaver-triple share, a one-time-padded
opening share, or a public constant of the query, and everything the server returns is its own
share. The wire RPCs are reads (role `ro`), allowed on replicas, and touch the database only to
read the named rows' stored cells. A server advertises support in `hello` →
`limits.wires = {version, max_wires, max_elements, ttl, max_ops, max_request_elements}`; a client must
not call them when it is absent (older servers answer `BadRequest: unknown method`).

A request is `{"m":"wire_exec","a":[[op, …]]}`; ops run in order and the reply is one result per op
(`null` unless stated). Ring elements (`R`) are decimal strings in `[0, n)` (JSON integers are also
accepted); a vector `V` is a list of `R`. Ops that carry a vector take a trailing span
`lo, width` so a long vector arrives in pieces: the output wire is created at `lo = 0` with the
full `width`, pieces must arrive in order, and a wire that is still being filled cannot be used.
In the table `tag` is the optional share of the SPDZ tag `α·X` (authenticated mode); all operands of
one op must agree on tagging.

| op | arguments | effect / reply |
|---|---|---|
| `load` | `out, table, col, rows, with_tag[, lo, width]` | `X_S` = stored cells of `rows` (`null` → 0); with tags also `__mac__<col>` |
| `loadsum` | `out, table, col, rows, with_tag[, more]` | width-1 wire = Σ stored cells (`more`: add into the existing wire) |
| `put` | `out, V, V\|null, lo, width` | a share dealt by the owner (the `ρ` of a division) |
| `add`, `sub` | `out, a, b` | elementwise on the shares |
| `neg` | `out, a` | |
| `mulc`, `addc` | `out, a, R` | × / + a public scalar (tag: `addc` leaves the tag share unchanged; the owner adds `α·c`) |
| `mulv`, `addv` | `out, a, V, lo, width` | × / + a public vector (also the `t⁻¹` multiplier of a division) |
| `bc` | `out, a, width` | broadcast a width-1 wire |
| `sum` | `out, a` | width-1 wire = Σ of the shares |
| `mul` | `out, a, b, {u,v,w,eo,go[,mu,mv,mw]}, lo, width` | Beaver product. The triple shares are `V`s; `eo = X_O−u_O`, `go = Y_O−v_O` are the owner's opening shares. Server: `e_S = X_S−u_S`, `g_S = Y_S−v_S`, `e = e_S+eo`, `g = g_S+go`, `Z_S = w_S + e·v_S + g·u_S + e·g` (stored as `out`; tag `mw + e·mv + g·mu`). Reply `[e_S V, g_S V, e-tag V\|null, g-tag V\|null]` |
| `reveal` | `a, lo, count` | reply `[V, V\|null]`: this side's share (and tag share) of the wire — the only way a value leaves the store |
| `free` | `[ids]` | drop wires |

Limits (`WireError`, DB-API `OperationalError`, naming the cap): `max_wires` live wires and
`max_elements` ring elements per session (a tagged wire counts twice), a server-wide
element cap, `max_ops` operations and `max_request_elements` ring elements per request, and a
`ttl` after which an unused wire is dropped. A session's wires are freed by `wire_free`, at
`tx_commit` / `tx_rollback` / transaction timeout, and on disconnect. Reference: `core/torusdb_core/wires.py`
(server), `core/torusdb_core/expr_shared.py` (owner), spec §5.10, review packet §3.3.

## 8. Compatibility

Adding a method or a result field is a MINOR change; renaming/removing a method,
changing an argument shape, or changing framing is MAJOR. Clients ignore unknown
result fields. Current: **protocol 2** (revision **2.1** adds `wire_exec` / `wire_free`, §9, and
`limits.wires` in `hello`; the integer `protocol` in `hello` stays 2 because a 2.0 client is
unaffected); the dialect is versioned separately (`spec/TorusSQL-Spec-v0.6.md`; dialect v0.6 itself
added expressions without any RPC — the shared-wire transport of §9 is a protocol revision, not a
dialect change; `mult_combine_batch` remains for the owner-computed mode).
