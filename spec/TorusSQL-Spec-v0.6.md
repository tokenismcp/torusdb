# TorusSQL Dialect Specification — v0.6

**Status:** current (unreleased until the next package release). Supersedes
`TorusSQL-Spec-v0.5.md` (kept for history; every v0.1–v0.5 statement keeps its
meaning — see §10). Conformance is executable: `spec/conformance/` (the open
validator and the engine must agree on every case).

v0.6 adds **arithmetic expressions**: `+ - * /` over encrypted, plain and literal
operands, products of **arbitrary multiplicative depth**, and **division** (by a
public value, and by an encrypted value). Everything else is v0.5.

---

## 1. Model

A table has typed columns, each with a **policy**:

| Policy | Stored on the server as | Usable in `WHERE`, `ORDER BY`, `GROUP BY`, `JOIN ON`, `MIN`/`MAX` | Usable in `SUM`, `AVG`, `k*col`, and in *linear* positions of an expression | Usable as an operand of a ciphertext × ciphertext product or an encrypted denominator (`a*b`, `DOT`, `a/b`) |
|---|---|:-:|:-:|:-:|
| `PLAIN` | the value itself | yes | as a public operand | n/a (public) |
| `ENC` | a one-time-padded scalar | no | yes | no |
| `PAIRED` | a one-time-padded scalar | no | yes | yes |
| `FHE` | a 384-byte ciphertext the server can add/multiply (INT only, experimental) | no | `SUM`/`AVG` only | `DOT` (two `FHE` columns); depth-1 products of integer-linear forms, aggregated, in expressions (§5.9) |

Types: `INT`, `RATIONAL` (exact fractions), `STR` (always `PLAIN`).
`AVG` accepts any numeric column (`PLAIN`, `ENC`, `PAIRED`).

What the *reference engine* does with these (informative; the dialect fixes the
meaning of the result, not the method): every intermediate of an expression is
a two-party additive sharing (the server holds one share, the owner the other);
sums and public-scalar multiples are local to each party (Π_lin); every product
of two encrypted operands is a Beaver-triple exchange (Π_mult) with one round per
multiplicative level; a division by an encrypted denominator opens only a
uniform masked product. §5.10 states exactly which party computes what.

## 2. Lexical

Case-insensitive keywords; identifiers `[A-Za-z_][A-Za-z_0-9]*`; strings in
single quotes (`''` escapes a quote); integers `-?[0-9]+`; `FRAC(n, d)` rational
literal (`d ≠ 0`); `NULL`; comments `-- …` and `/* … */`; an optional trailing `;`.
Operators `+ - * /` and parentheses (v0.6).
Reserved (cannot be aliases): `JOIN INNER LEFT OUTER ON WHERE GROUP ORDER HAVING
LIMIT AS FROM SELECT AND OR IN BY`.

Two lexical consequences of the expression grammar:

* The tokeniser reads `-5` as one integer literal. In operator position a
  negative literal is a subtraction (`a-1` is `a - 1`; `a -1` is too).
* `--` starts a comment, as in SQL. Write `a - -1` (or `a - (-1)`), never `a--1`.

## 3. Statements

```
CREATE TABLE [IF NOT EXISTS] t ( col type policy {, col type policy} )
DROP TABLE [IF EXISTS] t
CREATE INDEX ON t ( col )          -- PLAIN columns only; speeds = < <= > >= IN
DROP INDEX ON t ( col )
INSERT INTO t ( col {, col} ) VALUES ( lit {, lit} )      -- every column must be listed
UPDATE t SET col = lit {, col = lit} [WHERE pred]
DELETE FROM t [WHERE pred]
SELECT … (see §4)
```

`UPDATE` re-blinds encrypted columns with fresh masks. `DELETE` tombstones rows
(row ids are never reused). `WHERE` in `UPDATE`/`DELETE` follows §6. Expressions
appear in `SELECT` lists only (not in `INSERT`/`UPDATE` values or predicates).

## 4. SELECT

```
SELECT [DISTINCT] ( * | item {, item} )
FROM table [[AS] alias]
     { [INNER | LEFT [OUTER]] JOIN table [[AS] alias] ON colref = colref }
[WHERE pred]
[GROUP BY colref {, colref}]
[HAVING COUNT(*) op int]
[ORDER BY colref [ASC | DESC]]
[LIMIT int [OFFSET int]]

item   ::= proj [AS name]
proj   ::= expr | MIN(colref) | MAX(colref) | DOT(colref, colref)
colref ::= column | instance.column
```

`expr` is defined in §5.1. The v0.5 projections are all expressions of that grammar
or keep their v0.5 spelling:
`colref | COUNT(*) | SUM(colref) | AVG(colref) | int * colref | int * SUM(colref) | colref * colref`.

### 4.1 Instances, qualification, aliases

Each `FROM`/`JOIN` occurrence is a table **instance** named by its alias, else by
the table name. Instance names must be unique, so a table joined to itself needs
aliases. An alias *replaces* the table name (`FROM emp e` ⇒ `emp.col` is invalid,
`e.col` is valid). A bare column must be unambiguous across the instances in
scope, otherwise the statement is rejected (`ambiguous`). Qualified names also
work on single-table queries.

Output column names are `col` for single-table queries and `instance.col` when
joins are present (`SELECT *` expands every instance in order); `AS name` overrides.
An expression without `AS` is named by its canonical text (`sum(a*b)/count(*)`).

### 4.2 Joins

* The `ON` condition is **one equality** between a column of the joined table and
  a column of any *earlier* instance (either order). Both columns must be `PLAIN`,
  and both numeric or both `STR`.
* `INNER JOIN` keeps matching pairs; `LEFT [OUTER] JOIN` also keeps each left row
  with no match, with every column of the joined instance `NULL`.
* `NULL` keys never match (not even each other).
* Any number of joins; they apply left to right.
* Execution is a hash join at the owner on plaintext key columns. The server
  learns which rows were fetched, never an encrypted value (threat model §3).

### 4.3 Capability classes

`SUM`, `k*col`, `k*SUM`, `AVG`, `COUNT(*)`, `MIN/MAX` (PLAIN numeric), `a*b` and
`DOT(a,b)` (v0.1–v0.5) and, since v0.6, expressions (§5). With joins the operands
may come from different instances (`DOT(a.x, b.y)`, `SUM(p.budget)`,
`SUM(e.sal * d.bonus * d.fx)`); rows where an operand instance is `NULL` (left
join) are skipped by aggregates (`SUM`, `AVG`, `DOT`, `MIN`, `MAX`) and yield
`NULL` in per-row results, but are counted by `COUNT(*)`. An aggregate over zero
rows: `COUNT`→0, `SUM`→0, `DOT`→0, `AVG`/`MIN`/`MAX`→`NULL`.

### 4.4 Aggregates without `GROUP BY`

If any projection is an aggregate or a per-row encrypted expression
(`SUM AVG MIN MAX COUNT DOT k*col a*b`, or any v0.6 expression), the result is
**one row**; plain columns in that row are returned as a list of the selected
values. A *per-row* encrypted expression contributes one **list** (one entry per
selected row, `NULL` where an operand is `NULL`), exactly like `a * b` in v0.5;
an *aggregate* expression contributes one value. Per group, the same with
`GROUP BY`. `LIMIT`/`OFFSET` do not apply to a per-row encrypted expression
without `GROUP BY` (it is returned as one list), and `ORDER BY` has no effect on
an aggregate result (both rejected, as in v0.5).

### 4.5 GROUP BY / HAVING

Group keys are `PLAIN` columns of any instance. Every non-aggregate projection
must be a group key; `SELECT *` cannot be combined with `GROUP BY`. `HAVING` is
`COUNT(*) op n` and requires `GROUP BY`. Groups appear in first-seen order unless
`ORDER BY` is given; `NULL` forms its own group. Aggregate expressions are
evaluated once per group (`SELECT dept, SUM(a*b)/COUNT(*) … GROUP BY dept`).

### 4.6 ORDER BY / LIMIT / DISTINCT

`ORDER BY` takes one `PLAIN` column of any instance. It need not be selected,
except with `DISTINCT` or `GROUP BY` (then it must be selected / a group key).
`NULL` sorts **last** ascending and **first** descending. `LIMIT n [OFFSET m]`
apply after ordering (`OFFSET` skips `m` rows first). `DISTINCT` removes duplicate output rows (order-stable).

## 5. Arithmetic expressions (v0.6)

### 5.1 Grammar

```
expr    ::= term { ('+' | '-') term }
term    ::= unary { ('*' | '/') unary }
unary   ::= '-' unary | primary
primary ::= int | FRAC(int, int) | colref | '(' expr ')'
          | SUM(expr) | AVG(expr) | COUNT(*)
```

`*` and `/` bind tighter than `+` and `-`; all four are left-associative
(`a/b/c = (a/b)/c`, `a-b-c = (a-b)-c`). `SUM`/`AVG` arguments cannot contain
another aggregate. `MIN`, `MAX` and `DOT` stay whole projections (they cannot be
operands: `DOT(a,b)*2` is a parse error — write `2 * SUM(a*b)`).
An expression's tree height is limited to **100** (`ParseError` beyond: the
parser, validator and engine all recurse over it).

### 5.2 Kinds of expression

* **row** — contains columns outside aggregates (`a*b+c`, `s/2`). One value per
  selected row; returned as one list (§4.4).
* **agg** — contains aggregates and no bare columns (`SUM(a*b)/COUNT(*)`,
  `SUM(a)*SUM(b)`, `COUNT(*)*2`). One value per query or group.
* Mixing the two (`a + SUM(a)`), or an expression with neither (`1 + 2`), is
  rejected.

An operand is **encrypted** if it depends on an `ENC`/`PAIRED` column (directly or
through an aggregate of one) and **public** otherwise (literals, `PLAIN` columns,
`COUNT(*)`). A row expression must contain at least one `ENC`/`PAIRED` column
(an expression over `PLAIN` columns only is rejected: select the columns and
compute client-side); `SUM(expr)` needs an encrypted argument.

### 5.3 Policy rules (checked identically by the open validator and the engine)

1. `STR` columns cannot appear in an expression. `FHE` columns appear only in the
   shapes of §5.9 (v0.6.1) and never next to `PLAIN`/`ENC`/`PAIRED` columns; otherwise they keep
   `SUM`, `AVG`, `k*SUM`, `DOT`.
2. `+`, `-`, unary `-`, **public × encrypted** and **encrypted / public** are
   *linear*: any `ENC` or `PAIRED` column may appear there.
3. **Encrypted × encrypted** (a *ciphertext product*) and **a division whose
   denominator is encrypted** additionally require every `ENC`/`PAIRED` column
   in the operands involved to be `PAIRED` (an `ENC` column is additive-only).
   `s*a*b` with `s ENC` is rejected; `s + a*b` is fine.
4. Constants are folded exactly (`a / (1/3 + FRAC(1,6))` is `a / FRAC(1,2)`). A
   constant denominator equal to `0`, after folding, is rejected. Constants with
   `|numerator| > 2^126` or `denominator > 2^126` are rejected.
5. `col * col` where exactly one factor is `PLAIN` is a public-scalar product (v0.5
   rejected it); two `ENC` factors, or `PLAIN * PLAIN`, remain rejected.

### 5.4 Multiplicative depth

The **depth** of an expression is the largest number of sequential ciphertext
products on any path from a leaf to the result:

| node | depth |
|---|---|
| column, literal, `COUNT(*)` | 0 |
| `+ - neg`, public × encrypted, encrypted / public, `SUM/AVG(e)` | max of the operands' depths |
| encrypted × encrypted | 1 + max of the operands' depths |
| encrypted / encrypted | 1 + max of the operands' depths |
| public / encrypted (`100/c`) | depth of the denominator |

`a*b*c*d` (left-associative) has depth 3; `(a*b)*(c*d)` has depth 2 with three
products. Depth is the number of **request/response exchanges** the reference engine
spends on products (§5.10; one more per division by an encrypted value in
`expr_mode="shared"`); the number of products is `ct_muls` per row.
An engine MAY refuse expressions deeper than a configured maximum, MUST do so
with a depth error (`DepthLimitExceeded`, a `PlanError`) **before** sending any
request, and MUST support at least depth 3. The reference engine's default is
`max_mult_depth = 8` (`NoKeyClient(max_mult_depth=…)`, `connect(..., max_mult_depth=…)`);
it is an operational limit, not a dialect rule, so the open validator does not
apply it. Each level costs one round trip: raise the limit deliberately.

### 5.5 Division

`/` is **exact rational division**: `7/2` is `7/2`, never `3`. Results are `int`
when integral and `Fraction` otherwise.

* **By a public value** (`s/2`, `a/FRAC(2,3)`, `a/q` with `q PLAIN`): multiplication
  by the inverse of the denominator. No ciphertext product, no extra round.
* **By an encrypted value** (`a/b`, `100/c`, `SUM(a)/SUM(c)`): without decrypting the
  denominator, §5.10. If the numerator is also encrypted this is one more ciphertext product (depth +1).
* **Zero.** If a denominator evaluates to `0` in any row the query selects, the
  engine raises `DivisionByZero` (a `ZeroDivisionError` and an `ExecError`; DB-API
  `DataError`). Rows removed by `WHERE` do not count; `NULL` operands propagate
  and are skipped. `SUM(a)/COUNT(*)` over zero rows divides by zero and raises.
  A constant zero denominator is rejected at validation time instead (§5.3).
* **Never silent.** A quotient or product whose exact value lies outside the
  exactness contract (§7) raises `OutOfBudget`; it is never rounded or wrapped.

### 5.6 `NULL`

A row whose expression has a `NULL` operand (a `NULL` `PLAIN` cell, or the null
side of a `LEFT JOIN`) yields `NULL` in a per-row result and is skipped by `SUM`
and `AVG`. `AVG` over no rows is `NULL` and propagates through arithmetic.

### 5.7 Result types and ordering

A per-row expression returns one list in selected-row order (scan order, as for
`a*b`); an aggregate expression returns a number. No ordering is defined between
different expressions of one `SELECT`.

### 5.8 Compatibility with the v0.5 projection forms

The parser returns the v0.5 node for exactly the v0.5 shapes: `col`, `SUM(col)`,
`AVG(col)`, `COUNT(*)`, `k*col`, `-k*col`, `k*SUM(col)`, `col*col`, `MIN`, `MAX`,
`DOT`. Their results and rules are unchanged (in particular `col*col` still needs
two `PAIRED` columns and `DOT` still needs `INT`). Anything else that parses is an
expression. `SUM(a*b)` is the expression form of `DOT(a,b)` and, unlike `DOT`, is
also defined for `RATIONAL` columns.

### 5.9 `FHE` columns (revised in v0.6.1)

`FHE` columns keep `SUM`, `AVG`, `k*SUM` and depth-1 `DOT`. A statement over `FHE` columns is also an
expression when it is a **public affine combination** (`+`, `-`, unary `-`, `* literal`, `/ nonzero literal`; `AVG`'s `1/n`)
of terms with at least one **product** `L * R` whose operands are **integer-linear forms** `k1*c1 + ... + k0` of `FHE`
columns (`|k|, |k0| <= 2^40`, at most 16 columns), aggregated as `SUM(L*R)` (row by row), as `AL * AR` with `AL`, `AR`
integer-linear forms of `SUM(col)`s (`k1*SUM(c1) + ... + k0`), or `AVG(L*R)`; plain `SUM(L)` terms may accompany a
product. Examples: `SUM((a+2*b)*(c-d))`, `SUM(a)*SUM(b)`, `2*SUM(a*b) - SUM(c*d)/4 + 7`, `AVG(a*b)`.
The single spelling `SUM(x*y)` of two bare `FHE` columns (= `DOT(x,y)`) stays rejected, with the pre-v0.6.1 message.
Everything else is **rejected** with an error naming `FHE`; no wrong value is ever produced: a product of a product
(`SUM(a*b)*SUM(c)`, `SUM(a*b*c)`: the ciphertext scheme has one multiplicative level and an intermediate is never decrypted
or re-encrypted), division by anything but a literal, `x+1`, `SUM(x)/COUNT(*)`, non-integer or oversized operand coefficients,
`FHE` mixed with other column policies, per-row (non-aggregated) values, joins. The result of an `FHE` expression has
multiplicative depth 0 in the sense of §5.4 (no owner round trips exist); the ciphertext product is computed by the server
from public ciphertext data and opened by the owner, who then applies the public affine part exactly (`Fraction`). A result
term outside the key's range is an error. Integrity: delegated products are unauthenticated; an authenticated connection
verifies by recomputing at the owner (docs/fhe-columns.md).

### 5.10 Who computes what (informative: reference engine, `expr_mode="shared"`)

*Transport revision (wire protocol 2.1, no dialect change).* The first v0.6 engine evaluated
expressions at the owner (the owner unmasked every operand and computed every product itself;
that transport is still available as `expr_mode="owner"`, below). The reference engine now
implements the no-key paper's circuit composition Π_C: **every wire of the expression is a
two-party additive sharing over Z/nZ, and no operand, product or quotient is ever fetched,
unmasked or computed in plaintext by anyone's code.** Results, grammar, errors and caps are
unchanged; only who holds what changes. `docs/crypto-review-packet.md` §3.3 has the proof sketch.

**Wires.** A wire `X` is `X = X_S + X_O (mod n)`. A stored cell `x̃ = x + r` is the wire with
`X_S = x̃` (the server's own stored value) and `X_O = −r` (the mask the owner already holds); a
literal or plain value is public (`X_S = v`, `X_O = 0`). The server keeps its shares in a
**session-scoped wire store** (below); the owner keeps its shares locally.

| gate | server (on its shares) | owner (on its shares) | communication |
|---|---|---|---|
| `+`, `−`, unary `−`, × public, ÷ public (× `k⁻¹ mod n`), + public, `SUM`, `AVG`, broadcast | same operation on `X_S` | same operation on `X_O` (a public `+c` is added by the server only) | none |
| linear `SUM(Σκ·col)` | one `loadsum` (Σ of stored cells) | `−Σ r`, public coefficients | none beyond the batch |
| `X · Y` (encrypted × encrypted) | `e_S = X_S − u_S`, `g_S = Y_S − v_S`; then `Z_S = w_S + e·v_S + g·u_S + e·g`, **stored as a new wire** | deals a fresh Beaver triple `(u, v, w=uv)` per product element, additively shared (the server gets only its shares); `e_O = X_O − u_O`, `g_O = Y_O − v_O`; `Z_O = w_O + e·v_O + g·u_O` | one request/response **per multiplicative level**, batched over every row and sub-expression of the level; `e = e_S + e_O`, `g = g_S + g_O` are learned by both, uniform and independent of `X, Y` |
| `X / Y` (encrypted `Y`) | `[ρ]·[Y]` as above; then × `t⁻¹` | deals a uniform **non-zero** `ρ` (shared); sees `t = ρ·Y` (uniform on non-zero values); if `t = 0` (a zero denominator) substitutes a fresh random non-zero dummy; `[1/Y] = t⁻¹·[ρ]` | `t` is opened to the owner inside the product's request; the server learns only `t⁻¹` (a dummy when `Y = 0`): nothing about `Y`, not even whether it was zero. Then `x/Y = x·[1/Y]` is one more product level |
| result | sends **its share** of the result wire(s) (`wire_exec reveal`) | adds its own share, strict decode (`OutOfBudget`), `DivisionByZero` raised only after the last request | the server never receives the result or any intermediate |

* **Rounds.** `mult_rounds` = the sequential product levels = `depth` (§5.4) + one per sequential
  division by an **encrypted** value (the product `ρ·Y` is a level of its own). Dividing by a public
  value costs nothing. A query exchanges `mult_rounds + 1` requests (the last one reveals), chunked
  to the server's advertised `max_request_elements`. The reference client exposes
  `last_expr_cost = {mode, depth, mult_rounds, products, inversions, linear_sums, openings, wires,
  requests, reveals}`; `max_mult_depth` caps `mult_rounds` and is checked before any request.
* **Work.** The server does O(rows) ring operations per level on its shares; the owner does O(rows)
  local ring arithmetic per level on its shares (a fresh triple per product element, one opening
  pair) and sends/receives O(rows) openings per level. This O(rows) owner work is inherent to
  unconditionally secure two-party computation; what the owner does **not** do is fetch an operand
  cell, remove an operand's mask, or compute any product or quotient. There is no speed-up claim:
  the guarantee is *where the intermediates live*.
* **What each party learns.** The server: query shape (δ, products per level, row count, which
  rows), and uniform values only (`x̃`, its triple shares, `e_O`, `g_O`, `ρ_S`, `t⁻¹`); I(M; V_S)=0,
  unconditionally. The owner, **as the dealer of `(u, v)` and `ρ`**: the openings
  `e = X−u`, `g = Y−v` and `t = ρY`, together with values it dealt, determine the operands — so an
  owner *willing to compute them could*; this engine never does (nothing but the result is decoded;
  `tests/test_expr_shared*.py` pin it). Making the owner cryptographically blind to intermediates needs
  a third party or a computational assumption (OT/HE triple generation) and is out of scope (review
  packet §3.3, question (d)). A **multi-owner** deployment cannot use a single owner as dealer
  either (see the threat model).
* **Server state.** The wire store is per session, capped (`--wire-max-wires` 4096, `--wire-max-elements`
  4 000 000 per session and `--wire-max-total-elements` 32 000 000 server-wide; a tagged wire counts
  twice), expires unused wires after `--wire-ttl` (120 s), and is emptied at query end, on
  `COMMIT`/`ROLLBACK`/transaction timeout and on disconnect. Exceeding a cap is a `WireError`
  (DB-API `OperationalError`) naming the cap; nothing is silently truncated. The advertised limits
  are in `hello` → `limits.wires`. The store holds no key, mask, MAC key or plaintext, and the wire
  RPCs are `ro`-permitted reads (they read only the stored cells of the rows they are asked to load).
* **Integrity (`authenticated=True`).** Every wire also carries shares of its SPDZ tag `α·X` (the
  stored MAC cells are loaded exactly like the values; `α` is never sent). Every opening is
  MAC-checked by the owner, a division's opened `t` is MAC-checked **before** it is tested for zero
  (so an active attacker gets `IntegrityError`, never a zero oracle), and the revealed result is
  MAC-checked before it is decoded: a server that tampers with a stored cell, a share, an opening or
  a reply is detected except with probability ≤ (depth+1)·#checks/n (sketch: review packet §3.3).
  **Without `authenticated=True` the engine is secure against a semi-honest server only**: a lying
  server can shift any result by an amount it chooses and, by shifting a denominator's share, learn
  whether that denominator equals a guess (the owner's `DivisionByZero` is the oracle). Row sets
  (`WHERE`, joins, which rows exist) are plain data and are not authenticated in either mode.
* **Abort oracle.** A zero denominator does not change the request sequence the server sees
  (`tests/test_expr_shared*.py` compare the traces): the dummy `t` has the same distribution as a real one.
* **`expr_mode="owner"`** (driver option, `connect(..., expr_mode="owner")`, shell `--expr-mode owner`):
  the v0.6 transport — the owner reads and unmasks the operand cells, computes every product and
  quotient in plaintext, and the server only multiplies two openings (`mult_combine_batch`). It needs
  no wire RPC (works with any v2 server) and is kept for compatibility; its server view is also
  uniform, but nothing is held at the server and every operand is unmasked at the owner (review
  packet F-3 / F-18). Both modes return identical results.

## 6. Predicates

```
pred ::= and { OR and }        and ::= atom { AND atom }
atom ::= colref op literal  |  colref IN ( literal {, literal} )
      |  colref NOT IN ( literal {, literal} )
      |  colref BETWEEN literal AND literal        -- = col >= lo AND col <= hi
      |  colref IS [NOT] NULL
      |  colref [NOT] LIKE 'pattern'               -- STR columns; % any run, _ one char
op   ::= = != <> < > <= >=
```

Disjunctive normal form (no parentheses; `AND` binds tighter). Columns must be
`PLAIN`; a `NULL` operand makes every atom false except `IS NULL` (so `NOT IN`,
`NOT LIKE` and `!=` never match a NULL cell). `LIKE` is case-sensitive and has no
`ESCAPE` clause. In a join, atoms may reference any
instance; atoms on the `FROM` table are evaluated at the server's plaintext index,
others on the joined rows. Predicates take no expressions.

## 7. Exactness contract

Encrypted values are exact integers/rationals in `Z/nZ` (n ≈ 2^254). A value is
representable iff `|numerator| ≤ 2^126`, `denominator ≤ 2^126` and
`|numerator|·denominator < 2^189`. `INSERT`/`UPDATE` of anything else, and any
**result** (a sum that overflowed, a product, a quotient) outside that range,
raises `OutOfBudget` — a wrong value is never returned.

All arithmetic is exact ring/field arithmetic in `Z/nZ`, so an *intermediate* value
outside the range is harmless when the final result is back inside it
(`a*b/b` with `a*b ≈ 2^200` returns `a`); only the final result is decoded and
checked. A result outside the range is detected with probability `1 − 2^-64`
(the decode margin of v0.5), as for `SUM`. Rational `DOT` is rejected (§4.5 of
v0.1); `SUM(a*b)` over rational columns is exact.

## 8. Errors

`ParseError` (syntax, expression height > 100) · `ValidationError`/`PlanError`
(illegal under policy/type/scope rules — open validator and engine reject the same
statements, including every §5.3 rule) · `DepthLimitExceeded` (`PlanError`; engine
setting, §5.4) · `DivisionByZero` (`ExecError` and `ZeroDivisionError`; §5.5) ·
`OutOfBudget` · `IntegrityError` (authenticated mode detected tampering) · server
errors (`Unauthenticated`, `Forbidden`, `Busy`, `BadRequest`, `InternalError`).

## 9. Out of scope

Predicates, ordering, grouping or joining on encrypted columns; expressions in
predicates or in `INSERT`/`UPDATE` values; arithmetic on `FHE` columns beyond
§5.9 (depth > 1, division, per-row values); operators other than `+ - * /` (no `%`, `^`, functions); integer (truncating)
division; `MIN`/`MAX`/`DOT` as expression operands; `RIGHT`/`FULL`/`CROSS`
joins, non-equi joins, subqueries, `UNION`; multi-column `ORDER BY`; `HAVING`
other than `COUNT(*)`.

## 10. Changes

| Version | Added |
|---|---|
| 0.1 | CREATE/DROP/INSERT/SELECT, `SUM`, `k*col`, `a*b`, `DOT`, plain `WHERE =` |
| 0.2 | `COUNT(*)`, `AVG`, `MIN/MAX`, `AND/OR/IN`, comparison ops, `ORDER BY`, `LIMIT`, `AS` |
| 0.3 | `UPDATE`, `DELETE`, `DISTINCT`, `GROUP BY`, `HAVING COUNT(*)` |
| 0.4 | `[INNER] JOIN … ON a = b`, qualified names |
| 0.5+ | column policy `FHE` (INT; `SUM`, `AVG`, `COUNT`, `DOT`, projection — see docs/fhe-columns.md) |
| 0.5+ | `CREATE/DROP INDEX`, `IF [NOT] EXISTS`, `OFFSET`, `BETWEEN`, `NOT IN`, `IS [NOT] NULL`, `[NOT] LIKE` |
| 0.5 | table aliases, self-joins, multiple joins, `LEFT [OUTER] JOIN`, `GROUP BY`/`HAVING` over joins, `WHERE` on any joined table, `DOT`/`a*b` across tables, `ORDER BY` an unselected column, qualified names on single-table queries, strict exactness errors (`OutOfBudget`) |
| **0.6** | **arithmetic expressions** `+ - * /`, unary minus, parentheses, literals (`int`, `FRAC`); **products of arbitrary depth** (one round per level, configurable maximum, default 8; transport revised to secret-shared wires in wire protocol 2.1 without any dialect change, §5.10); **division** by public and by encrypted values with `DivisionByZero`; `SUM(expr)`, `AVG(expr)`, aggregate expressions (`SUM(a*b)/COUNT(*)`, `SUM(a)*SUM(b)`); `col * col` with one `PLAIN` factor |
| 0.6.1 | expressions over `FHE` columns: depth-1 products of integer-linear forms, aggregated, with a public affine part (§5.9) |

All v0.1–v0.5 statements keep their meaning and result. v0.6 only makes some
previously illegal statements legal (anything that used `/`, a product of more than
two operands, an arithmetic operator after a projection, or `PLAIN * PAIRED`); the
one parse-time difference is that a projection such as `SELECT 5 FROM t`, which v0.5
rejected as a syntax error, is now parsed and rejected by validation (no column).
