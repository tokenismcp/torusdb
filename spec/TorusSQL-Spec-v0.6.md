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
| `FHE` | a 384-byte ciphertext the server can add/multiply (INT only, experimental) | no | `SUM`/`AVG` only | `DOT` (two `FHE` columns) only — **not** in expressions (§5.9) |

Types: `INT`, `RATIONAL` (exact fractions), `STR` (always `PLAIN`).
`AVG` accepts any numeric column (`PLAIN`, `ENC`, `PAIRED`).

What the *reference engine* does with these (informative; the dialect fixes the
meaning of the result, not the method): sums and public-scalar multiples of
blinded cells are affine forms (Π_lin) that the server evaluates; every product
of two encrypted operands is a Beaver-triple exchange (Π_mult) with one owner
round per multiplicative level; inversion of an encrypted denominator is done by
the owner. §5.10 states exactly which party computes what.

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

1. `STR` and `FHE` columns cannot appear in an expression (`FHE` columns keep
   `SUM`, `AVG`, `k*SUM`, `DOT`; §5.9).
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
products. Depth is the number of **owner round trips** the reference engine
spends on products (§5.10); the number of products is `ct_muls` per row.
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
* **By an encrypted value** (`a/b`, `100/c`, `SUM(a)/SUM(c)`): owner-assisted, §5.10.
  If the numerator is also encrypted this is one more ciphertext product (depth +1).
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

### 5.9 `FHE` columns

`FHE` columns are unchanged: depth-1 `DOT` between two `FHE` columns, `SUM`, `AVG`,
`k*SUM`. Anything deeper, any division, and any arithmetic around them is
**rejected** with an error naming `FHE` (`x*y*x`, `x/2`, `x+1`,
`SUM(x)/COUNT(*)`, `SUM(x*y)`); no wrong value is ever produced. Lifting this
needs a ciphertext scheme with a server-side multiplication of products, which
the `FHE` column type does not have.

### 5.10 Who computes what (informative: reference engine)

* **Server** (holds blinded cells `s̃ = s + r` and plaintext columns; no key, no
  mask): (i) Π_lin — sums of stored blinded cells, used for a *linear* `SUM(...)`
  (`SUM(a + 2*b - s/4)` is one blinded sum per column); (ii) Π_mult — for each
  ciphertext product, the step `e·g mod n` on the two *openings* it is sent.
* **Owner** (the driver; holds the masks and the MAC key): removes the masks of
  every cell it reads; applies every linear gate and every public multiplication
  or division locally; draws a fresh Beaver triple `(u, v, w = uv)` per product,
  sends `e = s − u`, `g = s' − v`, and reconstructs `s·s' = w + e·v + g·u + e·g`;
  inverts encrypted denominators; decodes and checks the final result.
* **Not offloaded.** The owner reconstructs both operands of every product before
  opening them, so the server's `e·g` is a product of two numbers the owner already
  holds. Products therefore cost the owner O(rows) work and bandwidth; the round
  trip is kept because it is the protocol of the no-key paper (Π_C) and, in
  authenticated mode, checks that the server computed `e·g` (§9 of the paper).
  Review packet §3.2 and finding F-3.
* **Intermediates** (a product, a quotient) exist only at the owner. They reach the
  server only inside the next level's opening `e = x − u` with fresh uniform `u`
  (the Π_boot re-mask) and never in any other form; the server holds no
  intermediate, decrypts nothing, and receives no mask.
* **Division by an encrypted `y`.** Inversion does not commute with an additive
  mask, so the server cannot invert a blinded `y`. The owner unmasks `y` (it holds
  the mask; an intermediate it already holds), tests `y = 0`, computes `y⁻¹ mod n`,
  and uses it as an operand: `x · y⁻¹` is a public multiplication if `x` is public,
  otherwise one more ciphertext product. The owner thereby learns `y` — it is the
  data owner and learns the cells it reads anyway; the server learns nothing new
  (its view is the same uniform openings).
* **Rounds.** `mult_rounds = depth`: all products of one level (every row, every
  subexpression) share one `mult_combine_batch` exchange (chunked to the server's
  `max_items`). The reference client exposes `last_expr_cost` =
  `{depth, mult_rounds, products, inversions, linear_sums}` for the last `SELECT`.
* **Integrity.** Authenticated mode MAC-checks every stored cell the owner reads
  and every blinded sum, and checks `e·g` of every product. An intermediate has no
  MAC (it never leaves the owner); without `authenticated=True` a lying server can
  alter a product term undetected (as for `DOT`).
* **No new RPC.** Expressions use only `blinded_cells`, `blinded_sum`,
  `blinded_scaled_sum` (authenticated MAC check), `mult_combine_batch`,
  `matching_rowids` and `plain_cells`.

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
v0.5; operators other than `+ - * /` (no `%`, `^`, functions); integer (truncating)
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
| **0.6** | **arithmetic expressions** `+ - * /`, unary minus, parentheses, literals (`int`, `FRAC`); **products of arbitrary depth** (one owner round per level, configurable maximum, default 8); **division** by public and by encrypted values with `DivisionByZero`; `SUM(expr)`, `AVG(expr)`, aggregate expressions (`SUM(a*b)/COUNT(*)`, `SUM(a)*SUM(b)`); `col * col` with one `PLAIN` factor |

All v0.1–v0.5 statements keep their meaning and result. v0.6 only makes some
previously illegal statements legal (anything that used `/`, a product of more than
two operands, an arithmetic operator after a projection, or `PLAIN * PAIRED`); the
one parse-time difference is that a projection such as `SELECT 5 FROM t`, which v0.5
rejected as a syntax error, is now parsed and rejected by validation (no column).
