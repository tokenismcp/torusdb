# TorusSQL Dialect Specification — v0.5

**Status:** current. Supersedes `TorusSQL-Spec-v0.1.md` (kept for history; every
v0.1–v0.4 statement keeps its meaning — see §9). Conformance is executable:
`spec/conformance/` (open validator and engine must agree on every case).

---

## 1. Model

A table has typed columns, each with a **policy**:

| Policy | Stored on the server as | Usable in `WHERE`, `ORDER BY`, `GROUP BY`, `JOIN ON`, `MIN`/`MAX` | Usable in `SUM`, `AVG`, `k*col` | Usable in `DOT`, `a*b` |
|---|---|:-:|:-:|:-:|
| `PLAIN` | the value itself | yes | no | no |
| `ENC` | a one-time-padded scalar | no | yes | no |
| `PAIRED` | a one-time-padded scalar | no | yes | yes |

Types: `INT`, `RATIONAL` (exact fractions), `STR` (always `PLAIN`).
`AVG` accepts any numeric column (`PLAIN`, `ENC`, `PAIRED`).

Everything that the server can compute is an affine form (Π_lin) or a depth-1
product (Π_mult) over blinded scalars; everything else (predicates, ordering,
grouping, joining) runs on `PLAIN` columns at the owner or server index.

## 2. Lexical

Case-insensitive keywords; identifiers `[A-Za-z_][A-Za-z_0-9]*`; strings in
single quotes (`''` escapes a quote); integers `-?[0-9]+`; `FRAC(n, d)` rational
literal (`d ≠ 0`); `NULL`; comments `-- …` and `/* … */`; an optional trailing `;`.
Reserved (cannot be aliases): `JOIN INNER LEFT OUTER ON WHERE GROUP ORDER HAVING
LIMIT AS FROM SELECT AND OR IN BY`.

## 3. Statements

```
CREATE TABLE t ( col type policy {, col type policy} )
DROP TABLE t
INSERT INTO t ( col {, col} ) VALUES ( lit {, lit} )      -- every column must be listed
UPDATE t SET col = lit {, col = lit} [WHERE pred]
DELETE FROM t [WHERE pred]
SELECT … (see §4)
```

`UPDATE` re-blinds encrypted columns with fresh masks. `DELETE` tombstones rows
(row ids are never reused). `WHERE` in `UPDATE`/`DELETE` follows §5.

## 4. SELECT

```
SELECT [DISTINCT] ( * | item {, item} )
FROM table [[AS] alias]
     { [INNER | LEFT [OUTER]] JOIN table [[AS] alias] ON colref = colref }
[WHERE pred]
[GROUP BY colref {, colref}]
[HAVING COUNT(*) op int]
[ORDER BY colref [ASC | DESC]]
[LIMIT int]

item   ::= proj [AS name]
proj   ::= colref | COUNT(*) | SUM(colref) | AVG(colref) | MIN(colref) | MAX(colref)
         | int * colref | int * SUM(colref) | colref * colref | DOT(colref, colref)
colref ::= column | instance.column
```

### 4.1 Instances, qualification, aliases

Each `FROM`/`JOIN` occurrence is a table **instance** named by its alias, else by
the table name. Instance names must be unique, so a table joined to itself needs
aliases. An alias *replaces* the table name (`FROM emp e` ⇒ `emp.col` is invalid,
`e.col` is valid). A bare column must be unambiguous across the instances in
scope, otherwise the statement is rejected (`ambiguous`). Qualified names also
work on single-table queries.

Output column names are `col` for single-table queries and `instance.col` when
joins are present (`SELECT *` expands every instance in order); `AS name` overrides.

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

### 4.3 Capability classes (unchanged since v0.1)

`SUM`, `k*col`, `k*SUM`, `AVG`, `COUNT(*)`, `MIN/MAX` (PLAIN numeric), `a*b` and
`DOT(a,b)` (both `PAIRED`; `DOT` only `INT`). With joins the operands may come
from different instances (`DOT(a.x, b.y)`, `SUM(p.budget)`); rows where an operand
instance is `NULL` (left join) are skipped by aggregates (`SUM`, `AVG`, `DOT`,
`MIN`, `MAX`) and yield `NULL` in per-row results, but are counted by `COUNT(*)`.
An aggregate over zero rows: `COUNT`→0, `SUM`→0, `DOT`→0, `AVG`/`MIN`/`MAX`→`NULL`.

### 4.4 Aggregates without `GROUP BY`

If any projection is an aggregate or per-row encrypted expression
(`SUM AVG MIN MAX COUNT DOT k*col a*b`), the result is **one row**; plain columns
in that row are returned as a list of the selected values.

### 4.5 GROUP BY / HAVING

Group keys are `PLAIN` columns of any instance. Every non-aggregate projection
must be a group key; `SELECT *` cannot be combined with `GROUP BY`. `HAVING` is
`COUNT(*) op n` and requires `GROUP BY`. Groups appear in first-seen order unless
`ORDER BY` is given; `NULL` forms its own group.

### 4.6 ORDER BY / LIMIT / DISTINCT

`ORDER BY` takes one `PLAIN` column of any instance. It need not be selected,
except with `DISTINCT` or `GROUP BY` (then it must be selected / a group key).
`NULL` sorts **last** ascending and **first** descending. `LIMIT` applies after
ordering. `DISTINCT` removes duplicate output rows (order-stable).

## 5. Predicates

```
pred ::= and { OR and }        and ::= atom { AND atom }
atom ::= colref op literal  |  colref IN ( literal {, literal} )
op   ::= = != <> < > <= >=
```

Disjunctive normal form (no parentheses; `AND` binds tighter). Columns must be
`PLAIN`; a `NULL` operand makes an atom false. In a join, atoms may reference any
instance; atoms on the `FROM` table are evaluated at the server's plaintext index,
others on the joined rows.

## 6. Exactness contract

Encrypted values are exact integers/rationals in `Z/nZ` (n ≈ 2^254). A value is
representable iff `|numerator| ≤ 2^126`, `denominator ≤ 2^126` and
`|numerator|·denominator < 2^189`. `INSERT`/`UPDATE` of anything else, and any
result (e.g. a sum that overflowed) outside that range, raises `OutOfBudget` — a
wrong value is never returned. Rational `DOT` is rejected (§4.3 of v0.1).

## 7. Errors

`ParseError` (syntax) · `ValidationError`/`PlanError` (illegal under policy/type/
scope rules — open validator and engine reject the same statements) ·
`OutOfBudget` · `IntegrityError` (authenticated mode detected tampering) · server
errors (`Unauthenticated`, `Forbidden`, `Busy`, `BadRequest`, `InternalError`).

## 8. Out of scope

Predicates, ordering, grouping or joining on encrypted columns; multiplication
depth > 1; `RIGHT`/`FULL`/`CROSS` joins, non-equi joins, subqueries, `UNION`;
multi-column `ORDER BY`; `HAVING` other than `COUNT(*)`; `LIKE`; `NULL` literals
in predicates (`IS NULL`).

## 9. Changes

| Version | Added |
|---|---|
| 0.1 | CREATE/DROP/INSERT/SELECT, `SUM`, `k*col`, `a*b`, `DOT`, plain `WHERE =` |
| 0.2 | `COUNT(*)`, `AVG`, `MIN/MAX`, `AND/OR/IN`, comparison ops, `ORDER BY`, `LIMIT`, `AS` |
| 0.3 | `UPDATE`, `DELETE`, `DISTINCT`, `GROUP BY`, `HAVING COUNT(*)` |
| 0.4 | `[INNER] JOIN … ON a = b`, qualified names |
| **0.5** | table aliases, **self-joins**, **multiple joins**, **`LEFT [OUTER] JOIN`**, `GROUP BY`/`HAVING` over joins, `WHERE` on any joined table, `DOT`/`a*b` across tables, `ORDER BY` an unselected column, qualified names on single-table queries, strict exactness errors (`OutOfBudget`) |

All v0.1–v0.4 statements keep their meaning, with two deliberate tightenings
that turn previously latent faults into errors: a non-aggregated, non-grouped
column under `GROUP BY` is rejected (it used to return a list), and values outside
the exactness range are rejected instead of decoding to a wrong number.
