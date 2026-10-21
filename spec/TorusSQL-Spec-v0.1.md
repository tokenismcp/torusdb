# TorusSQL Specification — v0.1 (Draft)

> **Status:** Draft. This document defines the TorusSQL dialect: the SQL
> surface that a client may send to a TorusDB engine and the guarantees the
> engine makes back. It specifies **what** can be expressed and **what the
> result means** — never **how** the engine computes it.
>
> The execution engine (homomorphic operators, key management, query
> planning) is the closed TorusDB core and is intentionally out of scope.
> A conforming engine is free to implement these semantics by any means.

---

## 0. Design principles

1. **Capability-honest.** The dialect only admits operations the engine can
   evaluate over ciphertext. If an operation is not in this spec, it is not
   supported — there is no silent fallback that decrypts data server-side.
2. **Plaintext/ciphertext separation is in the type system.** Whether a
   column is readable by the server is declared at `CREATE TABLE` time via a
   *policy*, not inferred. The set of legal operations on a value is a
   function of its policy.
3. **Mechanism is invisible.** A query author reasons about *capabilities*
   (can I add these two encrypted columns? can I multiply them once?), never
   about curves, pairings, or noise budgets.
4. **Forward compatible.** Capability classes (§4) are versioned. New
   capabilities are additive; once a capability is in a released spec, its
   surface syntax and result semantics do not change incompatibly.

---

## 1. Lexical structure

- **Keywords** are case-insensitive (`SELECT` = `select`).
- **Identifiers** match `[A-Za-z_][A-Za-z_0-9]*` and are case-sensitive.
- **Integer literals**: `-?[0-9]+`.
- **String literals**: single-quoted, with `''` as an escaped quote:
  `'it''s'`.
- **Rational literals**: `FRAC(<int>, <int>)` with a non-zero denominator,
  e.g. `FRAC(2, 3)` denotes 2/3.
- **NULL**: the keyword `NULL`.
- **Comments**: `-- line` and `/* block */`.
- Statements may be terminated by an optional trailing `;`.

---

## 2. Type system

A column has a **base type** and a **policy**. Both are mandatory at
`CREATE TABLE`.

### 2.1 Base types

| Type       | Domain                                   | Literal form        |
|------------|------------------------------------------|---------------------|
| `INT`      | signed integers                          | `42`, `-7`          |
| `STR`      | UTF-8 text                               | `'alice'`           |
| `RATIONAL` | exact rationals a/b (b ≠ 0)              | `FRAC(2, 3)`        |

`RATIONAL` is a first-class numeric type — TorusSQL does **not** silently
coerce to floating point. An `INT` value `k` is the rational `k/1` and may
be used anywhere a `RATIONAL` is expected.

### 2.2 Policies

The policy declares what the server may do with the value and what it can
see.

| Policy   | Server can read? | Purpose                                              |
|----------|------------------|------------------------------------------------------|
| `PLAIN`  | yes              | filter keys, labels, anything safe to expose         |
| `ENC`    | no               | additive-homomorphic encrypted values                |
| `PAIRED` | no               | encrypted values that also admit one multiplication  |

`PAIRED` is a strict superset of `ENC` in capability: anything legal on an
`ENC` column is legal on a `PAIRED` column. `PAIRED` columns additionally
participate in `*` (ciphertext × ciphertext, §4.4) and `DOT` (§4.5). The
two policies are distinct because `PAIRED` storage is more expensive; an
author opts in only where multiplication is actually needed.

> **Note for engine implementors.** `ENC` and `PAIRED` are the only two
> ciphertext policies in v0.1. The spec deliberately exposes the existence
> of a "multipliable" policy without naming the technique that realizes it.

---

## 3. Statements

### 3.1 CREATE TABLE

```
CREATE TABLE <table> ( <column> <type> <policy> [, ...] )
```

```sql
CREATE TABLE payroll (
    id     INT      PLAIN,
    name   STR      ENC,
    salary RATIONAL ENC,
    rate   RATIONAL PAIRED,
    hours  RATIONAL PAIRED
);
```

### 3.2 DROP TABLE

```
DROP TABLE <table>
```

### 3.3 INSERT

```
INSERT INTO <table> ( <column> [, ...] ) VALUES ( <literal> [, ...] )
```

Each value is encrypted (or stored plain) according to its column's policy
at insert time. The column list and value list must have equal length.

```sql
INSERT INTO payroll (id, name, salary, rate, hours)
VALUES (1, 'alice', FRAC(8000,1), FRAC(50,1), FRAC(40,1));
```

### 3.4 SELECT

```
SELECT [ DISTINCT ] <projection_list> FROM <table>
       [ WHERE <predicate> ]
       [ GROUP BY <plain_column> [, <plain_column>]* ]
       [ HAVING COUNT( '*' ) <op> <int> ]
       [ ORDER BY <plain_column> [ ASC | DESC ] ]
       [ LIMIT <int> ]
```

`GROUP BY` partitions rows by one or more **`PLAIN`** key columns and produces
one output row per group, evaluating each aggregate (§4.2–§4.8) over that
group's rows. Every bare projected column must be a grouping column. `HAVING`
filters groups by their `COUNT(*)`. `DISTINCT` removes duplicate output rows.
Grouping on an encrypted column is rejected (the server cannot see its value).

```
projection_list ::= '*' | <aliased> [, <aliased>]*
aliased         ::= <projection> [ AS <name> ]      -- output-column alias
projection      ::= <column>                       -- pass-through
                  | SUM( <enc_column> )             -- §4.2
                  | <int> '*' <enc_column>          -- §4.3 per-row scale
                  | <int> '*' SUM( <enc_column> )   -- §4.3 scaled aggregate
                  | <enc_column> '*' <enc_column>   -- §4.4 formal multiply
                  | DOT( <int_column>, <int_column>)-- §4.5 inner product
                  | COUNT( '*' )                    -- §4.6 row count
                  | AVG( <num_column> )             -- §4.7 mean
                  | MIN( <plain_num_column> )       -- §4.8 min/max
                  | MAX( <plain_num_column> )       -- §4.8
predicate       ::= <and_group> [ OR <and_group> ]*            -- DNF (v0.2)
and_group       ::= <atom> [ AND <atom> ]*
atom            ::= <plain_column> <op> <literal>
                  | <plain_column> IN ( <literal> [, <literal>]* )
op              ::= '=' | '!=' | '<>' | '<' | '>' | '<=' | '>='
```

`AND` binds tighter than `OR` (no parentheses in v0.2), so the predicate is
in disjunctive normal form: an OR of AND-groups.

A `SELECT` returns a result set of encrypted and/or plaintext cells. The
key-holder decrypts client-side; the server never holds the decryption of
any `ENC`/`PAIRED` result.

#### WHERE (v0.2)

`WHERE` is a boolean combination (`AND`, `OR`, `IN`) of comparisons on
**`PLAIN` columns only**, in disjunctive normal form:

```sql
SELECT SUM(salary) FROM payroll WHERE dept = 5 AND grade >= 3;
SELECT id FROM payroll WHERE dept IN (5, 7) OR grade > 8;
```

`WHERE` defines the row set that aggregates (`SUM`, `DOT`, `COUNT`) consume.
Filtering on **encrypted** columns is still out of scope — predicate
evaluation over ciphertext is a separate capability class (§6). A conforming
engine MUST reject a predicate on an `ENC`/`PAIRED` column.

#### ORDER BY / LIMIT (v0.2)

`ORDER BY` sorts the **output rows** by a `PLAIN` column that appears in the
projection (or under `SELECT *`); `LIMIT` caps the number of output rows.
Both are presentation operations on the result — they do **not** change which
rows an aggregate consumes (that is `WHERE`'s job). `ORDER BY` on an encrypted
column is rejected (its plaintext order is not available to the server).

### 3.5 UPDATE (v0.3)

```
UPDATE <table> SET <column> = <literal> [, ...] [ WHERE <predicate> ]
```

Sets columns on the rows matching the (plaintext) predicate. Assigning an
`ENC`/`PAIRED` column re-encrypts the new value at the owner and re-blinds it;
the server only ever stores the new blinded scalar. Returns the affected count.

### 3.6 DELETE (v0.3)

```
DELETE FROM <table> [ WHERE <predicate> ]
```

Removes the rows matching the predicate (logical delete — subsequent queries
do not see them). Returns the affected count.

---

## 4. Capability classes

The heart of the spec. Each class defines an operation, the policies it
applies to, and the **exact value** the result decrypts to.

### 4.1 Pass-through (any policy)

A bare column reference returns the stored cell unchanged. `PLAIN` cells
come back readable; `ENC`/`PAIRED` cells come back as ciphertext for
client-side decryption.

### 4.2 Encrypted addition / aggregation — `SUM` (`ENC`, `PAIRED`)

```sql
SELECT SUM(salary) FROM payroll;
```

`SUM(c)` over an `ENC`/`PAIRED` column returns one ciphertext that decrypts
to the exact sum (in the `RATIONAL` domain) of the column's plaintext
values across the selected rows. Addition is **unbounded in count** — you
may sum arbitrarily many rows.

> Capability: additive homomorphism. Exact, no approximation.

### 4.3 Scalar multiplication — `<int> * <enc_column>` (`ENC`, `PAIRED`)

```sql
SELECT 12 * salary     FROM payroll;     -- per-row: each salary × 12
SELECT 12 * SUM(salary) FROM payroll;    -- aggregate: 12 × the encrypted total
```

A **public integer** `k` times an encrypted value scales it by `k`, exactly,
with the scalar plaintext and the value not:

- `k * col` is **per-row** — one scaled ciphertext per selected row.
- `k * SUM(col)` scales the **aggregate** — one ciphertext decrypting to
  `k · Σ(column)`.

> Capability: plaintext-by-ciphertext scaling. Exact, unbounded count.

### 4.4 Formal multiplication — `<enc_column> * <enc_column>` (`PAIRED` only)

```sql
SELECT rate * hours FROM payroll;       -- both operands encrypted
```

The product of **two encrypted `PAIRED` columns** returns a ciphertext
decrypting to the exact product of the two plaintext values. **Neither
operand is revealed to the server** — this is a true ciphertext × ciphertext
multiplication, not scalar multiplication.

**Depth limit (v0.1): one multiplication.** A value that is the result of a
`*` between two encrypted columns may afterward be **added** and
**aggregated** freely, but it may **not** be fed into a second encrypted ×
encrypted multiplication within the same query. Multiplicative depth > 1 is
out of scope for v0.1.

A conforming engine MUST reject a query that requires multiplicative
depth ≥ 2 over ciphertext with a clear error, rather than silently
decrypting an intermediate.

> Capability: depth-1 ciphertext multiplication. Exact within the engine's
> configured value range; see §5.

### 4.5 Encrypted inner product — `DOT(a, b)` (`INT PAIRED` only, v0.1)

```sql
SELECT DOT(rate, hours) FROM payroll;   -- Σ rateᵢ · hoursᵢ over selected rows
```

`DOT(a, b)` returns a single ciphertext decrypting to the exact sum of
element-wise products Σ (aᵢ · bᵢ) across the selected rows. It combines one
depth-1 multiplication per row with unbounded aggregation (§4.2), and is the
canonical primitive for encrypted weighted sums, linear-model inference, and
convolution.

> Capability: depth-1 multiply + aggregate, decoded in one step.

**v0.1 restriction: both operands must be `INT PAIRED` columns.** The
single-step aggregate decode is exact for integer operands. `DOT` over
`RATIONAL` columns is **not** in v0.1: aggregating rational products in one
step does not preserve the common denominator (the decoded value would be
`(Σ numerators) / (Σ denominators)`, which equals `Σ(aᵢ·bᵢ)` only for a
single term). Rational inner products are on the roadmap (§6). A conforming
engine MUST reject `DOT` over non-`INT` columns rather than return the
denominator-collapsed value.

> For a rational element-wise product *without* aggregation, use per-row
> `a * b` (§4.4), which is exact for `RATIONAL` because each row is decoded
> independently.

### 4.6 Row count — `COUNT(*)` (v0.2)

```sql
SELECT COUNT(*) FROM payroll WHERE dept = 5;
```

`COUNT(*)` returns the **plaintext** number of rows selected (after `WHERE`).
It reveals only a count — never any encrypted value — and is exact and
unbounded.

> Capability: plaintext cardinality of the selected row set.

### 4.7 Mean — `AVG(column)` (v0.2)

```sql
SELECT AVG(salary) FROM payroll WHERE dept = 5;
```

`AVG(c)` returns the exact rational mean `(Σ c) / n` over the selected rows.
On an **encrypted** column the result is a ciphertext that decrypts to the
exact mean (the divide-by-`n` is applied to the encrypted rational, so the
value never leaves ciphertext). On a `PLAIN` column it returns the exact
`Fraction`. `AVG` over an empty set is `NULL`.

> Capability: exact rational mean; encrypted in, encrypted out.

### 4.8 Extrema — `MIN(column)` / `MAX(column)` (`PLAIN` numeric, v0.2)

```sql
SELECT MIN(grade), MAX(grade) FROM payroll;
```

`MIN`/`MAX` return the least/greatest value of a **`PLAIN` numeric** column
over the selected rows (`NULL` if empty). They are **not** available on
encrypted columns — ordering over ciphertext is a research capability (§6).
A conforming engine MUST reject `MIN`/`MAX` on an `ENC`/`PAIRED` column.

> Capability: plaintext extrema. Encrypted extrema are out of scope.

---

## 5. Value-range and exactness contract

TorusSQL results are **exact integers/rationals**, not approximations —
with one operational bound the author must respect:

- Each engine session is configured for a **maximum recoverable magnitude**
  (a decode range). Results whose plaintext magnitude exceeds the
  configured range are **not silently wrapped or truncated** — the engine
  MUST return a range error.
- Multiplication (§4.4, §4.5) grows magnitude multiplicatively; an author
  computing `a * b` must ensure the session range covers the product.

The configured range is an engine deployment parameter, surfaced to clients
out-of-band (e.g. connection metadata), not a dialect keyword in v0.1.

> Rationale: this is the one place where the closed mechanism leaks an
> observable constraint. We make it explicit and honest rather than letting
> queries fail mysteriously.

---

## 6. Out of scope for v0.1 (Roadmap)

These are **deliberately excluded** so the spec never promises what the
engine cannot do today. Each is a candidate capability class for a future
version:

| Capability                          | Status   |
|-------------------------------------|----------|
| Plaintext `WHERE` (AND/OR/IN, comparisons) | ✅ shipped v0.2 |
| `ORDER BY` / `LIMIT` on plaintext   | ✅ shipped v0.2 |
| `COUNT(*)`                          | ✅ shipped v0.2 |
| `AVG` (encrypted mean)              | ✅ shipped v0.2 |
| `MIN` / `MAX` on plaintext          | ✅ shipped v0.2 |
| Per-row scalar mul + `k * SUM(col)` | ✅ shipped v0.2 |
| Column aliases (`AS`)               | ✅ shipped v0.2 |
| `GROUP BY` / `HAVING` on plaintext keys | ✅ shipped v0.3 |
| `DISTINCT`                          | ✅ shipped v0.3 |
| `UPDATE` / `DELETE`                 | ✅ shipped v0.3 |
| `NOT IN`, parenthesized predicates  | planned  |
| `JOIN` (plaintext keys)             | planned  |
| `DOT` over `RATIONAL` columns       | planned  |
| Equality filter on encrypted column | research |
| Range / ordering on encrypted column| research |
| `GROUP BY` over encrypted keys      | research |
| Multiplicative depth ≥ 2            | research |
| `LIKE` / substring on `STR ENC`     | research |

A capability moves from this table into §4 only when a conforming engine can
evaluate it over ciphertext with an exact, specified result. "Research"
means no honest construction exists yet.

---

## 7. Conformance

An engine is **TorusSQL v0.1 conformant** if, for every statement this spec
admits, it either (a) returns the exact specified result, or (b) returns a
typed error from a fixed set (parse / policy-violation / unsupported-
capability / range). It MUST NOT, under any input this spec admits, produce
a result by decrypting an `ENC`/`PAIRED` value server-side.

The conformance test suite lives at `torussql/spec/conformance/` (TBD) and
is the normative definition where this prose is ambiguous.

---

## Appendix A — Grammar (EBNF)

```ebnf
statement      = create | drop | insert | select ;

create         = "CREATE" "TABLE" ident "(" column { "," column } ")" ;
column         = ident type policy ;
type           = "INT" | "STR" | "RATIONAL" ;
policy         = "PLAIN" | "ENC" | "PAIRED" ;

drop           = "DROP" "TABLE" ident ;

insert         = "INSERT" "INTO" ident "(" ident { "," ident } ")"
                 "VALUES" "(" literal { "," literal } ")" ;

select         = "SELECT" ( "*" | proj { "," proj } )
                 "FROM" ident [ "WHERE" ident "=" literal ] ;
proj           = ident
               | "SUM" "(" ident ")"
               | num "*" ident
               | ident "*" ident
               | "DOT" "(" ident "," ident ")" ;

literal        = num | str | "NULL" | "FRAC" "(" num "," num ")" ;
ident          = letter { letter | digit | "_" } ;
num            = [ "-" ] digit { digit } ;
str            = "'" { char | "''" } "'" ;
```

---

*TorusSQL is the open developer surface of TorusDB. The dialect is open;
the engine that evaluates it is not.*
