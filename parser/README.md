<p align="center"><img src="https://raw.githubusercontent.com/tokenismcp/torusdb/main/assets/logo-128.png" alt="TorusDB" width="96"></p>

# torussql-parser

The open parser and static validator for the [TorusSQL](../README.md)
dialect. **Zero runtime dependencies, no engine, no crypto** — it turns
TorusSQL text into an AST and statically enforces the dialect's
capability/policy/type rules ([spec](../spec/TorusSQL-Spec-v0.1.md) §2, §4).

Drivers use it to reject illegal queries client-side before anything reaches
the server; the keyless engine's planner (`torusdb-core`) enforces the same rules
server-side. This package is the canonical statement of those rules. Python 3.10 or newer.

```python
from torussql_parser import parse, Schema, ValidationError

schema = Schema()
schema.apply(parse("CREATE TABLE payroll (id INT PLAIN, rate INT PAIRED, hours INT PAIRED)"))

schema.validate(parse("SELECT DOT(rate, hours) FROM payroll"))   # ok
schema.validate(parse("SELECT rate * hours FROM payroll"))       # ok

try:
    schema.validate(parse("SELECT id FROM payroll WHERE rate = 5"))
except ValidationError as e:
    print(e)   # WHERE on encrypted columns is not supported; use a PLAIN column for predicates (column 'rate' is paired)
```

## What it checks

- Grammar (CREATE / DROP / INSERT / UPDATE / DELETE / SELECT with joins, GROUP BY, ORDER BY, indexes,
  transactions) per the current spec, [v0.6](../spec/TorusSQL-Spec-v0.6.md) (which adds the arithmetic expression
  grammar and its policy rules, `torussql_parser.analyze_expr`).
- Policy rules: `SUM`/`k*col` need `ENC`/`PAIRED`; `*` and `DOT` need
  `PAIRED`; `WHERE` only on `PLAIN`.
- Type rules: `DOT` is `INT`-only; `STR` must be `PLAIN`.

What it does **not** do: execute, encrypt, decrypt, or talk to an engine or server.
That is `torusdb-core`'s job (and the `torussql` driver's).

## Develop

```bash
pip install -e ".[test]"       # from this directory
pytest
```
