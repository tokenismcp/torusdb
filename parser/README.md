# torussql-parser

The open parser and static validator for the [TorusSQL](../README.md)
dialect. **Zero runtime dependencies, no engine, no crypto** — it turns
TorusSQL text into an AST and statically enforces the dialect's
capability/policy/type rules ([spec](../spec/TorusSQL-Spec-v0.1.md) §2, §4).

Drivers use it to reject illegal queries client-side before anything reaches
the closed TorusDB engine; the engine's planner enforces the same rules
server-side. This package is the canonical statement of those rules.

```python
from torussql_parser import parse, Schema, ValidationError

schema = Schema()
schema.apply(parse("CREATE TABLE payroll (id INT PLAIN, rate INT PAIRED, hours INT PAIRED)"))

schema.validate(parse("SELECT DOT(rate, hours) FROM payroll"))   # ok
schema.validate(parse("SELECT rate * hours FROM payroll"))       # ok

try:
    schema.validate(parse("SELECT id FROM payroll WHERE rate = 5"))
except ValidationError as e:
    print(e)   # WHERE on encrypted columns is not supported in v0.1
```

## What it checks

- Grammar (CREATE / DROP / INSERT / SELECT) per the spec.
- Policy rules: `SUM`/`k*col` need `ENC`/`PAIRED`; `*` and `DOT` need
  `PAIRED`; `WHERE` only on `PLAIN`.
- Type rules: `DOT` is `INT`-only in v0.1; `STR` must be `PLAIN`.

What it does **not** do: execute, encrypt, decrypt, or talk to an engine.
That is the closed core's job.

## Develop

```bash
pip install -e ".[test]"
pytest
```
