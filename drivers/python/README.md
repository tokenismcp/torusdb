# torussql — Python driver (PEP 249) for TorusDB

Encrypted SQL over the **no-key delegation protocol**: the server holds no key.
The driver is the data owner — it blinds on INSERT, keeps the mask vault, and
unblinds + decodes results.

```python
import torussql

conn = torussql.connect("db.example.com", 8533,
                        tls=True, cafile="ca.pem",          # certificate verified
                        token="…",                           # server --token-file
                        vault_path="~/.torusdb/vault",       # durable, 0600
                        vault_passphrase="…")                # optional sealing
cur = conn.cursor()
cur.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary RATIONAL ENC)")
cur.executemany("INSERT INTO emp (id, dept, salary) VALUES (%s, %s, FRAC(%s,1))",
                [(1, 5, 8000), (2, 5, 9000)])          # one round trip
cur.execute("SELECT e.dept, SUM(e.salary) FROM emp e GROUP BY e.dept")
print(cur.fetchall())

with conn.transaction():                    # atomic, rolls back vault + server
    cur.execute("UPDATE emp SET salary = FRAC(9500,1) WHERE id = 2")
```

* **Requires the TorusDB engine package** (`ec-fhe-query`), distributed separately.
* TLS verifies the server certificate by default; `tls_insecure=True` is a
  development-only escape hatch.
* The mask vault is the only copy of your data's keys-to-readability — back it
  up (see `docs/ops-guide.md`, "Vault custody").
