# TorusSQL Quickstart

Ten minutes to an encrypted query. You will run a keyless server, connect as the
data owner, store salaries encrypted, and compute over them — the server never
sees a salary.

## 1. Install

```bash
pip install torusdb-server torussql      # release wheels or your index; engine wheels come with your licence
```

The engine packages (`ec-fhe-engine`, `ec-fhe-query`) are licensed separately; the
driver and server need them at runtime. The TypeScript (`@torusdb/driver`) and
Rust (`torusdb`) drivers and `torussql-parser` do not.

## 2. Start a server

```bash
torusdb-server --port 8533 --db ./demo.db        # durable; loopback only, no auth needed
```

For anything reachable from a network add `--token-file` and `--tls`
(see `ops-guide.md`; a non-loopback bind refuses to start without tokens).

## 3. Connect as the owner

```python
import torussql

conn = torussql.connect("127.0.0.1", 8533, vault_path="./demo.vault")
cur = conn.cursor()
```

`vault_path` is where **your** masks live — the only thing that can decrypt the
data. Without it the vault exists only in memory. Back it up.

## 4. Create, load, query

```python
cur.execute("""CREATE TABLE emp (
    id INT PLAIN, dept INT PLAIN, name STR PLAIN,
    salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)""")
cur.execute("CREATE TABLE dept (dept INT PLAIN, dname STR PLAIN)")

cur.executemany("INSERT INTO dept (dept, dname) VALUES (%s, %s)",
                [(5, "Eng"), (9, "Sales")])
cur.executemany(
    "INSERT INTO emp (id, dept, name, salary, rate, hours) "
    "VALUES (%s, %s, %s, FRAC(%s,1), %s, %s)",
    [(1, 5, "Ana", 8000, 50, 40), (2, 5, "Bo", 9000, 60, 35), (3, 9, "Cy", 7000, 45, 40)])

cur.execute("SELECT SUM(salary), AVG(salary) FROM emp");           print(cur.fetchall())
cur.execute("SELECT DOT(rate, hours) FROM emp");                   print(cur.fetchall())  # 4100+... on blinded data
cur.execute("""SELECT d.dname, COUNT(*), SUM(e.salary)
               FROM emp e JOIN dept d ON e.dept = d.dept
               GROUP BY d.dname ORDER BY d.dname""");             print(cur.fetchall())
cur.execute("""SELECT d.dname, e.name FROM dept d
               LEFT JOIN emp e ON e.dept = d.dept""");            print(cur.fetchall())
```

Rules of thumb: `PLAIN` columns can be filtered, grouped, ordered and joined but the
server can read them; `ENC`/`PAIRED` columns are hidden but support only `SUM`,
`AVG`, scaling and (`PAIRED`) one multiplication. See `spec/TorusSQL-Spec-v0.5.md`.

## 5. Transactions

```python
with conn.transaction():                      # all-or-nothing, server and vault
    cur.execute("UPDATE emp SET salary = FRAC(9500,1) WHERE id = 2")
    cur.execute("DELETE FROM emp WHERE id = 3")
```

## 6. Detect a lying server (recommended on hosts you do not control)

```python
conn = torussql.connect(..., authenticated=True)   # MAC every encrypted cell
```

Tampering then raises `IntegrityError`. Without it a malicious server could
return wrong aggregates undetected.

## 7. Next

* `ops-guide.md` — auth, TLS, backups, vault custody, monitoring.
* `threat-model.md` — exactly what the server can and cannot learn.
* `torusctl/torusctl.py --connect 127.0.0.1:8533` — an interactive shell.
