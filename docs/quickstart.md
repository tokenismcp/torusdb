# TorusSQL Quickstart

> **First time? Do [`GETTING_STARTED.md`](GETTING_STARTED.md) first** — the tested
> 10-minute path (install, server, encrypted `SUM`, FHE column, restart). This page is
> the longer tour that follows it: a multi-table payroll with joins, grouping,
> transactions and integrity checking. It assumes a running server and the install
> from there.

You will connect as the data owner, store salaries encrypted, and compute over
them — the server never sees a salary.

## 1. Install

Python **3.11 or newer** is required. From a checkout (nothing is published yet):

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install ./parser ./core ./drivers/python ./server    # later: pip install torusdb-server torussql
```

Everything is Apache-2.0 and self-contained. The TypeScript (`@torusdb/driver`) and
Rust (`torusdb`) drivers speak the same wire protocol and need only a running server.

## 2. Start a server

```bash
torusdb-server --port 8533 --db ./demo.db        # durable; loopback only, no auth needed (leave it running)
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
data. Without it the vault exists only in memory. Back it up. The code below creates
tables `emp` and `dept`: on a server that already has them (from running it twice) use
`DROP TABLE emp` / `DROP TABLE dept` first, or start with a fresh `--db`.

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
cur.execute("SELECT DOT(rate, hours) FROM emp");                   print(cur.fetchall())  # 5900 = 2000+2100+1800, on blinded data
cur.execute("""SELECT d.dname, COUNT(*), SUM(e.salary)
               FROM emp e JOIN dept d ON e.dept = d.dept
               GROUP BY d.dname ORDER BY d.dname""");             print(cur.fetchall())
cur.execute("""SELECT d.dname, e.name FROM dept d
               LEFT JOIN emp e ON e.dept = d.dept""");            print(cur.fetchall())
```

Rules of thumb: `PLAIN` columns can be filtered, grouped, ordered and joined but the
server can read them; `ENC`/`PAIRED` columns are hidden but support `SUM`, `AVG`, scaling, and arithmetic
expressions: `+ - * /`, products of any depth between `PAIRED` columns (one owner round trip
per multiplicative level, default maximum depth 8) and division (by a public value or an
encrypted one; exact rationals, a zero denominator is an error). For example
`SELECT SUM(rate * hours * 2) / COUNT(*) FROM emp`. `FHE` columns keep only `SUM`/`AVG`/`DOT`.
See `spec/TorusSQL-Spec-v0.6.md`; section 5.10 there says which party computes what.

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
return wrong aggregates undetected. Decide this **when the vault is created**: a vault
(and its tables) written without MACs is refused with "refusing to silently run
unprotected; use a new vault for authenticated mode", so use a fresh `vault_path`
and fresh tables for the authenticated mode.

## 7. Next

* `ops-guide.md` — auth, TLS, backups, vault custody, monitoring.
* `threat-model.md` — exactly what the server can and cannot learn.
* `torussql -h 127.0.0.1 -p 8533 --vault ./demo.vault` — an interactive shell (`torussql --help`;
  `-h` is the host, not help).
* `FHE` columns (the server multiplies ciphertexts), custody, replication: [`fhe-columns.md`](fhe-columns.md),
  [`custody.md`](custody.md), [`replication.md`](replication.md).
