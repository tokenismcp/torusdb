# Getting started (10 minutes)

One copy-paste path: install, start a server, store encrypted numbers, add them up
**on the server without it ever seeing them**, try an `FHE` column, restart and
check that nothing was lost. Every command below was run as written on a clean
machine; the `torussql ...` lines and the Python block are also executed by
`tests/test_docs_examples.py`.

> **You need Python 3.11 or newer** (`python3 --version`). macOS and many Linux
> distributions still ship 3.9/3.10 as `python3`; on those, `pip` stops with
> `requires a different Python: 3.9.x not in '>=3.11'`. Install a newer Python
> (python.org, `brew install python@3.12`, `apt install python3.12 python3.12-venv`,
> `uv python install 3.12`) and use it for the venv below.

## 1. Install

```bash
python3.12 -m venv .venv && source .venv/bin/activate
```

Packages are installed from this checkout (they are not on PyPI yet). Run this
in the repository root, the directory that contains `README.md`:

```bash
pip install ./parser ./core ./drivers/python ./server
```

Once published this becomes `pip install torusdb-server torussql`. Check it:

```bash
torusdb-server --version
torussql --version
```

## 2. Start a server

In a second terminal (activate the same venv), or add `&` to run it in the background:

```bash
torusdb-server --db ./demo.db
```

It prints `no-key TorusDB server 0.5.0 (HOLDS NO KEYS) on 127.0.0.1:8533 ...`.
It listens on loopback only, needs no password there, and `--db` makes it durable
(snapshot + journal next to that path). The server never holds a key: stealing
`demo.db` reveals nothing about encrypted columns.

## 3. Store encrypted numbers, add them up

`torussql` is the interactive shell (like `psql`). **You** are the data owner: the
shell blinds values before they leave your machine and keeps the one-time pads
("masks") in the **vault** file. Without the vault the encrypted data cannot be read,
so always pass `--vault`.

```bash
torussql --vault ./demo.vault
```

```
torussql> CREATE TABLE t (id INT PLAIN, v INT ENC);
OK (0)
torussql> INSERT INTO t (id, v) VALUES (1, 10);
OK (1)
torussql> INSERT INTO t (id, v) VALUES (2, 32);
OK (1)
torussql> SELECT SUM(v) FROM t;
sum(v)
------
42
(1 row)
torussql> \q
```

`PLAIN` columns are visible to the server (and can be filtered, grouped, joined);
`ENC`/`PAIRED` columns are hidden and support `SUM`, `AVG`, scaling and arithmetic
expressions (`+ - * /`, products of any depth between `PAIRED` columns, division; see
`spec/TorusSQL-Spec-v0.6.md`). The same thing non-interactively:

```bash
torussql --vault ./demo.vault -c "SELECT SUM(v) FROM t"
```

## 4. The same from Python

```python
import torussql

conn = torussql.connect("127.0.0.1", 8533, vault_path="./demo.vault")
cur = conn.cursor()
cur.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)")
cur.executemany("INSERT INTO emp (id, dept, salary, rate, hours) VALUES (%s, %s, FRAC(%s,1), %s, %s)",
                [(1, 5, 8000, 50, 40), (2, 5, 9000, 60, 35), (3, 9, 7000, 45, 40)])
cur.execute("SELECT SUM(salary) FROM emp")
print(cur.fetchall())                   # [(24000,)]  computed on blinded data
cur.execute("SELECT DOT(rate, hours) FROM emp")
print(cur.fetchall())                   # [(5900,)]   encrypted x encrypted: 2000 + 2100 + 1800
cur.execute("SELECT dept, SUM(salary) FROM emp GROUP BY dept ORDER BY dept")
print(cur.fetchall())                   # [(5, 17000), (9, 7000)]
```

Use the **same vault** (`vault_path` / `--vault`) every time you talk to the same
server, and a new table name if you run a block twice (`table ... already exists`).
Only one process may use a vault at a time (`... is in use by another process (one writer
per vault)`): quit the interactive shell (`\q`) before running the Python script.
Opening a table you did not create through your vault is read-only until you pass
`trust_server_schema=True` (shell: `--trust-server-schema`).

## 5. An FHE column (the server multiplies ciphertexts)

`FHE` columns are elliptic-curve FHE: the server itself adds and multiplies the
ciphertexts, and you keep only a **key file** (no per-cell masks). They need the
optional pairing library:

```bash
pip install "py_ecc>=6,<9" mclbn256
```

(`py_ecc` alone also works, about 150x slower; `mclbn256` is the native speed-up.)
Create the key once and keep it as safe as the vault, the data is unreadable without it:

```bash
export FHE_PASS='choose-a-long-passphrase'
torussql --fhe-keygen ./fhe.key --fhe-pass-env FHE_PASS
```

```bash
torussql --fhe-key ./fhe.key --fhe-pass-env FHE_PASS -c "CREATE TABLE pay (id INT PLAIN, rate INT FHE, hours INT FHE)" -c "INSERT INTO pay (id, rate, hours) VALUES (1, 40, 160)" -c "INSERT INTO pay (id, rate, hours) VALUES (2, 50, 120)" -c "SELECT SUM(rate) FROM pay" -c "SELECT DOT(rate, hours) FROM pay"
```

This prints `90` and `12400`. `SUM`/`DOT` were computed by the server on ciphertexts.
Add `authenticated=True` (shell: `--authenticated`) to detect a server that lies about
results; details in [`fhe-columns.md`](fhe-columns.md).

## 6. Restart: nothing is lost

Stop the server (Ctrl-C, or `kill` its process id: it writes a final checkpoint),
start it again, and read the data back with the same vault:

```bash
torusdb-server --db ./demo.db
```

```bash
torussql --vault ./demo.vault -c "SELECT SUM(v) FROM t"
```

It prints the `sum(v)` table with `42` again (and `torussql --vault ./demo.vault -c "SELECT SUM(salary) FROM emp"`
prints `24000`). Without `--vault` the same query fails with `this vault has no mask for t.v`: the server
cannot read the data and neither can anyone without your vault. The server state is `demo.db*`; the decryptability is
`demo.vault`. Back up **both**, and the FHE key file. Lose the vault and the `ENC`
columns are gone for good (PLAIN columns stay readable).

To start over: stop the server and delete `demo.db*`, `demo.vault*`, `fhe.key`.

## 7. Next

* Run it for real (tokens and roles, TLS, backups, metrics, replicas, Docker):
  [`ops-guide.md`](ops-guide.md), [`replication.md`](replication.md), [`storage.md`](storage.md).
* What the server can and cannot learn: [`threat-model.md`](threat-model.md). Read it before relying on this.
* Joins, `GROUP BY`, transactions, detecting a lying server (`authenticated=True`): [`quickstart.md`](quickstart.md).
* FHE columns, integrity anchors: [`fhe-columns.md`](fhe-columns.md).
* Keys held by nobody (k-of-n custodians): [`custody.md`](custody.md), [`masks.md`](masks.md).
* The language: [`../spec/TorusSQL-Spec-v0.5.md`](../spec/TorusSQL-Spec-v0.5.md); other languages:
  [TypeScript](../drivers/typescript/README.md), [Rust](../drivers/rust/README.md);
  runnable SQL: [`../examples/payroll.torusql`](../examples/payroll.torusql).
