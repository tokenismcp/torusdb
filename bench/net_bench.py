# SPDX-License-Identifier: Apache-2.0
"""End-to-end benchmark over a real TCP connection (server + driver).

    python bench/net_bench.py --rows 20000 [--json out.json]

Measures what an application actually sees: round trips, JSON framing, the
blinding/unblinding at the owner, and the server's modular arithmetic.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conftest  # noqa: F401,E402  (root bootstrap)

import torussql                                              # noqa: E402
from nokey_server import NoKeyTCPServer, ServerConfig        # noqa: E402


def timed(fn, repeat=3):
    runs = []
    out = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn()
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs), out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--json")
    ap.add_argument("--auth", action="store_true", help="authenticated (MAC) mode")
    args = ap.parse_args()
    n = args.rows

    srv = NoKeyTCPServer("127.0.0.1", 0, config=ServerConfig())
    host, port = srv.address
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = torussql.connect(host, port, authenticated=args.auth)
    cur = c.cursor()
    cur.execute("CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, salary INT ENC, "
                "rate INT PAIRED, hours INT PAIRED)")
    cur.execute("CREATE TABLE dept (dept INT PLAIN, name STR PLAIN)")
    cur.executemany("INSERT INTO dept (dept, name) VALUES (%s, %s)",
                    [(d, f"d{d}") for d in range(50)])

    res = {"rows": n, "authenticated": args.auth}
    sample = 300
    t0 = time.perf_counter()
    for i in range(sample):
        cur.execute("INSERT INTO emp (id, dept, salary, rate, hours) "
                    "VALUES (%s, %s, %s, %s, %s)", (i, i % 50, 1000 + i, 50, 40))
    res["insert_single_rows_per_s"] = round(sample / (time.perf_counter() - t0))
    t0 = time.perf_counter()
    cur.executemany("INSERT INTO emp (id, dept, salary, rate, hours) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    [(i, i % 50, 1000 + i, 50, 40) for i in range(n - sample)])
    res["insert_bulk_rows_per_s"] = round((n - sample) / (time.perf_counter() - t0))

    q = {
        "sum_all": "SELECT SUM(salary) FROM emp",
        "sum_filtered": "SELECT SUM(salary) FROM emp WHERE dept = 7",
        "count_filtered": "SELECT COUNT(*) FROM emp WHERE dept < 10",
        "group_by_sum": "SELECT dept, COUNT(*), SUM(salary) FROM emp GROUP BY dept",
        "join_group_sum": ("SELECT d.name, SUM(e.salary) FROM emp e JOIN dept d "
                           "ON e.dept = d.dept GROUP BY d.name"),
        "dot": "SELECT DOT(rate, hours) FROM emp WHERE dept < 5",
        "select_encrypted_1k": "SELECT id, salary FROM emp WHERE id < 1000",
    }
    for name, sql in q.items():
        secs, rows = timed(lambda s=sql: c.execute(s).rows, repeat=3)
        res[f"{name}_ms"] = round(secs * 1000, 1)
    res["server_requests"] = srv.engine.stats_snapshot()["requests"]
    print(json.dumps(res, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2))
    c.close(); srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    main()
