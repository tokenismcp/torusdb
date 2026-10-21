#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproducible benchmark harness for the no-key TorusDB engine.

Measures the in-process no-key path (no network) for the core operations at a
range of row counts, and reports overhead vs a plaintext baseline. The no-key
hot path is pure mod-n integer arithmetic (no curve / pairing / BSGS), so the
numbers are intended to dispel the "homomorphic = unusably slow" assumption.

Usage:
    python bench.py [--rows 100,1000,10000] [--repeat 3] [--json out.json]

Deterministic structure (fixed row values); the one-time-pad masks use the OS
RNG, so timings — not values — vary run to run. Results print as a Markdown
table and optionally dump to JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
for rel in ("ec_fhe_query", "ec_fhe_engine", "torussql/parser"):
    p = _REPO / rel
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from ecfhe_query.nokey_engine import NoKeyClient, NoKeyServer   # noqa: E402


def _timeit(fn, repeat: int) -> float:
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def _fresh_db(rows: int, authenticated: bool):
    server = NoKeyServer()
    client = NoKeyClient(server, authenticated=authenticated)
    client.execute("CREATE TABLE t (id INT PLAIN, dept INT PLAIN, "
                   "v RATIONAL ENC, a INT PAIRED, b INT PAIRED)")
    for i in range(rows):
        client.execute(f"INSERT INTO t (id, dept, v, a, b) "
                       f"VALUES ({i}, {i % 4}, FRAC({1000 + i},1), "
                       f"{i % 50 + 1}, {i % 30 + 1})")
    return client


def bench(rows_list: list[int], repeat: int, authenticated: bool) -> list[dict]:
    out = []
    for rows in rows_list:
        # insert throughput (build a fresh db, timed)
        t_insert = _timeit(lambda: _fresh_db(rows, authenticated), 1)
        client = _fresh_db(rows, authenticated)

        t_sum = _timeit(lambda: client.execute("SELECT SUM(v) FROM t"), repeat)
        t_sum_w = _timeit(
            lambda: client.execute("SELECT SUM(v) FROM t WHERE dept = 1"), repeat)
        t_dot = _timeit(lambda: client.execute("SELECT DOT(a, b) FROM t"), repeat)
        t_count = _timeit(lambda: client.execute("SELECT COUNT(*) FROM t"), repeat)

        # plaintext baseline for SUM (pure Python over the same magnitudes)
        vals = [1000 + i for i in range(rows)]
        t_plain_sum = _timeit(lambda: sum(vals), repeat)

        out.append({
            "rows": rows,
            "insert_total_ms": round(t_insert * 1e3, 2),
            "insert_per_row_us": round(t_insert / rows * 1e6, 2),
            "sum_ms": round(t_sum * 1e3, 3),
            "sum_where_ms": round(t_sum_w * 1e3, 3),
            "dot_ms": round(t_dot * 1e3, 3),
            "count_ms": round(t_count * 1e3, 3),
            "plain_sum_us": round(t_plain_sum * 1e6, 2),
        })
    return out


def print_table(results: list[dict], authenticated: bool) -> None:
    mode = "authenticated (MAC)" if authenticated else "confidential only"
    print(f"\nNo-key TorusDB benchmark — {mode}, in-process (no network)\n")
    cols = [("rows", "rows"), ("insert_per_row_us", "insert µs/row"),
            ("sum_ms", "SUM ms"), ("sum_where_ms", "SUM+WHERE ms"),
            ("dot_ms", "DOT ms"), ("count_ms", "COUNT ms"),
            ("plain_sum_us", "plain SUM µs")]
    print("| " + " | ".join(h for _, h in cols) + " |")
    print("|" + "|".join("---" for _ in cols) + "|")
    for r in results:
        print("| " + " | ".join(str(r[k]) for k, _ in cols) + " |")
    print()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", default="100,1000,5000")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--authenticated", action="store_true",
                    help="include the integrity MAC overhead")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    rows_list = [int(x) for x in args.rows.split(",")]

    results = bench(rows_list, args.repeat, args.authenticated)
    print_table(results, args.authenticated)
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"authenticated": args.authenticated, "results": results}, indent=2))
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
