# SPDX-License-Identifier: Apache-2.0
"""TPC-H subset benchmark for TorusSQL.

Implements a subset of the TPC-H decision-support benchmark adapted for
TorusSQL's encrypted-column surface:

  Q1-like  — single-table aggregation on encrypted columns with plaintext GROUP BY
  Q3-like  — two-table INNER JOIN + encrypted aggregation

The original TPC-H queries operate on a known plaintext schema. Here the
monetary (price, discount, tax) and quantity columns are encrypted; the
categorical and date-like columns remain PLAIN for WHERE/GROUP BY filtering.

Usage:
    python bench/tpch.py                  # default 1000 rows
    python bench/tpch.py --rows 10000
    python bench/tpch.py --rows 100 --json results_tpch.json
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conftest  # noqa: F401,E402  (root bootstrap)

from torusdb_core.nokey_engine import NoKeyClient, NoKeyServer


# ── Schema (TPC-H inspired, encrypted monetary columns) ─────────────────────

# lineitem(orderkey PLAIN, partkey PLAIN, suppkey PLAIN,
#          linenumber PLAIN, returnflag STR PLAIN, linestatus STR PLAIN,
#          quantity INT ENC, extendedprice INT ENC, discount INT ENC)
#
# orders(orderkey PLAIN, custkey PLAIN, orderstatus STR PLAIN,
#        orderpriority STR PLAIN)

_LINEITEM_DDL = (
    "CREATE TABLE lineitem ("
    "orderkey INT PLAIN, partkey INT PLAIN, suppkey INT PLAIN, "
    "linenumber INT PLAIN, returnflag STR PLAIN, linestatus STR PLAIN, "
    "quantity INT ENC, extendedprice INT ENC, discount INT ENC)"
)

_ORDERS_DDL = (
    "CREATE TABLE orders ("
    "orderkey INT PLAIN, custkey INT PLAIN, "
    "orderstatus STR PLAIN, orderpriority STR PLAIN)"
)

_RETURN_FLAGS = ("A", "N", "R")
_LINE_STATUSES = ("F", "O")
_ORDER_STATUSES = ("F", "O", "P")
_PRIORITIES = ("1-URGENT", "2-HIGH", "3-MEDIUM", "4-NOT SPECIFIED", "5-LOW")


def _seed(cli: NoKeyClient, n_lineitems: int, n_orders: int,
          rng: random.Random) -> None:
    for i in range(n_orders):
        cli.execute(
            f"INSERT INTO orders (orderkey, custkey, orderstatus, orderpriority) "
            f"VALUES ({i}, {rng.randint(1, n_orders // 2)}, "
            f"'{rng.choice(_ORDER_STATUSES)}', '{rng.choice(_PRIORITIES)}')"
        )
    for i in range(n_lineitems):
        orderkey = rng.randint(0, n_orders - 1)
        cli.execute(
            f"INSERT INTO lineitem "
            f"(orderkey, partkey, suppkey, linenumber, returnflag, linestatus, "
            f"quantity, extendedprice, discount) "
            f"VALUES ({orderkey}, {rng.randint(1, 200)}, {rng.randint(1, 100)}, "
            f"{rng.randint(1, 7)}, '{rng.choice(_RETURN_FLAGS)}', "
            f"'{rng.choice(_LINE_STATUSES)}', "
            f"{rng.randint(1, 50)}, {rng.randint(900, 100000)}, "
            f"{rng.randint(0, 10)})"
        )


def _time_ms(fn) -> tuple[float, object]:
    t0 = time.perf_counter()
    result = fn()
    return (time.perf_counter() - t0) * 1000, result


# ── Q1-like: aggregation on lineitem (encrypted cols, plain GROUP BY) ─────────

_Q1 = (
    "SELECT returnflag, linestatus, "
    "SUM(quantity), SUM(extendedprice), SUM(discount), COUNT(*) "
    "FROM lineitem "
    "GROUP BY returnflag, linestatus"
)

# ── Q3-like: join orders + lineitem, sum encrypted revenue ────────────────────

_Q3 = (
    "SELECT o.orderpriority, COUNT(*), SUM(l.extendedprice) "
    "FROM orders o JOIN lineitem l ON o.orderkey = l.orderkey "
    "WHERE o.orderstatus = 'O' "
    "GROUP BY o.orderpriority ORDER BY o.orderpriority"
)

# ── Q6-like: single table with encrypted agg (like Q1 without GROUP BY) ──────

_Q6 = "SELECT SUM(extendedprice), SUM(discount) FROM lineitem WHERE linenumber = 1"


def run_benchmark(n_rows: int = 1000) -> dict:
    rng = random.Random(42)
    n_orders = max(1, n_rows // 4)

    srv = NoKeyServer()
    cli = NoKeyClient(srv)
    cli.execute(_LINEITEM_DDL)
    cli.execute(_ORDERS_DDL)

    t_insert, _ = _time_ms(lambda: _seed(cli, n_rows, n_orders, rng))

    t_q1, rs_q1 = _time_ms(lambda: cli.execute(_Q1))
    t_q3, rs_q3 = _time_ms(lambda: cli.execute(_Q3))
    t_q6, rs_q6 = _time_ms(lambda: cli.execute(_Q6))

    return {
        "n_lineitems": n_rows,
        "n_orders": n_orders,
        "insert_ms": round(t_insert, 2),
        "insert_us_per_row": round(t_insert * 1000 / n_rows, 1),
        "q1_group_agg_ms": round(t_q1, 2),
        "q3_join_agg_ms": round(t_q3, 2),
        "q6_filter_agg_ms": round(t_q6, 2),
        "q1_groups": len(rs_q1.rows),
        "q3_matched_rows": sum(r[1] for r in rs_q3.rows),
    }


def _fmt(results: dict) -> str:
    lines = [
        f"TPC-H subset benchmark — {results['n_lineitems']} lineitem rows "
        f"× {results['n_orders']} order rows",
        "",
        f"  Insert       {results['insert_ms']:>8.1f} ms  "
        f"({results['insert_us_per_row']:.1f} µs/row)",
        f"  Q1 (GROUP BY SUM/COUNT × 3 enc cols)   {results['q1_group_agg_ms']:>8.1f} ms"
        f"  [{results['q1_groups']} groups]",
        f"  Q3 (JOIN + GROUP BY + SUM encrypted)  {results['q3_join_agg_ms']:>8.1f} ms"
        f"  [{results['q3_matched_rows']} matched rows]",
        f"  Q6 (filter + 2× encrypted SUM)         {results['q6_filter_agg_ms']:>8.1f} ms",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TPC-H subset benchmark for TorusSQL")
    parser.add_argument("--rows", type=int, default=1000,
                        help="number of lineitem rows (default 1000)")
    parser.add_argument("--json", metavar="FILE",
                        help="write results JSON to FILE")
    args = parser.parse_args()

    print(f"Running TPC-H subset benchmark ({args.rows} lineitem rows)…")
    results = run_benchmark(args.rows)
    print(_fmt(results))

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {args.json}")
