# SPDX-License-Identifier: Apache-2.0
"""Disk vs memory storage micro-benchmark (server-side store only, no network).

    python bench/storage_bench.py --rows 200000 --cache-rows 5000
"""
from __future__ import annotations

import argparse
import os
import resource
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for rel in ("core", "parser"):
    sys.path.insert(0, str(_REPO / rel))

from torusdb_core.store import MemoryTable, PagedTable      # noqa: E402


def rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024 * 1024 if sys.platform == "darwin" else 1024)


def run(kind: str, rows: int, cache: int, d: str) -> dict:
    t = MemoryTable() if kind == "memory" else PagedTable(os.path.join(d, "bench.heap"), cache)
    big = (1 << 253) + 7
    t0 = time.perf_counter()
    for i in range(rows):
        t.append({"id": i, "grp": i % 1000, "name": f"n{i % 97}", "v": big + i})
    t_ins = time.perf_counter() - t0
    t0 = time.perf_counter()
    t.create_index("grp")
    t_idx = time.perf_counter() - t0
    t0 = time.perf_counter()
    scan = [i for i in t.live_ids() if t.row(i)["name"] == "n5"]
    t_scan = time.perf_counter() - t0
    t0 = time.perf_counter()
    for k in range(200):
        hit = t.candidates([[("grp", "=", k)]])
    t_ix = (time.perf_counter() - t0) / 200
    t0 = time.perf_counter()
    s = sum(t.cells("v", list(range(0, rows, 7))))
    t_sum = time.perf_counter() - t0
    out = {"store": kind, "rows": rows, "insert_rows_per_s": int(rows / t_ins),
           "create_index_s": round(t_idx, 3), "full_scan_s": round(t_scan, 3),
           "indexed_eq_ms": round(t_ix * 1000, 3), "sum_1_7th_s": round(t_sum, 3),
           "heap_mb": round(getattr(t, "heap_len", 0) / 1e6, 1), "peak_rss_mb": round(rss_mb(), 1)}
    t.close()
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=100_000)
    ap.add_argument("--cache-rows", type=int, default=5_000)
    ap.add_argument("--kind", choices=("memory", "disk"), required=True)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as d:
        print(run(a.kind, a.rows, a.cache_rows, d))
