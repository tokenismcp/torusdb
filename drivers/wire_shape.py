# SPDX-License-Identifier: Apache-2.0
"""Language-neutral "shape" of the shared-wire requests an owner sends (expr_mode="shared").

Everything a server sees EXCEPT the (uniform) ring values: operation names, wire ids (renamed by first
use inside one request), spans / widths / counts, vector lengths and flags. The Python, TypeScript and Rust
drivers must produce byte-identical shapes for the same expression over the same table, which pins the
whole transport structure (gate order, batching, chunking, frees) across implementations. The shape
works on both the in-process form (ring elements are ints) and the JSON form (decimal strings).

    trace  = [["exec", [op, ...]] | ["free", n_ids | null], ...]      one entry per wire_* request
    op     = [name, arg, ...]  with  wire id -> "#k", list -> ["L", n], dict -> ["D", [[key, n], ...]],
             a public ring scalar (mulc / addc) -> "R", other strings -> "R", ints / bools / null as they are
"""
from __future__ import annotations

import hashlib
import json
import re

_ID = re.compile(r"^[0-9a-f]{12}\.[0-9]+$")
_SCALAR_OPS = ("mulc", "addc")


def op_shape(op, ids: dict) -> list:
    row = [op[0]]
    for k, x in enumerate(op[1:], start=1):
        if op[0] in _SCALAR_OPS and k == 3:
            row.append("R")
        elif isinstance(x, bool) or x is None:
            row.append(x)
        elif isinstance(x, int):
            row.append(x)
        elif isinstance(x, str):
            if _ID.match(x):
                row.append("#%d" % ids.setdefault(x, len(ids)))
            else:
                row.append("R")
        elif isinstance(x, (list, tuple)):
            row.append(["L", len(x)])
        elif isinstance(x, dict):
            row.append(["D", [[key, len(v)] for key, v in sorted(x.items())]])
        else:
            row.append("?")
    return row


def exec_entry(ops) -> list:
    ids: dict = {}
    return ["exec", [op_shape(o, ids) for o in ops]]


def free_entry(ids) -> list:
    return ["free", None if ids is None else len(ids)]


def digest(trace: list) -> str:
    return hashlib.sha256(json.dumps(trace, separators=(",", ":")).encode()).hexdigest()
