# SPDX-License-Identifier: Apache-2.0
"""Python reference peer for the cross-implementation FHE tests.

usage: fhe_peer.py HOST PORT JSON   with JSON = {"key": hex, "range": n, "auth": bool,
                                                  "dot_unverified": bool, "ops": [[kind, sql], ...]}
kind "exec" runs a statement, "query" prints its rows; "keyfile" [path, pass|null] saves the key.
Prints a JSON list: the rows of every "query" op (fractions as strings).
"""
import json
import sys
from fractions import Fraction

import torussql
from torusdb_core import fhe


def conv(x):
    return str(x) if isinstance(x, Fraction) else x


def main():
    host, port, spec = sys.argv[1], int(sys.argv[2]), json.loads(sys.argv[3])
    key = fhe.FheKey.from_secret_bytes(bytes.fromhex(spec["key"]), spec.get("range", 1_000_000))
    out = []
    conn = torussql.connect(host, port, fhe_key=key, authenticated=bool(spec.get("auth")),
                            fhe_allow_unverified_dot=bool(spec.get("dot_unverified")),
                            integrity_anchor=spec.get("anchor"),
                            trust_server_schema=True, timeout=240.0)
    try:
        for op in spec["ops"]:
            kind, sql = op[0], op[1]
            if kind == "exec":
                conn.execute(sql)
            elif kind == "query":
                out.append([[conv(c) for c in r] for r in conn.execute(sql).rows])
            elif kind == "verify":                       # anchored mode: full rescan against the anchor
                out.append(conn.verify_table(sql))
            elif kind == "adopt":
                out.append(conn.adopt_table(sql))
            elif kind == "leaf":                         # known-answer for the canonical row encoding + leaf PRF
                from fractions import Fraction
                from torusdb_core.fhe_anchor import row_material, schema_digest

                def pv(d):
                    t = d["t"]
                    return (None if t == "n" else bool(d["v"]) if t == "b" else int(d["v"]) if t == "i"
                            else d["v"] if t == "s" else Fraction(int(d["n"]), int(d["d"])))
                cols = [tuple(c) for c in op[2]]
                parts = [(None if n is None else int(n), bytes.fromhex(hc) if hc else None,
                          bytes.fromhex(ht) if ht else None) for n, hc, ht in op[5]]
                m = row_material(schema_digest(sql, cols), [pv(x) for x in op[4]], parts)
                out.append([m.hex(), str(key.anchor_leaf(sql, op[3], m))])
            elif kind == "anchor_ops":                   # drive a FileAnchor directly (format compatibility)
                from torusdb_core.fhe_anchor import Change, FileAnchor
                fa = FileAnchor(sql)
                res = []
                for st in op[2]:
                    m, a = st[0], st[1:]
                    if m == "begin_commit":
                        fa.begin_commit({t: Change(e, None if r is None else int(r), c) for t, (e, r, c) in a[0].items()}, a[1])
                    elif m == "finish_commit":
                        fa.finish_commit(a[0], a[1])
                    elif m == "abort":
                        fa.abort(a[0], a[1])
                    elif m == "set":
                        fa.set(a[0], int(a[1]), a[2], a[3])
                    elif m == "remove":
                        fa.remove(a[0], a[1] if len(a) > 1 else None)
                    elif m == "get":
                        e = fa.get(a[0])
                        res.append(None if e is None else {
                            "epoch": e.epoch, "root": str(e.root), "count": e.count,
                            "history": [[x, str(y), z] for x, y, z in e.history],
                            "pending": None if e.pending is None else {
                                "epoch": e.pending.epoch, "root": str(e.pending.root), "count": e.pending.count,
                                "txid": e.pending.txid, "drop": e.pending.drop, "created": e.pending.created}})
                out.append(res)
            elif kind == "keyfile":
                fhe.save_key(key, sql, op[2])
            elif kind == "loadkey":                      # a key file written by the TypeScript driver
                k = fhe.load_key(sql, op[2])
                out.append([k.secret_bytes.hex(), k.range])
            elif kind == "oracle":                       # the public-key pair identity must NOT reveal a guessed value
                from py_ecc.optimized_bn128 import G1, G2, add, multiply, neg, pairing
                import base64
                table, col, vals = sql, op[2], op[3]
                ids = conn._wire.call("matching_rowids", [table, None])
                cells = conn._wire.call("plain_cells", [table, col, ids])
                res, ctrl = [], []
                for w, v in zip(cells, vals):
                    c1, c2, d1, d2 = fhe.parse_cell(base64.b64decode(w["v"]), "pyecc")
                    lhs = pairing(G2, add(c2, neg(multiply(G1, v))))
                    res.append(lhs == pairing(key.Q2, c1))
                    # control: the BROKEN public key Q2 = s*G2 would make the identity hold (test has teeth)
                    ctrl.append(lhs == pairing(multiply(G2, key._s), c1))
                out.append(res)
                out.append(ctrl)
            elif kind == "indep":                        # r1 != r2 in every cell: e(D1,G1) != e(G2,C1)
                from py_ecc.optimized_bn128 import G1, G2, pairing
                table, col = sql, op[2]
                ids = conn._wire.call("matching_rowids", [table, None])
                cells = conn._wire.call("plain_cells", [table, col, ids])
                import base64
                res = []
                for w in cells:
                    c1, c2, d1, d2 = fhe.parse_cell(base64.b64decode(w["v"]), "pyecc")
                    res.append(pairing(d1, G1) != pairing(G2, c1))
                out.append(res)
            else:
                raise SystemExit(f"bad op {kind}")
    finally:
        conn.close()
    print(json.dumps(out))


main()
