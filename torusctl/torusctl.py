#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""torusctl — an interactive REPL for TorusSQL (a `psql` for TorusDB).

This is the reference client for the TorusSQL dialect (see
`../spec/TorusSQL-Spec-v0.1.md`). For now it drives the local TorusDB engine
in-process; once the wire protocol lands it will connect to a server instead.

Usage:
    python torusctl.py                 # in-memory session, fresh keys
    echo "SELECT ..." | python torusctl.py   # piped, one statement per line

Meta-commands (start with backslash):
    \\help            show this help
    \\tables          list tables in the catalog
    \\spec            print the supported capability cheat-sheet
    \\plain           toggle: show ciphertext results decrypted (default on)
    \\quit            exit
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


# ── Locate the local engine packages (ec_fhe_query + ec_fhe_engine) ──────────
def _bootstrap_engine_path() -> None:
    here = Path(__file__).resolve()
    # repo root is two levels up from torussql/torusctl/
    repo = here.parents[2]
    for pkg in ("ec_fhe_query", "ec_fhe_engine"):
        p = repo / pkg
        if p.is_dir() and str(p) not in sys.path:
            sys.path.insert(0, str(p))


_bootstrap_engine_path()


def _add_path(rel: str) -> None:
    repo = Path(__file__).resolve().parents[2]
    p = repo / rel
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))


class _Outcome:
    """Uniform result both backends return: a table (columns/rows) or a count."""
    def __init__(self, columns=None, rows=None, affected=None):
        self.columns = columns
        self.rows = rows
        self.affected = affected


class LocalBackend:
    """No-key engine: the in-process server holds NO key material and never
    decrypts; the client (this process, the data owner) holds the masks and
    unblinds at its own boundary (no-key delegation protocol Π)."""
    label = "local engine (no-key, server holds no keys)"

    def __init__(self, db_path: str | None = None):
        from ecfhe_query.nokey_engine import NoKeyClient, NoKeyServer
        self.server = NoKeyServer()
        self.client = NoKeyClient(self.server)
        if db_path:
            print("note: no-key persistence is not wired yet; running in-memory")

    @property
    def nokey_client(self):
        return self.client

    def execute(self, sql: str) -> _Outcome:
        rs = self.client.execute(sql)
        if hasattr(rs, "columns"):
            return _Outcome(columns=list(rs.columns), rows=rs.rows)
        return _Outcome(affected=rs if isinstance(rs, int) else 0)

    def tables(self):
        return list(self.server._schema)


class RemoteBackend:
    """Networked: talk to a keyless no-key TorusDB server. The server holds
    no keys; this CLI process is the data owner and holds the mask vault."""
    def __init__(self, host: str, port: int):
        _add_path("torussql/drivers/python")
        from torussql.nokey import connect
        self.conn = connect(host, port)
        self.label = f"remote {host}:{port} (no-key, server holds no keys)"

    def execute(self, sql: str) -> _Outcome:
        rs = self.conn.execute(sql)
        if hasattr(rs, "columns"):
            return _Outcome(columns=list(rs.columns), rows=rs.rows)
        return _Outcome(affected=rs if isinstance(rs, int) else 0)

    @property
    def nokey_client(self):
        return self.conn.client

    def tables(self):
        return None     # no catalog-introspection RPC yet


HELP = __doc__.split("Meta-commands")[1] if __doc__ else ""

SPEC_SHEET = """\
TorusSQL — supported surface (v0.4)
  CREATE TABLE t (col TYPE POLICY, ...)   TYPE = INT | STR | RATIONAL
                                          POLICY = PLAIN | ENC | PAIRED
  INSERT INTO t (cols) VALUES (lits)      lit  = 42 | 'txt' | FRAC(n,d) | NULL
  SELECT [DISTINCT] proj_list FROM t
         [[INNER] JOIN t2 ON t.col = t2.col]   col must be PLAIN on both sides
         [WHERE pred]                     pred = plain op lit | plain IN (..)
                                                 joined by AND / OR (DNF)
                                                 (WHERE applies to primary table only in JOIN)
         [GROUP BY plain_col]             partitions rows; one output per group
         [HAVING COUNT(*) op n]           filters groups by count
         [ORDER BY plain_col [ASC|DESC]] [LIMIT n]   op = = != <> < > <= >=
      proj = [t.]col                      [AS name]   — qualify as table.col in JOIN
           | SUM([t.]enc_col)             encrypted aggregation
           | AVG([t.]num_col)             mean (encrypted in, encrypted out)
           | MIN(plain_col) | MAX(plain_col)   plaintext extrema
           | k * enc_col                  per-row scalar multiply
           | k * SUM(enc_col)             scaled aggregate
           | enc_col * enc_col            encrypted x encrypted (PAIRED, depth-1)
           | DOT(int_col, int_col)        encrypted inner product (INT PAIRED)
           | COUNT(*)                     plaintext row count
  UPDATE t SET col=val [, col=val ...] [WHERE pred]
  DELETE FROM t [WHERE pred]
  DROP TABLE t
Out of scope: encrypted WHERE/ORDER/MIN/MAX, GROUP BY on encrypted cols,
              depth>=2 mul, HAVING on non-COUNT aggregates, multi-hop JOINs.
"""

import re as _re

_COMMENT_RE = _re.compile(r"--[^\n]*|/\*.*?\*/", _re.DOTALL)


def _is_only_comments(stmt: str) -> bool:
    """True if the fragment is whitespace/comments only (nothing to run)."""
    return not _COMMENT_RE.sub("", stmt).strip()


class Repl:
    def __init__(self, backend) -> None:
        self.backend = backend

    # ── result rendering ────────────────────────────────────────────────
    def _render(self, rs: "_Outcome") -> str:
        if rs.columns is None:
            # INSERT/CREATE/DROP return an affected-row count
            return f"OK ({rs.affected})"
        cols = rs.columns
        rows = [[self._cell(c) for c in row] for row in rs.rows]
        widths = [len(c) for c in cols]
        for row in rows:
            for i, c in enumerate(row):
                widths[i] = max(widths[i], len(c))
        line = lambda cells: " | ".join(
            c.ljust(widths[i]) for i, c in enumerate(cells))
        sep = "-+-".join("-" * w for w in widths)
        out = [line(cols), sep]
        out += [line(r) for r in rows]
        out.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")
        return "\n".join(out)

    @staticmethod
    def _cell(v) -> str:
        if v is None:
            return "NULL"
        # Ciphertext objects have no friendly str; mark them when not decrypted
        name = type(v).__name__
        if name in ("Ciphertext", "PairedCiphertext", "GTCiphertext"):
            return "<encrypted>"
        return str(v)

    # ── meta-commands ───────────────────────────────────────────────────
    def _meta(self, cmd: str) -> bool:
        c = cmd.strip().lower()
        if c in ("\\quit", "\\q", "\\exit"):
            return False
        if c in ("\\help", "\\h", "\\?"):
            print(HELP)
        elif c == "\\spec":
            print(SPEC_SHEET)
        elif c.startswith("\\custody"):
            self._custody(cmd.split()[1:])
        elif c in ("\\tables", "\\dt"):
            names = self.backend.tables()
            if names is None:
                print("(table listing not available over the wire in v0.1)")
            else:
                print("\n".join(names) if names else "(no tables)")
        else:
            print(f"unknown meta-command: {cmd!r} (try \\help)")
        return True

    # ── key custody (LSS threshold sharing of the mask vault) ────────────
    def _custody(self, args: list) -> None:
        usage = ("\\custody export <quorum> <n> <dir>   — seal vault, write "
                 "shares+anchor\n"
                 "\\custody import <dir> [indices...]    — recover from a quorum "
                 "of shares\n"
                 "\\custody refresh <dir>                — proactively rotate "
                 "the shares")
        if not args:
            print(usage); return
        try:
            client = self.backend.nokey_client
        except AttributeError:
            print("custody is only available on the no-key engine"); return
        from ecfhe_query import keymgmt as km
        sub = args[0].lower()
        try:
            if sub == "export" and len(args) == 4:
                q, n, d = int(args[1]), int(args[2]), args[3]
                bundle = km.export_bundle(client, q, n)
                anchor_id = km.write_bundle(d, bundle)
                print(f"sealed vault + anchor + {n} share files written to {d}/")
                print(f"anchor id (post on-chain): {anchor_id}")
                print(f"distribute share_1.json … share_{n}.json to custodians; "
                      f"any {q} recover the vault")
            elif sub == "import" and len(args) >= 2:
                d = args[1]
                sealed, anchor = km.read_public(d)
                idxs = [int(x) for x in args[2:]] or list(
                    range(1, anchor.quorum + 1))
                paths = [f"{d}/share_{i}.json" for i in idxs]
                recs = km.read_shares(paths)
                km.import_bundle(client, sealed, recs, anchor)
                print(f"vault recovered from {len(recs)} shares "
                      f"(quorum {anchor.quorum}); queries are now unblindable")
            elif sub == "refresh" and len(args) == 2:
                d = args[1]
                _sealed, anchor = km.read_public(d)
                recs = km.read_shares(
                    [f"{d}/share_{i}.json" for i in range(1, anchor.n + 1)])
                cust = km.VerifiableCustody(anchor.quorum, anchor.n)
                new_recs, new_anchor = cust.refresh_bundle(recs, anchor)
                km.write_shares(d, new_recs)
                with open(f"{d}/anchor.json", "w") as f:
                    f.write(new_anchor.to_json())
                print(f"refreshed to epoch {new_anchor.epoch}; old shares no "
                      f"longer combine. new anchor id: {new_anchor.digest()}")
            else:
                print(usage)
        except Exception as exc:  # noqa: BLE001
            print(f"custody error ({type(exc).__name__}): {exc}")

    # ── one statement ───────────────────────────────────────────────────
    def run_statement(self, sql: str) -> None:
        try:
            print(self._render(self.backend.execute(sql)))
        except Exception as exc:  # surface errors without a traceback
            print(f"ERROR ({type(exc).__name__}): {exc}")

    # ── loop ────────────────────────────────────────────────────────────
    def loop(self) -> None:
        if not sys.stdin.isatty():
            self._run_script(sys.stdin.read())
            return
        self._interactive()

    def _run_script(self, text: str) -> None:
        """Batch mode: run statements (split on ';') and meta-commands (lines
        starting with '\\'). Comments and whitespace are skipped."""
        buf = ""
        for raw in text.splitlines():
            if raw.lstrip().startswith("\\") and not buf.strip():
                self._meta(raw)
                continue
            buf += ("\n" if buf else "") + raw
            while ";" in buf:
                stmt, buf = buf.split(";", 1)
                if stmt.strip() and not _is_only_comments(stmt):
                    self.run_statement(stmt)
        if buf.strip() and not _is_only_comments(buf):
            self.run_statement(buf)

    def _interactive(self) -> None:
        print(f"torusctl — TorusSQL v0.1 ({self.backend.label})")
        print("Type \\help for meta-commands, \\spec for the surface, \\quit to exit.")
        buf = ""
        while True:
            try:
                line = input("torusql> " if not buf else "      .. ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.lstrip().startswith("\\") and not buf:
                if not self._meta(line):
                    break
                continue
            buf += ("\n" if buf else "") + line
            while ";" in buf:
                stmt, buf = buf.split(";", 1)
                if stmt.strip() and not _is_only_comments(stmt):
                    self.run_statement(stmt)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="TorusSQL REPL")
    ap.add_argument("--connect", metavar="HOST:PORT",
                    help="connect to a TorusDB server instead of running "
                         "the engine in-process")
    ap.add_argument("--db", metavar="PATH",
                    help="(local mode) load/persist the database at PATH")
    args = ap.parse_args()

    try:
        if args.connect:
            host, _, port = args.connect.partition(":")
            backend = RemoteBackend(host or "127.0.0.1", int(port or 8433))
        else:
            backend = LocalBackend(args.db)
    except Exception as exc:
        sys.stderr.write(f"torusctl: could not start: {exc}\n")
        sys.exit(1)

    Repl(backend).loop()


if __name__ == "__main__":
    main()
