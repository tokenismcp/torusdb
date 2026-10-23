# SPDX-License-Identifier: Apache-2.0
"""``torussql`` — an interactive shell for TorusDB (a ``psql`` for encrypted SQL).

    torussql -h 127.0.0.1 -p 8533 --token-env TORUSDB_TOKEN --vault ~/.torussql/vault
    torussql -c "SELECT SUM(salary) FROM emp"          # one statement, then exit
    torussql -f schema.sql                              # run a script
    echo "SELECT COUNT(*) FROM emp;" | torussql         # piped

The shell is the data owner: it holds the mask vault (or talks to a threshold mask
cluster), so encrypted results decrypt here and nowhere else. Without ``--vault``
the masks live only for this session and encrypted data written in it becomes
unreadable afterwards — the shell warns about that.

Meta-commands:  \\dt  list tables   \\d TABLE  describe   \\timing   \\q   \\?
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from . import nokey
from .nokey import Error


def split_statements(text: str) -> tuple[list[str], str]:
    """Split on ``;`` outside string literals and comments. Returns
    (complete statements, remaining partial text)."""
    out, cur, i, n = [], [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":                                   # string literal ('' escapes)
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            cur.append(text[i:j + 1]); i = j + 1
        elif text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif ch == ";":
            stmt = "".join(cur).strip()
            if stmt:
                out.append(stmt)
            cur = []; i += 1
        else:
            cur.append(ch); i += 1
    return out, "".join(cur)


def format_table(columns, rows) -> str:
    def cell(v):
        return "NULL" if v is None else str(v)
    body = [[cell(v) for v in r] for r in rows]
    w = [len(str(c)) for c in columns]
    for r in body:
        for k, v in enumerate(r):
            w[k] = max(w[k], len(v))
    line = lambda cs: " | ".join(str(c).ljust(w[k]) for k, c in enumerate(cs)).rstrip()
    out = [line(columns), "-+-".join("-" * x for x in w)] + [line(r) for r in body]
    out.append(f"({len(body)} row{'s' if len(body) != 1 else ''})")
    return "\n".join(out)


class Shell:
    def __init__(self, conn, *, timing: bool = False, out=None):
        self.conn, self.timing, self.out = conn, timing, out or sys.stdout
        self.failed = False

    def run(self, sql: str) -> bool:
        t0 = time.perf_counter()
        try:
            cur = self.conn.cursor()
            cur.execute(sql)
            if cur.description is not None:
                print(format_table([d[0] for d in cur.description], cur.fetchall()), file=self.out)
            else:
                print(f"OK ({cur.rowcount if cur.rowcount >= 0 else 0})", file=self.out)
        except Error as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            self.failed = True
            return False
        if self.timing:
            print(f"Time: {(time.perf_counter() - t0) * 1000:.2f} ms", file=self.out)
        return True

    def meta(self, line: str) -> bool:
        """Handle a backslash command; False = quit."""
        parts = line.strip().split()
        cmd = parts[0]
        if cmd in ("\\q", "\\quit", "\\exit"):
            return False
        if cmd in ("\\?", "\\h", "\\help"):
            print(__doc__.split("Meta-commands:")[1].strip(), file=self.out)
        elif cmd == "\\timing":
            self.timing = not self.timing
            print(f"Timing is {'on' if self.timing else 'off'}.", file=self.out)
        elif cmd in ("\\dt", "\\tables"):
            names = sorted(self.conn.client._schema)
            print("\n".join(names) if names else "(no tables)", file=self.out)
        elif cmd == "\\d" and len(parts) == 2:
            cols = self.conn.client._schema.get(parts[1])
            if cols is None:
                print(f"no such table: {parts[1]}", file=sys.stderr)
            else:
                print(format_table(["column", "type", "policy"], cols), file=self.out)
        else:
            print(f"unknown command {line.strip()!r} (try \\?)", file=sys.stderr)
        return True

    def feed(self, text: str, buf: str = "") -> str:
        stmts, rest = split_statements(buf + text)
        for s in stmts:
            self.run(s)
        return rest

    def repl(self) -> None:
        interactive = sys.stdin.isatty()
        try:
            import readline  # noqa: F401  (line editing / history where available)
        except ImportError:
            pass
        buf = ""
        while True:
            try:
                line = input(("torussql> " if not buf.strip() else "      -> ") if interactive else "")
            except EOFError:
                break
            except KeyboardInterrupt:
                print(); buf = ""; continue
            if not buf.strip() and line.strip().startswith("\\"):
                if not self.meta(line):
                    break
                continue
            buf = self.feed(line + "\n", buf)
        if buf.strip():
            print("ERROR: unterminated statement (missing ';')", file=sys.stderr)
            self.failed = True


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="torussql", description="Interactive shell for TorusDB.",
                                 add_help=False)
    ap.add_argument("--help", action="help")
    ap.add_argument("-h", "--host", default="127.0.0.1")
    ap.add_argument("-p", "--port", type=int, default=8533)
    ap.add_argument("--token-env", metavar="VAR", help="env var holding the API token")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--cafile")
    ap.add_argument("--tls-insecure", action="store_true", help="skip certificate checks (dev only)")
    ap.add_argument("--vault", metavar="PATH", help="mask vault file (persists decryptability)")
    ap.add_argument("--vault-pass-env", metavar="VAR", help="env var with the vault passphrase")
    ap.add_argument("--vault-prompt", action="store_true", help="prompt for the vault passphrase")
    ap.add_argument("--trust-server-schema", action="store_true",
                    help="allow writes to tables whose schema was learned from the server")
    ap.add_argument("--authenticated", action="store_true", help="enable integrity MACs")
    ap.add_argument("-c", "--command", action="append", metavar="SQL")
    ap.add_argument("-f", "--file", metavar="PATH")
    ap.add_argument("--timing", action="store_true")
    ap.add_argument("--version", action="version", version=f"torussql {nokey.__version__}"
                    if hasattr(nokey, "__version__") else "torussql")
    return ap


def main(argv=None) -> int:
    a = _parser().parse_args(argv)
    token = os.environ.get(a.token_env) if a.token_env else None
    if a.token_env and not token:
        print(f"error: ${a.token_env} is not set", file=sys.stderr)
        return 2
    passphrase = os.environ.get(a.vault_pass_env) if a.vault_pass_env else None
    if a.vault_prompt:
        passphrase = getpass.getpass("vault passphrase: ")
    if a.vault_pass_env and not passphrase:
        print(f"error: ${a.vault_pass_env} is not set", file=sys.stderr)
        return 2
    try:
        conn = nokey.connect(a.host, a.port, tls=a.tls, cafile=a.cafile,
                             tls_insecure=a.tls_insecure, token=token,
                             vault_path=a.vault, vault_passphrase=passphrase,
                             authenticated=a.authenticated,
                             trust_server_schema=a.trust_server_schema)
    except Exception as exc:                                    # noqa: BLE001
        print(f"torussql: could not connect to {a.host}:{a.port}: {exc}", file=sys.stderr)
        return 1
    sh = Shell(conn, timing=a.timing)
    try:
        if a.command or a.file:
            text = "".join(c.rstrip().rstrip(";") + ";\n" for c in (a.command or []))   # -c needs no ';' 
            if a.file:
                with open(a.file, encoding="utf-8") as f:
                    text += "\n" + f.read()
            rest = sh.feed(text + "\n")
            if rest.strip():
                print("ERROR: unterminated statement (missing ';')", file=sys.stderr)
                return 1
        else:
            if sys.stdin.isatty():
                print(f"torussql {a.host}:{a.port} — type \\? for help, \\q to quit")
                if not a.vault:
                    print("warning: no --vault; encrypted data written in this session "
                          "cannot be read back later", file=sys.stderr)
            sh.repl()
    finally:
        conn.close()
    return 1 if sh.failed else 0


if __name__ == "__main__":
    sys.exit(main())
