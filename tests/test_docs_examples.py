# SPDX-License-Identifier: Apache-2.0
"""The code shown in the README / quickstart must actually run."""
import threading
from fractions import Fraction

import pytest

import torussql
from nokey_server import NoKeyTCPServer


@pytest.fixture
def conn(tmp_path):
    srv = NoKeyTCPServer("127.0.0.1", 0)
    host, port = srv.address
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = torussql.connect(host, port, vault_path=str(tmp_path / "demo.vault"))
    yield c
    c.close(); srv.shutdown(); srv.server_close()


def test_quickstart_section_4_and_5(conn):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE emp (
        id INT PLAIN, dept INT PLAIN, name STR PLAIN,
        salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)""")
    cur.execute("CREATE TABLE dept (dept INT PLAIN, dname STR PLAIN)")
    cur.executemany("INSERT INTO dept (dept, dname) VALUES (%s, %s)", [(5, "Eng"), (9, "Sales")])
    cur.executemany(
        "INSERT INTO emp (id, dept, name, salary, rate, hours) "
        "VALUES (%s, %s, %s, FRAC(%s,1), %s, %s)",
        [(1, 5, "Ana", 8000, 50, 40), (2, 5, "Bo", 9000, 60, 35), (3, 9, "Cy", 7000, 45, 40)])
    cur.execute("SELECT SUM(salary), AVG(salary) FROM emp")
    assert cur.fetchall() == [(24000, 8000)]
    cur.execute("SELECT DOT(rate, hours) FROM emp")
    assert cur.fetchall() == [(50 * 40 + 60 * 35 + 45 * 40,)]
    cur.execute("""SELECT d.dname, COUNT(*), SUM(e.salary)
                   FROM emp e JOIN dept d ON e.dept = d.dept
                   GROUP BY d.dname ORDER BY d.dname""")
    assert cur.fetchall() == [("Eng", 2, 17000), ("Sales", 1, 7000)]
    cur.execute("""SELECT d.dname, e.name FROM dept d
                   LEFT JOIN emp e ON e.dept = d.dept""")
    assert sorted(cur.fetchall()) == [("Eng", "Ana"), ("Eng", "Bo"), ("Sales", "Cy")]
    with conn.transaction():
        cur.execute("UPDATE emp SET salary = FRAC(9500,1) WHERE id = 2")
        cur.execute("DELETE FROM emp WHERE id = 3")
    cur.execute("SELECT SUM(salary) FROM emp")
    assert cur.fetchall() == [(8000 + 9500,)]


def test_readme_sql_examples_validate():
    from torussql_parser.parser import parse
    from torussql_parser.validate import Schema
    sch = Schema()
    for ddl in ["CREATE TABLE emp (id INT PLAIN, dept INT PLAIN, mgr INT PLAIN, name STR PLAIN, "
                "salary RATIONAL ENC, rate INT PAIRED, hours INT PAIRED)",
                "CREATE TABLE dept (dept INT PLAIN, dname STR PLAIN)"]:
        sch.apply(parse(ddl))
    for sql in [
        "SELECT SUM(salary), AVG(salary) FROM emp WHERE dept = 5",
        "SELECT DOT(rate, hours) FROM emp",
        "SELECT d.dname, COUNT(*), SUM(e.salary) FROM emp e LEFT JOIN dept d ON e.dept = d.dept "
        "GROUP BY d.dname HAVING COUNT(*) > 1 ORDER BY d.dname LIMIT 10",
        "SELECT e.name, m.name FROM emp e JOIN emp m ON e.mgr = m.id",
        "UPDATE emp SET salary = FRAC(9500,1) WHERE id = 2", "DELETE FROM emp WHERE dept = 9",
    ]:
        sch.validate(parse(sql))


# ── docs/GETTING_STARTED.md: the whole tested path ────────────────────────────
import re
import shlex
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GETTING_STARTED = ROOT / "docs" / "GETTING_STARTED.md"


def _have_pyecc():
    try:
        import py_ecc  # noqa: F401
        return True
    except ImportError:
        return False


def _getting_started_steps():
    """The runnable parts of GETTING_STARTED.md, in document order."""
    steps = []
    for lang, body in re.findall(r"```(\w*)\n(.*?)```", GETTING_STARTED.read_text(), re.S):
        if lang == "python":
            steps.append(("python", body))
        elif lang == "bash":
            for line in body.splitlines():
                line = line.strip()
                if line.startswith("export FHE_PASS="):
                    steps.append(("env", line.split("=", 1)[1].strip("'\"")))
                elif line.startswith("torusdb-server --db"):
                    steps.append(("server", shlex.split(line)[2]))
                elif line.startswith("torussql "):
                    argv = shlex.split(line)[1:]
                    if ("-c" in argv or "--fhe-keygen" in argv or "--version" in argv):
                        steps.append(("shell", argv))
        elif "torussql>" in body:                                 # the interactive session
            stmts = [l.split("torussql> ", 1)[1] for l in body.splitlines()
                     if l.startswith("torussql> ") and not l.split("> ", 1)[1].startswith("\\")]
            argv = ["--vault", "./demo.vault"]
            for s in stmts:
                argv += ["-c", s]
            steps.append(("shell", argv))
    return steps


def test_getting_started_runs_end_to_end(tmp_path, monkeypatch, capsys):
    from torussql import cli
    monkeypatch.chdir(tmp_path)
    steps = _getting_started_steps()
    kinds = [k for k, _ in steps]
    assert kinds.count("server") == 2 and "python" in kinds and "shell" in kinds
    pyecc = _have_pyecc()
    srv = None
    port = None
    for kind, arg in steps:
        if kind == "env":
            monkeypatch.setenv("FHE_PASS", arg)
        elif kind == "server":
            if srv is not None:                                   # "restart" step
                srv.shutdown(); srv.server_close()
            srv = NoKeyTCPServer("127.0.0.1", 0, arg)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            port = srv.address[1]
        elif kind == "python":
            ns = {}
            exec(compile(arg.replace("8533", str(port)), "GETTING_STARTED.md", "exec"), ns)
            ns["conn"].close()                                    # a script exits; release the vault lock
        else:
            if any(a.startswith("--fhe") for a in arg) and not pyecc:
                continue
            if "--version" in arg:
                with pytest.raises(SystemExit) as ei:
                    cli.main(arg)
                assert ei.value.code == 0
                continue
            argv = list(arg) if "--fhe-keygen" in arg else arg + ["-p", str(port)]
            assert cli.main(argv) == 0, argv
    out = capsys.readouterr().out
    srv.shutdown(); srv.server_close()
    assert out.count("42") >= 2                  # SUM(v) before and after the restart
    assert "[(24000,)]" in out and "[(5900,)]" in out and "[(5, 17000), (9, 7000)]" in out
    if pyecc:
        assert re.search(r"^90\s*$", out, re.M) and re.search(r"^12400\s*$", out, re.M)


def test_getting_started_is_linked_first():
    readme = (ROOT / "README.md").read_text()
    quick = (ROOT / "docs" / "quickstart.md").read_text()
    assert "docs/GETTING_STARTED.md" in readme[:readme.index("Be precise about the guarantee")]
    assert "GETTING_STARTED.md" in quick[:700]
    assert "3.11" in GETTING_STARTED.read_text()[:1500]          # Python requirement is prominent


def test_relative_links_in_docs_resolve():
    files = [ROOT / n for n in ("README.md", "ROADMAP.md", "SECURITY.md", "CONTRIBUTING.md",
                                "RELEASING.md", "bench/README.md", "server/README.md",
                                "core/README.md", "parser/README.md", "drivers/python/README.md",
                                "drivers/typescript/README.md", "drivers/rust/README.md")]
    files += sorted((ROOT / "docs").glob("*.md")) + sorted((ROOT / "spec").glob("*.md"))
    bad = []
    for f in files:
        text = re.sub(r"```.*?```", "", f.read_text(), flags=re.S)
        for m in re.finditer(r"\]\(([^)\s]+)\)", text):
            url = m.group(1)
            if url.startswith(("http", "#", "mailto")):
                continue
            if not (f.parent / url.split("#")[0]).exists():
                bad.append((str(f.relative_to(ROOT)), url))
    assert not bad, bad


def test_documented_flags_exist_in_help():
    """Every `--flag` mentioned in the main docs is a real flag of one of the CLIs (or a known external one)."""
    import subprocess, sys
    cmds = [[sys.executable, str(ROOT / "server" / "nokey_server.py"), "--help"],
            [sys.executable, "-m", "torussql.cli", "--help"]]
    from torussql.custody.__main__ import main as _m  # noqa: F401  (needs py_ecc)
    real = set()
    import os
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        str(ROOT / p) for p in ("core", "parser", "drivers/python", "server")))
    for c in cmds:
        real |= set(re.findall(r"--[a-z][a-z0-9-]+", subprocess.run(c, capture_output=True, text=True, env=env).stdout))
    sub = ["identity-new", "ids-merge", "new-session", "dkg-start", "dkg-finish", "keygen-local", "share-check",
           "public-show", "serve", "open-test", "fhe-keygen-threshold", "fhe-open-test", "reshare-start",
           "reshare-finish", "mask-init", "mask-status", "mask-repair", "mask-gc", "mask-reshare"]
    for s in sub:
        real |= set(re.findall(r"--[a-z][a-z0-9-]+", subprocess.run(
            [sys.executable, "-m", "torussql.custody", s, "--help"], capture_output=True, text=True, env=env).stdout))
    for b in ("bench", "net_bench", "storage_bench", "tpch"):
        real |= set(re.findall(r"--[a-z][a-z0-9-]+", subprocess.run(
            [sys.executable, str(ROOT / "bench" / f"{b}.py"), "--help"], capture_output=True, text=True, env=env).stdout))
    external = {"--all-targets", "--example", "--features", "--from", "--interval", "--no-cache-dir", "--retries",
                "--start-period", "--timeout", "--port", "--rows", "--help", "--name", "--format", "--no-deps",
                "--allow-dirty", "--list", "--dry-run", "--find-links", "--no-index", "--wheel", "--outdir",
                "--force-reinstall", "--editable"}
    mentioned = set()
    for f in [ROOT / "README.md", ROOT / "bench" / "README.md", ROOT / "server" / "README.md",
              ROOT / "server" / "Dockerfile", *(ROOT / "docs").glob("*.md"),
              *(ROOT / "drivers").glob("*/README.md")]:
        mentioned |= set(re.findall(r"--[a-z][a-z0-9-]+", f.read_text()))
    assert not (mentioned - real - external), sorted(mentioned - real - external)


def test_first_run_error_messages_say_what_to_do(tmp_path):
    import nokey_server
    # token required but not given: the message names both the API argument and the shell flag
    srv = NoKeyTCPServer("127.0.0.1", 0, config=nokey_server.ServerConfig(tokens={"admin": "x" * 20})) \
        if hasattr(nokey_server, "ServerConfig") else None
    if srv is not None:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with pytest.raises(torussql.AuthenticationError) as ei:
            torussql.connect("127.0.0.1", srv.address[1])
        assert "token=" in str(ei.value) and "--token-env" in str(ei.value)
        srv.shutdown(); srv.server_close()
    # port in use: a one-line instruction, not a traceback
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
    with pytest.raises(SystemExit) as ei:
        nokey_server.main(["--port", str(s.getsockname()[1])])
    s.close()
    assert "cannot listen" in str(ei.value) and "--port" in str(ei.value)


def test_payroll_example_file_runs_with_the_documented_results(conn):
    """examples/payroll.torusql: every statement runs and the results quoted in its comments hold.

    The FHE section needs a key (`conn` has none, like a real session without --fhe-key); it is
    skipped here and re-run in isolation by test_payroll_example_fhe_section below."""
    from torussql.cli import split_statements
    text = (ROOT / "examples" / "payroll.torusql").read_text()
    stmts, rest = split_statements(text)
    assert not rest.strip() and len(stmts) > 15
    fhe_stmts = [sql for sql in stmts if "fhe_payroll" in sql.lower()]
    stmts = [sql for sql in stmts if sql not in fhe_stmts]
    got = {}
    for sql in stmts:
        got[" ".join(sql.split())] = conn.execute(sql).rows if sql.lstrip().upper().startswith("SELECT") \
            else conn.execute(sql)
    F = Fraction
    sel = {k: v for k, v in got.items() if k.upper().startswith("SELECT")}

    def rows(prefix):
        return next(v for k, v in sel.items() if k.startswith(prefix))
    assert rows("SELECT SUM(salary)") == [[24000]]
    assert rows("SELECT 12 * salary") == [[[96000, 108000, 84000]]]
    assert rows("SELECT DOT(rate, hours)") == [[5900]]
    assert rows("SELECT rate * (hours + overtime") == [[[2375, 2280, 2070]]]
    assert rows("SELECT rate * hours * (1 - tax) FROM") == [[[1600, 1575, 1440]]]
    assert rows("SELECT rate * hours * (1 - tax) * overtime") == [[[8000, 3150, 5760]]]
    assert rows("SELECT SUM(rate * hours * (1 - tax))") == [[4615]]
    assert rows("SELECT salary / 12") == [[[F(2000, 3), 750, F(1750, 3)]]]
    assert rows("SELECT salary / hours") == [[[200, F(1800, 7), 175]]]
    assert rows("SELECT SUM(rate * hours) / COUNT(*)") == [[F(5900, 3), F(4800, 23)]]
    assert rows("SELECT rate * hours + salary / 12") == \
        [[[2000 + F(2000, 3) - 5, 2100 + 750 - 2, 1800 + F(1750, 3) - 4]]]
    # depth = rounds: the depth-3 query used three batched owner round trips
    conn.execute("SELECT rate * hours * (1 - tax) * overtime FROM payroll")
    assert conn.client.last_expr_cost["mult_rounds"] == 3


def test_payroll_example_fhe_section_runs_with_the_documented_results(tmp_path):
    """The FHE part of examples/payroll.torusql (dialect v0.6.2), run on a connection that has the
    key the file's own comment says to pass with --fhe-key."""
    import threading

    from nokey_server import NoKeyTCPServer
    from torusdb_core import fhe
    from torussql.cli import split_statements

    text = (ROOT / "examples" / "payroll.torusql").read_text()
    stmts, _rest = split_statements(text)
    stmts = [sql for sql in stmts if "fhe_payroll" in sql.lower()]
    assert len(stmts) >= 6

    srv = NoKeyTCPServer("127.0.0.1", 0)
    host, port = srv.address
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    key = fhe.FheKey(value_range=50_000)
    conn = torussql.connect(host, port, vault_path=str(tmp_path / "fhe_demo.vault"), fhe_key=key)
    try:
        got = {}
        for sql in stmts:
            got[" ".join(sql.split())] = conn.execute(sql).rows if sql.lstrip().upper().startswith("SELECT") \
                else conn.execute(sql)
        sel = {k: v for k, v in got.items() if k.upper().startswith("SELECT")}

        def rows(prefix):
            return next(v for k, v in sel.items() if k.startswith(prefix))
        assert rows("SELECT SUM(rate) FROM fhe_payroll") == [[155]]
        assert rows("SELECT DOT(rate, hours)") == [[5900]]
        assert rows("SELECT rate * hours FROM fhe_payroll") == [[[2000, 2100, 1800]]]
        assert rows("SELECT SUM(rate * hours)") == [[5900]]
    finally:
        conn.close(); srv.shutdown(); srv.server_close()
