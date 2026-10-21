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
