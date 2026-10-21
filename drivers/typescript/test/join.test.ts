// SPDX-License-Identifier: Apache-2.0
// JOIN tests (mirror torussql/tests/test_join_v05.py) against a REAL server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Client, TorusError, eq, isIn } from "../src/torusdb";
import { skipReason, startServer, RunningServer, uniq } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
let db: Client;
let emp: string, dept: string, proj: string;

before(async () => {
  if (skip) return;
  srv = await startServer();
  db = await Client.connect(srv.host, srv.port);
  emp = uniq("emp"); dept = uniq("dept"); proj = uniq("proj");
  await db.createTable(emp, [
    { name: "eid", type: "int", policy: "plain" }, { name: "did", type: "int", policy: "plain" },
    { name: "mgr", type: "int", policy: "plain" }, { name: "name", type: "str", policy: "plain" },
    { name: "salary", type: "int", policy: "encrypted" }]);
  await db.createTable(dept, [
    { name: "did", type: "int", policy: "plain" }, { name: "dname", type: "str", policy: "plain" }]);
  await db.createTable(proj, [
    { name: "did", type: "int", policy: "plain" }, { name: "pname", type: "str", policy: "plain" },
    { name: "budget", type: "int", policy: "encrypted" }]);
  await db.insertMany(dept, [{ did: 10, dname: "Eng" }, { did: 20, dname: "Sales" }, { did: 30, dname: "Empty" }]);
  await db.insertMany(emp, [
    { eid: 1, did: 10, mgr: null, name: "Alice", salary: 100 },
    { eid: 2, did: 10, mgr: 1, name: "Bob", salary: 80 },
    { eid: 3, did: 20, mgr: 1, name: "Carol", salary: 70 },
    { eid: 4, did: 99, mgr: 3, name: "Dave", salary: 60 }]);
  await db.insertMany(proj, [
    { did: 10, pname: "Apollo", budget: 1000 }, { did: 10, pname: "Gemini", budget: 500 },
    { did: 20, pname: "Mercury", budget: 300 }]);
});
after(async () => { if (!skip) { db?.close(); await srv?.stop(); } });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

T("inner join with aliases returns matched rowid tuples", async () => {
  const j = await db.join(emp, [{ table: dept, alias: "d", leftCol: "did", rightCol: "did" }], { alias: "e" });
  assert.deepEqual(j.aliases, ["e", "d"]);
  assert.equal(db.joinCount(j), 3);
  const names = await db.joinColumn(j, "e", "name");
  const dnames = await db.joinColumn(j, "d", "dname");
  assert.deepEqual(names.map((n, i) => [n, dnames[i]]).sort(), [["Alice", "Eng"], ["Bob", "Eng"], ["Carol", "Sales"]]);
});

T("LEFT join keeps unmatched left rows with a null rowid", async () => {
  const j = await db.join(emp, [{ table: dept, alias: "d", leftCol: "did", rightCol: "did", kind: "left" }], { alias: "e" });
  assert.equal(db.joinCount(j), 4);
  const pairs = (await Promise.all([db.joinColumn(j, "e", "name"), db.joinColumn(j, "d", "dname")]))
    .reduce((a, b) => a.map((x, i) => [x, b[i]]) as any);
  assert.deepEqual((pairs as any).sort(), [["Alice", "Eng"], ["Bob", "Eng"], ["Carol", "Sales"], ["Dave", null]]);
  assert.equal(j.tuples.filter((t) => t[1] === null).length, 1);
});

T("inner vs left counts, empty right table, empty inner join", async () => {
  const inner = await db.join(emp, [{ table: dept, leftCol: "did", rightCol: "did" }]);
  const left = await db.join(emp, [{ table: dept, leftCol: "did", rightCol: "did", kind: "left" }]);
  assert.deepEqual([db.joinCount(inner), db.joinCount(left)], [3, 4]);
  const a = uniq("a"), b = uniq("b");
  await db.createTable(a, [{ name: "k", type: "int", policy: "plain" }]);
  await db.createTable(b, [{ name: "k", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }]);
  await db.insertMany(a, [{ k: 1 }, { k: 2 }]);
  const l = await db.join(a, [{ table: b, leftCol: "k", rightCol: "k", kind: "left" }]);
  assert.deepEqual(l.tuples, [[0, null], [1, null]]);
  assert.equal(await db.joinSum(l, b, "v"), 0n);
  const i = await db.join(a, [{ table: b, leftCol: "k", rightCol: "k" }]);
  assert.deepEqual(i.tuples, []);
  assert.equal(db.joinCount(i), 0);
});

T("self-join with aliases: manager lookup and the correct side's SUM", async () => {
  const j = await db.join(emp, [{ table: emp, alias: "m", leftCol: "mgr", rightCol: "eid" }], { alias: "e" });
  assert.equal(db.joinCount(j), 3);
  const e = await db.joinColumn(j, "e", "name"), m = await db.joinColumn(j, "m", "name");
  assert.deepEqual(e.map((x, i) => [x, m[i]]).sort(), [["Bob", "Alice"], ["Carol", "Alice"], ["Dave", "Carol"]]);
  assert.equal(await db.joinSum(j, "m", "salary"), 100n + 100n + 70n);   // manager side; Alice counted twice
  assert.equal(await db.joinSum(j, "e", "salary"), 80n + 70n + 60n);
});

T("three-table join: ON may reference any earlier alias; sums across tables", async () => {
  const j = await db.join(emp, [
    { table: dept, alias: "d", leftAlias: "e", leftCol: "did", rightCol: "did" },
    { table: proj, alias: "p", leftAlias: "d", leftCol: "did", rightCol: "did" }], { alias: "e" });
  assert.equal(db.joinCount(j), 5);
  assert.equal(await db.joinSum(j, "e", "salary"), 100n * 2n + 80n * 2n + 70n);
  assert.equal(await db.joinSum(j, "p", "budget"), 1000n + 500n + 1000n + 500n + 300n);
  // second ON references emp instead of the preceding dept
  const j2 = await db.join(emp, [
    { table: dept, alias: "d", leftCol: "did", rightCol: "did" },
    { table: proj, alias: "p", leftAlias: "e", leftCol: "did", rightCol: "did" }], { alias: "e" });
  assert.equal(db.joinCount(j2), 5);
});

T("LEFT join aggregates skip the NULL side", async () => {
  const j = await db.join(dept, [{ table: proj, alias: "p", leftCol: "did", rightCol: "did", kind: "left" }], { alias: "d" });
  assert.equal(db.joinCount(j), 4);
  assert.equal(await db.joinSum(j, "p", "budget"), 1800n);
});

T("WHERE on the left table is pushed to the server", async () => {
  const j = await db.join(emp, [{ table: dept, alias: "d", leftCol: "did", rightCol: "did" }],
    { alias: "e", where: isIn("eid", [1, 3]) });
  assert.equal(db.joinCount(j), 2);
  assert.equal(await db.joinSum(j, "e", "salary"), 170n);
  const j2 = await db.join(emp, [{ table: dept, leftCol: "did", rightCol: "did" }], { where: eq("did", 10) });
  assert.equal(db.joinCount(j2), 2);
});

T("NULL join keys never match (inner or left)", async () => {
  const a = uniq("na"), b = uniq("nb");
  for (const t of [a, b]) await db.createTable(t, [{ name: "k", type: "int", policy: "plain" }]);
  await db.insertMany(a, [{ k: null }, { k: 1 }]);
  await db.insertMany(b, [{ k: null }, { k: 1 }]);
  assert.equal(db.joinCount(await db.join(a, [{ table: b, leftCol: "k", rightCol: "k" }])), 1);
  assert.equal(db.joinCount(await db.join(a, [{ table: b, leftCol: "k", rightCol: "k", kind: "left" }])), 2);
});

T("deleted (tombstoned) rows are excluded and updates are reflected", async () => {
  const e2 = uniq("e2"), d2 = uniq("d2");
  await db.createTable(e2, [{ name: "did", type: "int", policy: "plain" }, { name: "salary", type: "int", policy: "encrypted" }]);
  await db.createTable(d2, [{ name: "did", type: "int", policy: "plain" }]);
  await db.insertMany(d2, [{ did: 1 }, { did: 2 }]);
  await db.insertMany(e2, [{ did: 1, salary: 100 }, { did: 2, salary: 80 }, { did: 3, salary: 60 }]);
  await db.deleteRows(d2, eq("did", 2));
  const j = await db.join(e2, [{ table: d2, leftCol: "did", rightCol: "did" }]);
  assert.equal(db.joinCount(j), 1);
  const jl = await db.join(e2, [{ table: d2, leftCol: "did", rightCol: "did", kind: "left" }]);
  assert.equal(await db.joinSum(jl, e2, "salary"), 240n);
  await db.update(e2, { salary: 500 }, eq("did", 1));
  assert.equal(await db.joinSum(await db.join(e2, [{ table: d2, leftCol: "did", rightCol: "did" }]), e2, "salary"), 500n);
});

T("cross-table DOT, including LEFT join skipping the NULL side", async () => {
  const a = uniq("da"), b = uniq("db");
  await db.createTable(a, [{ name: "k", type: "int", policy: "plain" }, { name: "x", type: "int", policy: "paired" }]);
  await db.createTable(b, [{ name: "k", type: "int", policy: "plain" }, { name: "y", type: "int", policy: "paired" }]);
  await db.insertMany(a, [{ k: 1, x: 3 }, { k: 2, x: 4 }]);
  await db.insertMany(b, [{ k: 1, y: 10 }]);
  const inner = await db.join(a, [{ table: b, leftCol: "k", rightCol: "k" }]);
  assert.equal(await db.joinDot(inner, a, "x", b, "y"), 30n);
  const left = await db.join(a, [{ table: b, leftCol: "k", rightCol: "k", kind: "left" }]);
  assert.equal(await db.joinDot(left, a, "x", b, "y"), 30n);
  await db.insert(b, { k: 2, y: 100 });
  assert.equal(await db.joinDot(await db.join(a, [{ table: b, leftCol: "k", rightCol: "k" }]), a, "x", b, "y"), 430n);
});

T("bad joins are typed errors (nothing sent for bad shapes)", async () => {
  const kind = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;
  await assert.rejects(db.join(emp, [{ table: dept, leftCol: "salary", rightCol: "did" }]), kind("InterfaceError"));   // encrypted key
  await assert.rejects(db.join(emp, [{ table: dept, leftCol: "did", rightCol: "nope" }]), kind("InterfaceError"));
  await assert.rejects(db.join(emp, [{ table: emp, leftCol: "mgr", rightCol: "eid" }]), kind("InterfaceError"));      // duplicate alias
  await assert.rejects(db.join(emp, [{ table: dept, leftAlias: "zz", leftCol: "did", rightCol: "did" }]), kind("InterfaceError"));
  await assert.rejects(db.join(emp, [{ table: "nosuch", leftCol: "did", rightCol: "did" }]), kind("InterfaceError"));
  const j = await db.join(emp, [{ table: dept, alias: "d", leftCol: "did", rightCol: "did" }]);
  await assert.rejects(db.joinSum(j, "q", "salary"), kind("InterfaceError"));
});
