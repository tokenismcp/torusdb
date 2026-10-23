// SPDX-License-Identifier: Apache-2.0
// Integration tests against a REAL keyless server (subprocess).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Client, TorusError, eq, gt, ge, ne, isIn, and, or, Column } from "../src/torusdb";
import { skipReason, startServer, RunningServer, EMP_COLS, uniq } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
let db: Client;

before(async () => {
  if (skip) return;
  srv = await startServer();
  db = await Client.connect(srv.host, srv.port);
});
after(async () => {
  if (skip) return;
  db?.close();
  await srv?.stop();
});

const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

async function seedEmp(): Promise<string> {
  const t = uniq("emp");
  await db.createTable(t, EMP_COLS);
  await db.insert(t, { id: 1, dept: 5, salary: { num: 8000n, den: 1n }, rate: 50, hours: 40 });
  await db.insert(t, { id: 2, dept: 5, salary: { num: 9000n, den: 1n }, rate: 60, hours: 35 });
  await db.insert(t, { id: 3, dept: 9, salary: { num: 7000n, den: 1n }, rate: 45, hours: 40 });
  return t;
}

T("hello negotiates protocol 2", async () => {
  assert.equal(db.serverInfo.protocol, 2);
  assert.equal(db.serverInfo.auth_required, false);
  assert.equal(await db.ping(), true);
});

T("SUM / COUNT / DOT on the example data (with and without WHERE)", async () => {
  const t = await seedEmp();
  assert.equal(await db.sum(t, "salary"), 24000n);
  assert.equal(await db.sum(t, "salary", eq("dept", 5)), 17000n);
  assert.equal(await db.count(t), 3);
  assert.equal(await db.count(t, eq("dept", 5)), 2);
  assert.equal(await db.dot(t, "rate", "hours"), 5900n);
  assert.equal(await db.dot(t, "rate", "hours", eq("dept", 5)), 50n * 40n + 60n * 35n);
  assert.equal(await db.sum(t, "salary", eq("dept", 777)), 0n);
  assert.equal(await db.dot(t, "rate", "hours", eq("dept", 777)), 0n);
});

T("rational SUM and AVG are exact", async () => {
  const t = uniq("rat");
  await db.createTable(t, [{ name: "k", type: "int", policy: "plain" }, { name: "v", type: "rational", policy: "encrypted" }]);
  await db.insert(t, { k: 1, v: { num: 1n, den: 2n } });
  await db.insert(t, { k: 2, v: { num: 1n, den: 3n } });
  await db.insert(t, { k: 3, v: { num: -3n, den: 5n } });
  assert.deepEqual(await db.sum(t, "v"), { num: 7n, den: 30n });
  assert.deepEqual(await db.sum(t, "v", and(ge("k", 1), ne("k", 3))), { num: 5n, den: 6n });
  assert.deepEqual(await db.avg(t, "v", or(eq("k", 1), eq("k", 2))), { num: 5n, den: 12n });
  assert.equal(await db.avg(t, "v", eq("k", 99)), null);
  assert.deepEqual(await db.avg(t, "v", eq("k", 1)), { num: 1n, den: 2n });
});

T("predicate builders: IN, comparison, and/or", async () => {
  const t = await seedEmp();
  assert.equal(await db.count(t, isIn("id", [1, 3])), 2);
  assert.equal(await db.count(t, gt("id", 1)), 2);
  assert.equal(await db.count(t, and(eq("dept", 5), gt("id", 1))), 1);
  assert.equal(await db.count(t, or(eq("id", 1), eq("id", 3))), 2);
  assert.equal(await db.sum(t, "salary", and(or(eq("id", 1), eq("id", 3)), eq("dept", 9))), 7000n);
});

T("select reveals plain and encrypted columns", async () => {
  const t = await seedEmp();
  const rows = await db.select(t, ["id", "salary"], eq("dept", 5));
  assert.deepEqual(rows, [{ id: 1n, salary: 8000n }, { id: 2n, salary: 9000n }]);
});

T("UPDATE re-blinds encrypted cells and refreshes masks; plain updates work", async () => {
  const t = await seedEmp();
  assert.equal(await db.update(t, { salary: { num: 500n, den: 1n } }, eq("id", 1)), 1);
  assert.equal(await db.sum(t, "salary"), 500n + 9000n + 7000n);
  assert.equal(await db.update(t, { dept: 9 }, eq("dept", 5)), 2);
  assert.equal(await db.count(t, eq("dept", 9)), 3);
  assert.equal(await db.update(t, { salary: 1 }, eq("id", 424242)), 0);
  assert.equal(db.inTransaction, false);
});

T("DELETE tombstones rows and aggregates skip them", async () => {
  const t = await seedEmp();
  assert.equal(await db.deleteRows(t, eq("id", 2)), 1);
  assert.equal(await db.count(t), 2);
  assert.equal(await db.sum(t, "salary"), 15000n);
  assert.equal(await db.deleteRows(t, eq("id", 2)), 0);
  assert.deepEqual((await db.tableInfo(t)).deleted, [1]);
});

T("insertMany blinds locally and uses one insert_many RPC", async () => {
  const t = uniq("bulk");
  await db.createTable(t, [{ name: "k", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }]);
  const rows = Array.from({ length: 200 }, (_, i) => ({ k: i, v: i * 3 }));
  const ids = await db.insertMany(t, rows);
  assert.equal(ids.length, 200);
  assert.deepEqual(ids, Array.from({ length: 200 }, (_, i) => i));
  assert.equal(await db.sum(t, "v"), BigInt(3 * (199 * 200 / 2)));
  assert.equal(await db.sum(t, "v", gt("k", 99)), BigInt(3 * (199 * 200 / 2 - 99 * 100 / 2)));
  assert.deepEqual(await db.insertMany(t, []), []);
  // the call count is observable in server stats (admin when auth is off)
  const st = await db.stats();
  assert.ok(JSON.stringify(st).includes("insert_many"));
});

T("insertMany is all-or-nothing on a bad row (no masks leak)", async () => {
  const t = uniq("bulk2");
  await db.createTable(t, [{ name: "k", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }]);
  const before = db.maskCount;
  await assert.rejects(db.insertMany(t, [{ k: 1, v: 1 }, { k: 2, v: null as any }]), TorusError);
  assert.equal(db.maskCount, before);
  assert.equal(await db.count(t), 0);
  assert.equal((await db.tableInfo(t)).rows, 0);
});

T("tables / tableInfo / syncSchema from a second connection", async () => {
  const t = await seedEmp();
  assert.ok((await db.tables()).includes(t));
  assert.deepEqual(await db.tableInfo(t), { rows: 3, deleted: [], indexes: [] });
  const other = await Client.connect(srv.host, srv.port);   // schema only, no vault
  try {
    assert.equal(await other.count(t, eq("dept", 5)), 2);
    // plain columns readable; encrypted ones need the owner's vault
    assert.deepEqual((await other.select(t, ["id"], eq("dept", 9))), [{ id: 3n }]);
    await assert.rejects(other.sum(t, "salary"), (e: any) => e instanceof TorusError && /no mask/.test(e.message));
  } finally { other.close(); }
});

T("encrypted overflow is reported as OutOfBudget, not a wrong number", async () => {
  const t = uniq("big");
  await db.createTable(t, [{ name: "v", type: "int", policy: "encrypted" }]);
  const huge = (1n << 126n);
  await db.insert(t, { v: huge });
  await db.insert(t, { v: huge });
  await assert.rejects(db.sum(t, "v"), (e: any) => e.kind === "OutOfBudget");
  await assert.rejects(db.insert(t, { v: 1n << 127n }), (e: any) => e.kind === "OutOfBudget");
});

T("local misuse is a typed InterfaceError (nothing sent)", async () => {
  const t = await seedEmp();
  await assert.rejects(db.insert(t, { id: 1 } as any), (e: any) => e.kind === "InterfaceError");
  await assert.rejects(db.insert(t, { id: 1, dept: 1, salary: "x" as any, rate: 1, hours: 1 }), (e: any) => e.kind === "InterfaceError");
  await assert.rejects(db.insert(t, { id: 1, dept: 1, salary: 1, rate: 1, hours: 1, nope: 1 } as any), (e: any) => e.kind === "InterfaceError");
  await assert.rejects(db.sum("no_such_table_x", "v"), (e: any) => e.kind === "InterfaceError");
  await assert.rejects(db.sum(t, "id"), (e: any) => e.kind === "InterfaceError");   // plain column
  await assert.rejects(db.insert(t, { id: 1.5, dept: 1, salary: 1, rate: 1, hours: 1 }), (e: any) => e.kind === "InterfaceError");
});

T("server errors carry a typed kind", async () => {
  const t = await seedEmp();
  const dup = await db.createTable(t, EMP_COLS).catch((e) => e);
  assert.ok(dup instanceof TorusError, String(dup));
  assert.ok(typeof dup.kind === "string" && dup.kind.length > 0);
  assert.ok(dup instanceof Error);
  // server-side BadRequest: predicate on a column that does not exist
  const bad = await db.count(t, eq("nope", 1)).catch((e) => e);
  assert.ok(bad instanceof TorusError);
  assert.equal(bad.kind, "BadRequest");
  // the connection stays usable after an error reply
  assert.equal(await db.count(t), 3);
});

T("admin RPCs on an auth-less server: stats works; backup/checkpoint report cleanly", async () => {
  const st = await db.stats();
  assert.ok(st && typeof st === "object");
  const r = await db.checkpoint().then(() => "ok", (e) => e);
  assert.ok(r === "ok" || r instanceof TorusError);
  const b = await db.backup().then(() => "ok", (e) => e);
  assert.ok(b === "ok" || b instanceof TorusError);
  assert.equal(await db.ping(), true);
});

T("dropTable (admin) forgets masks", async () => {
  const t = await seedEmp();
  const n = db.maskCount;
  await db.dropTable(t);
  assert.equal(db.maskCount, n - 9);
  assert.ok(!(await db.tables()).includes(t));
});

T("concurrent calls on one connection are serialized correctly", async () => {
  const t = await seedEmp();
  const rs = await Promise.all(Array.from({ length: 25 }, (_, i) =>
    i % 2 ? db.sum(t, "salary") : db.count(t)));
  rs.forEach((r, i) => assert.equal(r, i % 2 ? 24000n : 3));
});

T("string plain columns round-trip and filter", async () => {
  const t = uniq("s");
  const cols: Column[] = [{ name: "name", type: "str", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }];
  await db.createTable(t, cols);
  await db.insert(t, { name: "alice's \"x\"\né", v: 1 });
  await db.insert(t, { name: "bob", v: 2 });
  assert.equal(await db.sum(t, "v", eq("name", "alice's \"x\"\né")), 1n);
  assert.deepEqual(await db.select(t, ["name"], eq("name", "bob")), [{ name: "bob" }]);
});

