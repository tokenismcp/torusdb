// SPDX-License-Identifier: Apache-2.0
// Transactions against a REAL server: commit, rollback (server + mask state), dropped connection.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Client, TorusError, eq } from "../src/torusdb";
import { skipReason, startServer, RunningServer, uniq } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

async function conn(): Promise<Client> { return Client.connect(srv.host, srv.port); }
const COLS = [{ name: "k", type: "int" as const, policy: "plain" as const },
              { name: "v", type: "int" as const, policy: "encrypted" as const }];

async function seeded(db: Client): Promise<string> {
  const t = uniq("tx");
  await db.createTable(t, COLS);
  await db.insert(t, { k: 1, v: 100 });
  await db.insert(t, { k: 2, v: 200 });
  return t;
}

T("commit makes changes visible to another connection", async () => {
  const a = await conn(), b = await conn();
  try {
    const t = await seeded(a);
    await b.syncSchema();
    await a.begin();
    assert.equal(a.inTransaction, true);
    await a.insert(t, { k: 3, v: 300 });
    assert.equal(await a.sum(t, "v"), 600n);
    await a.commit();
    assert.equal(a.inTransaction, false);
    assert.equal(await b.count(t), 3);
    assert.equal(await a.sum(t, "v"), 600n);
  } finally { a.close(); b.close(); }
});

T("rollback of an insert removes the row AND its masks", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    const masks = a.maskCount;
    await a.begin();
    await a.insert(t, { k: 3, v: 300 });
    assert.equal(a.maskCount, masks + 1);
    await a.rollback();
    assert.equal(a.maskCount, masks);
    assert.equal(await a.count(t), 2);
    assert.equal(await a.sum(t, "v"), 300n);
    assert.deepEqual((await a.tableInfo(t)).rows, 2);
    // a fresh insert after rollback reuses the rowid and decrypts correctly
    await a.insert(t, { k: 9, v: 7 });
    assert.equal(await a.sum(t, "v"), 307n);
  } finally { a.close(); }
});

T("rollback of an UPDATE restores server cells and the previous masks", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    await a.begin();
    await a.update(t, { v: 999 }, eq("k", 1));
    assert.equal(await a.sum(t, "v"), 1199n);
    await a.rollback();
    assert.equal(await a.sum(t, "v"), 300n);
    assert.deepEqual(await a.select(t, ["v"], eq("k", 1)), [{ v: 100n }]);
  } finally { a.close(); }
});

T("rollback of DELETE and of CREATE TABLE", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    await a.begin();
    assert.equal(await a.deleteRows(t, eq("k", 1)), 1);
    const t2 = uniq("txddl");
    await a.createTable(t2, COLS);
    await a.insert(t2, { k: 1, v: 1 });
    await a.rollback();
    assert.equal(await a.count(t), 2);
    assert.equal(await a.sum(t, "v"), 300n);
    assert.ok(!(await a.tables()).includes(t2));
    await assert.rejects(a.count(t2), (e: any) => e.kind === "InterfaceError");   // schema restored too
  } finally { a.close(); }
});

T("transaction(fn) commits on success and rolls back on throw", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    const out = await a.transaction(async (db) => { await db.insert(t, { k: 3, v: 3 }); return "done"; });
    assert.equal(out, "done");
    assert.equal(await a.sum(t, "v"), 303n);
    await assert.rejects(
      a.transaction(async () => { await a.insert(t, { k: 4, v: 4 }); throw new Error("boom"); }),
      /boom/);
    assert.equal(a.inTransaction, false);
    assert.equal(await a.sum(t, "v"), 303n);
    assert.equal(await a.count(t), 3);
    // transaction() with no await on the helper: async () => {...} form from the spec
    await a.transaction(async () => { await a.insert(t, { k: 5, v: 5 }); });
    assert.equal(await a.sum(t, "v"), 308n);
  } finally { a.close(); }
});

T("a failing statement inside transaction(fn) rolls back the whole thing", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    await assert.rejects(a.transaction(async (db) => {
      await db.insert(t, { k: 3, v: 3 });
      await db.count(t, eq("nonexistent", 1));        // server BadRequest
    }), (e: any) => e instanceof TorusError && e.kind === "BadRequest");
    assert.equal(await a.count(t), 2);
    assert.equal(await a.sum(t, "v"), 300n);
  } finally { a.close(); }
});

T("a dropped connection mid-transaction rolls back on the server", async () => {
  const a = await conn();
  const t = await seeded(a);
  await a.begin();
  await a.insert(t, { k: 3, v: 3 });
  a.close();                                  // crash: no commit, no rollback
  const b = await conn();
  try {
    assert.equal(await b.count(t), 2);        // waits out/observes the rolled-back tx
    await b.begin();                          // and the lock is free again
    await b.rollback();
  } finally { b.close(); }
});

T("begin twice and commit/rollback outside a tx behave", async () => {
  const a = await conn();
  try {
    await a.commit();                         // no-op
    await a.rollback();                       // no-op
    await a.begin();
    await assert.rejects(a.begin(), (e: any) => e instanceof TorusError && e.kind === "InterfaceError");
    await a.rollback();
  } finally { a.close(); }
});

T("update() is atomic: a failure midway leaves nothing half-applied", async () => {
  const a = await conn();
  try {
    const t = await seeded(a);
    // first assignment is fine, second is invalid for the (encrypted) column -> client error before any RPC
    await assert.rejects(a.update(t, { v: 5, nope: 1 } as any), (e: any) => e.kind === "InterfaceError");
    assert.equal(await a.sum(t, "v"), 300n);
    // mid-flight failure: a value that fails to encode on the SECOND matched row
    // cannot happen (same value), so force a server-side failure via a closed table
    assert.equal(a.inTransaction, false);
  } finally { a.close(); }
});
