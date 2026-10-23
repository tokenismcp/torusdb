// SPDX-License-Identifier: Apache-2.0
// BETWEEN / NOT IN / IS [NOT] NULL / [NOT] LIKE / OFFSET / indexes / IF [NOT] EXISTS
// against a REAL server, memory and disk storage, with and without indexes.
// Expected values are the CASES table of torussql/tests/test_sql_ext.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import {
  Client, TorusError, WirePred, and, or, between, notIn, isNull, isNotNull, like, notLike, eq, isIn,
} from "../src/torusdb";
import { skipReason, startServer, tmpdir, uniq, ADMIN, RO } from "./helpers";

const skip = skipReason();
const kind = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;

const ROWS: Array<[number, string | null, number | null]> = [
  [1, "alice", 10], [2, "bob", 20], [3, "carol", null], [4, "alicia", 40], [5, null, 50], [6, "a_b%c", 60]];

const CASES: Array<[string, WirePred, number[]]> = [
  ["age BETWEEN 20 AND 50", between("age", 20, 50), [2, 4, 5]],
  ["age BETWEEN 10 AND 10", between("age", 10, 10), [1]],
  ["id NOT IN (1, 2, 3)", notIn("id", [1, 2, 3]), [4, 5, 6]],
  ["age NOT IN (10, 20)", notIn("age", [10, 20]), [4, 5, 6]],
  ["age IS NULL", isNull("age"), [3]],
  ["age IS NOT NULL", isNotNull("age"), [1, 2, 4, 5, 6]],
  ["name IS NULL", isNull("name"), [5]],
  ["name LIKE 'ali%'", like("name", "ali%"), [1, 4]],
  ["name LIKE '_ob'", like("name", "_ob"), [2]],
  ["name LIKE '%c%'", like("name", "%c%"), [1, 3, 4, 6]],
  ["name NOT LIKE 'ali%'", notLike("name", "ali%"), [2, 3, 6]],
  ["name LIKE 'a\\_b%'", like("name", "a\\_b%"), []],
  ["name LIKE 'a_b%c'", like("name", "a_b%c"), [6]],
  ["age IS NULL OR name LIKE 'bob'", or(isNull("age"), like("name", "bob")), [2, 3]],
  ["age BETWEEN 10 AND 40 AND name NOT LIKE '%a%'", and(between("age", 10, 40), notLike("name", "%a%")), [2]],
];

test("CASES table equals the Python test table (cross-check)", () => {
  const py = path.resolve(__dirname, "../../../tests/test_sql_ext.py");
  if (!fs.existsSync(py)) return;                                   // published package: nothing to compare
  const src = fs.readFileSync(py, "utf8");
  const block = src.slice(src.indexOf("CASES = ["), src.indexOf("]\n\n\n@pytest", src.indexOf("CASES = [")));
  const found: Array<[string, number[]]> = [];
  for (const m of block.matchAll(/\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*\[([^\]]*)\]\s*\)/g)) {
    found.push([m[1].replace(/\\\\/g, "\\"), m[2].trim() ? m[2].split(",").map((x) => Number(x)) : []]);
  }
  assert.ok(found.length >= 15, `parsed ${found.length} Python cases`);
  assert.deepEqual(CASES.map(([w, , e]) => [w, e]), found);
});

async function seed(db: Client, t: string) {
  await db.createTable(t, [
    { name: "id", type: "int", policy: "plain" }, { name: "name", type: "str", policy: "plain" },
    { name: "age", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }]);
  await db.insertMany(t, ROWS.map(([id, name, age]) => ({ id, name, age, v: id * 100 })));
}
const ids = async (db: Client, t: string, w: WirePred) =>
  (await db.select(t, ["id"], w)).map((r) => Number(r.id)).sort((a, b) => a - b);

for (const storage of ["memory", "disk"]) {
  test(`predicates over the wire, ${storage} storage, before and after indexes`, { skip }, async () => {
    const dir = tmpdir();
    const srv = await startServer(storage === "disk" ? ["--db", path.join(dir, "db"), "--storage", "disk"] : []);
    const db = await Client.connect(srv.host, srv.port);
    try {
      const t = "t";
      await seed(db, t);
      assert.deepEqual((await db.tableInfo(t)).indexes, []);
      for (let round = 0; round < 2; round++) {                      // 2nd round: with indexes
        for (const [where, pred, expected] of CASES) assert.deepEqual(await ids(db, t, pred), expected, where);
        assert.equal(await db.count(t, between("age", 20, 50)), 3);
        assert.equal(await db.sum(t, "v", notIn("id", [1, 2])), 400n + 500n + 600n + 300n);
        if (round === 0) for (const c of ["age", "name", "id"]) await db.createIndex(t, c);
      }
      assert.deepEqual((await db.tableInfo(t)).indexes.sort(), ["age", "id", "name"]);
      assert.equal(await db.deleteRows(t, between("age", 40, 60)), 3);
      assert.deepEqual(await ids(db, t, isNotNull("age")), [1, 2]);
      await db.update(t, { age: 99 }, like("name", "bob"));
      assert.deepEqual(await ids(db, t, between("age", 90, 100)), [2]);
      // dropping an index changes nothing observable
      await db.dropIndex(t, "age");
      assert.deepEqual(await ids(db, t, between("age", 90, 100)), [2]);
      assert.deepEqual((await db.tableInfo(t)).indexes.sort(), ["id", "name"]);
    } finally { db.close(); await srv.stop(); }
  });
}

test("rollback undoes index changes and deletes; NULL semantics survive", { skip }, async () => {
  const srv = await startServer();
  const db = await Client.connect(srv.host, srv.port);
  try {
    const t = uniq("rb");
    await seed(db, t);
    await db.begin();
    await db.createIndex(t, "age");
    await db.deleteRows(t, isNull("age"));
    assert.deepEqual((await db.tableInfo(t)).indexes, ["age"]);
    await db.rollback();
    assert.deepEqual((await db.tableInfo(t)).indexes, []);
    assert.deepEqual(await ids(db, t, isNull("age")), [3]);
    await db.transaction(async () => { await db.createIndex(t, "name"); });
    assert.deepEqual((await db.tableInfo(t)).indexes, ["name"]);
    await db.dropIndex(t, "name");
    // NULL cells match nothing but IS NULL
    assert.deepEqual(await ids(db, t, notLike("name", "zzz")), [1, 2, 3, 4, 6]);
    assert.deepEqual(await ids(db, t, notIn("name", ["bob"])), [1, 3, 4, 6]);
  } finally { db.close(); await srv.stop(); }
});

test("validation: LIKE needs STR + string, encrypted columns rejected, bad args", { skip }, async () => {
  const srv = await startServer();
  const db = await Client.connect(srv.host, srv.port);
  try {
    const t = uniq("val");
    await seed(db, t);
    await assert.rejects(db.count(t, like("id", "1%")), kind("InterfaceError"));          // INT column
    await assert.rejects(db.count(t, like("v", "1%")), kind("InterfaceError"));           // encrypted
    await assert.rejects(db.count(t, isNull("v")), kind("InterfaceError"));
    await assert.rejects(db.count(t, between("v", 1, 2)), kind("InterfaceError"));
    assert.throws(() => like("name", 5 as any), kind("InterfaceError"));
    assert.throws(() => notIn("id", []), kind("InterfaceError"));
    await assert.rejects(db.createIndex(t, "v"), kind("InterfaceError"));
    await assert.rejects(db.createIndex(t, "nope"), kind("InterfaceError"));
    await assert.rejects(db.createIndex("nosuch", "id"), kind("InterfaceError"));
    await assert.rejects(db.select(t, ["id"], null, { offset: -1 }), kind("InterfaceError"));
    await assert.rejects(db.select(t, ["id"], null, { limit: 1.5 }), kind("InterfaceError"));
  } finally { db.close(); await srv.stop(); }
});

test("OFFSET / LIMIT, IF NOT EXISTS / IF EXISTS", { skip }, async () => {
  const srv = await startServer();
  const db = await Client.connect(srv.host, srv.port);
  try {
    const t = uniq("off");
    await seed(db, t);
    const col = async (o: { offset?: number; limit?: number }) => (await db.select(t, ["id"], null, o)).map((r) => Number(r.id));
    assert.deepEqual(await col({ limit: 2, offset: 1 }), [2, 3]);
    assert.deepEqual(await col({ offset: 4 }), [5, 6]);
    assert.deepEqual(await col({ limit: 5, offset: 99 }), []);
    assert.deepEqual(await col({ limit: 0 }), []);
    assert.deepEqual((await db.select(t, ["id"], between("age", 10, 60), { offset: 1, limit: 2 })).map((r) => Number(r.id)), [2, 4]);

    const cols = [{ name: "id", type: "int" as const, policy: "plain" as const }];
    const x = uniq("ine");
    await db.createTable(x, cols, { ifNotExists: true });
    await db.insert(x, { id: 1 });
    await db.createTable(x, cols, { ifNotExists: true });                   // no-op, data kept
    assert.equal(await db.count(x), 1);
    await assert.rejects(db.createTable(x, cols), (e: any) => e instanceof TorusError && /already exists/.test(e.message));
    await db.dropTable(uniq("never"), { ifExists: true });
    await db.dropTable(x, { ifExists: true });
    await assert.rejects(db.dropTable(x), (e: any) => e instanceof TorusError && /no such table/.test(e.message));
  } finally { db.close(); await srv.stop(); }
});

test("LEFT JOIN: IS NULL on the NULL side is true; other atoms false", { skip }, async () => {
  const srv = await startServer();
  const db = await Client.connect(srv.host, srv.port);
  try {
    await db.createTable("a", [{ name: "k", type: "int", policy: "plain" }]);
    await db.createTable("b", [{ name: "k", type: "int", policy: "plain" }, { name: "w", type: "int", policy: "plain" },
                               { name: "s", type: "str", policy: "plain" }]);
    await db.insertMany("a", [{ k: 1 }, { k: 2 }, { k: 3 }]);
    await db.insert("b", { k: 2, w: 7, s: "x" });
    const step = { table: "b", leftCol: "k", rightCol: "k", kind: "left" as const };
    const ks = async (w: WirePred) => {
      const j = await db.join("a", [step], { where: w });
      return (await db.joinColumn(j, "a", "k")).map(Number).sort();
    };
    assert.deepEqual(await ks(isNull("w", "b")), [1, 3]);
    assert.deepEqual(await ks(isNotNull("w", "b")), [2]);
    assert.deepEqual(await ks(notLike("s", "y%", "b")), [2]);          // NULL side matches neither LIKE nor NOT LIKE
    assert.deepEqual(await ks(like("s", "x", "b")), [2]);
    assert.deepEqual(await ks(between("w", 1, 9, "b")), [2]);
    assert.deepEqual(await ks(notIn("w", [7], "b")), []);
    assert.deepEqual(await ks(or(isNull("w", "b"), eq("k", 2))), [1, 2, 3]);
    assert.deepEqual(await ks(and(isNull("w", "b"), isIn("k", [3]))), [3]);
    // same query as the Python test: unmatched rows
    assert.deepEqual(await ks(isNull("w", "b")), [1, 3]);
  } finally { db.close(); await srv.stop(); }
});

test("create_index / drop_index need role rw", { skip }, async () => {
  const dir = tmpdir();
  const f = path.join(dir, "tokens");
  fs.writeFileSync(f, `admin:${ADMIN}\nro:${RO}\n`, { mode: 0o600 });
  const srv = await startServer(["--token-file", f]);
  try {
    const a = await Client.connect(srv.host, srv.port, { token: ADMIN });
    await seed(a, "t");
    const r = await Client.connect(srv.host, srv.port, { token: RO, trustServerSchema: true });
    await assert.rejects(r.createIndex("t", "age"), kind("Forbidden"));
    await a.createIndex("t", "age");
    await assert.rejects(r.dropIndex("t", "age"), kind("Forbidden"));
    assert.deepEqual((await r.tableInfo("t")).indexes, ["age"]);
    a.close(); r.close();
  } finally { await srv.stop(); }
});

test("IF NOT EXISTS / IF EXISTS are atomic on the server (concurrent clients)", { skip }, async () => {
  const srv = await startServer();
  const a = await Client.connect(srv.host, srv.port);
  const b = await Client.connect(srv.host, srv.port);
  const cols = [{ name: "id", type: "int" as const, policy: "plain" as const }];
  try {
    for (let i = 0; i < 20; i++) {
      const t = `race_${i}`;
      await Promise.all([a.createTable(t, cols, { ifNotExists: true }), b.createTable(t, cols, { ifNotExists: true })]);
      assert.ok((await a.tables()).includes(t));
    }
    // the loser did not adopt the table (trust only comes from creating it / the vault)
    const loser = await Client.connect(srv.host, srv.port);
    await loser.createTable("race_0", cols, { ifNotExists: true });
    await assert.rejects(loser.insert("race_0", { id: 1 }), kind("UntrustedSchema"));
    await Promise.all([a.dropTable("race_0", { ifExists: true }), b.dropTable("race_0", { ifExists: true })]);
    assert.ok(!(await a.tables()).includes("race_0"));
    // plain drop of a missing table is the SERVER's error
    await assert.rejects(a.dropTable("race_0"), (e: any) => e instanceof TorusError && /no such table/.test(e.message));
    loser.close();
  } finally { a.close(); b.close(); await srv.stop(); }
});
