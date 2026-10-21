// SPDX-License-Identifier: Apache-2.0
// Regression tests for the independent audit findings (F1..F17).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import {
  Client, TorusError, TransactionInDoubt, eq, or, encodeRational, decode, N, Column,
} from "../src/torusdb";
import { fake, base, HELLO, proxy, rawRpc } from "./fake";
import { skipReason, startServer, RunningServer, uniq, tmpdir } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const R = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);   // needs the real server
const kind = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;
const KV: Column[] = [{ name: "k", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "encrypted" }];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── F1: lost COMMIT reply ────────────────────────────────────────────────────
R("F1: commit reply lost but the server committed -> masks are KEPT", async () => {
  const px = await proxy(srv);
  const db = await Client.connect("127.0.0.1", px.port, { timeoutMs: 3000 });
  const t = uniq("f1a");
  await db.createTable(t, KV);
  await db.insert(t, { k: 1, v: 100 });
  await db.begin();
  await db.insert(t, { k: 2, v: 200 });
  px.lose("tx_commit", "reply");
  await db.commit();                              // settled via tx_status -> committed
  assert.equal(db.inTransaction, false);
  assert.equal(await db.sum(t, "v"), 300n);       // the new row still decrypts
  const other = await Client.connect(srv.host, srv.port);
  assert.equal(await other.count(t), 2);
  other.close(); db.close(); px.close();
});

R("F1: commit request lost (never processed) -> definite rollback of the vault", async () => {
  const px = await proxy(srv);
  const db = await Client.connect("127.0.0.1", px.port, { timeoutMs: 3000 });
  const t = uniq("f1b");
  await db.createTable(t, KV);
  await db.insert(t, { k: 1, v: 100 });
  const masks = db.maskCount;
  await db.begin();
  await db.insert(t, { k: 2, v: 200 });
  px.lose("tx_commit", "request");
  await assert.rejects(db.commit(), kind("ConnectionError"));
  assert.equal(db.maskCount, masks);
  assert.equal(db.inTransaction, false);
  const other = await Client.connect(srv.host, srv.port);
  assert.equal(await other.count(t), 1);
  other.close(); db.close(); px.close();
});

R("F1: outcome unobtainable -> TransactionInDoubt keeps BOTH states, resolvable later", async () => {
  for (const committed of [true, false]) {
    const px = await proxy(srv);
    const db = await Client.connect("127.0.0.1", px.port, { timeoutMs: 3000 });
    const t = uniq("f1c");
    await db.createTable(t, KV);
    await db.insert(t, { k: 1, v: 100 });
    const masks = db.maskCount;
    await db.begin();
    await db.insert(t, { k: 2, v: 200 });
    px.lose("tx_commit", "reply", true);          // server commits, reply lost, proxy goes DOWN
    const e: any = await db.commit().catch((x) => x);
    assert.ok(e instanceof TransactionInDoubt, String(e));
    assert.equal(e.kind, "TransactionInDoubt");
    assert.match(e.txid, /^[0-9a-f]{32}$/);
    assert.deepEqual(db.inDoubtTransactions, [e.txid]);
    assert.equal(db.maskCount, masks + 1);        // NOT restored
    await assert.rejects(db.insert(t, { k: 3, v: 3 }), /in-doubt/);   // writes refused
    await px.resume();
    await db.reconnect();
    if (committed) {
      assert.equal(await db.resolveTransaction(e.txid), true);   // asks the server
      assert.equal(await db.sum(t, "v"), 300n);
    } else {
      await db.resolveTransaction(e.txid, false);               // caller says "rolled back"
      assert.equal(db.maskCount, masks);
    }
    assert.deepEqual(db.inDoubtTransactions, []);
    db.close(); px.close();
  }
});

test("F1: Busy 'timed out' inside a transaction drops the local tx at once and rolls the session back", async () => {
  const f = await fake(base({
    insert: (_a, n) => n === 1 ? { ok: 0 } : { err: "Busy: transaction timed out and was rolled back; issue ROLLBACK" },
  }));
  const db = await Client.connect("127.0.0.1", f.port);
  await db.createTable("t", KV);
  await db.insert("t", { k: 1, v: 1 });
  const masks = db.maskCount;
  await db.begin();
  assert.ok(JSON.parse(f.bodies[f.bodies.indexOf(f.bodies.find((b) => b.includes('"tx_begin"'))!)]).a[0].length === 32);
  await assert.rejects(db.insert("t", { k: 2, v: 2 }), kind("Busy"));
  assert.equal(db.inTransaction, false);
  assert.equal(db.maskCount, masks);
  assert.equal(f.seen[f.seen.length - 1], "tx_rollback");
  db.close(); f.close();
});

// ── F2: untrusted schema ─────────────────────────────────────────────────────
test("F2: a server that relabels encrypted columns as plain never receives plaintext", async () => {
  const f = await fake(base({
    tables: { ok: ["t"] },
    schema: { ok: [["id", "int", "plain"], ["v", "int", "plain"]] },     // the lie
  }));
  const db = await Client.connect("127.0.0.1", f.port);
  await assert.rejects(db.insert("t", { id: 1, v: 424242 }), kind("UntrustedSchema"));
  await assert.rejects(db.insertMany("t", [{ id: 1, v: 424242 }]), kind("UntrustedSchema"));
  await assert.rejects(db.update("t", { v: 424242 }), kind("UntrustedSchema"));
  assert.ok(!f.seen.includes("insert") && !f.seen.includes("insert_many") && !f.seen.includes("update_cell"));
  assert.ok(f.bodies.every((b) => !b.includes("424242")));
  db.close(); f.close();
});

test("F2: policies from the vault are the trust anchor; later server relabels are ignored", async () => {
  const dir = tmpdir();
  const vf = path.join(dir, "v.json");
  const f1 = await fake(base());
  const a = await Client.connect("127.0.0.1", f1.port);
  await a.createTable("t", KV);                      // v is ENCRYPTED, locally
  a.saveVault(vf);
  a.close(); f1.close();
  const f2 = await fake(base({
    tables: { ok: ["t"] },
    schema: { ok: [["k", "int", "plain"], ["v", "int", "plain"]] },     // now the server lies
    insert: { ok: 0 },
  }));
  const b = await Client.connect("127.0.0.1", f2.port, { vaultPath: vf });
  await b.insert("t", { k: 1, v: 424242 });
  const sent = JSON.parse(f2.bodies[f2.seen.indexOf("insert")]).a[1];
  assert.equal(sent.k.v, "1");
  assert.notEqual(sent.v.v, "424242");               // blinded, not plaintext
  assert.ok(!f2.bodies.some((x) => x.includes('"424242"') && x.includes("insert")));
  b.close(); f2.close();
});

test("F2: unknown policy strings are treated as encrypted; trustServerSchema opts in", async () => {
  const f = await fake(base({
    tables: { ok: ["t"] },
    schema: { ok: [["k", "int", "plain"], ["v", "int", "super-secret"]] },
    insert: { ok: 0 },
  }));
  const db = await Client.connect("127.0.0.1", f.port, { trustServerSchema: true });
  await db.insert("t", { k: 1, v: 424242 });
  const sent = JSON.parse(f.bodies[f.seen.indexOf("insert")]).a[1];
  assert.notEqual(sent.v.v, "424242");               // unknown policy => blinded
  db.close(); f.close();
});

R("F2: reads of plain columns stay allowed on untrusted tables; trustTable() lifts the write block", async () => {
  const w = await Client.connect(srv.host, srv.port);
  const t = uniq("f2");
  await w.createTable(t, KV);
  await w.insert(t, { k: 5, v: 1 });
  const r = await Client.connect(srv.host, srv.port);
  assert.equal(await r.count(t), 1);
  assert.deepEqual(await r.select(t, ["k"]), [{ k: 5n }]);
  await assert.rejects(r.insert(t, { k: 6, v: 2 }), kind("UntrustedSchema"));
  r.trustTable(t);
  await r.insert(t, { k: 6, v: 2 });
  w.close(); r.close();
});

// ── F3 / F5: framing, memory ─────────────────────────────────────────────────
test("F3: a 20 MB reply delivered in 1 KiB writes is linear-time", async () => {
  const f = await fake(base({ stats: { big: 20 * 1024 * 1024 } }));
  const db = await Client.connect("127.0.0.1", f.port, { timeoutMs: 20000 });
  const t0 = Date.now();
  const st = await db.stats();
  assert.equal(st.x.length, 20 * 1024 * 1024);
  assert.ok(Date.now() - t0 < 8000, `took ${Date.now() - t0} ms`);
  db.close(); f.close();
});

test("F3: unsolicited / extra frames are a ProtocolError and kill the connection", async () => {
  const f = await fake(base({ ping: { frames: [{ ok: "pong" }, { ok: "pong" }] } }));
  const db = await Client.connect("127.0.0.1", f.port);
  await assert.rejects(db.ping(), kind("ProtocolError"));
  await assert.rejects(db.ping(), (e: any) => e instanceof TorusError);
  f.close();
  const g = await fake(base());
  const d2 = await Client.connect("127.0.0.1", g.port);
  g.push(Buffer.from([0, 0, 0, 2, 123, 125]));        // data nobody asked for
  await sleep(100);
  await assert.rejects(d2.ping(), kind("ProtocolError"));
  g.close();
});

test("F3/F5: a lying length header is rejected before any payload is buffered", async () => {
  const f = await fake(base({ stats: { hdr: 0xffffffff } }));
  const db = await Client.connect("127.0.0.1", f.port, { timeoutMs: 5000 });
  const t0 = Date.now();
  await assert.rejects(db.stats(), kind("ProtocolError"));
  assert.ok(Date.now() - t0 < 2000);
  f.close();
  // cap follows hello.max_frame
  const g = await fake(base({ hello: { ok: { ...HELLO.ok, max_frame: 4096 } }, stats: { hdr: 5000 } }));
  const d2 = await Client.connect("127.0.0.1", g.port, { timeoutMs: 5000 });
  await assert.rejects(d2.stats(), kind("ProtocolError"));
  g.close();
});

test("F5: huge digit strings and wrong-length arrays are ProtocolErrors", async () => {
  const f = await fake(base({
    tables: { ok: ["t"] },
    schema: { ok: [["k", "int", "plain"], ["v", "int", "encrypted"]] },
    matching_rowids: { ok: [0, 1] },
    blinded_sum: { raw: JSON.stringify({ ok: "9".repeat(200000) }) },
    blinded_cells: { raw: JSON.stringify({ ok: [{ t: "i", v: "1" }] }) },       // 1 item for 2 ids
    mult_combine_batch: { ok: ["1"] },
  }));
  const ops: Array<(db: Client) => Promise<unknown>> = [(db) => db.sum("t", "v"), (db) => db.select("t", ["v"])];
  const g = await fake(base({ tables: { ok: ["t"] }, schema: { ok: [["k", "int", "plain"], ["v", "int", "encrypted"]] },
    matching_rowids: { ok: [0] }, blinded_sum: { ok: "9".repeat(95) } }));   // inside the frame cap, over the digit cap
  const d = await Client.connect("127.0.0.1", g.port);
  d.trustTable("t");
  await assert.rejects(d.sum("t", "v"), kind("ProtocolError"));
  d.close(); g.close();
  for (const op of ops) {
    const db = await Client.connect("127.0.0.1", f.port);
    db.trustTable("t");
    await assert.rejects(op(db), kind("ProtocolError"));
    db.close();
  }
  f.close();
});

// ── F6: serialization ────────────────────────────────────────────────────────
R("F6: concurrent transaction(fn) calls on one client do not interleave", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = uniq("f6");
  await db.createTable(t, KV);
  const a = db.transaction(async () => { await db.insert(t, { k: 1, v: 1 }); await sleep(80); throw new Error("abort-a"); }).catch((e) => e.message);
  const b = db.transaction(async () => { await db.insert(t, { k: 2, v: 2 }); });
  const c = db.insert(t, { k: 3, v: 3 });                    // plain call racing the transactions
  const [ra] = await Promise.all([a, b, c]);
  assert.equal(ra, "abort-a");
  assert.deepEqual((await db.select(t, ["k"])).map((r) => r.k).sort(), [2n, 3n]);
  assert.equal(await db.sum(t, "v"), 5n);
  assert.equal(db.inTransaction, false);
  db.close();
});

// ── F7 ───────────────────────────────────────────────────────────────────────
test("F7: encodeRational reduces BEFORE the budget check", () => {
  const big = 1n << 127n;
  assert.equal(encodeRational(big, big), 1n);
  assert.deepEqual(decode(encodeRational(3n * big, 2n * big)), { num: 3n, den: 2n });
  assert.deepEqual(decode(encodeRational(-6n, -4n)), { num: 3n, den: 2n });
  assert.throws(() => encodeRational((1n << 127n) + 2n, 3n), kind("OutOfBudget"));
});

// ── F8: authenticated mode ───────────────────────────────────────────────────
R("F8: MAC mode catches a lying server (value or MAC tampering)", async () => {
  const db = await Client.connect(srv.host, srv.port, { authenticated: true });
  const t = uniq("f8");
  await db.createTable(t, [{ name: "k", type: "int", policy: "plain" }, { name: "a", type: "int", policy: "paired" }, { name: "b", type: "int", policy: "paired" }]);
  await db.insertMany(t, [{ k: 1, a: 3, b: 10 }, { k: 2, a: 4, b: 100 }]);
  assert.equal(await db.sum(t, "a"), 7n);
  assert.equal(await db.dot(t, "a", "b"), 430n);
  assert.deepEqual(await db.select(t, ["a"]), [{ a: 3n }, { a: 4n }]);
  await db.update(t, { a: 5 }, eq("k", 1));
  assert.equal(await db.sum(t, "a"), 9n);
  // the server (any other client) rewrites a stored cell
  const forged = { t: "i", v: "123456789" };
  assert.equal((await rawRpc(srv.port, "update_cell", [t, 0, "a", forged])).ok, null);
  await assert.rejects(db.sum(t, "a"), kind("IntegrityError"));
  await assert.rejects(db.select(t, ["a"]), kind("IntegrityError"));
  await assert.rejects(db.dot(t, "a", "b"), kind("IntegrityError"));
  // tampering with only the MAC cell is caught too
  const t2 = uniq("f8b");
  await db.createTable(t2, [{ name: "a", type: "int", policy: "paired" }]);
  await db.insert(t2, { a: 9 });
  assert.equal(await db.sum(t2, "a"), 9n);
  await rawRpc(srv.port, "update_cell", [t2, 0, "__mac__a", forged]);
  await assert.rejects(db.sum(t2, "a"), kind("IntegrityError"));
  db.close();
});

R("F8: the MAC key survives a vault round trip; mode mismatches are refused", async () => {
  const vf = path.join(tmpdir(), "v.json");
  const a = await Client.connect(srv.host, srv.port, { authenticated: true });
  const t = uniq("f8c");
  await a.createTable(t, [{ name: "a", type: "int", policy: "encrypted" }]);
  await a.insert(t, { a: 7 });
  a.saveVault(vf);
  a.close();
  const b = await Client.connect(srv.host, srv.port, { authenticated: true, vaultPath: vf });
  assert.equal(await b.sum(t, "a"), 7n);
  b.close();
  await assert.rejects(Client.connect(srv.host, srv.port, { vaultPath: vf }), /authenticated/);
});

// ── F9: reply validation ─────────────────────────────────────────────────────
test("F9: malformed replies are always typed ProtocolErrors (never TypeError / undefined)", async () => {
  const garbage: unknown[] = [null, 5, "x", [], {}, [1, 2], { t: "i" }, [{ t: "i", v: 1 }], 9007199254740993, -1, 1.5, true];
  for (const g of garbage) {
    const f = await fake(base({
      tables: { ok: ["t"] },
      schema: { ok: [["k", "int", "plain"], ["v", "int", "encrypted"]] },
      insert: { ok: g }, insert_many: { ok: g }, matching_rowids: { ok: g }, blinded_sum: { ok: g },
      blinded_cells: { ok: g }, plain_cells: { ok: g }, table_info: { ok: g }, delete_rows: { ok: g },
      checkpoint: { ok: g }, backup: { ok: g }, stats: { ok: g }, mult_combine_batch: { ok: g },
    }));
    const db = await Client.connect("127.0.0.1", f.port);
    db.trustTable("t");
    const ops: Array<() => Promise<unknown>> = [
      () => db.insert("t", { k: 1, v: 1 }), () => db.insertMany("t", [{ k: 1, v: 1 }]),
      () => db.sum("t", "v"), () => db.count("t"), () => db.select("t", ["k", "v"]),
      () => db.tableInfo("t"), () => db.deleteRows("t"), () => db.checkpoint(), () => db.backup(),
      () => db.stats(), () => db.findOrphans(), () => db.avg("t", "v"),
    ];
    for (const op of ops) {
      if (db["tr" as keyof Client] !== undefined) throw new Error("transport leaked");
      try { await op(); } catch (e) {
        assert.ok(e instanceof TorusError, `non-TorusError ${e} for reply ${JSON.stringify(g)}`);
      }
    }
    db.close(); f.close();
  }
});

test("F9: a rowid beyond 2^53 and a hostile hello are rejected", async () => {
  const f = await fake(base({ tables: { ok: ["t"] }, schema: { ok: [["k", "int", "plain"]] }, insert: { raw: '{"ok": 9007199254740993}' } }));
  const db = await Client.connect("127.0.0.1", f.port);
  db.trustTable("t");
  await assert.rejects(db.insert("t", { k: 1 }), kind("ProtocolError"));
  f.close();
  for (const h of [{ protocol: "2", auth_required: false }, { protocol: 2, auth_required: "no" }, { protocol: 2, auth_required: false, max_frame: -5 }, [], null]) {
    const g = await fake(base({ hello: { ok: h } }));
    await assert.rejects(Client.connect("127.0.0.1", g.port), kind("ProtocolError"));
    g.close();
  }
});

// ── F10: secrets are not inspectable ─────────────────────────────────────────
R("F10: masks, token and MAC key are not reachable through inspect / JSON / properties", async () => {
  const token = "super-secret-token-0123456789";
  const f = await fake(base({ hello: { ok: { ...HELLO.ok, auth_required: true } }, auth: { ok: { role: "rw" } } }));
  const db = await Client.connect("127.0.0.1", f.port, { token, authenticated: true, tlsInsecure: undefined });
  await db.createTable("t", KV);
  await db.insert("t", { k: 1, v: 1 }).catch(() => undefined);
  const seen = [util.inspect(db, { depth: 10, showHidden: true }), JSON.stringify(db), JSON.stringify(Object.getOwnPropertyNames(db)),
                util.format("%o", db), String(Object.keys(db))].join("\n");
  assert.ok(!seen.includes(token));
  assert.equal((db as any).masks, undefined);
  assert.equal((db as any).alpha, undefined);
  assert.equal((db as any).token, undefined);
  assert.ok(!/[0-9]{40,}/.test(seen), "a long number (mask/alpha) leaked");
  db.close(); f.close();
});

// ── F11 ──────────────────────────────────────────────────────────────────────
test("F11: findOrphans never trusts a hostile `rows` count", async () => {
  const f = await fake(base({
    tables: { ok: ["t"] }, schema: { ok: [["k", "int", "plain"], ["v", "int", "encrypted"]] },
    table_info: { ok: { rows: 1e18, deleted: [] } }, matching_rowids: { ok: [0, 1] },
  }));
  const db = await Client.connect("127.0.0.1", f.port);
  const t0 = Date.now();
  assert.deepEqual(await db.findOrphans(), { t: [0, 1] });
  assert.ok(Date.now() - t0 < 2000);
  assert.ok(!f.seen.includes("table_info"));
  db.close(); f.close();
});

// ── F14: vault validation / durability ───────────────────────────────────────
test("F14: loadVault rejects corrupt content with typed errors", async () => {
  const f = await fake(base());
  const db = await Client.connect("127.0.0.1", f.port);
  const d = tmpdir();
  const cases: Array<[string, unknown]> = [
    ["negative rowid", { version: 2, masks: [["t", -1, "v", "5"]] }],
    ["fractional rowid", { version: 2, masks: [["t", 1.5, "v", "5"]] }],
    ["non-decimal mask", { version: 2, masks: [["t", 1, "v", "0x10"]] }],
    ["negative mask", { version: 2, masks: [["t", 1, "v", "-5"]] }],
    ["mask >= N", { version: 2, masks: [["t", 1, "v", N.toString()]] }],
    ["huge mask", { version: 2, masks: [["t", 1, "v", "9".repeat(5000)]] }],
    ["bad schema", { version: 2, masks: [], schema: { t: [["a", "int"]] } }],
    ["wrong version", { version: 9, masks: [] }],
  ];
  for (const [name, doc] of cases) {
    const p = path.join(d, "v.json");
    fs.writeFileSync(p, JSON.stringify(doc));
    assert.throws(() => db.loadVault(p), kind("InterfaceError"), name);
  }
  fs.writeFileSync(path.join(d, "v.json"), "{garbage");
  assert.throws(() => db.loadVault(path.join(d, "v.json")), kind("InterfaceError"));
  assert.equal(db.maskCount, 0);                     // nothing half-loaded
  db.close(); f.close();
});

test("F14: saveVault creates missing parent directories (0600 file)", async () => {
  const f = await fake(base());
  const db = await Client.connect("127.0.0.1", f.port);
  const p = path.join(tmpdir(), "a", "b", "vault.json");
  db.saveVault(p);
  assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  db.close(); f.close();
});

R("F14: transactions use an undo journal (large vault, implicit UPDATE restores correctly)", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = uniq("f14");
  await db.createTable(t, KV);
  await db.insertMany(t, Array.from({ length: 2000 }, (_, i) => ({ k: i, v: i })));
  const before = await db.sum(t, "v");
  await db.begin();
  await db.update(t, { v: 1 }, eq("k", 7));
  await db.rollback();
  assert.equal(await db.sum(t, "v"), before);
  db.close();
});

// ── F15: names that collide with Object.prototype ────────────────────────────
R("F15: tables, columns and aliases called constructor / toString / hasOwnProperty work", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = "constructor";
  await db.createTable(t, [{ name: "toString", type: "int", policy: "plain" }, { name: "hasOwnProperty", type: "int", policy: "encrypted" }]);
  await db.insert(t, { toString: 1, hasOwnProperty: 5 });
  assert.equal(await db.sum(t, "hasOwnProperty"), 5n);
  assert.equal(Object.getOwnPropertyDescriptor((await db.select(t, ["toString"]))[0], "toString")!.value, 1n);
  const j = await db.join(t, [{ table: t, alias: "valueOf", leftCol: "toString", rightCol: "toString" }], { alias: "toString" });
  assert.equal(j.tuples.length, 1);
  assert.equal(await db.joinSum(j, "valueOf", "hasOwnProperty"), 5n);
  await assert.rejects(db.insert(t, { toString: 1 } as any), kind("InterfaceError"));   // 'hasOwnProperty' missing (inherited names don't count)
  await assert.rejects(db.createTable("__evil", KV), kind("InterfaceError"));
  db.close();
});

// ── F16 ──────────────────────────────────────────────────────────────────────
test("F16: option validation", async () => {
  await assert.rejects(Client.connect("192.0.2.1", 1, { token: "x".repeat(20) }), /unencrypted/);
  await assert.rejects(Client.connect("127.0.0.1", 1, { ca: "x" }), kind("InterfaceError"));
  await assert.rejects(Client.connect("127.0.0.1", 1, { tlsInsecure: true }), kind("InterfaceError"));
  for (const bad of [NaN, -1, Infinity]) {
    await assert.rejects(Client.connect("127.0.0.1", 1, { timeoutMs: bad }), kind("InterfaceError"));
  }
  // loopback may carry a token in the clear; allowInsecureToken overrides for remote
  const f = await fake(base());
  const ok = await Client.connect("127.0.0.1", f.port, { token: "x".repeat(20) });
  ok.close(); f.close();
});

test("F16: requests larger than the server's max_frame are refused locally", async () => {
  const f = await fake(base({ hello: { ok: { ...HELLO.ok, max_frame: 2048 } }, tables: { ok: ["t"] }, schema: { ok: [["k", "int", "plain"], ["v", "int", "encrypted"]] }, insert_many: { ok: [] } }));
  const db = await Client.connect("127.0.0.1", f.port);
  db.trustTable("t");
  const rows = Array.from({ length: 200 }, (_, i) => ({ k: i, v: i }));
  await assert.rejects(db.insertMany("t", rows), kind("InterfaceError"));
  assert.ok(!f.seen.includes("insert_many"));
  assert.equal(await db.ping(), true);               // the connection survived
  db.close(); f.close();
});

// ── F17 ──────────────────────────────────────────────────────────────────────
R("F17: DOT needs paired INT columns; join WHERE over joined tables is honoured", async () => {
  const db = await Client.connect(srv.host, srv.port);
  const t = uniq("f17");
  await db.createTable(t, [
    { name: "k", type: "int", policy: "plain" }, { name: "e", type: "int", policy: "encrypted" },
    { name: "p", type: "int", policy: "paired" }, { name: "r", type: "rational", policy: "paired" }]);
  await db.insert(t, { k: 1, e: 1, p: 2, r: { num: 1n, den: 2n } });
  await assert.rejects(db.dot(t, "e", "p"), kind("PlanError"));
  await assert.rejects(db.dot(t, "p", "r"), kind("PlanError"));
  assert.equal(await db.dot(t, "p", "p"), 4n);

  const emp = uniq("e17"), dept = uniq("d17");
  await db.createTable(emp, [{ name: "eid", type: "int", policy: "plain" }, { name: "did", type: "int", policy: "plain" }, { name: "sal", type: "int", policy: "encrypted" }]);
  await db.createTable(dept, [{ name: "did", type: "int", policy: "plain" }, { name: "dname", type: "str", policy: "plain" }]);
  await db.insertMany(dept, [{ did: 10, dname: "Eng" }, { did: 20, dname: "Sales" }]);
  await db.insertMany(emp, [{ eid: 1, did: 10, sal: 100 }, { eid: 2, did: 10, sal: 80 }, { eid: 3, did: 20, sal: 70 }, { eid: 4, did: 99, sal: 60 }]);
  const step = { table: dept, alias: "d", leftCol: "did", rightCol: "did" };
  const j1 = await db.join(emp, [step], { alias: "e", where: eq("dname", "Eng", "d") });
  assert.equal(j1.tuples.length, 2);
  assert.equal(await db.joinSum(j1, "e", "sal"), 180n);
  const j2 = await db.join(emp, [{ ...step, kind: "left" }], { alias: "e", where: or(eq("dname", "Sales", "d"), eq("eid", 1, "e")) });
  assert.equal(j2.tuples.length, 2);                             // Carol (Sales) + Alice (eid 1)
  const j3 = await db.join(emp, [{ ...step, kind: "left" }], { alias: "e", where: eq("dname", "Eng", "d") });
  assert.equal(j3.tuples.length, 2);                             // NULL side (Dave) never matches
  await assert.rejects(db.count(emp, eq("eid", 1, "e")), kind("InterfaceError"));   // alias atoms never go to the server
  await assert.rejects(db.join(emp, [step], { alias: "e", where: eq("sal", 1, "e") }).then(() => db.join(emp, [step], { alias: "e", where: eq("sal", 1, "d") })), kind("InterfaceError"));
  db.close();
});

// ── timeouts: a drip-fed reply is bounded by a TOTAL deadline ────────────────
test("timeout is a total deadline, not per read", async () => {
  const f = await fake(base({ stats: { hdr: 100 } }));
  const db = await Client.connect("127.0.0.1", f.port, { timeoutMs: 400 });
  const t0 = Date.now();
  await assert.rejects(db.stats(), kind("TimeoutError"));
  assert.ok(Date.now() - t0 < 2500);
  f.close();
});
