// SPDX-License-Identifier: Apache-2.0
// Anchored table-state integrity (src/anchor.ts, `integrityAnchor`): every attack runs against an anchored owner
// (must fail) and, where the attack is observable without an anchor, against an owner WITHOUT one (the negative
// control: the same lie silently succeeds, so the anchor - not the tags alone - is what stops it).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as net from "net";
import * as path from "path";
import {
  Client, FheKey, TorusError, FileAnchor, MemoryAnchor, StaleServerError, canonValue, schemaDigest, rowMaterial, eq, gt, isNull,
  FHE_CELL_BYTES,
} from "../src/torusdb";
import { skipReason, startServer, RunningServer, uniq, tmpdir, runPeer, mclPath } from "./helpers";
import { startProxy, Proxy } from "./anchor_proxy";

const VEC = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../../../proto/fhe-vectors.json"), "utf8"));
const SECRET = VEC.secret as string;
const KEY = FheKey.fromHex(SECRET, 100_000);
const OPTS = { timeoutMs: 240_000 };
const kind = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;
const IE = kind("IntegrityError");
const skip = skipReason();
let mem: RunningServer;
before(async () => { if (!skip) mem = await startServer([], mclPath() ? { PYTHONPATH: mclPath()! } : {}); });
after(async () => { if (!skip) await mem?.stop(); });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

const COLS = [
  { name: "id", type: "int" as const, policy: "plain" as const },
  { name: "dept", type: "int" as const, policy: "plain" as const },
  { name: "rate", type: "int" as const, policy: "fhe" as const },
];
const ROWS = [[1, 5, 40], [2, 5, 55], [3, 7, 30], [4, 5, 20]];
const anchorFile = () => path.join(tmpdir("anchor-"), "anchor.json");

async function owner(file: string | undefined, o: object = {}, host = mem.host, port = mem.port): Promise<Client> {
  return Client.connect(host, port, { fheKey: KEY, authenticated: true, ...(file ? { integrityAnchor: file } : {}), ...OPTS, ...o });
}
async function seeded(file: string | undefined, rows = ROWS): Promise<{ db: Client; t: string }> {
  const db = await owner(file);
  const t = uniq("emp");
  await db.createTable(t, COLS);
  for (const [id, dept, rate] of rows) await db.insert(t, { id, dept, rate });
  return { db, t };
}

// ── raw access (what the server operator can do) ─────────────────────────────
function frame(b: Buffer): Buffer { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); }
function rawCall(m: string, a: unknown[], host = mem.host, port = mem.port): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host, port });
    let buf = Buffer.alloc(0);
    s.on("error", reject);
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) { s.destroy(); resolve(JSON.parse(buf.subarray(4, 4 + buf.readUInt32BE(0)).toString())); }
    });
    s.write(frame(Buffer.from(JSON.stringify({ m, a }))));
  });
}
const xc = (b: Uint8Array) => ({ t: "x", v: Buffer.from(b).toString("base64") });
const ints = (v: number | bigint) => ({ t: "i", v: String(v) });
async function cells(t: string, id: number): Promise<Record<string, any>> {
  const o: Record<string, any> = {};
  for (const c of ["id", "dept", "rate", "__fmac__rate", "__fnonce__rate"]) o[c] = (await rawCall("plain_cells", [t, c, [id]])).ok[0];
  return o;
}
async function restore(t: string, id: number, st: Record<string, any>) {
  for (const [c, w] of Object.entries(st)) assert.ok(!(await rawCall("update_cell", [t, id, c, w])).err);
}
async function rawAddRow(t: string, id: number, dept: number, rate: number) {
  const r = await rawCall("insert", [t, { id: ints(id), dept: ints(dept), rate: xc(KEY.encrypt(rate)), __fmac__rate: xc(KEY.encrypt(0)), __fnonce__rate: ints(777) }]);
  assert.ok(!r.err, r.err);
}
const DEPT5 = async (db: Client, t: string) => [await db.sum(t, "rate", eq("dept", 5)), await db.count(t, eq("dept", 5))];

// ── the anchor store and the canonical encoding (no server) ──────────────────
for (const [name, make] of [["MemoryAnchor", () => new MemoryAnchor()], ["FileAnchor", () => new FileAnchor(anchorFile())]] as const) {
  test(`${name}: compare-and-swap on the epoch, pending, finish/abort, history, all-or-nothing`, () => {
    const a = make();
    assert.equal(a.get("t"), null);
    a.beginCommit(new Map([["t", { expectEpoch: null, root: 0n, count: 0 }]]), "tx0");                       // CREATE
    assert.equal(a.get("t")!.pending!.epoch, 1);
    assert.equal(a.get("t")!.epoch, 0);
    assert.throws(() => a.beginCommit(new Map([["t", { expectEpoch: 0, root: 5n, count: 1 }]]), "tx1"), /pending/);
    a.finishCommit(["t"], "tx0");
    let e = a.get("t")!;
    assert.deepEqual([e.epoch, e.root, e.count, e.pending], [1, 0n, 0, null]);
    a.beginCommit(new Map([["t", { expectEpoch: 1, root: 99n, count: 2 }]]), "tx2");
    a.abort(["t"], "tx2");
    e = a.get("t")!;
    assert.deepEqual([e.epoch, e.root, e.pending], [1, 0n, null]);
    assert.throws(() => a.beginCommit(new Map([["t", { expectEpoch: 0, root: 7n, count: 1 }]]), "tx3"), /epoch/);
    a.beginCommit(new Map([["t", { expectEpoch: 1, root: 99n, count: 2 }]]), "tx4");
    assert.throws(() => a.finishCommit(["t"], "someone-else"), kind("AnchorConflict"));
    a.finishCommit(["t"], "tx4");
    a.finishCommit(["t"], "tx4");                                                                         // idempotent
    e = a.get("t")!;
    assert.deepEqual([e.epoch, e.root, e.count], [2, 99n, 2]);
    assert.deepEqual(e.history[e.history.length - 1], [1, 0n, 0]);
    assert.throws(() => a.beginCommit(new Map([["t", { expectEpoch: 2, root: 1n, count: 1 }], ["u", { expectEpoch: 5, root: 1n, count: 1 }]]), "tx5"), kind("AnchorConflict"));
    assert.equal(a.get("t")!.pending, null);
    assert.equal(a.get("u"), null);
    a.beginCommit(new Map([["t", { expectEpoch: 2, root: null, count: 0 }]]), "tx6");                       // drop
    a.finishCommit(["t"], "tx6");
    assert.equal(a.get("t"), null);
    for (let i = 0; i < 12; i++) a.set("h", BigInt(i), i, i === 0 ? null : i - 1);                          // history keeps the last 8
    assert.equal(a.get("h")!.history.length, 8);
    assert.throws(() => a.set("h", 1n, 1, 3), kind("AnchorConflict"));
  });
}

test("FileAnchor: 0600, crash-safe writes, refuses lax permissions / corrupt / unknown version / symlink / missing dir", () => {
  const dir = tmpdir("anchorfile-");
  const p = path.join(dir, "a.json");
  const a = new FileAnchor(p);
  a.set("t", 123n, 4, null);
  assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  assert.equal(JSON.parse(fs.readFileSync(p, "utf8")).v, 1);
  assert.deepEqual(fs.readdirSync(dir).filter((f) => f.includes(".tmp.")), []);                          // temporary files are gone
  assert.equal(new FileAnchor(p).get("t")!.root, 123n);
  fs.chmodSync(p, 0o644);
  assert.throws(() => a.get("t"), /permissions/);
  fs.chmodSync(p, 0o600);
  fs.writeFileSync(p, "not json", { mode: 0o600 });
  assert.throws(() => a.get("t"), /corrupt/);                                                             // never silently start from empty
  fs.writeFileSync(p, JSON.stringify({ format: "torussql-fhe-anchor", v: 99, tables: {} }), { mode: 0o600 });
  assert.throws(() => a.get("t"), /version/);
  fs.rmSync(p);
  const target = path.join(dir, "elsewhere.json");
  fs.writeFileSync(target, "{}", { mode: 0o600 });
  fs.symlinkSync(target, p);
  assert.throws(() => a.get("t"), kind("AnchorFileError"));
  assert.throws(() => a.set("t", 1n, 1, null), kind("AnchorFileError"));
  assert.throws(() => new FileAnchor(path.join(dir, "nodir", "a.json")), /directory/);
});

test("two FileAnchor objects on one file are serialised", () => {
  const p = anchorFile();
  const a = new FileAnchor(p), b = new FileAnchor(p);
  a.beginCommit(new Map([["t", { expectEpoch: null, root: 5n, count: 1 }]]), "x");
  assert.throws(() => b.beginCommit(new Map([["t", { expectEpoch: 0, root: 6n, count: 2 }]]), "y"), kind("AnchorConflict"));
  a.finishCommit(["t"], "x");
  b.beginCommit(new Map([["t", { expectEpoch: 1, root: 6n, count: 2 }]]), "y");
  b.finishCommit(["t"], "y");
  assert.equal(a.get("t")!.epoch, 2);
});

test("canonical values are unambiguous (bool = int = fraction with denominator 1)", () => {
  assert.deepEqual(canonValue(5n), canonValue({ num: 5n, den: 1n }));
  assert.deepEqual(canonValue(1n), canonValue(true));
  const forms = [null, 0n, "0", "", { num: 1n, den: 2n }, 1n, "1", false];
  assert.equal(new Set(forms.map((v) => canonValue(v as any).toString("hex"))).size, 7);                 // false == 0n by design
});

T("known answers: canonical row material and leaf equal the Python implementation bit for bit", async () => {
  const cols = [["id", "int", "plain"], ["name", "str", "plain"], ["f", "rational", "plain"], ["rate", "int", "fhe"], ["h", "int", "fhe"]];
  const cases: Array<{ plain: any[]; fhe: Array<[string | null, string | null, string | null]>; rid: number }> = [
    { rid: 0, plain: [{ t: "i", v: "5" }, { t: "s", v: "café ü中😀" }, { t: "f", n: "-7", d: "3" }], fhe: [["12345", "ab".repeat(32), "cd".repeat(32)], [null, null, null]] },
    { rid: 2 ** 40 + 3, plain: [{ t: "i", v: "-123456789012345678901234567890" }, { t: "n" }, { t: "i", v: "0" }], fhe: [["1" + "0".repeat(30), "00".repeat(32), "ff".repeat(32)], ["1", "11".repeat(32), "22".repeat(32)]] },
    { rid: 7, plain: [{ t: "b", v: true }, { t: "s", v: "" }, { t: "f", n: "4", d: "2" }], fhe: [[null, "01".repeat(32), null], ["99", null, "02".repeat(32)]] },
  ];
  const table = "tést";
  const out = runPeer(mem.host, mem.port, { key: SECRET, range: VEC.range, ops: cases.map((c) => ["leaf", table, cols, c.rid, c.plain, c.fhe]) });
  const sdig = schemaDigest(table, cols.map(([name, type, policy]) => ({ name, type, policy })));
  cases.forEach((c, k) => {
    const gcd = (x: bigint, y: bigint): bigint => (y === 0n ? (x < 0n ? -x : x) : gcd(y, x % y));
    const fw = (w: any) => {
      if (w.t === "n") return null;
      if (w.t === "b") return w.v as boolean;
      if (w.t === "i") return BigInt(w.v);
      if (w.t === "s") return w.v as string;
      const g = gcd(BigInt(w.n), BigInt(w.d)), n = BigInt(w.n) / g, d = BigInt(w.d) / g;
      return d === 1n ? n : { num: n, den: d };
    };
    const plain = c.plain.map(fw);
    const parts = c.fhe.map(([n, hc, ht]) => [n === null ? null : BigInt(n), hc ? Buffer.from(hc, "hex") : null, ht ? Buffer.from(ht, "hex") : null] as [bigint | null, Buffer | null, Buffer | null]);
    const m = rowMaterial(sdig, plain, parts);
    assert.equal(m.toString("hex"), out[k][0], `material ${k}`);
    assert.equal(KEY.anchorLeaf(table, c.rid, m).toString(), out[k][1], `leaf ${k}`);
  });
});

T("anchor file format is interchangeable with Python's FileAnchor (both directions)", async () => {
  const p = anchorFile();
  const a = new FileAnchor(p);
  a.beginCommit(new Map([["t", { expectEpoch: null, root: 12345678901234567890123456789n, count: 3 }]]), "tx-ts");
  const dumpAll = (steps: any[]) => runPeer(mem.host, mem.port, { key: SECRET, ops: [["anchor_ops", p, steps]] })[0];
  const [pend] = dumpAll([["get", "t"]]);
  assert.deepEqual(pend, { epoch: 0, root: "0", count: 0, history: [], pending: { epoch: 1, root: "12345678901234567890123456789", count: 3, txid: "tx-ts", drop: false, created: true } });
  a.finishCommit(["t"], "tx-ts");
  // Python continues on the same file: a second commit, then a table of its own and a drop
  const res = dumpAll([
    ["begin_commit", { t: [1, "5", 4], "ué": [null, "9", 1] }, "tx-py"], ["finish_commit", ["t", "ué"], "tx-py"],
    ["set", "w", "77", 2, null], ["get", "t"], ["get", "ué"], ["get", "w"]]);
  assert.deepEqual(res.map((e: any) => e && [e.epoch, e.root, e.count, e.pending]), [[2, "5", 4, null], [1, "9", 1, null], [0, "77", 2, null]]);
  const b = new FileAnchor(p);
  assert.deepEqual([b.get("t")!.epoch, b.get("t")!.root, b.get("t")!.count], [2, 5n, 4]);
  assert.deepEqual(b.get("t")!.history.map((h) => h[0]), [0, 1]);
  assert.equal(b.get("ué")!.root, 9n);
  assert.deepEqual(b.tables(), ["t", "ué", "w"]);
  // and back: TypeScript drops/aborts, Python reads
  b.beginCommit(new Map([["t", { expectEpoch: 2, root: null, count: 0 }]]), "tx-drop");
  b.abort(["t"], "tx-drop");
  b.remove("w");
  const [t2] = dumpAll([["get", "t"]]);
  assert.equal(t2.pending, null);
  assert.equal(t2.epoch, 2);
  assert.equal(JSON.parse(fs.readFileSync(p, "utf8")).format, "torussql-fhe-anchor");
  assert.equal(fs.statSync(p).mode & 0o777, 0o600);
});

// ── options ──────────────────────────────────────────────────────────────────
T("integrityAnchor needs authenticated + an FHE key; a bad anchor object is refused", async () => {
  const p = anchorFile();
  await assert.rejects(Client.connect(mem.host, mem.port, { fheKey: KEY, integrityAnchor: p }), kind("InterfaceError"));
  await assert.rejects(Client.connect(mem.host, mem.port, { authenticated: true, integrityAnchor: p }), kind("InterfaceError"));
  await assert.rejects(Client.connect(mem.host, mem.port, { fheKey: KEY, authenticated: true, integrityAnchor: {} as any }), kind("InterfaceError"));
  const db = await owner(undefined);
  await assert.rejects(db.verifyTable("x"), kind("InterfaceError"));
  await assert.rejects(db.adoptTable("x"), kind("InterfaceError"));
  db.close();
});

// ── honest flows ─────────────────────────────────────────────────────────────
T("honest flows: insert, insertMany, update, delete, WHERE from the snapshot (NULL semantics), SUM/AVG/COUNT/DOT, caching per epoch", async () => {
  const p = anchorFile();
  const db = await owner(p);
  const t = uniq("emp");
  await db.createTable(t, [...COLS, { name: "note", type: "str", policy: "plain" }]);
  const e0 = new FileAnchor(p).get(t)!;
  assert.deepEqual([e0.epoch, e0.root, e0.count], [1, 0n, 0]);                                           // anchored from the first byte
  for (const [id, dept, rate] of ROWS) await db.insert(t, { id, dept, rate, note: id === 3 ? null : `n${id}` });
  assert.deepEqual(await DEPT5(db, t), [115n, 3]);
  assert.deepEqual(await db.avg(t, "rate", eq("dept", 5)), { num: 115n, den: 3n });
  assert.equal(await db.scaledSum(t, "rate", 3), 435n);
  assert.deepEqual((await db.select(t, ["id", "rate"], gt("id", 2))).map((r) => [r.id, r.rate]), [[3n, 30n], [4n, 20n]]);
  assert.deepEqual((await db.select(t, ["id"], isNull("note"))).map((r) => r.id), [3n]);                  // NULL semantics kept
  assert.equal(await db.count(t, eq("note", "n2")), 1);
  assert.equal(await db.dot(t, "rate", "rate", eq("dept", 5)), BigInt(40 * 40 + 55 * 55 + 20 * 20));      // authenticated auto = local
  const scans = db.anchorStats.scans;
  for (let i = 0; i < 5; i++) await db.sum(t, "rate");
  assert.equal(db.anchorStats.scans, scans);                                                              // cached: no rescan
  await db.update(t, { rate: 99, note: "x" }, eq("id", 2));
  await db.update(t, { dept: 8 }, eq("dept", 7));
  assert.deepEqual(await DEPT5(db, t), [159n, 3]);
  assert.equal(await db.deleteRows(t, eq("id", 4)), 1);
  assert.deepEqual(await DEPT5(db, t), [139n, 2]);
  const ids = await db.insertMany(t, [{ id: 10, dept: 5, rate: 1, note: "a" }, { id: 11, dept: 5, rate: 2, note: "b" }]);
  assert.deepEqual(ids, [4, 5]);                                                                          // slot ids are never reused
  assert.deepEqual(await DEPT5(db, t), [142n, 4]);
  assert.equal(db.anchorStats.scans, scans);                                                              // still no scan: deltas are tracked
  assert.deepEqual(await db.verifyTable(t), { table: t, rows: 5, slots: 6, epoch: new FileAnchor(p).get(t)!.epoch });
  // an explicit transaction commits one anchor epoch for all its changes
  const ep = new FileAnchor(p).get(t)!.epoch;
  await db.transaction(async () => { await db.insert(t, { id: 20, dept: 1, rate: 3, note: "t" }); await db.update(t, { rate: 4 }, eq("id", 20)); });
  assert.equal(new FileAnchor(p).get(t)!.epoch, ep + 1);
  // a fresh owner (new process) rescans once and agrees
  const other = await owner(p);
  assert.equal(await other.sum(t, "rate"), 1n + 2n + 4n + 99n + 40n + 30n);
  assert.equal(other.anchorStats.scans, 1);
  other.close(); db.close();
});

T("mixed tables: PAIRED columns next to FHE ones, and plain-only tables, work under an anchor", async () => {
  const p = anchorFile();
  const db = await owner(p);
  const t = uniq("mix"), pl = uniq("plainonly");
  await db.createTable(t, [{ name: "id", type: "int", policy: "plain" }, { name: "x", type: "int", policy: "paired" }, { name: "y", type: "int", policy: "fhe" }]);
  await db.createTable(pl, [{ name: "id", type: "int", policy: "plain" }, { name: "s", type: "int", policy: "encrypted" }]);
  await db.insert(t, { id: 1, x: 6, y: 7 });
  await db.insert(t, { id: 2, x: 2, y: 3 });
  await db.insert(pl, { id: 1, s: 5 });
  assert.equal(await db.sum(t, "y"), 10n);
  assert.equal(await db.sum(t, "x"), 8n);
  assert.equal(await db.dot(t, "x", "x"), 40n);
  assert.equal(await db.sum(pl, "s"), 5n);
  assert.equal(new FileAnchor(p).get(pl), null);                                                          // no FHE column: not anchored
  await db.update(t, { x: 9, y: 1 }, eq("id", 1));
  assert.equal(await db.sum(t, "x"), 11n);
  assert.equal((await db.verifyTable(t)).rows, 2);
  db.close();
});

T("drop + recreate resets the anchor entry; a rolled-back CREATE leaves nothing; a failed statement rolls back its delta", async () => {
  const p = anchorFile();
  const db = await owner(p);
  const t = uniq("dr");
  await db.createTable(t, COLS);
  await db.insert(t, { id: 1, dept: 1, rate: 1 });
  await db.dropTable(t);
  assert.equal(new FileAnchor(p).get(t), null);
  await db.createTable(t, COLS);
  assert.deepEqual([new FileAnchor(p).get(t)!.root, new FileAnchor(p).get(t)!.count], [0n, 0]);
  await db.insert(t, { id: 1, dept: 1, rate: 5 });
  assert.equal(await db.sum(t, "rate"), 5n);
  const u = uniq("rb");
  await db.begin();
  await db.createTable(u, COLS);
  await db.rollback();
  assert.equal(new FileAnchor(p).get(u), null);
  assert.deepEqual(await db.tables().then((ts) => ts.includes(u)), false);
  // a statement that fails midway (value out of range) leaves anchor and snapshot untouched
  const ep = new FileAnchor(p).get(t)!.epoch;
  await db.insert(t, { id: 2, dept: 1, rate: 6 });
  await assert.rejects(db.update(t, { rate: 10_000_000 }, null), kind("OutOfBudget"));
  assert.equal(new FileAnchor(p).get(t)!.epoch, ep + 1);
  assert.equal(await db.sum(t, "rate"), 11n);
  assert.equal((await db.verifyTable(t)).rows, 2);
  db.close();
});

T("scan is chunked by hello.limits.fhe.max_scan_rows; the size guard refuses oversized tables", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  db.close();
  const px = await startProxy(mem);
  px.hooks.resp = (r, resp) => {
    if (r.m === "hello" && resp.ok) resp.ok.limits = { ...(resp.ok.limits ?? {}), fhe: { ...(resp.ok.limits?.fhe ?? {}), max_scan_rows: 2 } };
    return resp;
  };
  const small = await owner(p, {}, "127.0.0.1", px.port);
  assert.equal((await small.verifyTable(t)).rows, 4);
  assert.equal(px.seen.filter((m) => m === "fhe_rows").length, 3);                                        // 2 + 2 + terminal
  small.close(); px.close();
  const guard = await owner(p, { integrityAnchorMaxRows: 3 });
  await assert.rejects(guard.verifyTable(t), (e: any) => e.kind === "InterfaceError" && /limit/.test(e.message));
  guard.close();
});

T("adopt: a table that existed before the anchor is refused until adopted (trust on first use), honest only as of that moment", async () => {
  const p = anchorFile();
  const { db: plain, t } = await seeded(undefined);                                                       // authenticated, NOT anchored
  const a = await owner(p);
  await a.syncSchema();
  await assert.rejects(a.sum(t, "rate"), kind("AnchorMissingError"));
  await assert.rejects(a.count(t), kind("AnchorMissingError"));
  a.trustTable(t);
  const r = await a.adoptTable(t);
  assert.deepEqual([r.rows, r.slots], [4, 4]);
  assert.deepEqual(await DEPT5(a, t), [115n, 3]);
  await assert.rejects(a.adoptTable(t), (e: any) => /already has an anchor entry/.test(e.message));
  // a lie told AT adoption becomes the truth: after a raw delete, adopting again with replace pins the lie
  await rawCall("delete_rows", [t, [0]]);
  await assert.rejects(a.verifyTable(t), IE);
  assert.equal((await a.adoptTable(t, { replace: true })).rows, 3);
  assert.deepEqual(await DEPT5(a, t), [75n, 2]);                                                          // pinned: the lie is now the anchored state
  a.close(); plain.close();
});

// ── the attacks ──────────────────────────────────────────────────────────────
T("selection lie: the server drops a row from matching_rowids - undetected without an anchor, irrelevant with one", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  const px = await startProxy(mem);
  px.hooks.resp = (r, resp) => (r.m === "matching_rowids" && Array.isArray(resp.ok) ? { ok: resp.ok.slice(0, -1) } : undefined);
  const control = await owner(undefined, {}, "127.0.0.1", px.port);                                       // authenticated, no anchor
  control.trustTable(t);
  assert.deepEqual(await DEPT5(control, t), [95n, 2]);                                                    // WRONG, silently (true: 115, 3)
  const anchored = await owner(p, {}, "127.0.0.1", px.port);
  const n0 = px.seen.length;
  assert.deepEqual(await DEPT5(anchored, t), [115n, 3]);                                                  // right: the row set comes from the anchor
  assert.equal(px.seen.slice(n0).includes("matching_rowids"), false);
  control.close(); anchored.close(); db.close(); px.close();
});

T("lying scan: dropped slot, dead flag on a live row, extra row, wrong shape, forged hash, forged plain value", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  db.close();
  const px = await startProxy(mem);
  const edits: Record<string, (rows: any[]) => any[]> = {
    dropped: (r) => r.filter((x) => x[0] !== 1),
    dead: (r) => r.map((x) => (x[0] === 1 ? [1, 1] : x)),
    extra: (r) => [...r, [r.length, 0, r[0][2], r[0][3]]],
    shape: (r) => r.map((x) => (x[0] === 0 ? [0, 0, [x[2][0]], x[3]] : x)),
    hash: (r) => r.map((x) => (x[0] === 2 ? [2, 0, x[2], [[x[3][0][0], "00".repeat(32), x[3][0][2]]]] : x)),
    plain: (r) => r.map((x) => (x[0] === 3 ? [3, 0, [x[2][0], { t: "i", v: "6" }], x[3]] : x)),
    nonce: (r) => r.map((x) => (x[0] === 3 ? [3, 0, x[2], [[{ t: "i", v: "5" }, x[3][0][1], x[3][0][2]]]] : x)),
    junk: (r) => r.map((x) => (x[0] === 0 ? [0, 0, x[2], [[{ t: "s", v: "x" }, x[3][0][1], x[3][0][2]]]] : x)),
  };
  let mode = "";
  px.hooks.resp = (r, resp) => (r.m === "fhe_rows" && mode && resp.ok && resp.ok.rows.length ? { ok: { n: resp.ok.n, rows: edits[mode](resp.ok.rows) } } : undefined);
  for (const m of Object.keys(edits)) {
    mode = m;
    const x = await owner(p, {}, "127.0.0.1", px.port);
    await assert.rejects(x.verifyTable(t), IE, m);
    x.close();
  }
  mode = "";
  const ok = await owner(p, {}, "127.0.0.1", px.port);
  assert.equal((await ok.verifyTable(t)).rows, 4);
  ok.close(); px.close();
});

T("the server adds a row (raw insert): invisible to a cached owner, caught by the next scan; an unanchored owner counts it", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  const plain = await owner(undefined);
  plain.trustTable(t);
  await plain.syncSchema();
  await rawAddRow(t, 9, 5, 1000);
  assert.deepEqual(await DEPT5(db, t), [115n, 3]);                                                        // cached owner never asks the server for the row set
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(DEPT5(fresh, t), IE);
  await assert.rejects(fresh.verifyTable(t), IE);
  assert.equal(await plain.count(t, eq("dept", 5)), 4);                                                   // control: COUNT silently includes the planted row
  await assert.rejects(plain.sum(t, "rate"), IE);                                                         // (the planted row has no valid tag: SUM is caught by the tags alone)
  fresh.close(); plain.close(); db.close();
});

T("the server hides a row (tombstone via raw delete_rows): caught; without an anchor the count silently shrinks", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  await rawCall("delete_rows", [t, [1]]);
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(DEPT5(fresh, t), IE);
  const plain = await owner(undefined);
  await plain.syncSchema();
  assert.deepEqual(await DEPT5(plain, t), [60n, 2]);                                                      // control: silently wrong
  fresh.close(); plain.close(); db.close();
});

T("the server hides a DELETE (swallows delete_rows): caught at the next scan; unanchored the row lives on", async () => {
  const p = anchorFile();
  const px = await startProxy(mem);
  const mk = async (file: string | undefined) => {
    const db = await owner(file, {}, "127.0.0.1", px.port);
    const t = uniq("hd");
    await db.createTable(t, COLS);
    for (const [id, dept, rate] of ROWS) await db.insert(t, { id, dept, rate });
    return { db, t };
  };
  const a = await mk(p), c = await mk(undefined);
  px.hooks.req = (r) => (r.m === "delete_rows" ? { reply: { ok: r.a[1].length } } : undefined);
  assert.equal(await a.db.deleteRows(a.t, eq("id", 1)), 1);
  assert.equal(await c.db.deleteRows(c.t, eq("id", 1)), 1);
  px.hooks.req = undefined;
  assert.deepEqual(await DEPT5(c.db, c.t), [115n, 3]);                                                    // control: the "deleted" row is still there
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(DEPT5(fresh, a.t), (e: any) => IE(e) || e instanceof StaleServerError);           // the un-deleted state is the PREVIOUS epoch
  fresh.close(); a.db.close(); c.db.close(); px.close();
});

T("rollback of the whole table to an older complete state is a StaleServerError; control: silently accepted", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  const old = await cells(t, 0);                                                                          // epoch A state of row 0
  await db.update(t, { rate: 41 }, eq("id", 1));                                                          // epoch B
  assert.equal(await db.sum(t, "rate", eq("id", 1)), 41n);
  const plain = await owner(undefined);
  plain.trustTable(t); await plain.syncSchema();
  await restore(t, 0, old);                                                                               // the server restores a backup
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(fresh.sum(t, "rate"), (e: any) => e instanceof StaleServerError && /behind the anchor/.test(e.message));
  assert.equal(await plain.sum(t, "rate", eq("id", 1)), 40n);                                             // control: the old value is served and every tag verifies
  fresh.close(); plain.close(); db.close();
  // rolling back an INSERT (tombstoning the new row) is the same older state
  const q = anchorFile();
  const { db: d2, t: t2 } = await seeded(q);
  await d2.insert(t2, { id: 5, dept: 5, rate: 5 });
  await rawCall("delete_rows", [t2, [4]]);
  const f2 = await owner(q); await f2.syncSchema();
  await assert.rejects(f2.count(t2), StaleServerError);
  f2.close(); d2.close();
});

T("replay of ONE old row version (cell + tag + nonce restored together) is caught; the control accepts the stale value", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  const old = await cells(t, 0);
  await db.update(t, { rate: 41 }, eq("id", 1));
  await db.update(t, { rate: 56 }, eq("id", 2));                                                          // so the state matches NO older epoch
  await restore(t, 0, old);
  const plain = await owner(undefined);
  plain.trustTable(t); await plain.syncSchema();
  assert.equal(await plain.sum(t, "rate", eq("id", 1)), 40n);                                             // control: silently stale
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(fresh.sum(t, "rate"), (e: any) => IE(e) && !(e instanceof StaleServerError));
  // the cached owner notices at the cell level: the stored bytes differ from the anchored hashes
  await assert.rejects(db.select(t, ["rate"], eq("id", 1)), IE);
  await assert.rejects(db.sum(t, "rate"), IE);
  fresh.close(); plain.close(); db.close();
});

T("swapped rows (PLAIN dept exchanged by the server): caught; the unanchored selection silently changes", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  await rawCall("update_cell", [t, 0, "dept", ints(7)]);
  await rawCall("update_cell", [t, 2, "dept", ints(5)]);
  const plain = await owner(undefined);
  plain.trustTable(t); await plain.syncSchema();
  assert.deepEqual(await DEPT5(plain, t), [105n, 3]);                                                    // control: silently different rows
  const fresh = await owner(p);
  await fresh.syncSchema();
  await assert.rejects(DEPT5(fresh, t), IE);
  assert.deepEqual(await DEPT5(db, t), [115n, 3]);                                                        // the cached owner keeps answering from the anchored plain values
  fresh.close(); plain.close(); db.close();
});

T("honest scan, other cells later: bytes that differ from the scanned hashes are refused (cached owner)", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  db.close();
  const px = await startProxy(mem);
  const owner2 = await owner(p, {}, "127.0.0.1", px.port);
  await owner2.syncSchema();
  assert.equal((await owner2.verifyTable(t)).rows, 4);
  const other = (await rawCall("plain_cells", [t, "rate", [3]])).ok[0];
  px.hooks.resp = (r, resp) => (r.m === "plain_cells" && r.a[1] === "rate" && resp.ok ? { ok: resp.ok.map(() => other) } : undefined);
  await assert.rejects(owner2.select(t, ["rate"], eq("id", 1)), IE);
  px.hooks.resp = undefined;
  assert.deepEqual((await owner2.select(t, ["rate"], eq("id", 1))).map((r) => r.rate), [40n]);
  owner2.close(); px.close();
});

T("local DOT under an anchor catches a tampered operand cell", async () => {
  const p = anchorFile();
  const { db, t } = await seeded(p);
  assert.equal(await db.dot(t, "rate", "rate"), BigInt(40 * 40 + 55 * 55 + 30 * 30 + 20 * 20));
  await rawCall("update_cell", [t, 1, "rate", xc(KEY.encrypt(1))]);
  await assert.rejects(db.dot(t, "rate", "rate"), IE);
  db.close();
});

// ── commit protocol ──────────────────────────────────────────────────────────
T("lost COMMIT reply, server committed: finished via tx_status; lost before processing: aborted (anchor and server agree)", async () => {
  const p = anchorFile();
  const px = await startProxy(mem);
  const db = await owner(p, {}, "127.0.0.1", px.port);
  const t = uniq("lc");
  await db.createTable(t, COLS);
  await db.insert(t, { id: 1, dept: 5, rate: 10 });
  const A = () => new FileAnchor(p).get(t)!;
  const ep = A().epoch;
  px.hooks.resp = (r) => (r.m === "tx_commit" ? "drop" : undefined);                                       // forwarded, reply lost
  await db.insert(t, { id: 2, dept: 5, rate: 20 });                                                       // the driver reconnects and asks tx_status
  px.hooks.resp = undefined;
  assert.deepEqual([A().epoch, A().pending], [ep + 1, null]);
  assert.deepEqual(await DEPT5(db, t), [30n, 2]);
  assert.equal((await db.verifyTable(t)).rows, 2);
  px.hooks.req = (r) => (r.m === "tx_commit" ? "kill" : undefined);                                        // never reached the server
  await assert.rejects(db.insert(t, { id: 3, dept: 5, rate: 30 }), (e: any) => e instanceof TorusError);
  px.hooks.req = undefined;
  assert.deepEqual([A().epoch, A().pending], [ep + 1, null]);
  assert.deepEqual(await DEPT5(db, t), [30n, 2]);
  assert.equal((await db.verifyTable(t)).rows, 2);
  await db.insert(t, { id: 4, dept: 5, rate: 40 });
  assert.deepEqual(await DEPT5(db, t), [70n, 3]);
  db.close(); px.close();
});

T("in doubt: pending stays in the anchor and the next connect settles it by scanning (committed -> finish, not processed -> abort)", async () => {
  for (const committed of [true, false]) {
    const p = anchorFile();
    const px = await startProxy(mem);
    const db = await owner(p, {}, "127.0.0.1", px.port);
    const t = uniq("id");
    await db.createTable(t, COLS);
    await db.insert(t, { id: 1, dept: 5, rate: 10 });
    const ep = new FileAnchor(p).get(t)!.epoch;
    if (committed) px.hooks.resp = (r) => { if (r.m === "tx_commit") { px.refuse.value = true; return "drop"; } return undefined; };
    else px.hooks.req = (r) => { if (r.m === "tx_commit") { px.refuse.value = true; return "kill"; } return undefined; };
    await assert.rejects(db.insert(t, { id: 2, dept: 5, rate: 20 }), (e: any) => e.kind === "TransactionInDoubt");
    const e1 = new FileAnchor(p).get(t)!;
    assert.equal(e1.epoch, ep);
    assert.ok(e1.pending && e1.pending.epoch === ep + 1);                                                 // the anchor remembers what was about to happen
    db.close(); px.close();
    const again = await owner(p);                                                                          // direct connection
    const e2 = new FileAnchor(p).get(t)!;
    assert.equal(e2.pending, null);
    assert.equal(e2.epoch, committed ? ep + 1 : ep);
    assert.deepEqual(await DEPT5(again, t), committed ? [30n, 2] : [10n, 1]);
    assert.equal((await again.verifyTable(t)).rows, committed ? 2 : 1);
    again.close();
  }
});

T("a pending record whose state is neither the old nor the new one (the server tampers after a crash) is an integrity error on connect", async () => {
  const p = anchorFile();
  const px = await startProxy(mem);
  const db = await owner(p, {}, "127.0.0.1", px.port);
  const t = uniq("pend");
  await db.createTable(t, COLS);
  for (const [id, dept, rate] of ROWS) await db.insert(t, { id, dept, rate });
  px.hooks.resp = (r) => { if (r.m === "tx_commit") { px.refuse.value = true; return "drop"; } return undefined; };
  await assert.rejects(db.insert(t, { id: 9, dept: 5, rate: 9 }), (e: any) => e.kind === "TransactionInDoubt");
  db.close(); px.close();
  assert.ok(new FileAnchor(p).get(t)!.pending);
  await rawCall("delete_rows", [t, [0]]);                                                                 // the server then tampers
  await assert.rejects(owner(p), (e: any) => IE(e) && /does not match the anchor/.test(e.message));
});

T("two owners share one anchor file: each sees the other's commits; a foreign epoch advance aborts an open transaction", async () => {
  const p = anchorFile();
  const { db: a, t } = await seeded(p);
  const b = await owner(p);
  await b.syncSchema(); b.trustTable(t);
  assert.deepEqual(await DEPT5(b, t), [115n, 3]);
  await b.insert(t, { id: 9, dept: 5, rate: 1 });
  assert.deepEqual(await DEPT5(a, t), [116n, 4]);                                                         // a notices the epoch moved and rescans
  await a.insert(t, { id: 10, dept: 5, rate: 2 });
  assert.deepEqual(await DEPT5(b, t), [118n, 5]);
  // another owner commits (here: directly in the anchor) while a's transaction is open
  await a.begin();
  await a.insert(t, { id: 11, dept: 5, rate: 3 });
  const f = new FileAnchor(p), e = f.get(t)!;
  f.beginCommit(new Map([[t, { expectEpoch: e.epoch, root: e.root, count: e.count }]]), "other");
  f.finishCommit([t], "other");
  await assert.rejects(a.commit(), kind("AnchorConflict"));
  assert.equal(a.inTransaction, false);
  assert.equal((await rawCall("table_info", [t])).ok.rows, 6);                                            // the server rolled a's insert back (5 live + ... slots)
  a.close(); b.close();
});

// ── Python <-> TypeScript, one anchor file, one server ───────────────────────
T("cross-implementation: Python writes and verifies what TypeScript wrote, and back, on one shared anchor file", async () => {
  const p = anchorFile();
  const db = await owner(p);
  const t = uniq("xanch");
  await db.createTable(t, COLS);
  for (const [id, dept, rate] of ROWS) await db.insert(t, { id, dept, rate });
  await db.update(t, { rate: 41 }, eq("id", 1));
  await db.deleteRows(t, eq("id", 3));
  const q = (sql: string) => ["query", sql];
  const res = runPeer(mem.host, mem.port, {
    key: SECRET, range: 100_000, auth: true, anchor: p, ops: [
      ["verify", t],                                                                                      // Python rescans the whole table against the TS-maintained anchor
      q(`SELECT SUM(rate), AVG(rate), COUNT(*) FROM ${t} WHERE dept = 5`),
      q(`SELECT id, rate FROM ${t} WHERE id = 1`),
      ["exec", `INSERT INTO ${t} (id, dept, rate) VALUES (5, 5, 7)`],                                     // Python writes + advances the anchor
      ["exec", `UPDATE ${t} SET rate = 77 WHERE id = 2`],
      ["exec", `DELETE FROM ${t} WHERE id = 4`],
      ["verify", t],
    ],
  });
  assert.deepEqual([res[0].rows, res[0].slots], [3, 4]);
  assert.deepEqual(res[1], [[116, "116/3", 3]]);
  assert.deepEqual(res[2], [[1, 41]]);
  assert.deepEqual([res[3].rows, res[3].slots], [3, 5]);                                                   // 1, 2, 5 live
  // TypeScript reads Python's writes (the epoch moved: one rescan), verifies, and continues
  assert.deepEqual(await DEPT5(db, t), [41n + 77n + 7n, 3]);
  assert.equal((await db.verifyTable(t)).rows, 3);
  await db.insert(t, { id: 6, dept: 6, rate: 6 });
  const fin = runPeer(mem.host, mem.port, { key: SECRET, range: 100_000, auth: true, anchor: p, ops: [["verify", t], q(`SELECT COUNT(*) FROM ${t}`)] });
  assert.equal(fin[0].rows, 4);
  assert.deepEqual(fin[1], [[4]]);
  // a Python-created table is read by TypeScript under the same anchor
  const t2 = uniq("pyc");
  runPeer(mem.host, mem.port, { key: SECRET, range: 100_000, auth: true, anchor: p, ops: [
    ["exec", `CREATE TABLE ${t2} (id INT PLAIN, dept INT PLAIN, rate INT FHE)`],
    ["exec", `INSERT INTO ${t2} (id, dept, rate) VALUES (1, 5, 11)`], ["exec", `INSERT INTO ${t2} (id, dept, rate) VALUES (2, 5, 22)`]] });
  await db.syncSchema(); db.trustTable(t2);
  assert.deepEqual(await DEPT5(db, t2), [33n, 2]);
  assert.equal((await db.verifyTable(t2)).rows, 2);
  db.close();
});
