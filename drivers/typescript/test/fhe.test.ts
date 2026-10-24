// SPDX-License-Identifier: Apache-2.0
// FHE columns (EC-FHE on BN254): known-answer vectors, rejection tests, key files, and end-to-end
// flows against the REAL Python server (memory and disk storage), including the Python reference
// as a cross-implementation peer and a lying-server proxy for the integrity checks.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as net from "net";
import * as path from "path";
import * as util from "util";
import { Client, FheKey, TorusError, eq, gt, Column, FHE_CELL_BYTES } from "../src/torusdb";
import { _internals as I, FHE_N, FHE_P, sumCells, addSums, mulDots } from "../src/fhe";
import { skipReason, startServer, RunningServer, uniq, tmpdir, mclPath, runPeer } from "./helpers";

const kind = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;
const VEC = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../../../proto/fhe-vectors.json"), "utf8"));
const hex = (h: string) => Buffer.from(h, "hex");

// ── known-answer tests (no server) ───────────────────────────────────────────
test("vectors: every cell, SUM, scaled SUM and DOT blob of proto/fhe-vectors.json decrypts", () => {
  const key = FheKey.fromHex(VEC.secret, VEC.range);
  assert.deepEqual(VEC.cells_a.map((c: string) => key.decryptCell(hex(c))), VEC.values_a);
  assert.deepEqual(VEC.cells_b.map((c: string) => key.decryptCell(hex(c))), VEC.values_b);
  assert.equal(key.decryptSum(hex(VEC.sum_blob)), VEC.sum_expected);
  assert.equal(key.decryptSum(hex(VEC.scaled3_sum_blob)), VEC.scaled3_expected);
  assert.equal(key.decryptDot(hex(VEC.dot_blob_pyecc)), VEC.dot_expected);           // tag 0x01, g_pyecc
  assert.equal(key.decryptDot(hex(VEC.dot_blob_mcl)), VEC.dot_expected);             // tag 0x02, g_mcl
  assert.equal(hex(VEC.dot_blob_pyecc)[0], 1);
  assert.equal(hex(VEC.dot_blob_mcl)[0], 2);
  // our own sums of the vector cells equal the published blobs' plaintexts
  const cellsA = VEC.cells_a.map(hex);
  assert.equal(key.decryptSum(sumCells(cellsA)), 105);
  assert.equal(key.decryptSum(sumCells(cellsA, 3n)), 315);
  assert.equal(key.decryptSum(sumCells(cellsA, -2n)), -210);
  assert.equal(key.decryptSum(addSums(sumCells(cellsA.slice(0, 2)), sumCells(cellsA.slice(2)))), 105);
  // partial DOT blobs combine by component-wise GT multiplication: (blob * blob) decrypts to 2 * dot
  assert.equal(key.decryptDot(mulDots(hex(VEC.dot_blob_pyecc), hex(VEC.dot_blob_pyecc))), 2 * VEC.dot_expected);
  assert.equal(key.decryptDot(mulDots(hex(VEC.dot_blob_mcl), hex(VEC.dot_blob_mcl))), 2 * VEC.dot_expected);
  assert.throws(() => mulDots(hex(VEC.dot_blob_pyecc), hex(VEC.dot_blob_mcl)), kind("ProtocolError"));
});

test("vectors: GT generators are the published constants and have order n; G2 generator is on the twist", () => {
  assert.equal(I.fp12To(I.GT_GEN[1]).toString("hex"), VEC.gt_generators.pyecc_tag01);
  assert.equal(I.fp12To(I.GT_GEN[2]).toString("hex"), VEC.gt_generators.mcl_tag02);
  for (const tag of [1, 2]) {
    assert.deepEqual(I.fp12Pow(I.GT_GEN[tag], FHE_N), I.FP12_ONE);
    assert.notDeepEqual(I.fp12Pow(I.GT_GEN[tag], FHE_N / 3n), I.FP12_ONE);
  }
  assert.ok(I.C2.onCurve(I.G2_AFF));
  assert.ok(I.C1.onCurve(I.G1_AFF));
  // n * G = infinity on both curves
  assert.ok(I.C1.isInf(I.C1.mul(I.C1.fromAff(I.G1_AFF), FHE_N)));
  assert.ok(I.C2.isInf(I.C2.mul(I.C2.fromAff(I.G2_AFF), FHE_N)));
});

test("vectors: MAC alpha, gamma, tag cells and tag-sum blob", () => {
  const key = FheKey.fromHex(VEC.secret, VEC.range);
  const m = VEC.mac;
  assert.equal("0x" + key.alpha().toString(16), m.alpha);
  assert.deepEqual(m.row_ids.map((i: number) => "0x" + key.gamma(m.table, m.column, i).toString(16)), m.gamma);
  assert.equal(key.decryptSumVerified(hex(VEC.sum_blob), hex(m.tag_sum_blob), m.table, m.column, m.row_ids), VEC.sum_expected);
  m.row_ids.forEach((id: number, k: number) => {
    assert.equal(key.decryptCellVerified(hex(VEC.cells_a[k]), hex(m.tag_cells[k]), m.table, m.column, id), VEC.values_a[k]);
  });
  // the tag of each vector cell is Enc(alpha*v + gamma): our own tag verifies too
  assert.equal(key.decryptCellVerified(key.encrypt(7), key.tag(7, "emp", "rate", 2), "emp", "rate", 2), 7);
  // tampering
  const kind_ = kind("IntegrityError");
  assert.throws(() => key.decryptSumVerified(hex(VEC.sum_blob), hex(m.tag_sum_blob), m.table, m.column, [0, 1, 2]), kind_);
  assert.throws(() => key.decryptSumVerified(hex(VEC.sum_blob), hex(m.tag_sum_blob), m.table, m.column, m.row_ids, 2), kind_);
  assert.throws(() => key.decryptSumVerified(hex(VEC.scaled3_sum_blob), hex(m.tag_sum_blob), m.table, m.column, m.row_ids), kind_);
  assert.throws(() => key.decryptSumVerified(hex(VEC.sum_blob), hex(m.tag_sum_blob), m.table, "other", m.row_ids), kind_);
  assert.throws(() => key.decryptCellVerified(hex(VEC.cells_a[0]), hex(m.tag_cells[1]), m.table, m.column, 0), kind_);
  assert.throws(() => key.decryptCellVerified(hex(VEC.cells_a[0]), hex(m.tag_cells[0]), m.table, m.column, 1), kind_);
  assert.throws(() => key.decryptCellVerified(hex(VEC.cells_a[0]), null, m.table, m.column, 0), kind_);
  assert.throws(() => key.decryptCellVerified(key.encrypt(41), hex(m.tag_cells[0]), m.table, m.column, 0), kind_);
});

// ── scheme properties and rejections (no server) ─────────────────────────────
test("encrypt/decrypt: edge values, range, fresh randomness, bigint and number inputs", () => {
  const key = FheKey.generate(5000);
  for (const v of [0, 1, -1, 4999, -4999, 5000, -5000]) assert.equal(key.decryptCell(key.encrypt(v)), v);
  assert.equal(key.decryptCell(key.encrypt(123n)), 123);
  assert.throws(() => key.encrypt(5001), kind("OutOfBudget"));
  assert.throws(() => key.encrypt(-5001n), kind("OutOfBudget"));
  assert.throws(() => key.encrypt(1.5), kind("InterfaceError"));
  assert.throws(() => key.encrypt(NaN), kind("InterfaceError"));
  assert.throws(() => key.encrypt("5" as any), kind("InterfaceError"));
  const a = key.encrypt(5), b = key.encrypt(5);
  assert.equal(a.length, FHE_CELL_BYTES);
  assert.notDeepEqual(a, b);                                          // randomised
  assert.notDeepEqual(a.subarray(0, 64), b.subarray(0, 64));
  // a sum over the range raises instead of wrapping
  const big = FheKey.generate(100);
  assert.throws(() => big.decryptSum(sumCells([big.encrypt(90), big.encrypt(90)])), kind("OutOfBudget"));
  assert.equal(big.decryptSum(sumCells([])), 0);
});

test("encrypt: C1 and D1 use independent randomness, tags use scalars beyond the range", () => {
  const key = FheKey.generate(1000);
  // a tag is an arbitrary scalar mod n (alpha*v + gamma): decrypting it as a value must fail (out of range)
  const tag = key.tag(5, "t", "c", 1);
  assert.throws(() => key.decryptCell(tag), kind("OutOfBudget"));
  // the sum blob of a cell is exactly its first 128 bytes
  const c = key.encrypt(9);
  assert.deepEqual(sumCells([c]), c.subarray(0, 128));
});

test("rejections: malformed cells, points, blobs and keys", () => {
  const key = FheKey.generate(1000);
  const c = key.encrypt(3);
  assert.throws(() => key.decryptCell(c.subarray(0, 383)), kind("ProtocolError"));
  assert.throws(() => key.decryptCell(Buffer.concat([c, Buffer.alloc(1)])), kind("ProtocolError"));
  assert.throws(() => key.decryptCell(Buffer.alloc(0)), kind("ProtocolError"));
  const off = Buffer.from(c); off[70] ^= 0x55;                         // C2 no longer on the curve
  assert.throws(() => key.decryptCell(off), kind("ProtocolError"));
  const big = Buffer.from(c); big.fill(0xff, 0, 32);                    // x >= p
  assert.throws(() => key.decryptCell(big), kind("ProtocolError"));
  assert.throws(() => sumCells([c.subarray(0, 100)]), kind("ProtocolError"));
  assert.throws(() => key.decryptSum(Buffer.alloc(127)), kind("ProtocolError"));
  assert.throws(() => addSums(Buffer.alloc(128), Buffer.alloc(5)), kind("ProtocolError"));
  // DOT blobs
  const dot = hex(VEC.dot_blob_pyecc);
  const k2 = FheKey.fromHex(VEC.secret, VEC.range);
  assert.throws(() => k2.decryptDot(dot.subarray(0, 1536)), kind("ProtocolError"));
  const tag3 = Buffer.from(dot); tag3[0] = 3;
  assert.throws(() => k2.decryptDot(tag3), kind("ProtocolError"));
  const hi = Buffer.from(dot); hi.fill(0xff, 1, 33);                    // coefficient >= p
  assert.throws(() => k2.decryptDot(hi), kind("ProtocolError"));
  // wrong back-end tag for the data: the result is garbage, never a wrong number
  const swapped = Buffer.from(dot); swapped[0] = 2;
  assert.throws(() => k2.decryptDot(swapped), kind("OutOfBudget"));
  // a hostile server answer that is not in the target group (small-subgroup oracle on the secret)
  const hostile = Buffer.from(dot);
  hostile.fill(0, 385, 769); hostile[385 + 31] = 2;                     // c01 = 2 (order is not n)
  assert.throws(() => k2.decryptDot(hostile), kind("ProtocolError"));
  // keys
  assert.throws(() => FheKey.fromSecretBytes(Buffer.alloc(31, 1)), kind("InterfaceError"));
  assert.throws(() => FheKey.fromSecretBytes(Buffer.alloc(32)), kind("InterfaceError"));          // s = 0
  assert.throws(() => FheKey.fromSecretBytes(Buffer.from(FHE_N.toString(16).padStart(64, "0"), "hex")), kind("InterfaceError"));
  assert.throws(() => FheKey.fromHex("zz"), kind("InterfaceError"));
  assert.throws(() => FheKey.generate(0), kind("InterfaceError"));
  assert.throws(() => FheKey.generate(2 ** 41), kind("InterfaceError"));
  assert.throws(() => FheKey.generate(1.5), kind("InterfaceError"));
  assert.ok(FHE_P > FHE_N);
});

test("the secret never shows in inspect, JSON or String()", () => {
  const key = FheKey.fromHex(VEC.secret, 1000);
  for (const s of [util.inspect(key), util.inspect({ key }), JSON.stringify({ key }), String(key), `${key}`]) {
    assert.ok(!s.includes(VEC.secret), s);
    assert.ok(!s.includes(BigInt("0x" + VEC.secret).toString()));
  }
  assert.deepEqual(Object.keys(key), []);
});

test("key files: plain and sealed round trip, wrong passphrase, damaged and foreign files", () => {
  const dir = tmpdir();
  const key = FheKey.generate(12345);
  const sealed = path.join(dir, "sealed.key"), plain = path.join(dir, "plain.key");
  key.save(sealed, "correct horse");
  key.save(plain, null);
  assert.equal(fs.statSync(sealed).mode & 0o777, 0o600);
  assert.ok(fs.readFileSync(sealed, "latin1").startsWith("TORUSFHEKEY1 sealed "));
  assert.ok(!fs.readFileSync(sealed, "latin1").includes(key.secretBytes().toString("hex")));
  assert.ok(fs.readFileSync(plain, "latin1").startsWith("TORUSFHEKEY1 plain\n"));
  for (const [f, pw] of [[sealed, "correct horse"], [plain, undefined]] as const) {
    const k = FheKey.load(f, pw);
    assert.equal(k.range, 12345);
    assert.deepEqual(k.secretBytes(), key.secretBytes());
    assert.equal(k.decryptCell(key.encrypt(77)), 77);
  }
  assert.throws(() => FheKey.load(sealed, "wrong"), kind("InterfaceError"));
  assert.throws(() => FheKey.load(sealed), /passphrase is required/);
  const dmg = Buffer.from(fs.readFileSync(sealed)); dmg[dmg.length - 5] ^= 1;
  fs.writeFileSync(path.join(dir, "dmg.key"), dmg);
  assert.throws(() => FheKey.load(path.join(dir, "dmg.key"), "correct horse"), kind("InterfaceError"));
  fs.writeFileSync(path.join(dir, "foreign"), "hello");
  assert.throws(() => FheKey.load(path.join(dir, "foreign")), /not an FHE key file/);
  assert.throws(() => FheKey.load(path.join(dir, "missing")), kind("InterfaceError"));
});

test("performance probe: encrypt 100 cells, decrypt, BSGS table build", () => {
  const key = FheKey.generate(1_000_000);
  let t = Date.now();
  key.encrypt(1);                                                     // builds the fixed-base tables
  const first = Date.now() - t;
  t = Date.now();
  const cells = Array.from({ length: 100 }, (_, i) => key.encrypt(i * 7 - 300));
  const enc = Date.now() - t;
  t = Date.now();
  const vals = cells.map((c) => key.decryptCell(c));
  const dec = Date.now() - t;
  assert.deepEqual(vals.slice(0, 3), [-300, -293, -286]);
  console.log(`# perf: first encrypt (tables) ${first} ms, 100 encrypts ${enc} ms, 100 decrypts ${dec} ms`);
  assert.ok(enc < 20000);
});

// ── end to end against the real server ───────────────────────────────────────
const skip = skipReason();
const EMP: Column[] = [
  { name: "id", type: "int", policy: "plain" },
  { name: "dept", type: "int", policy: "plain" },
  { name: "rate", type: "int", policy: "fhe" },
  { name: "hours", type: "int", policy: "fhe" },
];
const ROWS = [[1, 5, 40, 160], [2, 5, 55, 150], [3, 7, 30, 120], [4, 5, 20, 100]];
const DOT_ALL = 40 * 160 + 55 * 150 + 30 * 120 + 20 * 100;           // 20250
const DOT_D5 = 40 * 160 + 55 * 150 + 20 * 100;                       // 16650
const SECRET = VEC.secret as string;
const OPTS = { timeoutMs: 240_000 };

let mem: RunningServer;
let native: RunningServer | undefined;                                // server with mclbn256 (optional)
before(async () => {
  if (skip) return;
  mem = await startServer();
  if (mclPath()) native = await startServer([], { PYTHONPATH: mclPath()! });
});
after(async () => { if (!skip) { await mem?.stop(); await native?.stop(); } });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);

async function seed(db: Client, t: string, rows = ROWS): Promise<number[]> {
  await db.createTable(t, EMP);
  const ids: number[] = [];
  for (const [id, dept, rate, hours] of rows) ids.push(await db.insert(t, { id, dept, rate, hours }));
  return ids;
}

function frame(b: Buffer): Buffer {
  const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]);
}
/** One raw RPC on its own connection (what a hostile or buggy client could do). */
function rawCall(host: string, port: number, m: string, a: unknown[]): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host, port });
    let buf = Buffer.alloc(0);
    s.on("error", reject);
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        s.destroy();
        resolve(JSON.parse(buf.subarray(4, 4 + buf.readUInt32BE(0)).toString()));
      }
    });
    s.write(frame(Buffer.from(JSON.stringify({ m, a }))));
  });
}

/** A proxy in front of `up` that rewrites `fhe_sum` requests (a lying server: modes scale, drop, dup,
 *  swapcol) or kills the connection when an integrity tag is written (mode killtag). */
async function lyingProxy(up: RunningServer): Promise<{ server: net.Server; port: number; mode: { value: string }; seen: string[] }> {
  const mode = { value: "none" };
  const seen: string[] = [];
  const server = net.createServer((cli) => {
    const upc = net.createConnection({ host: up.host, port: up.port });
    let buf = Buffer.alloc(0);
    cli.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        const n = buf.readUInt32BE(0);
        const req = JSON.parse(buf.subarray(4, 4 + n).toString());
        buf = buf.subarray(4 + n);
        seen.push(req.m);
        if (req.m === "fhe_sum" && !String(req.a[1]).startsWith("__fmac__")) {
          const ids: number[] = req.a[2];
          if (mode.value === "scale") req.a[3] = (req.a[3] ?? 1) * 2;
          if (mode.value === "drop") req.a[2] = ids.slice(0, -1);
          if (mode.value === "dup") req.a[2] = [...ids, ids[0]];
          if (mode.value === "swapcol") req.a[1] = "hours";
        }
        const tagWrite = (req.m === "update_cell" && String(req.a[2]).startsWith("__fmac__")) ||
          (req.m === "update_cells" && req.a[1].some((it: any[]) => String(it[1]).startsWith("__fmac__")));
        if (mode.value === "killtag" && tagWrite) {
          cli.destroy(); upc.destroy();                                  // the tag write never arrives
          return;
        }
        upc.write(frame(Buffer.from(JSON.stringify(req))));
      }
    });
    upc.on("data", (d) => cli.write(d));
    cli.on("close", () => upc.destroy());
    upc.on("close", () => cli.destroy());
    cli.on("error", () => undefined); upc.on("error", () => undefined);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { server, port: (server.address() as net.AddressInfo).port, mode, seen };
}
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

for (const storage of ["memory", "disk"]) {
  T(`FHE end to end, ${storage} storage: insert, select, SUM/AVG/k*SUM/COUNT, DOT, update, delete, rollback`, async () => {
    const dir = tmpdir();
    const srv = storage === "disk" ? await startServer(["--db", path.join(dir, "db"), "--storage", "disk"]) : mem;
    const key = FheKey.fromHex(SECRET, 100_000);
    const db = await Client.connect(srv.host, srv.port, { fheKey: key, ...OPTS });
    try {
      const t = uniq("emp");
      const ids = await seed(db, t);
      assert.deepEqual(ids, [0, 1, 2, 3]);
      // the server stores opaque 384-byte ciphertexts
      const raw = await rawCall(srv.host, srv.port, "plain_cells", [t, "rate", ids]);
      assert.equal(raw.ok.length, 4);
      for (const w of raw.ok) { assert.equal(w.t, "x"); assert.equal(Buffer.from(w.v, "base64").length, 384); }

      assert.deepEqual(await db.select(t, ["id", "rate", "hours"], eq("dept", 5)),
        [{ id: 1n, rate: 40n, hours: 160n }, { id: 2n, rate: 55n, hours: 150n }, { id: 4n, rate: 20n, hours: 100n }]);
      assert.deepEqual((await db.select(t, ["rate"], gt("id", 2))).map((r) => r.rate), [30n, 20n]);
      assert.equal(await db.sum(t, "rate"), 145n);
      assert.equal(await db.sum(t, "rate", eq("dept", 5)), 115n);
      assert.equal(await db.sum(t, "rate", eq("dept", 99)), 0n);
      assert.deepEqual(await db.avg(t, "rate", eq("dept", 5)), { num: 115n, den: 3n });
      assert.equal(await db.avg(t, "rate", eq("dept", 99)), null);
      assert.equal(await db.avg(t, "hours", eq("dept", 7)), 120n);
      assert.equal(await db.count(t, eq("dept", 5)), 3);
      assert.equal(await db.scaledSum(t, "rate", 3), 435n);
      assert.equal(await db.scaledSum(t, "hours", -2, eq("dept", 5)), -820n);
      assert.equal(await db.scaledSum(t, "hours", 0), 0n);
      assert.equal(await db.dot(t, "rate", "hours", null, "pyecc"), BigInt(DOT_ALL));
      assert.equal(await db.dot(t, "rate", "hours", eq("dept", 5), "pyecc"), BigInt(DOT_D5));
      assert.equal(await db.dot(t, "rate", "hours", eq("dept", 99)), 0n);

      // update: a fresh ciphertext per row; delete; rollback restores
      assert.equal(await db.update(t, { rate: 60 }, eq("id", 1)), 1);
      assert.equal(await db.sum(t, "rate"), 165n);
      assert.equal(await db.update(t, { rate: -7n, hours: 0 }, eq("dept", 7)), 1);
      assert.deepEqual((await db.select(t, ["rate", "hours"], eq("id", 3)))[0], { rate: -7n, hours: 0n });
      await db.begin();
      await db.update(t, { rate: 1 }, null);
      assert.equal(await db.sum(t, "rate"), 4n);
      await db.rollback();
      assert.equal(await db.sum(t, "rate"), 128n);
      assert.equal(await db.deleteRows(t, eq("id", 4)), 1);
      assert.equal(await db.sum(t, "rate"), 108n);
      await assert.rejects(db.transaction(async () => { await db.insert(t, { id: 9, dept: 1, rate: 2, hours: 3 }); throw new Error("x"); }));
      assert.equal(await db.count(t), 3);
      assert.equal(await db.sum(t, "rate"), 108n);

      // insertMany + a second client holding only the key (no vault, no masks) reads everything
      const t2 = uniq("many");
      await db.createTable(t2, EMP);
      const many = await db.insertMany(t2, Array.from({ length: 30 }, (_, i) => ({ id: i, dept: i % 3, rate: i, hours: -i })));
      assert.equal(many.length, 30);
      const other = await Client.connect(srv.host, srv.port, { fheKey: FheKey.fromHex(SECRET, 100_000), ...OPTS });
      try {
        assert.equal(await other.sum(t2, "rate"), 435n);
        assert.equal(await other.sum(t2, "hours", eq("dept", 1)), -145n);
        assert.deepEqual(await other.avg(t2, "rate"), { num: 29n, den: 2n });
        // untrusted schema: reads work, writes are refused until the caller vouches for the table
        assert.deepEqual((await other.select(t2, ["rate"], eq("id", 7)))[0], { rate: 7n });
        await assert.rejects(other.insert(t2, { id: 99, dept: 0, rate: 1, hours: 1 }), kind("UntrustedSchema"));
        await assert.rejects(other.update(t2, { rate: 1 }, eq("id", 1)), kind("UntrustedSchema"));
        other.trustTable(t2);
        await other.insert(t2, { id: 99, dept: 0, rate: 1, hours: 1 });
        assert.equal(await db.sum(t2, "rate"), 436n);
      } finally { other.close(); }
      // a client with no key can still use the server but not FHE columns
      const nokey = await Client.connect(srv.host, srv.port, OPTS);
      try {
        assert.equal(await nokey.count(t2), 31);
        await assert.rejects(nokey.sum(t2, "rate"), /no FHE key/);
        await assert.rejects(nokey.select(t2, ["rate"]), /no FHE key/);
        nokey.trustTable(t2);
        await assert.rejects(nokey.insert(t2, { id: 1, dept: 1, rate: 1, hours: 1 }), /no FHE key/);
      } finally { nokey.close(); }
      // findOrphans ignores FHE columns (they need no masks)
      assert.deepEqual(await db.findOrphans(), {});
      await db.dropTable(t2);
      await db.dropTable(t);
    } finally { db.close(); if (storage === "disk") await srv.stop(); }
  });
}

T("FHE validation parity: INT only, no predicates/index/join/per-row k*col, range, binary values, mixed DOT", async () => {
  const key = FheKey.fromHex(SECRET, 1000);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    await assert.rejects(db.createTable(uniq("bad"), [{ name: "s", type: "str", policy: "fhe" }]), kind("InterfaceError"));
    await assert.rejects(db.createTable(uniq("bad"), [{ name: "s", type: "rational", policy: "fhe" }]), kind("InterfaceError"));
    const t = uniq("val");
    await db.createTable(t, [...EMP, { name: "p", type: "int", policy: "paired" }, { name: "s", type: "str", policy: "plain" }]);
    const row = { id: 1, dept: 1, rate: 5, hours: 6, p: 7, s: "x" };
    await db.insert(t, row);
    await db.insert(t, { ...row, id: 2, rate: -1000, hours: 1000 });                 // the range limits are inclusive
    // values: integers only, within the key's range
    for (const bad of [null, true, "5", { num: 1n, den: 2n }, 1.5, NaN, new Uint8Array(384), undefined]) {
      await assert.rejects(db.insert(t, { ...row, rate: bad as any }), kind("InterfaceError"), String(bad));
    }
    await assert.rejects(db.insert(t, { ...row, rate: 1001 }), kind("OutOfBudget"));
    await assert.rejects(db.insert(t, { ...row, hours: -1001n }), kind("OutOfBudget"));
    await assert.rejects(db.insert(t, { ...row, s: new Uint8Array(384) as any }), kind("InterfaceError"));  // binary only in FHE cells
    assert.deepEqual(await db.insertMany(t, [{ ...row, id: 3, rate: { num: 4n, den: 2n } }]), [2]);              // 4/2 is the integer 2
    await assert.rejects(db.update(t, { rate: 5000 }, eq("id", 1)), kind("OutOfBudget"));
    assert.equal(await db.count(t), 3);
    assert.equal(await db.sum(t, "rate"), 5n - 1000n + 2n);
    // no WHERE / index / join / per-row scaling on FHE columns
    await assert.rejects(db.count(t, eq("rate", 5)), kind("InterfaceError"));
    await assert.rejects(db.select(t, ["id"], gt("hours", 1)), kind("InterfaceError"));
    await assert.rejects(db.update(t, { id: 1 }, eq("rate", 5)), kind("InterfaceError"));
    await assert.rejects(db.createIndex(t, "rate"), kind("InterfaceError"));
    await assert.rejects(db.scaledSum(t, "p", 2), kind("InterfaceError"));
    await assert.rejects(db.scaledSum(t, "id", 2), kind("InterfaceError"));
    await assert.rejects(db.scaledSum(t, "rate", 2 ** 41), kind("InterfaceError"));
    await assert.rejects(db.scaledSum(t, "rate", 1.5), kind("InterfaceError"));
    await assert.rejects(db.scaledSum(t, "rate", 1000), kind("OutOfBudget"));       // k*sum beyond the range
    const j = await db.join(t, [{ table: t, alias: "b", leftCol: "id", rightCol: "id" }]);
    await assert.rejects(db.joinSum(j, "b", "rate"), kind("InterfaceError"));
    await assert.rejects(db.joinColumn(j, "b", "rate"), kind("InterfaceError"));
    await assert.rejects(db.joinDot(j, t, "rate", "b", "hours"), kind("PlanError"));
    // DOT: two FHE columns only; FHE and PAIRED do not mix; INT; unknown back end
    await assert.rejects(db.dot(t, "rate", "p"), kind("PlanError"));
    await assert.rejects(db.dot(t, "p", "hours"), kind("PlanError"));
    await assert.rejects(db.dot(t, "rate", "id"), kind("PlanError"));
    await assert.rejects(db.dot(t, "rate", "hours", null, "bogus" as any), kind("InterfaceError"));
    await assert.rejects(db.dot(t, "p", "p", null, "pyecc"), kind("InterfaceError"));
    // a key whose range is smaller than a result raises instead of wrapping
    const small = await Client.connect(mem.host, mem.port, { fheKey: FheKey.fromHex(SECRET, 100), ...OPTS });
    try {
      small.trustTable(t);
      await assert.rejects(small.sum(t, "hours"), kind("OutOfBudget"));            // 1006 > 100
      await assert.rejects(small.select(t, ["hours"], eq("id", 2)), kind("OutOfBudget"));
    } finally { small.close(); }
    // the server itself refuses binary values elsewhere, garbage in FHE columns, and over-long lists
    const call = (m: string, a: unknown[]) => rawCall(mem.host, mem.port, m, a);
    assert.match((await call("update_cell", [t, 0, "id", { t: "x", v: b64(Buffer.alloc(384)) }])).err, /not an FHE column/);
    assert.match((await call("update_cell", [t, 0, "rate", { t: "x", v: b64(Buffer.alloc(10)) }])).err, /invalid FHE ciphertext/);
    assert.match((await call("update_cell", [t, 0, "rate", { t: "i", v: "7" }])).err, /FHE/);
    assert.match((await call("fhe_sum", [t, "id", [0]])).err, /not an FHE column/);
    assert.match((await call("fhe_sum", [t, "rate", new Array(5001).fill(0)])).err, /at most/);
  } finally { db.close(); }
});

T("FHE SUM beyond one chunk (2100 rows, 2 fhe_sum calls) and bulk insert", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("big");
    await db.createTable(t, [{ name: "id", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "fhe" }]);
    const n = 2100;
    const ids = await db.insertMany(t, Array.from({ length: n }, (_, i) => ({ id: i, v: (i % 7) - 3 })));
    assert.equal(ids.length, n);
    const expected = Array.from({ length: n }, (_, i) => (i % 7) - 3).reduce((a, b) => a + b, 0);
    assert.equal(await db.sum(t, "v"), BigInt(expected));
    assert.equal(await db.scaledSum(t, "v", 5), BigInt(5 * expected));
    const rows = await db.select(t, ["v"], null, { offset: 2090, limit: 10 });
    assert.deepEqual(rows.map((r) => Number(r.v)), Array.from({ length: 10 }, (_, i) => ((2090 + i) % 7) - 3));
  } finally { db.close(); }
});

T("DOT backends: explicit pyecc, server default, and the native back end when the server has mclbn256", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const db = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("dot");
    await seed(db, t, ROWS.slice(0, 3));
    const want = BigInt(40 * 160 + 55 * 150 + 30 * 120);
    assert.equal(await db.dot(t, "rate", "hours", null, "pyecc"), want);
    if (!native) { console.log("# skipped native DOT (set TORUSDB_MCL_PATH to a dir with mclbn256)"); return; }
    await assert.rejects(db.dot(t, "rate", "hours", null, "mcl"), /unavailable|back end/);   // pure-Python server
  } finally { db.close(); }
  if (!native) return;
  const nd = await Client.connect(native.host, native.port, { fheKey: key, ...OPTS });
  try {
    const t = uniq("dotn");
    await nd.createTable(t, EMP);
    // 120 rows: the default back end (native) in chunks of 50, and the explicit ones
    const rows = Array.from({ length: 120 }, (_, i) => ({ id: i, dept: i % 2, rate: (i % 11) - 5, hours: (i % 13) - 6 }));
    await nd.insertMany(t, rows);
    const want = BigInt(rows.reduce((a, r) => a + r.rate * r.hours, 0));
    assert.equal(await nd.dot(t, "rate", "hours"), want);                            // server default = mcl
    assert.equal(await nd.dot(t, "rate", "hours", null, "mcl"), want);               // chunks of 2000
    assert.equal(await nd.dot(t, "rate", "hours", eq("dept", 0)),
      BigInt(rows.filter((r) => r.dept === 0).reduce((a, r) => a + r.rate * r.hours, 0)));
    assert.equal(await nd.dot(t, "rate", "hours", eq("id", 3), "pyecc"), BigInt(rows[3].rate * rows[3].hours));  // 1 row, pure Python
  } finally { nd.close(); }
});

// ── authenticated mode ───────────────────────────────────────────────────────
for (const storage of ["memory", "disk"]) {
  T(`FHE authenticated, ${storage} storage: tags, verified reads/SUM/AVG/k*SUM, tamper detection, DOT opt-in`, async () => {
    const dir = tmpdir();
    const srv = storage === "disk" ? await startServer(["--db", path.join(dir, "db"), "--storage", "disk"]) : mem;
    const key = FheKey.fromHex(SECRET, 100_000);
    const db = await Client.connect(srv.host, srv.port, { fheKey: key, authenticated: true, ...OPTS });
    try {
      const t = uniq("auth");
      await seed(db, t);
      // tags are stored server-side as one more 384-byte cell per row
      const tags = await rawCall(srv.host, srv.port, "plain_cells", [t, "__fmac__rate", [0, 1, 2, 3]]);
      for (const w of tags.ok) assert.equal(Buffer.from(w.v, "base64").length, 384);
      assert.equal(await db.sum(t, "rate"), 145n);
      assert.equal(await db.sum(t, "rate", eq("dept", 5)), 115n);
      assert.equal(await db.scaledSum(t, "rate", 3), 435n);
      assert.equal(await db.scaledSum(t, "hours", -2, eq("dept", 5)), -820n);
      assert.deepEqual(await db.avg(t, "rate", eq("dept", 5)), { num: 115n, den: 3n });
      assert.deepEqual(await db.select(t, ["id", "rate"], eq("id", 3)), [{ id: 3n, rate: 30n }]);
      assert.equal(await db.update(t, { rate: 60 }, eq("id", 1)), 1);
      assert.equal(await db.sum(t, "rate"), 165n);
      assert.equal(await db.deleteRows(t, eq("id", 4)), 1);
      assert.equal(await db.sum(t, "rate"), 145n);
      // insertMany tags every row too (and a rolled-back insert leaves nothing behind)
      const ids = await db.insertMany(t, [{ id: 10, dept: 1, rate: 1, hours: 2 }, { id: 11, dept: 1, rate: 2, hours: 3 }]);
      assert.equal(await db.sum(t, "rate", eq("dept", 1)), 3n);
      assert.deepEqual((await db.select(t, ["hours"], eq("dept", 1))).map((r) => r.hours), [2n, 3n]);
      assert.equal(ids.length, 2);
      await assert.rejects(db.insert(t, { id: 12, dept: 1, rate: 10_000_000, hours: 1 }), kind("OutOfBudget"));
      assert.equal(await db.count(t), 5);
      // DOT has no integrity protection: refused unless explicitly accepted
      await assert.rejects(db.dot(t, "rate", "hours", eq("id", 2), "pyecc"), /no integrity protection/);
      const lax = await Client.connect(srv.host, srv.port, { fheKey: key, authenticated: true, fheAllowUnverifiedDot: true, ...OPTS });
      try {
        lax.trustTable(t);
        assert.equal(await lax.dot(t, "rate", "hours", eq("id", 2), "pyecc"), BigInt(55 * 150));
      } finally { lax.close(); }

      // ── a lying storage layer: values altered through raw RPCs ──
      const good = (await rawCall(srv.host, srv.port, "plain_cells", [t, "rate", [1]])).ok[0];
      const lie = key.encrypt(999);
      assert.equal((await rawCall(srv.host, srv.port, "update_cell", [t, 1, "rate", { t: "x", v: b64(lie) }])).ok, null);
      await assert.rejects(db.sum(t, "rate"), kind("IntegrityError"));
      await assert.rejects(db.scaledSum(t, "rate", 2), kind("IntegrityError"));
      await assert.rejects(db.avg(t, "rate"), kind("IntegrityError"));
      await assert.rejects(db.select(t, ["rate"], eq("id", 2)), kind("IntegrityError"));
      await rawCall(srv.host, srv.port, "update_cell", [t, 1, "rate", good]);
      assert.equal(await db.sum(t, "rate"), 148n);
      // a row swapped together with its tag
      const cell = async (i: number, c: string) => (await rawCall(srv.host, srv.port, "plain_cells", [t, c, [i]])).ok[0];
      const [r0, m0, r2, m2] = [await cell(0, "rate"), await cell(0, "__fmac__rate"), await cell(2, "rate"), await cell(2, "__fmac__rate")];
      await rawCall(srv.host, srv.port, "update_cell", [t, 0, "rate", r2]);
      await rawCall(srv.host, srv.port, "update_cell", [t, 0, "__fmac__rate", m2]);
      await assert.rejects(db.select(t, ["rate"], eq("id", 1)), kind("IntegrityError"));
      await assert.rejects(db.sum(t, "rate"), kind("IntegrityError"));
      await rawCall(srv.host, srv.port, "update_cell", [t, 0, "rate", r0]);
      await rawCall(srv.host, srv.port, "update_cell", [t, 0, "__fmac__rate", m0]);
      assert.equal(await db.sum(t, "rate"), 148n);
    } finally { db.close(); if (storage === "disk") await srv.stop(); }
  });
}

T("FHE authenticated: untagged data is refused; a lying server (rewritten fhe_sum requests) is caught", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const plainc = await Client.connect(mem.host, mem.port, { fheKey: key, ...OPTS });
  const t = uniq("untag");
  try {
    await seed(plainc, t);
    const auth = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: true, ...OPTS });
    try {
      auth.trustTable(t);
      await assert.rejects(auth.sum(t, "rate"), kind("IntegrityError"));
      await assert.rejects(auth.select(t, ["rate"]), kind("IntegrityError"));
      await assert.rejects(auth.avg(t, "rate"), kind("IntegrityError"));
    } finally { auth.close(); }
  } finally { plainc.close(); }

  // a proxy that rewrites fhe_sum requests: scaled, dropping a row, duplicating a row, wrong column
  const px = await lyingProxy(mem);
  const proxy = px.server, port = px.port;
  const setMode = (m: string) => { px.mode.value = m; };
  try {
    // tagged data written through the real server, read through the proxy
    const t2 = uniq("lie");
    const w = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: true, ...OPTS });
    await seed(w, t2);
    w.close();
    const db = await Client.connect("127.0.0.1", port, { fheKey: key, authenticated: true, ...OPTS });
    try {
      db.trustTable(t2);
      assert.equal(await db.sum(t2, "rate"), 145n);
      assert.equal(await db.scaledSum(t2, "rate", 3), 435n);
      for (const m of ["scale", "drop", "dup", "swapcol"]) {
        setMode(m);
        await assert.rejects(db.sum(t2, "rate"), kind("IntegrityError"), m);
        await assert.rejects(db.scaledSum(t2, "rate", 3), kind("IntegrityError"), m);
        await assert.rejects(db.avg(t2, "rate"), kind("IntegrityError"), m);
      }
      setMode("none");
      assert.equal(await db.sum(t2, "rate"), 145n);
      // WITHOUT authentication the same lies go undetected (the owner decrypts a wrong number)
      const naive = await Client.connect("127.0.0.1", port, { fheKey: key, ...OPTS });
      try {
        naive.trustTable(t2);
        setMode("drop");
        assert.notEqual(await naive.sum(t2, "rate"), 145n);
        setMode("scale");
        assert.equal(await naive.sum(t2, "rate"), 290n);
      } finally { setMode("none"); naive.close(); }
    } finally { db.close(); }
  } finally { proxy.close(); }
});

T("FHE authenticated INSERT is atomic: a dropped connection on the tag write leaves no row", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const px = await lyingProxy(mem);
  const db = await Client.connect("127.0.0.1", px.port, { fheKey: key, authenticated: true, ...OPTS });
  try {
    const t = uniq("atom");
    await db.createTable(t, [{ name: "id", type: "int", policy: "plain" }, { name: "v", type: "int", policy: "fhe" }]);
    await db.insert(t, { id: 1, v: 10 });
    px.mode.value = "killtag";                                            // the connection dies when the tag is written
    await assert.rejects(db.insert(t, { id: 2, v: 20 }), (e: any) => e instanceof TorusError && e.kind === "ConnectionError");
    assert.equal(db.inTransaction, false);
    px.mode.value = "none";
    await db.reconnect();
    assert.equal((await db.tableInfo(t)).rows, 1);                        // rolled back with the dead session
    assert.equal(await db.sum(t, "v"), 10n);
    await db.insert(t, { id: 3, v: 30 });
    assert.equal(await db.sum(t, "v"), 40n);
  } finally { db.close(); px.server.close(); }
});

// ── cross-implementation: TypeScript <-> the Python reference ────────────────
T("cross-implementation: cells written by TypeScript are read by Python, and vice versa (plain and authenticated)", async () => {
  for (const auth of [false, true]) {
    const key = FheKey.fromHex(SECRET, 100_000);
    const db = await Client.connect(mem.host, mem.port, { fheKey: key, authenticated: auth, fheAllowUnverifiedDot: true, ...OPTS });
    try {
      const t = uniq(auth ? "xauth" : "xplain");
      await seed(db, t);                                                        // TypeScript writes
      const res = runPeer(mem.host, mem.port, {
        key: SECRET, range: 100_000, auth, dot_unverified: true, ops: [
          ["query", `SELECT id, rate, hours FROM ${t} WHERE id = 2`],
          ["query", `SELECT SUM(rate), AVG(rate), COUNT(*) FROM ${t} WHERE dept = 5`],
          ["query", `SELECT 3 * SUM(rate), -2 * SUM(hours) FROM ${t}`],
          ["query", `SELECT DOT(rate, hours) FROM ${t} WHERE dept = 5`],
          ["indep", t, "rate"],
          // Python writes, TypeScript reads below
          ["exec", `INSERT INTO ${t} (id, dept, rate, hours) VALUES (5, 5, -9, 11)`],
          ["exec", `UPDATE ${t} SET rate = 77 WHERE id = 3`],
        ],
      });
      assert.deepEqual(res[0], [[2, 55, 150]]);
      assert.deepEqual(res[1], [[115, "115/3", 3]]);
      assert.deepEqual(res[2], [[435, -1060]]);
      assert.deepEqual(res[3], [[DOT_D5]]);
      assert.deepEqual(res[4], new Array(4).fill(true));                      // r1 != r2 in every cell we wrote
      assert.deepEqual((await db.select(t, ["id", "rate", "hours"], eq("id", 5)))[0], { id: 5n, rate: -9n, hours: 11n });
      assert.equal(await db.sum(t, "rate"), BigInt(40 + 55 + 77 + 20 - 9));
      assert.equal(await db.scaledSum(t, "hours", 2), BigInt(2 * (160 + 150 + 120 + 100 + 11)));
      assert.equal(await db.dot(t, "rate", "hours", eq("id", 5), "pyecc"), -99n);
    } finally { db.close(); }
  }
});

T("cross-implementation: sealed key files interoperate with Python's save_key / load_key", async () => {
  const dir = tmpdir();
  const pyFile = path.join(dir, "py.key"), pyPlain = path.join(dir, "pyplain.key"), tsFile = path.join(dir, "ts.key");
  runPeer(mem.host, mem.port, { key: SECRET, range: 4321, ops: [["keyfile", pyFile, "pässwörd"], ["keyfile", pyPlain, null]] });
  const k = FheKey.load(pyFile, "pässwörd");
  assert.equal(k.range, 4321);
  assert.equal(k.secretBytes().toString("hex"), SECRET);
  assert.equal(FheKey.load(pyPlain).range, 4321);
  FheKey.fromHex(SECRET, 777).save(tsFile, "hunter2");
  const out = runPeer(mem.host, mem.port, { key: SECRET, ops: [["loadkey", tsFile, "hunter2"]] });
  assert.deepEqual(out, [[SECRET, 777]]);
});

// ── batched cell writes (update_cells) and server-published limits ───────────
T("authenticated FHE writes use ONE update_cells call per batch; update_cells is atomic", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const px = await lyingProxy(mem);
  const db = await Client.connect("127.0.0.1", px.port, { fheKey: key, authenticated: true, ...OPTS });
  try {
    const t = uniq("batch");
    await seed(db, t, ROWS);
    assert.equal(px.seen.filter((m) => m === "update_cell").length, 0);
    assert.equal(px.seen.filter((m) => m === "update_cells").length, 4);          // one per single-row INSERT
    let before = px.seen.length;
    await db.insertMany(t, Array.from({ length: 6 }, (_, i) => ({ id: 10 + i, dept: 1, rate: i, hours: i })));
    let calls = px.seen.slice(before);
    assert.equal(calls.filter((m) => m === "update_cells").length, 1);            // 6 rows x 2 tags = 12 cells, one RPC
    assert.equal(calls.includes("update_cell"), false);
    before = px.seen.length;
    assert.equal(await db.update(t, { rate: 7 }, eq("dept", 1)), 6);
    calls = px.seen.slice(before);
    assert.equal(calls.filter((m) => m === "update_cells").length, 1);            // 6 rows x (value + tag)
    assert.equal(calls.includes("update_cell"), false);
    assert.equal(await db.sum(t, "rate", eq("dept", 1)), 42n);                    // all tags verify
    // atomicity on the server: the second item is invalid, so the first is rolled back too
    const c1 = (await rawCall(mem.host, mem.port, "plain_cells", [t, "rate", [0]])).ok[0];
    const r = await rawCall(mem.host, mem.port, "update_cells", [t, [[0, "rate", { t: "x", v: b64(key.encrypt(999)) }], [1, "rate", { t: "x", v: b64(Buffer.alloc(5)) }]]]);
    assert.match(r.err, /FHE|ciphertext/);
    assert.deepEqual((await rawCall(mem.host, mem.port, "plain_cells", [t, "rate", [0]])).ok[0], c1);
    const ok = await rawCall(mem.host, mem.port, "update_cells", [t, [[0, "rate", c1]]]);
    assert.equal(ok.ok, 1);
  } finally { db.close(); px.server.close(); }
});

import { fake, HELLO } from "./fake";

const FAKE_SCHEMA = [["id", "int", "plain"], ["v", "int", "fhe"]];
function fheFake(hello: any, extra: (m: string, a: any[]) => any = () => undefined) {
  const key = FheKey.fromHex(SECRET, 100_000);
  const one = key.encrypt(1);
  return fake((m, a) => {
    const x = extra(m, a);
    if (x !== undefined) return x;
    switch (m) {
      case "hello": return hello;
      case "tables": return { ok: ["t"] };
      case "schema": return { ok: FAKE_SCHEMA };
      case "matching_rowids": return { ok: Array.from({ length: 20 }, (_, i) => i) };
      case "fhe_sum": return { ok: sumCells((a[2] as number[]).map(() => one)).toString("base64") };
      case "fhe_dot": { const d = Buffer.from(VEC.dot_blob_pyecc, "hex"); if (a[6] === "mcl") d[0] = 2; return { ok: d.toString("base64") }; }
      case "update_cells": return { ok: (a[1] as unknown[]).length };
      case "insert_many": return { ok: (a[1] as unknown[]).map((_, i) => i) };
      case "insert": return { ok: 0 };
      case "tx_begin": case "tx_commit": return { ok: null };
      default: return { ok: null };
    }
  });
}
const helloWith = (limits?: unknown) => ({ ok: { ...HELLO.ok, ...(limits ? { limits } : {}) } });
const LIMITS = { max_items: 3, fhe: { max_sum_rows: 7, max_dot_rows: { pyecc: 5, mcl: 6 },
  recommended_dot_rows: { pyecc: 3, mcl: 4 }, backends: ["pyecc"], default_backend: "auto" } };

test("hello.limits shrinks fhe_sum / fhe_dot / update_cells chunks; without limits the defaults apply", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  for (const withLimits of [true, false]) {
    const f = await fheFake(helloWith(withLimits ? LIMITS : undefined));
    const plain = await Client.connect("127.0.0.1", f.port, { fheKey: key });
    const db = await Client.connect("127.0.0.1", f.port, { fheKey: key, authenticated: true });
    try {
      plain.trustTable("t"); db.trustTable("t");
      const count = (m: string) => f.seen.filter((x) => x === m).length;
      assert.equal(await plain.sum("t", "v"), 20n);
      assert.equal(count("fhe_sum"), withLimits ? 3 : 1);                           // 20 ids in chunks of 7 | one call
      assert.equal(await plain.dot("t", "v", "v"), BigInt(844 * (withLimits ? 7 : 1)));   // default back end: pyecc sizing (3 | 50)
      let sizes = f.bodies.filter((b) => b.includes('"fhe_dot"')).map((b) => JSON.parse(b).a[2].length);
      assert.deepEqual(sizes, withLimits ? [3, 3, 3, 3, 3, 3, 2] : [20]);
      await plain.dot("t", "v", "v", null, "mcl").catch(() => undefined);           // mcl: recommended 4 (cap 6)
      sizes = f.bodies.filter((b) => b.includes('"fhe_dot"') && b.includes('"mcl"')).map((b) => JSON.parse(b).a[2].length);
      assert.deepEqual(sizes, withLimits ? [4, 4, 4, 4, 4] : [20]);
      // update_cells batches follow max_items (3) when published, else 2000
      await db.insertMany("t", Array.from({ length: 4 }, (_, i) => ({ id: i, v: i })));
      sizes = f.bodies.filter((b) => b.includes('"update_cells"')).map((b) => JSON.parse(b).a[1].length);
      assert.deepEqual(sizes, withLimits ? [3, 1] : [4]);
    } finally { plain.close(); db.close(); f.close(); }
  }
});

test("an old server without update_cells: fall back to update_cell once, remember it", async () => {
  const key = FheKey.fromHex(SECRET, 100_000);
  const f = await fheFake(helloWith(), (m) => m === "update_cells" ? { err: "BadRequest: unknown method 'update_cells'" } : undefined);
  const db = await Client.connect("127.0.0.1", f.port, { fheKey: key, authenticated: true });
  try {
    db.trustTable("t");
    await db.insert("t", { id: 1, v: 5 });
    await db.insert("t", { id: 2, v: 6 });
    await db.insertMany("t", [{ id: 3, v: 1 }, { id: 4, v: 2 }]);
    assert.equal(f.seen.filter((m) => m === "update_cells").length, 1);            // asked once only
    assert.equal(f.seen.filter((m) => m === "update_cell").length, 4);             // 1 + 1 + 2 tags by repetition
  } finally { db.close(); f.close(); }
});
