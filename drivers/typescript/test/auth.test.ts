// SPDX-License-Identifier: Apache-2.0
// Authentication and roles against a REAL server started with --token-file.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { Client, TorusError, eq } from "../src/torusdb";
import { skipReason, startServer, RunningServer, uniq, tmpdir, ADMIN, RO, RW } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => {
  if (skip) return;
  const f = path.join(tmpdir(), "tokens");
  fs.writeFileSync(f, `admin:${ADMIN}\nrw:${RW}\nro:${RO}\n`, { mode: 0o600 });
  srv = await startServer(["--token-file", f]);
});
after(async () => { if (!skip) await srv?.stop(); });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);
const COLS = [{ name: "k", type: "int" as const, policy: "plain" as const },
              { name: "v", type: "int" as const, policy: "encrypted" as const }];
const kindOf = (k: string) => (e: any) => e instanceof TorusError && e.kind === k;

T("missing token fails with a clear error (no server round trip needed)", async () => {
  await assert.rejects(Client.connect(srv.host, srv.port), (e: any) =>
    e.kind === "Unauthenticated" && /requires a token/.test(e.message));
});

T("wrong token is rejected and the token is never echoed in the error", async () => {
  const bad = "wrong-token-0123456789xyz";
  const e: any = await Client.connect(srv.host, srv.port, { token: bad }).catch((x) => x);
  assert.ok(e instanceof TorusError);
  assert.equal(e.kind, "Unauthenticated");
  assert.ok(!String(e.message).includes(bad));
  assert.ok(!String(e.stack).includes(bad));
});

T("raw unauthenticated RPC is refused (server-side check)", async () => {
  const net = await import("net");
  const sock = net.createConnection({ host: srv.host, port: srv.port });
  await new Promise((r) => sock.once("connect", r));
  const body = Buffer.from(JSON.stringify({ m: "tables", a: [] }));
  const hdr = Buffer.alloc(4); hdr.writeUInt32BE(body.length);
  sock.write(Buffer.concat([hdr, body]));
  let reply = Buffer.alloc(0);                       // read one complete frame
  await new Promise<void>((resolve) => {
    sock.on("data", (d: Buffer) => {
      reply = Buffer.concat([reply, d]);
      if (reply.length >= 4 && reply.length >= 4 + reply.readUInt32BE(0)) resolve();
    });
  });
  assert.match(reply.subarray(4).toString(), /Unauthenticated/);
  sock.destroy();
});

T("rw token can read and write; hello reports auth_required", async () => {
  const db = await Client.connect(srv.host, srv.port, { token: RW });
  try {
    assert.equal(db.serverInfo.auth_required, true);
    const t = uniq("auth");
    await db.createTable(t, COLS);
    await db.insert(t, { k: 1, v: 10 });
    await db.insert(t, { k: 2, v: 20 });
    assert.equal(await db.sum(t, "v"), 30n);
  } finally { db.close(); }
});

T("ro role can read blinded data but cannot write", async () => {
  const w = await Client.connect(srv.host, srv.port, { token: RW });
  const t = uniq("auth_ro");
  await w.createTable(t, COLS);
  await w.insert(t, { k: 1, v: 10 });
  const r = await Client.connect(srv.host, srv.port, { token: RO });
  try {
    assert.equal(await r.count(t), 1);
    await assert.rejects(r.insert(t, { k: 2, v: 5 }), kindOf("Forbidden"));
    await assert.rejects(r.deleteRows(t, eq("k", 1)), kindOf("Forbidden"));
    await assert.rejects(r.createTable(uniq("nope"), COLS), kindOf("Forbidden"));
    await assert.rejects(r.begin(), kindOf("Forbidden"));
    assert.equal(r.inTransaction, false);
    assert.equal(r.maskCount, 0);               // nothing leaked into the vault
    assert.equal(await w.count(t), 1);
  } finally { r.close(); w.close(); }
});

T("only admin may call stats / checkpoint / backup / drop", async () => {
  const w = await Client.connect(srv.host, srv.port, { token: RW });
  try {
    await assert.rejects(w.stats(), kindOf("Forbidden"));
    await assert.rejects(w.checkpoint(), kindOf("Forbidden"));
    await assert.rejects(w.backup(), kindOf("Forbidden"));
    const t = uniq("auth_drop");
    await w.createTable(t, COLS);
    await assert.rejects(w.dropTable(t), kindOf("Forbidden"));
    assert.ok((await w.tables()).includes(t));       // schema untouched on failure
  } finally { w.close(); }
  const a = await Client.connect(srv.host, srv.port, { token: ADMIN });
  try {
    const st = await a.stats();
    assert.ok(st && typeof st === "object");
    assert.equal(await a.ping(), true);
    const t = uniq("auth_drop2");
    await a.createTable(t, COLS);
    await a.dropTable(t);
    assert.ok(!(await a.tables()).includes(t));
  } finally { a.close(); }
});
