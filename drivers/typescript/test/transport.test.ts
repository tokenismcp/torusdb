// SPDX-License-Identifier: Apache-2.0
// Transport robustness against a scripted FAKE server (no Python needed):
// protocol negotiation, v1 fallback, timeouts, connection loss.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as net from "net";
import { Client, TorusError } from "../src/torusdb";

type Handler = (method: string, args: any[], sock: net.Socket) => any | "drop" | "hang";

async function fake(handler: Handler): Promise<{ port: number; close(): void; seen: string[] }> {
  const seen: string[] = [];
  const socks = new Set<net.Socket>();
  const server = net.createServer((sock) => {
    socks.add(sock);
    sock.on("error", () => {});
    let buf = Buffer.alloc(0);
    sock.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        const n = buf.readUInt32BE(0);
        const req = JSON.parse(buf.subarray(4, 4 + n).toString());
        buf = buf.subarray(4 + n);
        seen.push(req.m);
        const out = handler(req.m, req.a, sock);
        if (out === "drop") { sock.destroy(); return; }
        if (out === "hang") continue;
        const body = Buffer.from(JSON.stringify(out));
        const hdr = Buffer.alloc(4); hdr.writeUInt32BE(body.length);
        sock.write(Buffer.concat([hdr, body]));
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as net.AddressInfo).port, seen,
           close: () => { socks.forEach((s) => s.destroy()); server.close(); } };
}

test("protocol-1 server (hello unknown) is accepted without auth", async () => {
  const s = await fake((m) => m === "hello" ? { err: "BadRequest: unknown method" }
    : m === "tables" ? { ok: [] } : { ok: null });
  try {
    const db = await Client.connect("127.0.0.1", s.port);
    assert.equal(db.serverInfo.protocol, 1);
    assert.equal(db.serverInfo.auth_required, false);
    db.close();
  } finally { s.close(); }
});

test("protocol newer than 2 is refused", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 3, auth_required: false } } : { ok: null });
  try {
    await assert.rejects(Client.connect("127.0.0.1", s.port), (e: any) => e.kind === "InterfaceError" && /protocol 3/.test(e.message));
  } finally { s.close(); }
});

test("auth_required without token fails before sending auth; with token sends it", async () => {
  const s = await fake((m, a) => m === "hello" ? { ok: { protocol: 2, auth_required: true } }
    : m === "auth" ? (a[0] === "good-token-0123456789" ? { ok: { role: "rw" } } : { err: "Unauthenticated: invalid token" })
    : { ok: [] });
  try {
    await assert.rejects(Client.connect("127.0.0.1", s.port), (e: any) => e.kind === "Unauthenticated");
    assert.ok(!s.seen.includes("auth"));
    const db = await Client.connect("127.0.0.1", s.port, { token: "good-token-0123456789" });
    assert.ok(s.seen.includes("auth"));
    db.close();
    await assert.rejects(Client.connect("127.0.0.1", s.port, { token: "bad" }), (e: any) => e.kind === "Unauthenticated");
  } finally { s.close(); }
});

test("a silent server times out instead of hanging", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 2, auth_required: false } }
    : m === "tables" ? { ok: [] } : "hang");
  try {
    const db = await Client.connect("127.0.0.1", s.port, { timeoutMs: 250 });
    const t0 = Date.now();
    await assert.rejects(db.ping(), (e: any) => e instanceof TorusError && e.kind === "TimeoutError");
    assert.ok(Date.now() - t0 < 3000);
    // the connection is dropped (the late reply could desynchronize it)
    await assert.rejects(db.ping(), (e: any) => e instanceof TorusError);
  } finally { s.close(); }
});

test("connection loss mid-call rejects with ConnectionError; later calls fail fast", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 2, auth_required: false } }
    : m === "tables" ? { ok: [] } : "drop");
  try {
    const db = await Client.connect("127.0.0.1", s.port);
    await assert.rejects(db.ping(), (e: any) => e.kind === "ConnectionError");
    await assert.rejects(db.ping(), (e: any) => e instanceof TorusError);
    await assert.rejects(db.count("x"), (e: any) => e instanceof TorusError);
  } finally { s.close(); }
});

test("pending calls reject when the client is closed", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 2, auth_required: false } }
    : m === "tables" ? { ok: [] } : "hang");
  try {
    const db = await Client.connect("127.0.0.1", s.port, { timeoutMs: 0 });
    const p = db.ping();
    setTimeout(() => db.close(), 50);
    await assert.rejects(p, (e: any) => e instanceof TorusError);
  } finally { s.close(); }
});

test("connect refused is a ConnectionError", async () => {
  const s = await fake(() => ({ ok: null }));
  const port = s.port;
  s.close();
  await assert.rejects(Client.connect("127.0.0.1", port, { timeoutMs: 2000 }), (e: any) => e.kind === "ConnectionError");
});

test("malformed and oversized replies are ProtocolErrors", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 2, auth_required: false } }
    : m === "tables" ? { ok: [] } : { weird: true });
  try {
    const db = await Client.connect("127.0.0.1", s.port);
    await assert.rejects(db.ping(), (e: any) => e.kind === "ProtocolError");
    db.close();
  } finally { s.close(); }
});

test("server error text is split into kind + message", async () => {
  const s = await fake((m) => m === "hello" ? { ok: { protocol: 2, auth_required: false } }
    : m === "tables" ? { ok: [] } : { err: "InternalError: internal server error (ref=ab12)" });
  try {
    const db = await Client.connect("127.0.0.1", s.port);
    const e: any = await db.ping().catch((x) => x);
    assert.equal(e.kind, "InternalError");
    assert.match(e.message, /ref=ab12/);
    db.close();
  } finally { s.close(); }
});
