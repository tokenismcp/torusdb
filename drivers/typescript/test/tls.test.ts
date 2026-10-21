// SPDX-License-Identifier: Apache-2.0
// TLS against a REAL server: verified by default, explicit opt-out only.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { Client, TorusError } from "../src/torusdb";
import { skipReason, startServer, RunningServer, tmpdir } from "./helpers";

let skip = skipReason();
let srv: RunningServer;
let dir = "";
let cert = "";
before(async () => {
  if (skip) return;
  dir = tmpdir();
  cert = path.join(dir, "c.pem");
  const key = path.join(dir, "k.pem");
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { timeout: 30000 });
  if (r.status !== 0) { skip = "openssl could not generate a certificate"; return; }
  srv = await startServer(["--tls", "--cert", cert, "--key", key]);
});
after(async () => { if (srv) await srv.stop(); });
const T = (name: string, fn: () => Promise<void>) => test(name, async (t) => { if (skip) return t.skip(skip); await fn(); });

T("self-signed server is REJECTED by default", async () => {
  const e: any = await Client.connect("localhost", srv.port, { tls: true }).catch((x) => x);
  assert.ok(e instanceof TorusError);
  assert.equal(e.kind, "ConnectionError");
  assert.match(e.message, /self.signed|unable to verify|certificate/i);
});

T("trusting the CA via `ca` works (hostname verified)", async () => {
  const db = await Client.connect("localhost", srv.port, { tls: true, ca: fs.readFileSync(cert) });
  assert.equal(await db.ping(), true);
  db.close();
  const ip = await Client.connect("127.0.0.1", srv.port, { tls: true, ca: fs.readFileSync(cert) });
  assert.equal(await ip.ping(), true);
  ip.close();
});

T("hostname mismatch is rejected even with the right CA", async () => {
  // the cert is only valid for localhost/127.0.0.1; ::1 is not on it
  const e: any = await Client.connect("127.0.0.2", srv.port, { tls: true, ca: fs.readFileSync(cert), timeoutMs: 3000 }).catch((x) => x);
  assert.ok(e instanceof TorusError);
});

T("tlsInsecure must be explicit and then works", async () => {
  const db = await Client.connect("localhost", srv.port, { tls: true, tlsInsecure: true });
  assert.equal(await db.ping(), true);
  db.close();
});

T("plain TCP to a TLS server fails cleanly (no hang)", async () => {
  const e: any = await Client.connect(srv.host, srv.port, { timeoutMs: 1500 }).catch((x) => x);
  assert.ok(e instanceof TorusError);
});
