// SPDX-License-Identifier: Apache-2.0
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { Client } from "../src/torusdb";
import { skipReason, startServer, RunningServer, uniq, tmpdir } from "./helpers";

const skip = skipReason();
let srv: RunningServer;
before(async () => { if (!skip) srv = await startServer(); });
after(async () => { if (!skip) await srv?.stop(); });
const T = (name: string, fn: () => Promise<void>) => test(name, { skip }, fn);
const COLS = [{ name: "k", type: "int" as const, policy: "plain" as const },
              { name: "v", type: "rational" as const, policy: "encrypted" as const }];

T("saveVault is 0600, atomic (no temp files left) and loadVault restores decryption", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "vault.json");
  const a = await Client.connect(srv.host, srv.port);
  const t = uniq("vault");
  await a.createTable(t, COLS);
  await a.insert(t, { k: 1, v: { num: 1n, den: 3n } });
  await a.insert(t, { k: 2, v: { num: 2n, den: 3n } });
  a.saveVault(file);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(dir), ["vault.json"]);
  a.saveVault(file);                                   // overwrite stays 0600
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  a.close();

  // a new process-equivalent: no vault -> cannot decrypt; with vault -> can
  const noVault = await Client.connect(srv.host, srv.port);
  await assert.rejects(noVault.sum(t, "v"), /no mask/);
  noVault.close();
  const b = await Client.connect(srv.host, srv.port, { vaultPath: file });
  try {
    assert.equal(await b.sum(t, "v"), 1n);
    // new inserts through the restored vault keep working and persist again
    await b.insert(t, { k: 3, v: 5 });
    b.saveVault();
  } finally { b.close(); }
});
