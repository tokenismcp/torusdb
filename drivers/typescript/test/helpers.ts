// SPDX-License-Identifier: Apache-2.0
// Test helpers: start a REAL keyless TorusDB server (Python) as a subprocess.
import { spawn, spawnSync, ChildProcess } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Column } from "../src/torusdb";

// compiled to <root>/drivers/typescript/build-test/test -> repo root is 4 up
const REPO = path.resolve(__dirname, "../../../..");
export const SERVER_PY = path.join(REPO, "server/nokey_server.py");
export const VECTORS = path.resolve(__dirname, "../../../vectors.json");

export const ADMIN = "admin-token-0123456789";
export const RO = "ro-token-0123456789abc";
export const RW = "rw-token-0123456789abc";

export function findPython(): string | null {
  const cands = [process.env.TORUSDB_PYTHON, path.join(REPO, ".venv/bin/python"),
                 path.join(REPO, "../.venv/bin/python")];   // monorepo dev layout
  if (!process.env.TORUSDB_PYTHON) cands.push("python3");
  for (const c of cands) {
    if (!c) continue;
    if (c.includes(path.sep) && !fs.existsSync(c)) continue;
    const r = spawnSync(c, ["-c", "import sys; sys.exit(0)"], { timeout: 10000 });
    if (r.status === 0) return c;
  }
  return null;
}

/** Why integration tests are skipped (undefined = they run). */
export function skipReason(): string | undefined {
  const why = skipReasonInner();
  // In CI (TORUSDB_REQUIRE_INTEGRATION=1) a missing server is a FAILURE,
  // never a silent skip.
  if (why && process.env.TORUSDB_REQUIRE_INTEGRATION) {
    throw new Error(`integration tests are required but cannot run: ${why}`);
  }
  return why;
}

function skipReasonInner(): string | undefined {
  if (!fs.existsSync(SERVER_PY)) return `server not found at ${SERVER_PY}`;
  const py = findPython();
  if (!py) return "no usable Python interpreter (set TORUSDB_PYTHON)";
  // make sure the interpreter can actually import the server's deps
  const r = spawnSync(py, [SERVER_PY, "--help"], { timeout: 20000 });
  if (r.status !== 0) return `server did not start with ${py}: ${String(r.stderr).slice(0, 200)}`;
  return undefined;
}

export interface RunningServer {
  host: string;
  port: number;
  stop(): Promise<void>;
}

export function startServer(extra: string[] = []): Promise<RunningServer> {
  const py = findPython()!;
  return new Promise((resolve, reject) => {
    const child: ChildProcess = spawn(py, [SERVER_PY, "--host", "127.0.0.1", "--port", "0", "--log-level", "WARNING", ...extra],
      { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONUNBUFFERED: "1" } });
    let out = "", err = "";
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; child.kill("SIGKILL"); reject(new Error("server start timeout\n" + out + err)); } }, 30000);
    child.stderr!.on("data", (d) => { err += d; });
    child.stdout!.on("data", (d) => {
      out += d;
      const m = /on ([\d.]+):(\d+)/.exec(out.split("\n")[0]);
      if (m && !done) {
        done = true;
        clearTimeout(timer);
        resolve({
          host: m[1], port: Number(m[2]),
          stop: () => new Promise<void>((res) => {
            if (child.exitCode !== null) return res();
            child.once("exit", () => res());
            child.kill("SIGTERM");
            setTimeout(() => child.kill("SIGKILL"), 5000).unref();
          }),
        });
      }
    });
    child.on("exit", (code) => { if (!done) { done = true; clearTimeout(timer); reject(new Error(`server exited early (${code})\n${err}`)); } });
  });
}

export function tmpdir(prefix = "torusdb-ts-"): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

let seq = 0;
export function uniq(base: string): string { return `${base}_${process.pid}_${++seq}`; }

export const EMP_COLS: Column[] = [
  { name: "id", type: "int", policy: "plain" },
  { name: "dept", type: "int", policy: "plain" },
  { name: "salary", type: "rational", policy: "encrypted" },
  { name: "rate", type: "int", policy: "paired" },
  { name: "hours", type: "int", policy: "paired" },
];
