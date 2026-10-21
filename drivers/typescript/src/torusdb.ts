// SPDX-License-Identifier: Apache-2.0
// TorusDB no-key driver for TypeScript / Node (protocol v2).
//
// Talks the no-key delegation protocol to a keyless TorusDB server: the server
// holds no keys and only blinded scalars; this driver (the data owner) holds
// the mask vault, blinds on insert, and unblinds + decodes results. Confidence
// at the server is a one-time pad (I(M;V_S)=0).
//
// Language drivers expose a programmatic API (not raw SQL parsing - that
// lives in the Python `torussql-parser`). The wire protocol and field
// arithmetic are identical across drivers; see ../vectors.json for the
// cross-language conformance vectors this implementation is checked against.

import * as net from "net";
import * as tls from "tls";
import * as fs from "fs";
import * as path from "path";
import { randomBytes } from "crypto";

/** Newest wire protocol this driver speaks. */
export const PROTOCOL_VERSION = 2;

// BN254 group order - the field modulus for the no-key scalar ring Z/nZ.
export const N =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Same decode budget as the Python reference (ecfhe.nokey): |num|*den < N/2^64.
const MARGIN_BITS = 64n;
const RANGE = N >> MARGIN_BITS;

// ── errors ──────────────────────────────────────────────────────────────────
/**
 * Every failure surfaces as a TorusError. `kind` is the server's error class
 * (the text before the first ": " - e.g. "Unauthenticated", "Forbidden",
 * "Busy", "BadRequest", "InternalError", "PlanError") or one of the local
 * kinds: "ConnectionError" (cannot connect / connection lost / TLS failure),
 * "TimeoutError", "ProtocolError" (malformed or unsupported peer),
 * "InterfaceError" (client closed / misuse), "OutOfBudget" (value or
 * aggregate outside the exactly representable range).
 */
export class TorusError extends Error {
  readonly kind: string;
  constructor(kind: string, message: string) {
    super(message);
    this.name = "TorusError";
    this.kind = kind;
    Object.setPrototypeOf(this, TorusError.prototype);
  }
}

function serverError(text: string): TorusError {
  const m = /^([A-Za-z][A-Za-z0-9_]*): ([\s\S]*)$/.exec(text);
  return m ? new TorusError(m[1], m[2]) : new TorusError("ServerError", text);
}

// ── field arithmetic (BigInt, exact) ────────────────────────────────────────
function mod(a: bigint, m: bigint = N): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modInv(a: bigint, m: bigint = N): bigint {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new TorusError("ValueError", "not invertible");
  return mod(oldS, m);
}

function randScalar(): bigint {
  // 32 uniform bytes reduced mod N (negligible bias at 254 bits)
  return mod(BigInt("0x" + randomBytes(32).toString("hex")));
}

// ── encode / decode (Z/nZ <-> int / rational) ───────────────────────────────
export type Rational = { num: bigint; den: bigint };
export type Decoded = bigint | Rational;

function abs(a: bigint): bigint {
  return a < 0n ? -a : a;
}

export function encodeInt(v: bigint): bigint {
  if (abs(v) > BOUND) {
    throw new TorusError("OutOfBudget",
      `integer of ${abs(v).toString(2).length} bits exceeds the encodable range (|v| <= ~2^126)`);
  }
  return mod(v);
}
export function encodeRational(num: bigint, den: bigint): bigint {
  if (den === 0n) throw new TorusError("ValueError", "zero denominator");
  if (den < 0n) { num = -num; den = -den; }
  if (abs(num) > BOUND || den > BOUND || abs(num) * den >= RANGE) {
    throw new TorusError("OutOfBudget",
      `fraction ${num}/${den} exceeds the encodable range`);
  }
  return mod(mod(num) * modInv(mod(den)));
}

function isqrt(n: bigint): bigint {
  if (n < 0n) throw new Error("isqrt of negative");
  if (n < 2n) return n;
  let x = n, y = (x + 1n) / 2n;
  while (y < x) { x = y; y = (x + n / x) / 2n; }
  return x;
}

const BOUND = isqrt(N / 2n);

/** Reduce num/den to lowest terms; returns a bigint when the denominator is 1. */
export function rational(num: bigint, den: bigint): Decoded {
  if (den === 0n) throw new TorusError("ValueError", "zero denominator");
  if (den < 0n) { num = -num; den = -den; }
  let a = abs(num), b = den;
  while (b !== 0n) [a, b] = [b, a % b];
  if (a > 1n) { num /= a; den /= a; }
  return den === 1n ? num : { num, den };
}

// Wang rational reconstruction: recover a/b with |a|,b <= BOUND, a = s*b (mod N).
// Strict (like the Python reference): throws OutOfBudget when the result is not
// comfortably inside the uniqueness range, instead of returning a wrong number.
export function decode(s: bigint): Decoded {
  s = mod(s);
  let [r0, r1] = [N, s];
  let [t0, t1] = [0n, 1n];
  while (r1 > BOUND) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  let a = r1, b = t1;
  if (b < 0n) { a = -a; b = -b; }
  if (b === 0n) {
    throw new TorusError("OutOfBudget", "rational reconstruction failed (out of budget)");
  }
  if (abs(a) * b >= RANGE) {
    throw new TorusError("OutOfBudget",
      "decoded value is outside the exactly-representable range - an aggregate " +
      "probably overflowed; the result cannot be trusted");
  }
  return rational(a, b);
}

function isRational(v: unknown): v is Rational {
  return typeof v === "object" && v !== null &&
    typeof (v as Rational).num === "bigint" && typeof (v as Rational).den === "bigint";
}

// ── wire value codec (mirrors proto/nokey_wire.py) ──────────────────────────
type WireVal =
  | { t: "n" } | { t: "b"; v: boolean } | { t: "i"; v: string }
  | { t: "s"; v: string } | { t: "f"; n: string; d: string };

/** A user-facing cell value. */
export type Value = null | boolean | bigint | number | string | Rational;

function wv(v: Value | undefined): WireVal {
  if (v === null || v === undefined) return { t: "n" };
  if (typeof v === "boolean") return { t: "b", v };
  if (typeof v === "bigint") return { t: "i", v: v.toString() };
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) {
      throw new TorusError("InterfaceError",
        `number ${v} is not a safe integer; pass a bigint or a {num,den} rational`);
    }
    return { t: "i", v: BigInt(v).toString() };
  }
  if (typeof v === "string") return { t: "s", v };
  if (isRational(v)) {
    const r = rational(v.num, v.den);
    return typeof r === "bigint"
      ? { t: "f", n: r.toString(), d: "1" }
      : { t: "f", n: r.num.toString(), d: r.den.toString() };
  }
  throw new TorusError("InterfaceError", "cannot wire-encode " + typeof v);
}

function uwv(d: WireVal): Value {
  switch (d?.t) {
    case "n": return null;
    case "b": return d.v;
    case "i": return BigInt(d.v);
    case "s": return d.v;
    case "f": return rational(BigInt(d.n), BigInt(d.d));
  }
  throw new TorusError("ProtocolError", "bad wire tag " + (d as any)?.t);
}

function toBig(x: unknown): bigint {
  try {
    return BigInt(x as any);
  } catch {
    throw new TorusError("ProtocolError", "expected an integer from the server");
  }
}

// ── column spec ──────────────────────────────────────────────────────────────
export type Policy = "plain" | "encrypted" | "paired";
export type ColType = "int" | "str" | "rational";
export interface Column { name: string; type: ColType; policy: Policy; }

// ── connection options ──────────────────────────────────────────────────────
export interface ConnectOptions {
  /** API token; required when the server runs with --token-file. Never logged. */
  token?: string;
  /** Socket timeout per request in ms (default 30000; 0 disables). */
  timeoutMs?: number;
  /** Wrap the connection in TLS. The certificate AND hostname are verified. */
  tls?: boolean;
  /** PEM CA certificate(s) trusted for the server (in addition to nothing else
   *  when given; omit to use Node's default roots). */
  ca?: string | Buffer | Array<string | Buffer>;
  /** DANGEROUS: skip certificate verification. Encrypted but unauthenticated.
   *  Local development only. Never the default. */
  tlsInsecure?: boolean;
  /** Mask-vault file: loaded on connect if it exists; default path of
   *  saveVault()/loadVault(). */
  vaultPath?: string;
  /** Learn tables that exist on the server but not here (schema only). Default true. */
  syncSchema?: boolean;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_FRAME_IN = 256 * 1024 * 1024;     // client-side sanity cap on replies

// ── transport: length-prefixed JSON frames, strictly request/response ───────
class Transport {
  private sock: net.Socket;
  private buf: Buffer = Buffer.alloc(0);
  private pending: { res: (b: Buffer) => void; rej: (e: TorusError) => void } | null = null;
  private fatal: TorusError | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(sock: net.Socket, readonly timeoutMs: number) {
    this.sock = sock;
    sock.on("data", (c: Buffer) => { this.buf = Buffer.concat([this.buf, c]); this.drain(); });
    sock.on("error", (e) => this.fail(new TorusError("ConnectionError", `connection lost: ${e.message}`)));
    sock.on("close", () => this.fail(new TorusError("ConnectionError", "connection lost: server closed the connection")));
    sock.on("end", () => this.fail(new TorusError("ConnectionError", "connection lost: server closed the connection")));
  }

  get closed(): boolean { return this.fatal !== null; }

  private fail(e: TorusError) {
    if (this.fatal) return;
    this.fatal = e;
    const p = this.pending;
    this.pending = null;
    if (p) p.rej(e);
    this.sock.destroy();
  }

  private drain() {
    if (!this.pending || this.buf.length < 4) return;
    const n = this.buf.readUInt32BE(0);
    if (n > MAX_FRAME_IN) {
      this.fail(new TorusError("ProtocolError", `declared reply frame too large: ${n} bytes`));
      return;
    }
    if (this.buf.length < 4 + n) return;
    const payload = Buffer.from(this.buf.subarray(4, 4 + n));
    this.buf = this.buf.subarray(4 + n);
    const p = this.pending;
    this.pending = null;
    p.res(payload);
  }

  /** Send one frame and await exactly one reply. Calls are serialized. */
  request(payload: Buffer): Promise<Buffer> {
    const run = () => new Promise<Buffer>((res, rej) => {
      if (this.fatal) return rej(this.fatal);
      let timer: NodeJS.Timeout | undefined;
      const done = <T>(f: (x: T) => void) => (x: T) => { if (timer) clearTimeout(timer); f(x); };
      this.pending = { res: done(res), rej: done(rej) };
      if (this.timeoutMs > 0) {
        timer = setTimeout(() => {
          // the reply may still arrive later and desynchronize the stream:
          // the only safe move is to drop the connection.
          this.fail(new TorusError("TimeoutError", `no reply within ${this.timeoutMs} ms; connection dropped`));
        }, this.timeoutMs);
      }
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(payload.length, 0);
      this.sock.write(Buffer.concat([hdr, payload]), (err) => {
        if (err) this.fail(new TorusError("ConnectionError", `connection lost: ${err.message}`));
      });
      this.drain();
    });
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  /** Close now; any in-flight call rejects. */
  destroy() {
    this.fail(new TorusError("InterfaceError", "connection is closed"));
  }
}

function isIp(host: string): boolean {
  return net.isIP(host) !== 0;
}

function openSocket(host: string, port: number, o: ConnectOptions, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (e: TorusError | null, s?: net.Socket) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (e) { try { sock.destroy(); } catch { /* ignore */ } reject(e); } else resolve(s!);
    };
    let sock: net.Socket;
    if (o.tls) {
      const opts: tls.ConnectionOptions = {
        host, port,
        rejectUnauthorized: !o.tlsInsecure,      // verified unless explicitly disabled
        minVersion: "TLSv1.2",
      };
      if (!isIp(host)) opts.servername = host;
      if (o.ca !== undefined) opts.ca = o.ca;
      sock = tls.connect(opts, () => finish(null, sock));
    } else {
      sock = net.createConnection({ host, port }, () => finish(null, sock));
    }
    sock.on("error", (e) => finish(new TorusError("ConnectionError",
      `${o.tls ? "TLS/" : ""}cannot connect to ${host}:${port}: ${e.message}`)));
    const timer = timeoutMs > 0
      ? setTimeout(() => finish(new TorusError("TimeoutError", `connect to ${host}:${port} timed out`)), timeoutMs)
      : undefined;
  });
}

// ── plaintext WHERE predicate (DNF), mirrors nokey_wire ─────────────────────
type Atom = { c: string; op?: string; v?: WireVal; in?: WireVal[] };
export type WirePred = { or: Atom[][] };

function cmp(op: string) {
  return (col: string, value: Value): WirePred => ({ or: [[{ c: col, op, v: wv(value) }]] });
}
export const eq = cmp("=");
export const ne = cmp("!=");
export const lt = cmp("<");
export const le = cmp("<=");
export const gt = cmp(">");
export const ge = cmp(">=");
export function isIn(col: string, values: Value[]): WirePred {
  return { or: [[{ c: col, in: values.map(wv) }]] };
}
/** a AND b AND ... (distributes over OR, staying in DNF). */
export function and(...preds: WirePred[]): WirePred {
  let groups: Atom[][] = [[]];
  for (const p of preds) {
    const next: Atom[][] = [];
    for (const g of groups) for (const h of p.or) next.push([...g, ...h]);
    groups = next;
  }
  return { or: groups };
}
/** a OR b OR ... */
export function or(...preds: WirePred[]): WirePred {
  return { or: preds.flatMap((p) => p.or) };
}

// ── joins ────────────────────────────────────────────────────────────────────
export interface JoinStep {
  /** Table joined in. */
  table: string;
  /** Alias for this instance (default: the table name). */
  alias?: string;
  /** Alias of an EARLIER instance (or the left table) that owns `leftCol`.
   *  Default: the left (FROM) table. */
  leftAlias?: string;
  /** PLAIN column of the earlier instance. */
  leftCol: string;
  /** PLAIN column of the joined table. */
  rightCol: string;
  /** Default "inner". */
  kind?: "inner" | "left";
}
export interface JoinOptions {
  /** Alias of the left (FROM) table (default: its name). */
  alias?: string;
  /** WHERE predicate on the left table (evaluated by the server's plaintext index). */
  where?: WirePred | null;
}

/** Row ids per table instance; `null` is the NULL side of a LEFT JOIN. */
export interface JoinResult {
  /** Instance aliases in tuple order. */
  readonly aliases: string[];
  /** alias -> table name. */
  readonly tables: Record<string, string>;
  /** One rowid (or null) per alias, per joined row. */
  readonly tuples: Array<Array<number | null>>;
}

function plainKey(v: Value): string | null {
  if (v === null) return null;                    // NULL never matches
  if (typeof v === "bigint") return "i" + v;
  if (typeof v === "string") return "s" + v;
  if (typeof v === "boolean") return "i" + (v ? 1 : 0);
  if (typeof v === "number") return "i" + v;
  return "f" + v.num + "/" + v.den;               // reduced rational (den>1)
}

// ── the no-key client ────────────────────────────────────────────────────────
const SEP = "\u0000";
type MaskMap = Map<string, bigint>;
function mkey(table: string, rowid: number, col: string): string {
  return table + SEP + rowid + SEP + col;
}

export class Client {
  private tr: Transport;
  private masks: MaskMap = new Map();                 // "table\0rowid\0col" -> r
  private schema = new Map<string, Column[]>();
  private inTx = false;
  private txSnapshot: { masks: MaskMap; schema: Map<string, Column[]> } | null = null;
  private vaultFile: string | undefined;
  /** What the server said in `hello` (protocol 1 servers: {protocol:1,...}). */
  serverInfo: { protocol: number; server?: string; auth_required: boolean;
                max_frame?: number; persistent?: boolean } =
    { protocol: 1, auth_required: false };

  private constructor(tr: Transport, vaultFile?: string) {
    this.tr = tr;
    this.vaultFile = vaultFile;
  }

  static async connect(host = "127.0.0.1", port = 8533, opts: ConnectOptions = {}): Promise<Client> {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const sock = await openSocket(host, port, opts, timeoutMs);
    const db = new Client(new Transport(sock, timeoutMs), opts.vaultPath);
    try {
      await db.handshake(opts.token);
      if (opts.vaultPath && fs.existsSync(opts.vaultPath)) db.loadVault(opts.vaultPath);
      if (opts.syncSchema !== false) await db.syncSchema();
    } catch (e) {
      db.tr.destroy();
      throw e;
    }
    return db;
  }

  private async handshake(token?: string): Promise<void> {
    try {
      this.serverInfo = await this.call("hello", []);
    } catch (e) {
      if (e instanceof TorusError && e.kind === "BadRequest" &&
          (/unknown method/.test(e.message) || /_rpc_hello/.test(e.message))) {
        this.serverInfo = { protocol: 1, auth_required: false };   // protocol-1 server
      } else {
        throw e;
      }
    }
    const proto = this.serverInfo.protocol ?? 1;
    if (proto > PROTOCOL_VERSION) {
      throw new TorusError("InterfaceError",
        `server speaks protocol ${proto}; this driver supports up to ${PROTOCOL_VERSION} - upgrade the driver`);
    }
    if (this.serverInfo.auth_required) {
      if (token === undefined || token === "") {
        throw new TorusError("Unauthenticated", "the server requires a token (pass { token } to connect)");
      }
      await this.call("auth", [token]);
    }
  }

  private async call(method: string, args: unknown[]): Promise<any> {
    if (this.tr.closed) throw new TorusError("InterfaceError", "connection is closed");
    const raw = await this.tr.request(Buffer.from(JSON.stringify({ m: method, a: args })));
    let resp: any;
    try {
      resp = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new TorusError("ProtocolError", "server sent malformed JSON");
    }
    if (resp === null || typeof resp !== "object") throw new TorusError("ProtocolError", "bad reply");
    if (resp.err !== undefined) throw serverError(String(resp.err));
    if (!("ok" in resp)) throw new TorusError("ProtocolError", "reply has neither ok nor err");
    return resp.ok;
  }

  /** Close the connection. An open transaction is rolled back by the server. */
  close(): void {
    this.inTx = false;
    this.txSnapshot = null;
    this.tr.destroy();
  }

  // — operations —
  async ping(): Promise<boolean> { return (await this.call("ping", [])) === "pong"; }
  /** Server counters (admin token when auth is on). */
  async stats(): Promise<any> { return this.call("stats", []); }
  /** Force a durable checkpoint (admin). Returns the server's generation number. */
  async checkpoint(): Promise<number> { return this.call("checkpoint", []); }
  /** Ask the server to write a checksummed backup (admin); returns its path. */
  async backup(): Promise<string> { return this.call("backup", []); }
  async tables(): Promise<string[]> { return this.call("tables", []); }
  async tableInfo(table: string): Promise<{ rows: number; deleted: number[] }> {
    return this.call("table_info", [table]);
  }

  /** Learn tables that exist on the server but not here (schema only; decrypting
   *  encrypted columns still needs the owner's vault). Returns the new names. */
  async syncSchema(): Promise<string[]> {
    const added: string[] = [];
    for (const t of await this.tables()) {
      if (this.schema.has(t)) continue;
      const cols: Array<[string, ColType, Policy]> = await this.call("schema", [t]);
      this.schema.set(t, cols.map(([name, type, policy]) => ({ name, type, policy })));
      added.push(t);
    }
    return added;
  }

  // — DDL —
  async createTable(name: string, columns: Column[]): Promise<void> {
    await this.call("create", [name, columns.map((c) => [c.name, c.type, c.policy])]);
    this.schema.set(name, columns.map((c) => ({ ...c })));
  }

  /** Drop a table (admin). Forgets its masks. */
  async dropTable(name: string): Promise<void> {
    await this.call("drop", [name]);
    this.schema.delete(name);
    const prefix = name + SEP;
    for (const k of [...this.masks.keys()]) if (k.startsWith(prefix)) this.masks.delete(k);
  }

  private cols(table: string): Column[] {
    const s = this.schema.get(table);
    if (!s) throw new TorusError("InterfaceError", `unknown table: ${table}`);
    return s;
  }
  private col(table: string, name: string): Column {
    const c = this.cols(table).find((c) => c.name === name);
    if (!c) throw new TorusError("InterfaceError", `no such column: ${table}.${name}`);
    return c;
  }

  // — blinding —
  private encodeCell(v: Value, table: string, c: Column): bigint {
    if (v === null || v === undefined) {
      throw new TorusError("InterfaceError", `encrypted column ${table}.${c.name} cannot hold NULL`);
    }
    if (typeof v === "string") {
      throw new TorusError("InterfaceError", `cannot encrypt a string (${table}.${c.name})`);
    }
    if (typeof v === "boolean") return v ? 1n : 0n;
    if (isRational(v)) return encodeRational(v.num, v.den);
    if (typeof v === "number" && !Number.isSafeInteger(v)) {
      throw new TorusError("InterfaceError", `number ${v} is not a safe integer; pass a bigint`);
    }
    return encodeInt(BigInt(v));
  }

  private blindRow(table: string, row: Record<string, Value>): { wire: Record<string, WireVal>; pending: Array<[string, bigint]> } {
    const cols = this.cols(table);
    const known = new Set(cols.map((c) => c.name));
    for (const k of Object.keys(row)) {
      if (!known.has(k)) throw new TorusError("InterfaceError", `no such column: ${table}.${k}`);
    }
    const wire: Record<string, WireVal> = {};
    const pending: Array<[string, bigint]> = [];
    for (const c of cols) {
      if (!(c.name in row)) {
        throw new TorusError("InterfaceError", `INSERT must provide column ${table}.${c.name}`);
      }
      const v = row[c.name];
      if (c.policy === "plain") {
        wire[c.name] = wv(v);
      } else {
        const s = this.encodeCell(v, table, c);
        const r = randScalar();
        wire[c.name] = { t: "i", v: mod(s + r).toString() };
        pending.push([c.name, r]);
      }
    }
    return { wire, pending };
  }

  // — INSERT: blind encrypted cells, keep masks locally —
  async insert(table: string, row: Record<string, Value>): Promise<number> {
    const { wire, pending } = this.blindRow(table, row);
    const rowid: number = await this.call("insert", [table, wire]);
    for (const [col, r] of pending) this.masks.set(mkey(table, rowid, col), r);
    return rowid;
  }

  /** Bulk insert: every row is blinded locally and sent in ONE `insert_many`
   *  round trip (all-or-nothing on the server). Returns the new row ids. */
  async insertMany(table: string, rows: Array<Record<string, Value>>): Promise<number[]> {
    if (rows.length === 0) return [];
    const blinded = rows.map((r) => this.blindRow(table, r));
    const ids: number[] = await this.call("insert_many", [table, blinded.map((b) => b.wire)]);
    if (!Array.isArray(ids) || ids.length !== rows.length) {
      throw new TorusError("ProtocolError", "insert_many returned a wrong number of row ids");
    }
    blinded.forEach((b, k) => { for (const [col, r] of b.pending) this.masks.set(mkey(table, ids[k], col), r); });
    return ids;
  }

  // — UPDATE / DELETE —
  /** UPDATE ... SET col = value WHERE pred. Atomic: wrapped in an implicit
   *  transaction when none is open. Returns the number of rows changed. */
  async update(table: string, assignments: Record<string, Value>, where?: WirePred | null): Promise<number> {
    for (const col of Object.keys(assignments)) this.col(table, col);
    return this.atomically(async () => {
      const idxs = await this.matching(table, where);
      for (const i of idxs) {
        for (const [col, v] of Object.entries(assignments)) {
          const c = this.col(table, col);
          if (c.policy === "plain") {
            await this.call("update_cell", [table, i, col, wv(v)]);
          } else {
            const s = this.encodeCell(v, table, c);
            const r = randScalar();
            await this.call("update_cell", [table, i, col, { t: "i", v: mod(s + r).toString() }]);
            this.masks.set(mkey(table, i, col), r);
          }
        }
      }
      return idxs.length;
    });
  }

  /** DELETE FROM table WHERE pred (tombstones the rows). Returns how many were removed. */
  async deleteRows(table: string, where?: WirePred | null): Promise<number> {
    this.cols(table);
    const idxs = await this.matching(table, where);
    if (idxs.length === 0) return 0;
    return this.call("delete_rows", [table, idxs]);
  }

  private async atomically<T>(fn: () => Promise<T>): Promise<T> {
    if (this.inTx) return fn();
    await this.begin();
    let out: T;
    try {
      out = await fn();
    } catch (e) {
      try { await this.rollback(); } catch { /* keep the original error */ }
      throw e;
    }
    await this.commit();
    return out;
  }

  // — transactions —
  get inTransaction(): boolean { return this.inTx; }

  /** Open a transaction. The client snapshots the mask vault and schema so a
   *  rollback (or failed commit) restores them exactly. */
  async begin(): Promise<void> {
    if (this.inTx) throw new TorusError("InterfaceError", "a transaction is already open");
    const snap = { masks: new Map(this.masks), schema: new Map(this.schema) };
    await this.call("tx_begin", []);          // if this throws nothing changed
    this.txSnapshot = snap;
    this.inTx = true;
  }

  private restore(): void {
    if (this.txSnapshot) {
      this.masks = this.txSnapshot.masks;
      this.schema = this.txSnapshot.schema;
    }
    this.txSnapshot = null;
    this.inTx = false;
  }

  async commit(): Promise<void> {
    if (!this.inTx) return;                    // no-op, as in the Python driver
    try {
      await this.call("tx_commit", []);
    } catch (e) {
      // the server did not commit (error, timeout, lost connection): the only
      // safe client state is the pre-transaction one
      this.restore();
      throw e;
    }
    this.txSnapshot = null;
    this.inTx = false;
  }

  async rollback(): Promise<void> {
    if (!this.inTx) return;
    try {
      await this.call("tx_rollback", []);
    } finally {
      this.restore();                          // masks restored even if the RPC failed
    }
  }

  /** `await db.transaction(async () => { ... })` - commit on success, roll back on throw. */
  async transaction<T>(fn: (db: Client) => Promise<T>): Promise<T> {
    await this.begin();
    let out: T;
    try {
      out = await fn(this);
    } catch (e) {
      try { await this.rollback(); } catch { /* keep the original error */ }
      throw e;
    }
    await this.commit();
    return out;
  }

  // — row selection —
  private async matching(table: string, where?: WirePred | null): Promise<number[]> {
    this.cols(table);
    return this.call("matching_rowids", [table, where ?? null]);
  }

  private mask(table: string, i: number, col: string): bigint {
    const m = this.masks.get(mkey(table, i, col));
    if (m === undefined) {
      throw new TorusError("InterfaceError",
        `no mask for ${table}[${i}].${col}: row not inserted by this vault`);
    }
    return m;
  }

  // — Π_lin: SUM over the matched rows (no server key) —
  async sum(table: string, col: string, where?: WirePred | null): Promise<Decoded> {
    return this.sumIds(table, col, await this.matching(table, where));
  }

  private async sumIds(table: string, col: string, idxs: number[]): Promise<Decoded> {
    this.encryptedCol(table, col);
    const blinded = toBig(await this.call("blinded_sum", [table, col, idxs]));
    let mask = 0n;
    for (const i of idxs) mask = mod(mask + this.mask(table, i, col));
    return decode(mod(blinded - mask));
  }

  private encryptedCol(table: string, col: string): Column {
    const c = this.col(table, col);
    if (c.policy === "plain") {
      throw new TorusError("InterfaceError", `${table}.${col} is a PLAIN column; nothing to unblind`);
    }
    return c;
  }

  async count(table: string, where?: WirePred | null): Promise<number> {
    return (await this.matching(table, where)).length;
  }

  /** AVG = SUM / COUNT as an exact rational (null over zero rows). */
  async avg(table: string, col: string, where?: WirePred | null): Promise<Decoded | null> {
    const idxs = await this.matching(table, where);
    if (idxs.length === 0) return null;
    return divide(await this.sumIds(table, col, idxs), BigInt(idxs.length));
  }

  // — Π_mult: encrypted inner product sum a_i*b_i (Beaver triples) —
  async dot(table: string, left: string, right: string, where?: WirePred | null): Promise<Decoded> {
    const idxs = await this.matching(table, where);
    return this.dotPairs(table, left, idxs, table, right, idxs);
  }

  private async dotPairs(lt: string, lc: string, lids: number[],
                         rt: string, rc: string, rids: number[]): Promise<Decoded> {
    this.encryptedCol(lt, lc); this.encryptedCol(rt, rc);
    if (lids.length === 0) return 0n;
    const ls = await this.unblindCells(lt, lc, lids);
    const rs = await this.unblindCells(rt, rc, rids);
    const openings: [string, string][] = [];
    const triples: { u: bigint; v: bigint; w: bigint }[] = [];
    for (let k = 0; k < lids.length; k++) {
      const u = randScalar(), v = randScalar(), w = mod(u * v);
      triples.push({ u, v, w });
      openings.push([mod(ls[k] - u).toString(), mod(rs[k] - v).toString()]);
    }
    const egs: string[] = await this.call("mult_combine_batch", [openings]);
    if (!Array.isArray(egs) || egs.length !== openings.length) {
      throw new TorusError("ProtocolError", "mult_combine_batch returned a wrong number of results");
    }
    let acc = 0n;
    for (let k = 0; k < openings.length; k++) {
      const [e, g] = openings[k].map(BigInt);
      const { u, v, w } = triples[k];
      acc = mod(acc + w + e * v + g * u + toBig(egs[k]));
    }
    return decode(acc);
  }

  /** Blinded cells minus masks = the encoded scalars (not yet decoded). */
  private async unblindCells(table: string, col: string, ids: number[]): Promise<bigint[]> {
    const wires: WireVal[] = await this.call("blinded_cells", [table, col, ids]);
    return wires.map((w, k) => mod(toBig((uwv(w) as bigint)) - this.mask(table, ids[k], col)));
  }

  // — reveal columns —
  /** Plain or decrypted values of `col` for the given row ids (null id -> null). */
  async column(table: string, col: string, ids: Array<number | null>): Promise<Value[]> {
    const c = this.col(table, col);
    const uniq = [...new Set(ids.filter((i): i is number => i !== null))].sort((a, b) => a - b);
    const got = new Map<number, Value>();
    if (uniq.length) {
      if (c.policy === "plain") {
        const ws: WireVal[] = await this.call("plain_cells", [table, col, uniq]);
        ws.forEach((w, k) => got.set(uniq[k], uwv(w)));
      } else {
        const ss = await this.unblindCells(table, col, uniq);
        ss.forEach((s, k) => got.set(uniq[k], decode(s)));
      }
    }
    return ids.map((i) => (i === null ? null : got.get(i)!));
  }

  /** SELECT cols FROM table WHERE pred (plain columns as stored, encrypted ones unblinded). */
  async select(table: string, columns: string[], where?: WirePred | null): Promise<Array<Record<string, Value>>> {
    const idxs = await this.matching(table, where);
    const vecs = await Promise.all(columns.map((c) => this.column(table, c, idxs)));
    return idxs.map((_i, k) => Object.fromEntries(columns.map((c, j) => [c, vecs[j][k]])));
  }

  // — JOIN: client-side hash join over plaintext keys (like the Python engine) —
  /**
   * Hash join of `left` with each step in turn. Join keys must be PLAIN
   * columns (the server only ever sees plaintext keys it already stores; no
   * blinded value is touched). NULL keys never match. Returns row-id tuples.
   */
  async join(left: string, steps: JoinStep[], opts: JoinOptions = {}): Promise<JoinResult> {
    this.cols(left);
    const firstAlias = opts.alias ?? left;
    const aliases = [firstAlias];
    const tables: Record<string, string> = { [firstAlias]: left };
    let tuples: Array<Array<number | null>> = (await this.matching(left, opts.where)).map((i) => [i]);

    for (const st of steps) {
      const alias = st.alias ?? st.table;
      if (alias in tables) throw new TorusError("InterfaceError", `duplicate alias: ${alias}`);
      const leftAlias = st.leftAlias ?? firstAlias;
      if (!(leftAlias in tables)) {
        throw new TorusError("InterfaceError", `unknown or later alias in ON clause: ${leftAlias}`);
      }
      const lt = tables[leftAlias];
      if (this.col(lt, st.leftCol).policy !== "plain" || this.col(st.table, st.rightCol).policy !== "plain") {
        throw new TorusError("InterfaceError", "JOIN keys must be PLAIN columns");
      }
      const kind = st.kind ?? "inner";
      if (kind !== "inner" && kind !== "left") throw new TorusError("InterfaceError", `bad join kind: ${kind}`);

      const rightIds = await this.matching(st.table, null);
      const rightKeys = await this.column(st.table, st.rightCol, rightIds);
      const rightMap = new Map<string, number[]>();
      rightIds.forEach((rid, k) => {
        const key = plainKey(rightKeys[k]);
        if (key === null) return;                                // NULL never equals NULL
        const l = rightMap.get(key);
        if (l) l.push(rid); else rightMap.set(key, [rid]);
      });
      const lpos = aliases.indexOf(leftAlias);
      const lkeys = await this.column(lt, st.leftCol, tuples.map((t) => t[lpos]));
      const stepped: Array<Array<number | null>> = [];
      tuples.forEach((t, k) => {
        const key = plainKey(lkeys[k]);
        const matches = key === null ? undefined : rightMap.get(key);
        if (matches && matches.length) for (const m of matches) stepped.push([...t, m]);
        else if (kind === "left") stepped.push([...t, null]);
      });
      tuples = stepped;
      aliases.push(alias);
      tables[alias] = st.table;
    }
    return { aliases, tables, tuples };
  }

  private aliasPos(j: JoinResult, alias: string): number {
    const p = j.aliases.indexOf(alias);
    if (p < 0) throw new TorusError("InterfaceError", `unknown join alias: ${alias}`);
    return p;
  }

  /** Values of alias.col for every joined row (null on the NULL side). */
  async joinColumn(j: JoinResult, alias: string, col: string): Promise<Value[]> {
    const p = this.aliasPos(j, alias);
    return this.column(j.tables[alias], col, j.tuples.map((t) => t[p]));
  }

  /** SUM(alias.col) over the joined rows via Π_lin; the NULL side is skipped
   *  and a row joined k times counts k times. */
  async joinSum(j: JoinResult, alias: string, col: string): Promise<Decoded> {
    const p = this.aliasPos(j, alias);
    const ids = j.tuples.map((t) => t[p]).filter((i): i is number => i !== null);
    return this.sumIds(j.tables[alias], col, ids);
  }

  /** COUNT(*) of the joined rows. */
  joinCount(j: JoinResult): number { return j.tuples.length; }

  /** DOT(a.x, b.y) over joined rows where both sides are non-null (Π_mult). */
  async joinDot(j: JoinResult, aliasA: string, colA: string, aliasB: string, colB: string): Promise<Decoded> {
    const pa = this.aliasPos(j, aliasA), pb = this.aliasPos(j, aliasB);
    const rows = j.tuples.filter((t) => t[pa] !== null && t[pb] !== null);
    return this.dotPairs(j.tables[aliasA], colA, rows.map((t) => t[pa] as number),
                         j.tables[aliasB], colB, rows.map((t) => t[pb] as number));
  }

  // — orphans: rows on the server this vault cannot decrypt (crash between
  //   the server accepting an INSERT and the vault being saved) —
  async findOrphans(): Promise<Record<string, number[]>> {
    const out: Record<string, number[]> = {};
    for (const [table, cols] of this.schema) {
      const enc = cols.filter((c) => c.policy !== "plain").map((c) => c.name);
      if (!enc.length) continue;
      const info = await this.tableInfo(table);
      const dead = new Set(info.deleted);
      const bad: number[] = [];
      for (let i = 0; i < info.rows; i++) {
        if (!dead.has(i) && enc.some((c) => !this.masks.has(mkey(table, i, c)))) bad.push(i);
      }
      if (bad.length) out[table] = bad;
    }
    return out;
  }

  // — vault persistence —
  /**
   * Write the mask vault to a JSON file ATOMICALLY (temp file + fsync +
   * rename) with mode 0600. The vault is the owner's one long-lived secret:
   * losing it loses the data, leaking it breaks confidentiality.
   */
  saveVault(file?: string): void {
    const target = file ?? this.vaultFile;
    if (!target) throw new TorusError("InterfaceError", "no vault path given");
    const entries = [...this.masks].map(([k, r]) => {
      const [table, rowid, col] = k.split(SEP);
      return [table, Number(rowid), col, r.toString()];
    });
    const body = JSON.stringify({ version: 1, masks: entries });
    const tmp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
    } catch (e) {
      fs.closeSync(fd);
      fs.rmSync(tmp, { force: true });
      throw e;
    }
    fs.closeSync(fd);
    try {
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, target);
    } catch (e) {
      fs.rmSync(tmp, { force: true });
      throw e;
    }
    this.vaultFile = this.vaultFile ?? target;
  }

  /** Replace the in-memory mask vault with the one in `file`. */
  loadVault(file?: string): void {
    const src = file ?? this.vaultFile;
    if (!src) throw new TorusError("InterfaceError", "no vault path given");
    let doc: any;
    try {
      doc = JSON.parse(fs.readFileSync(src, "utf8"));
    } catch (e) {
      throw new TorusError("InterfaceError", `cannot read vault ${src}: ${(e as Error).message}`);
    }
    if (!doc || doc.version !== 1 || !Array.isArray(doc.masks)) {
      throw new TorusError("InterfaceError", `${src} is not a TorusDB vault`);
    }
    const m: MaskMap = new Map();
    for (const e of doc.masks) {
      if (!Array.isArray(e) || e.length !== 4) throw new TorusError("InterfaceError", "corrupt vault entry");
      m.set(mkey(String(e[0]), Number(e[1]), String(e[2])), BigInt(e[3]));
    }
    this.masks = m;
    this.vaultFile = this.vaultFile ?? src;
  }

  /** Number of masks currently held (diagnostics/tests). */
  get maskCount(): number { return this.masks.size; }
}

/** a / d as an exact rational (reduced; bigint when integral). */
function divide(a: Decoded, d: bigint): Decoded {
  const num = typeof a === "bigint" ? a : a.num;
  const den = typeof a === "bigint" ? 1n : a.den;
  return rational(num, den * d);
}
