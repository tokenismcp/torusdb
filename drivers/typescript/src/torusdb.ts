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
//
// Trust model: the SERVER IS UNTRUSTED. Nothing it sends is believed without
// validation, and it never decides which columns are encrypted: the policies
// the client created or loaded from its own vault are the trust anchor.

import * as net from "net";
import * as tls from "tls";
import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import { randomBytes } from "crypto";
import { AsyncLocalStorage } from "async_hooks";
import { TorusError } from "./errors";
import {
  FheKey, FheBackend, newNonce, FHE_CELL_BYTES, FHE_DOT_BYTES, FHE_SUM_BYTES, addSums as fheAddSums, mulDots as fheMulDots,
} from "./fhe";

export {
  FheKey, FHE_CELL_BYTES, FHE_DEFAULT_RANGE, FHE_MAX_RANGE, sumCells as fheSumCells,
  addSums as fheAddSums, mulDots as fheMulDots,
} from "./fhe";
export type { FheBackend } from "./fhe";

/** Newest wire protocol this driver speaks. */
export const PROTOCOL_VERSION = 2;

// BN254 group order - the field modulus for the no-key scalar ring Z/nZ.
export const N =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Same decode budget as the Python reference (ecfhe.nokey):
//   ints: |v| <= isqrt(N/2);  fractions: |num|,den <= isqrt(N/2) and |num|*den < N>>64
const MARGIN_BITS = 64n;
const RANGE = N >> MARGIN_BITS;

// ── errors ──────────────────────────────────────────────────────────────────
export { TorusError };

/**
 * A COMMIT was sent but its reply was lost, and the outcome could not be
 * learned from the server. The client keeps BOTH possible vault states; call
 * `reconnect()` then `resolveTransaction(txid)` (or pass the answer you got
 * elsewhere as `resolveTransaction(txid, committed)`). Writes are refused
 * until every in-doubt transaction is resolved.
 */
export class TransactionInDoubt extends TorusError {
  readonly txid: string;
  constructor(txid: string, message: string) {
    super("TransactionInDoubt", message);
    this.name = "TransactionInDoubt";
    this.txid = txid;
    Object.setPrototypeOf(this, TransactionInDoubt.prototype);
  }
}

function serverError(text: string): TorusError {
  const m = /^([A-Za-z][A-Za-z0-9_]*): ([\s\S]*)$/.exec(text);
  return m ? new TorusError(m[1], m[2]) : new TorusError("ServerError", text);
}
const proto = (m: string) => new TorusError("ProtocolError", m);
const usage = (m: string) => new TorusError("InterfaceError", m);

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
function gcd(a: bigint, b: bigint): bigint {
  a = abs(a); b = abs(b);
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function isqrt(n: bigint): bigint {
  if (n < 0n) throw new Error("isqrt of negative");
  if (n < 2n) return n;
  let x = n, y = (x + 1n) / 2n;
  while (y < x) { x = y; y = (x + n / x) / 2n; }
  return x;
}

const BOUND = isqrt(N / 2n);

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
  const g = gcd(num, den);                  // reduce FIRST: 2^127/2^127 is just 1
  if (g > 1n) { num /= g; den /= g; }
  if (abs(num) > BOUND || den > BOUND || abs(num) * den >= RANGE) {
    throw new TorusError("OutOfBudget",
      `fraction ${num}/${den} exceeds the encodable range`);
  }
  return mod(mod(num) * modInv(mod(den)));
}

/** Reduce num/den to lowest terms; returns a bigint when the denominator is 1. */
export function rational(num: bigint, den: bigint): Decoded {
  if (den === 0n) throw new TorusError("ValueError", "zero denominator");
  if (den < 0n) { num = -num; den = -den; }
  const g = gcd(num, den);
  if (g > 1n) { num /= g; den /= g; }
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

// ── strict reply validation ─────────────────────────────────────────────────
/** Request-size limits a server publishes in `hello` (absent on older servers: conservative defaults apply). */
export interface ServerLimits {
  maxItems?: number;
  fhe?: {
    maxSumRows?: number;
    maxDotRows: { pyecc?: number; mcl?: number };
    recommendedDotRows: { pyecc?: number; mcl?: number };
  };
}
const posInt = (x: unknown): number | undefined =>
  typeof x === "number" && Number.isSafeInteger(x) && x >= 1 ? x : undefined;

/** Longest decimal string accepted for any integer from the server. */
export const MAX_DIGITS = 90;
const DEC = /^-?[0-9]+$/;

function parseBig(x: unknown, what: string): bigint {
  if (typeof x !== "string" || x.length === 0 || x.length > MAX_DIGITS + 1 || !DEC.test(x) ||
      x.replace("-", "").length > MAX_DIGITS) {
    throw proto(`bad integer in ${what}`);
  }
  return BigInt(x);
}
function rowId(x: unknown, what: string): number {
  if (typeof x !== "number" || !Number.isSafeInteger(x) || x < 0) throw proto(`bad row id in ${what}`);
  return x;
}
function arr(x: unknown, what: string, len?: number): unknown[] {
  if (!Array.isArray(x)) throw proto(`${what}: expected a list`);
  if (len !== undefined && x.length !== len) throw proto(`${what}: expected ${len} items, got ${x.length}`);
  return x;
}
function str(x: unknown, what: string): string {
  if (typeof x !== "string") throw proto(`${what}: expected a string`);
  return x;
}
function obj(x: unknown, what: string): Record<string, unknown> {
  if (x === null || typeof x !== "object" || Array.isArray(x)) throw proto(`${what}: expected an object`);
  return x as Record<string, unknown>;
}
function safeInt(x: unknown, what: string): number {
  if (typeof x !== "number" || !Number.isSafeInteger(x)) throw proto(`${what}: expected an integer`);
  return x;
}

// ── wire value codec (mirrors proto/nokey_wire.py) ──────────────────────────
type WireVal =
  | { t: "n" } | { t: "b"; v: boolean } | { t: "i"; v: string }
  | { t: "s"; v: string } | { t: "f"; n: string; d: string }
  | { t: "x"; v: string };                       // binary (FHE ciphertext cells only)

/** A user-facing cell value. */
export type Value = null | boolean | bigint | number | string | Rational;

function wv(v: Value | undefined): WireVal {
  if (v === null || v === undefined) return { t: "n" };
  if (v instanceof Uint8Array) throw usage("binary values are only accepted as FHE ciphertexts; this column is not an FHE column");
  if (typeof v === "boolean") return { t: "b", v };
  if (typeof v === "bigint") return { t: "i", v: v.toString() };
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) {
      throw usage(`number ${v} is not a safe integer; pass a bigint or a {num,den} rational`);
    }
    return { t: "i", v: BigInt(v).toString() };
  }
  if (typeof v === "string") return { t: "s", v };
  if (isRational(v)) {
    if (v.den === 0n) throw usage("zero denominator");
    const r = rational(v.num, v.den);
    return typeof r === "bigint"
      ? { t: "f", n: r.toString(), d: "1" }
      : { t: "f", n: r.num.toString(), d: r.den.toString() };
  }
  throw usage("cannot wire-encode " + typeof v);
}

function uwv(d: unknown): Value {
  const o = obj(d, "wire value");
  switch (o.t) {
    case "n": return null;
    case "b": if (typeof o.v !== "boolean") break; return o.v;
    case "i": return parseBig(o.v, "int cell");
    case "s": if (typeof o.v !== "string") break; return o.v;
    case "f": {
      const n = parseBig(o.n, "numerator"), dd = parseBig(o.d, "denominator");
      if (dd === 0n) throw proto("zero denominator from server");
      return rational(n, dd);
    }
    default: throw proto("bad wire tag");
  }
  throw proto("bad wire value");
}

/** An FHE ciphertext cell as a wire value. The length is checked before anything is sent. */
function wvCell(cell: Uint8Array): WireVal {
  if (!(cell instanceof Uint8Array) || cell.length !== FHE_CELL_BYTES) {
    throw usage(`an FHE cell is exactly ${FHE_CELL_BYTES} bytes, got ${cell instanceof Uint8Array ? cell.length : typeof cell}`);
  }
  return { t: "x", v: Buffer.from(cell).toString("base64") };
}

/** A binary cell from the server: null for a NULL cell, else exactly `len` canonical-base64 bytes. */
function binCell(d: unknown, what: string, len = FHE_CELL_BYTES): Buffer | null {
  const o = obj(d, what);
  if (o.t === "n") return null;
  if (o.t !== "x" || typeof o.v !== "string") throw proto(`${what}: expected a binary cell`);
  const b = Buffer.from(o.v, "base64");
  if (b.length !== len || b.toString("base64") !== o.v) throw proto(`${what}: a binary cell must be ${len} bytes of canonical base64`);
  return b;
}

/** A base64 blob reply (fhe_sum / fhe_dot) of exactly `len` bytes. */
function blob(d: unknown, what: string, len: number): Buffer {
  if (typeof d !== "string") throw proto(`${what}: expected a base64 string`);
  const b = Buffer.from(d, "base64");
  if (b.length !== len || b.toString("base64") !== d) throw proto(`${what}: expected ${len} bytes of canonical base64`);
  return b;
}

/** A server blinded scalar (must be an int cell). */
function scalarCell(d: unknown): bigint {
  const v = uwv(d);
  if (typeof v !== "bigint") throw proto("blinded cell is not an integer");
  return mod(v);
}

// ── column spec ──────────────────────────────────────────────────────────────
export type Policy = "plain" | "encrypted" | "paired" | "fhe";
export type ColType = "int" | "str" | "rational";
export interface Column { name: string; type: ColType; policy: Policy; }

const POLICIES = ["plain", "encrypted", "paired", "fhe"];
const TYPES = ["int", "str", "rational"];
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Any policy string the client does not recognise is treated as ENCRYPTED. */
function normPolicy(p: unknown): Policy {
  return typeof p === "string" && POLICIES.includes(p) ? (p as Policy) : "encrypted";
}
function normType(t: unknown): ColType {
  return typeof t === "string" && TYPES.includes(t) ? (t as ColType) : "int";
}
function checkName(kind: string, n: string) {
  if (typeof n !== "string" || n.length === 0) throw usage(`${kind} name must be a non-empty string`);
  if (n.startsWith("__")) throw usage(`${kind} names starting with "__" are reserved: ${n}`);
}

// ── connection options ──────────────────────────────────────────────────────
export interface ConnectOptions {
  /** API token; required when the server runs with --token-file. Never logged. */
  token?: string;
  /** Socket timeout per request in ms (default 30000; 0 disables). */
  timeoutMs?: number;
  /** Wrap the connection in TLS. The certificate AND hostname are verified. */
  tls?: boolean;
  /** PEM CA certificate(s) trusted for the server (replaces Node's roots). Needs `tls`. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** DANGEROUS: skip certificate verification. Local development only. Needs `tls`. */
  tlsInsecure?: boolean;
  /** Send the token over an UNENCRYPTED connection to a non-loopback host
   *  (refused by default: the token would travel in the clear). */
  allowInsecureToken?: boolean;
  /** Mask-vault file: loaded on connect if it exists; default path of
   *  saveVault()/loadVault(). */
  vaultPath?: string;
  /** Learn tables that exist on the server but not here (schema only). Default true.
   *  Tables learned this way are UNTRUSTED: reads of plain columns work, writes are refused. */
  syncSchema?: boolean;
  /** Allow writes to tables whose encryption policies were learned from the
   *  server. DANGEROUS: a lying server can mark encrypted columns "plain" and
   *  make this client send them in the clear. */
  trustServerSchema?: boolean;
  /** Authenticated (SPDZ MAC) mode: every encrypted cell carries a one-time-
   *  padded MAC alpha*s (hidden `__mac__<col>` cells, alpha kept in the vault)
   *  and every affine result / read is verified; a lying server is caught
   *  (IntegrityError). Must match how the table was written. */
  authenticated?: boolean;
  /** The owner's key for `fhe` columns (see {@link FheKey}). Needed for INSERT/UPDATE/reads/SUM/DOT on them.
   *  With `authenticated: true`, FHE cells also carry integrity tags in a hidden `__fmac__<col>` column. */
  fheKey?: FheKey;
  /** How DOT on two FHE columns is computed. "delegated": the server multiplies ciphertexts with its
   *  pairing (fast, O(1) client work) but the result CANNOT be integrity-checked - a lying server can
   *  make you decrypt a wrong number, and the result must lie in the key's range. "local": the owner reads
   *  both operand columns (every cell verified against its tag when `authenticated`), decrypts and
   *  multiplies/sums the plaintexts itself (verified, O(n) decryptions, no range limit on the result).
   *  "auto" (default): "delegated" unless `authenticated`, in which case "local". */
  fheDotMode?: "auto" | "local" | "delegated";
  /** Backward-compatible alias: with `authenticated: true` and mode "auto", selects "delegated". */
  fheAllowUnverifiedDot?: boolean;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const HARD_MAX_FRAME = 64 * 1024 * 1024;     // never accept a bigger reply
const HELLO_MAX_FRAME = 1024 * 1024;         // until hello says otherwise
const LIST_CHUNK = 100_000;                  // server rejects lists > 200 000
const INDOUBT_POLLS = 10;

function isLoopback(h: string): boolean {
  if (h === "localhost" || h === "::1" || h === "[::1]") return true;
  return net.isIPv4(h) && h.startsWith("127.");
}

// ── transport: length-prefixed JSON frames, strictly request/response ───────
class Transport {
  private sock: net.Socket;
  private chunks: Buffer[] = [];
  private have = 0;
  private pending: { res: (b: Buffer) => void; rej: (e: TorusError) => void; cap: number } | null = null;
  private fatal: TorusError | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  /** Largest reply frame accepted. */
  maxRead = HELLO_MAX_FRAME;
  /** Largest request frame the server accepts. */
  maxWrite = HELLO_MAX_FRAME;

  constructor(sock: net.Socket, readonly timeoutMs: number) {
    this.sock = sock;
    sock.on("data", (c: Buffer) => this.onData(c));
    sock.on("error", (e) => this.fail(new TorusError("ConnectionError", `connection lost: ${e.message}`)));
    sock.on("close", () => this.fail(new TorusError("ConnectionError", "connection lost: server closed the connection")));
    sock.on("end", () => this.fail(new TorusError("ConnectionError", "connection lost: server closed the connection")));
  }

  get closed(): boolean { return this.fatal !== null; }
  /** Why the connection died (the original error). */
  get reason(): TorusError { return this.fatal ?? usage("connection is closed"); }

  private fail(e: TorusError) {
    if (this.fatal) return;
    this.fatal = e;
    this.chunks = []; this.have = 0;
    const p = this.pending;
    this.pending = null;
    if (p) p.rej(e);
    this.sock.destroy();
  }

  private onData(c: Buffer) {
    if (this.fatal) return;
    if (!this.pending) {                       // nothing asked for: hostile/desynchronized
      this.fail(proto("unsolicited data from server"));
      return;
    }
    this.chunks.push(c);
    this.have += c.length;
    this.drain();
  }

  /** Remove and return the first k buffered bytes. */
  private take(k: number): Buffer {
    const out: Buffer[] = [];
    let need = k;
    while (need > 0) {
      const c = this.chunks[0];
      if (c.length <= need) { out.push(c); this.chunks.shift(); need -= c.length; }
      else { out.push(c.subarray(0, need)); this.chunks[0] = c.subarray(need); need = 0; }
    }
    this.have -= k;
    return out.length === 1 ? out[0] : Buffer.concat(out, k);
  }

  private drain() {
    const p = this.pending;
    if (!p || this.have < 4) return;
    // peek the header without consuming
    const first = this.chunks[0];
    const hdr = first.length >= 4 ? first.subarray(0, 4) : Buffer.concat(this.chunks, this.have).subarray(0, 4);
    const n = hdr.readUInt32BE(0);
    if (n > p.cap) {
      this.fail(proto(`declared reply frame too large: ${n} bytes (limit ${p.cap})`));
      return;
    }
    if (this.have < 4 + n) return;
    this.take(4);
    const payload = this.take(n);
    this.pending = null;
    if (this.have > 0) {                       // bytes beyond the one reply we asked for
      this.fail(proto("unsolicited data from server"));
      p.rej(this.fatal!);
      return;
    }
    p.res(payload);
  }

  /** Send one frame and await exactly one reply. Calls are serialized. */
  request(payload: Buffer, maxReply?: number): Promise<Buffer> {
    const run = () => new Promise<Buffer>((res, rej) => {
      if (this.fatal) return rej(this.fatal);
      if (payload.length > this.maxWrite) {
        return rej(usage(`request of ${payload.length} bytes exceeds the server's max_frame (${this.maxWrite})`));
      }
      let timer: NodeJS.Timeout | undefined;
      const done = <T>(f: (x: T) => void) => (x: T) => { if (timer) clearTimeout(timer); f(x); };
      const cap = Math.min(this.maxRead, maxReply ?? this.maxRead);
      this.pending = { res: done(res), rej: done(rej), cap };
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
      if (net.isIP(host) === 0) opts.servername = host;
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
// An atom may carry an alias `a` (JOIN post-filters); such atoms are never sent
// to the server.
type Atom = { c: string; op?: string; v?: WireVal; in?: WireVal[]; a?: string };
export type WirePred = { or: Atom[][] };

function cmp(op: string) {
  return (col: string, value: Value, alias?: string): WirePred => {
    const atom: Atom = { c: col, op, v: wv(value) };
    if (alias !== undefined) atom.a = alias;
    return { or: [[atom]] };
  };
}
export const eq = cmp("=");
export const ne = cmp("!=");
export const lt = cmp("<");
export const le = cmp("<=");
export const gt = cmp(">");
export const ge = cmp(">=");
export function isIn(col: string, values: Value[], alias?: string): WirePred {
  const atom: Atom = { c: col, in: values.map(wv) };
  if (alias !== undefined) atom.a = alias;
  return { or: [[atom]] };
}
function atom1(col: string, op: string, v: WireVal, alias?: string): WirePred {
  const a: Atom = { c: col, op, v };
  if (alias !== undefined) a.a = alias;
  return { or: [[a]] };
}
/** `col IS NULL` (the only atom that matches NULL cells; true on the NULL side of a LEFT JOIN). */
export function isNull(col: string, alias?: string): WirePred { return atom1(col, "is_null", { t: "n" }, alias); }
/** `col IS NOT NULL`. */
export function isNotNull(col: string, alias?: string): WirePred { return atom1(col, "not_null", { t: "n" }, alias); }
/** `col LIKE pattern` (STR columns only; % = any run, _ = one char, case-sensitive, no ESCAPE). */
export function like(col: string, pattern: string, alias?: string): WirePred {
  if (typeof pattern !== "string") throw usage("LIKE needs a string pattern");
  return atom1(col, "like", { t: "s", v: pattern }, alias);
}
/** `col NOT LIKE pattern` (NULL cells match neither LIKE nor NOT LIKE). */
export function notLike(col: string, pattern: string, alias?: string): WirePred {
  if (typeof pattern !== "string") throw usage("LIKE needs a string pattern");
  return atom1(col, "not_like", { t: "s", v: pattern }, alias);
}
/** `col BETWEEN lo AND hi`, sent as (col >= lo) AND (col <= hi). */
export function between(col: string, lo: Value, hi: Value, alias?: string): WirePred {
  return and(ge(col, lo, alias), le(col, hi, alias));
}
/** `col NOT IN (values)`, sent as an AND of `!=` atoms (NULL cells never match). */
export function notIn(col: string, values: Value[], alias?: string): WirePred {
  if (values.length === 0) throw usage("NOT IN needs at least one value");
  return and(...values.map((v) => ne(col, v, alias)));
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

/** Predicate as sent to a single-table RPC: alias-qualified atoms are refused. */
function wirePred(p?: WirePred | null): WirePred | null {
  if (p === undefined || p === null) return null;
  for (const g of p.or) for (const a of g) {
    if (a.a !== undefined) throw usage("alias-qualified predicates are only valid in join() options");
  }
  return p;
}

function cmpVals(a: Value, b: Value): number | null {
  const num = (v: Value): Rational | null =>
    typeof v === "bigint" ? { num: v, den: 1n } : typeof v === "number" ? { num: BigInt(v), den: 1n }
    : typeof v === "boolean" ? { num: v ? 1n : 0n, den: 1n } : isRational(v) ? v : null;
  const x = num(a), y = num(b);
  if (x && y) { const l = x.num * y.den, r = y.num * x.den; return l < r ? -1 : l > r ? 1 : 0; }
  if (typeof a === "string" && typeof b === "string") return a < b ? -1 : a > b ? 1 : 0;
  return null;                                // incomparable types
}
function likeRegex(p: string): RegExp {
  let out = "";
  for (const ch of p) out += ch === "%" ? "[\\s\\S]*" : ch === "_" ? "[\\s\\S]" : ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp("^" + out + "$", "u");
}
function atomMatches(val: Value, a: Atom): boolean {
  if (a.op === "is_null") return val === null;
  if (a.op === "not_null") return val !== null;
  if (val === null) return false;             // SQL: a NULL operand makes the atom false
  if (a.op === "like" || a.op === "not_like") {
    if (typeof val !== "string") return false;
    const pat = uwv(a.v);
    if (typeof pat !== "string") throw usage("LIKE needs a string pattern");
    return likeRegex(pat).test(val) === (a.op === "like");
  }
  if (a.in) return a.in.some((w) => cmpVals(val, uwv(w) as Value) === 0);
  const c = cmpVals(val, uwv(a.v) as Value);
  if (c === null) return a.op === "!=" || a.op === "<>";
  switch (a.op) {
    case "=": return c === 0;
    case "!=": case "<>": return c !== 0;
    case "<": return c < 0;
    case ">": return c > 0;
    case "<=": return c <= 0;
    case ">=": return c >= 0;
  }
  throw usage(`bad operator: ${a.op}`);
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
  /** WHERE predicate over PLAIN columns. Atoms on the left table (no alias, or
   *  the left alias) are evaluated by the server's index; atoms built with an
   *  alias (e.g. `eq("dname", "Eng", "d")`) filter the joined rows client-side.
   *  NULL operands (LEFT JOIN null side) make an atom false, as in SQL. */
  where?: WirePred | null;
}

/** Row ids per table instance; `null` is the NULL side of a LEFT JOIN. */
export interface JoinResult {
  /** Instance aliases in tuple order. */
  readonly aliases: string[];
  /** alias -> table name (null-prototype object). */
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
const MAC = "__mac__";
const FMAC = "__fmac__";
const FNONCE = "__fnonce__";
const FHE_SUM_CHUNK = 2000;                  // ids per fhe_sum call (server cap 5000)
const FHE_DOT_CHUNK_NATIVE = 2000;           // server cap 6000 with the native back end
const FHE_DOT_CHUNK = 50;                    // server cap 300 with pure Python (~0.2 s per row)
const FHE_READ_CHUNK = 5000;                 // cells per plain_cells call (~600 bytes each)
const FHE_WRITE_CHUNK = 2000;                // items per update_cells call
const FHE_MAX_K = 1n << 40n;
function mkey(table: string, rowid: number, col: string): string {
  return table + SEP + rowid + SEP + col;
}
interface TableDef { cols: Column[]; trusted: boolean }
type Undo = Array<[string, bigint | undefined]>;
type SchemaMap = Map<string, TableDef>;

interface Target { host: string; port: number; opts: ConnectOptions; timeoutMs: number }

function chunked<T>(xs: T[]): T[][] {
  if (xs.length <= LIST_CHUNK) return [xs];
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += LIST_CHUNK) out.push(xs.slice(i, i + LIST_CHUNK));
  return out;
}

export class Client {
  #tr: Transport;
  #masks = new Map<string, bigint>();            // "table\0rowid\0col" -> r  (SECRET)
  #schema: SchemaMap = new Map();
  #inTx = false;
  #txid: string | null = null;
  #undo: Undo | null = null;                     // mask journal of the open transaction
  #txSchema: SchemaMap | null = null;            // schema at begin()
  #inDoubt = new Map<string, { undo: Undo; schema: SchemaMap }>();
  #vaultFile: string | undefined;
  #token: string | undefined;                    // SECRET (kept only to reconnect)
  #target: Target;
  #trustServerSchema: boolean;
  #authenticated: boolean;
  #alpha = 0n;                                   // SECRET MAC key
  #fhe: FheKey | undefined;                      // SECRET key of the FHE columns
  #fheDotMode: "local" | "delegated";
  #updateCells = true;                           // false once the server answered "unknown method" for update_cells
  #als = new AsyncLocalStorage<boolean>();
  #tail: Promise<void> = Promise.resolve();
  /** What the server said in `hello` (protocol 1 servers: {protocol:1,...}). */
  serverInfo: { protocol: number; server?: string; auth_required: boolean;
                max_frame?: number; persistent?: boolean; limits?: ServerLimits } =
    { protocol: 1, auth_required: false };

  private constructor(tr: Transport, target: Target, o: ConnectOptions) {
    this.#tr = tr;
    this.#target = target;
    this.#vaultFile = o.vaultPath;
    this.#token = o.token;
    this.#trustServerSchema = o.trustServerSchema === true;
    this.#authenticated = o.authenticated === true;
    if (o.fheKey !== undefined && !(o.fheKey instanceof FheKey)) throw usage("fheKey must be an FheKey");
    this.#fhe = o.fheKey;
    const mode = o.fheDotMode ?? "auto";
    if (mode !== "auto" && mode !== "local" && mode !== "delegated") {
      throw usage(`fheDotMode must be "auto", "local" or "delegated", got ${String(mode)}`);
    }
    this.#fheDotMode = mode !== "auto" ? mode
      : this.#authenticated && o.fheAllowUnverifiedDot !== true ? "local" : "delegated";
    if (this.#authenticated) this.#alpha = 1n + (randScalar() % (N - 1n));
  }

  static async connect(host = "127.0.0.1", port = 8533, opts: ConnectOptions = {}): Promise<Client> {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw usage("timeoutMs must be a finite number >= 0");
    }
    if (!opts.tls && (opts.ca !== undefined || opts.tlsInsecure)) {
      throw usage("`ca` / `tlsInsecure` were given without `tls: true`; refusing to continue unencrypted");
    }
    if (opts.token && !opts.tls && !isLoopback(host) && !opts.allowInsecureToken) {
      throw usage(`refusing to send the token to ${host} over an unencrypted connection; ` +
        `use tls: true (or allowInsecureToken: true if you really mean it)`);
    }
    const target: Target = { host, port, opts: { ...opts, token: undefined, fheKey: undefined }, timeoutMs };
    const tr = await Client.openTransport(target, opts.token);
    const db = new Client(tr.tr, target, opts);
    db.serverInfo = tr.info;
    try {
      if (opts.vaultPath && fs.existsSync(opts.vaultPath)) db.loadVault(opts.vaultPath);
      if (opts.syncSchema !== false) await db.syncSchema();
    } catch (e) {
      db.#tr.destroy();
      throw e;
    }
    return db;
  }

  /** Connect + hello + auth. */
  private static async openTransport(t: Target, token?: string): Promise<{ tr: Transport; info: Client["serverInfo"] }> {
    const sock = await openSocket(t.host, t.port, t.opts, t.timeoutMs);
    const tr = new Transport(sock, t.timeoutMs);
    try {
      let info: Client["serverInfo"];
      try {
        info = Client.parseHello(await Client.rawCall(tr, "hello", []));
      } catch (e) {
        if (e instanceof TorusError && e.kind === "BadRequest" &&
            (/unknown method/.test(e.message) || /_rpc_hello/.test(e.message))) {
          info = { protocol: 1, auth_required: false };              // protocol-1 server
        } else {
          throw e;
        }
      }
      if (info.protocol > PROTOCOL_VERSION) {
        throw usage(`server speaks protocol ${info.protocol}; this driver supports up to ${PROTOCOL_VERSION} - upgrade the driver`);
      }
      tr.maxRead = Math.min(info.max_frame ?? HARD_MAX_FRAME, HARD_MAX_FRAME);
      tr.maxWrite = info.max_frame ?? HARD_MAX_FRAME;
      if (info.auth_required) {
        if (token === undefined || token === "") {
          throw new TorusError("Unauthenticated", "the server requires a token (pass { token } to connect)");
        }
        await Client.rawCall(tr, "auth", [token]);
      }
      return { tr, info };
    } catch (e) {
      tr.destroy();
      throw e;
    }
  }

  private static parseHello(h: unknown): Client["serverInfo"] {
    const o = obj(h, "hello");
    const protocol = safeInt(o.protocol, "hello.protocol");
    if (protocol < 1) throw proto("hello.protocol: bad value");
    if (typeof o.auth_required !== "boolean") throw proto("hello.auth_required: expected a boolean");
    const info: Client["serverInfo"] = { protocol, auth_required: o.auth_required };
    if (o.server !== undefined) info.server = str(o.server, "hello.server");
    if (o.max_frame !== undefined) {
      const m = safeInt(o.max_frame, "hello.max_frame");
      if (m < 1024) throw proto("hello.max_frame: implausibly small");
      info.max_frame = m;
    }
    if (o.persistent !== undefined) {
      if (typeof o.persistent !== "boolean") throw proto("hello.persistent: expected a boolean");
      info.persistent = o.persistent;
    }
    // limits are advisory sizing hints: malformed parts are ignored, never trusted blindly
    if (o.limits !== null && typeof o.limits === "object" && !Array.isArray(o.limits)) {
      const l = o.limits as Record<string, any>;
      const lim: ServerLimits = { maxItems: posInt(l.max_items) };
      const f = l.fhe;
      if (f !== null && typeof f === "object" && !Array.isArray(f)) {
        const pair = (x: any) => (x !== null && typeof x === "object" ? { pyecc: posInt(x.pyecc), mcl: posInt(x.mcl) } : {});
        lim.fhe = { maxSumRows: posInt(f.max_sum_rows), maxDotRows: pair(f.max_dot_rows), recommendedDotRows: pair(f.recommended_dot_rows) };
      }
      info.limits = lim;
    }
    return info;
  }

  private static async rawCall(tr: Transport, method: string, args: unknown[], maxReply?: number): Promise<unknown> {
    if (tr.closed) throw tr.reason;
    const raw = await tr.request(Buffer.from(JSON.stringify({ m: method, a: args })), maxReply);
    let resp: unknown;
    try {
      resp = JSON.parse(raw.toString("utf8"));
    } catch {
      throw proto("server sent malformed JSON");
    }
    if (resp === null || typeof resp !== "object" || Array.isArray(resp)) throw proto("bad reply");
    const r = resp as Record<string, unknown>;
    if (r.err !== undefined) throw serverError(typeof r.err === "string" ? r.err : "malformed error");
    if (!("ok" in r)) throw proto("reply has neither ok nor err");
    return r.ok;
  }

  /** One RPC, with transaction-state bookkeeping (see F1 in the changelog). */
  private async call(method: string, args: unknown[], maxReply?: number): Promise<unknown> {
    try {
      return await Client.rawCall(this.#tr, method, args, maxReply);
    } catch (e) {
      if (this.#inTx && e instanceof TorusError && method !== "tx_commit" && method !== "tx_rollback") {
        if (e.kind === "ConnectionError" || e.kind === "TimeoutError") {
          this.abortLocal();                    // the server rolls back when the session dies
        } else if (e.kind === "Busy" && /timed out/.test(e.message)) {
          this.abortLocal();                    // the server aborted the transaction
          await this.bestEffortRollback();      // and keeps the session aborted until ROLLBACK
        }
      }
      throw e;
    }
  }

  private async bestEffortRollback(): Promise<void> {
    try { await Client.rawCall(this.#tr, "tx_rollback", []); } catch { /* nothing more to do */ }
  }

  // ── mutual exclusion of whole logical operations (F6) ──
  private async exclusive<T>(fn: () => Promise<T>): Promise<T> {
    if (this.#als.getStore()) return fn();     // already inside the exclusive section
    const prev = this.#tail;
    let release!: () => void;
    this.#tail = new Promise<void>((r) => { release = r; });
    await prev;
    try {
      return await this.#als.run(true, fn);
    } finally {
      release();
    }
  }

  /** Close the connection. An open transaction is rolled back by the server. */
  close(): void {
    this.#inTx = false;
    this.#undo = null;
    this.#txSchema = null;
    this.#tr.destroy();
  }

  // Never reveal secrets through console.log / util.inspect / JSON.stringify.
  [util.inspect.custom](): string {
    return `Client { host: ${JSON.stringify(this.#target.host)}, port: ${this.#target.port}, ` +
      `closed: ${this.#tr.closed}, inTransaction: ${this.#inTx}, masks: ${this.#masks.size} (redacted) }`;
  }
  toJSON(): string { return "[TorusDB Client]"; }

  // — operations —
  ping(): Promise<boolean> { return this.exclusive(async () => (await this.call("ping", [])) === "pong"); }
  /** Server counters (admin token when auth is on). */
  stats(): Promise<any> {
    return this.exclusive(async () => obj(await this.call("stats", []), "stats"));
  }
  /** Force a durable checkpoint (admin). Returns the server's generation number. */
  checkpoint(): Promise<number> {
    return this.exclusive(async () => safeInt(await this.call("checkpoint", []), "checkpoint"));
  }
  /** Ask the server to write a checksummed backup (admin); returns its path. */
  backup(): Promise<string> {
    return this.exclusive(async () => str(await this.call("backup", []), "backup"));
  }
  tables(): Promise<string[]> {
    return this.exclusive(async () =>
      arr(await this.call("tables", []), "tables").map((t) => str(t, "tables item")));
  }
  tableInfo(table: string): Promise<{ rows: number; deleted: number[]; indexes: string[] }> {
    return this.exclusive(async () => {
      const o = obj(await this.call("table_info", [table]), "table_info");
      const rows = safeInt(o.rows, "table_info.rows");
      if (rows < 0) throw proto("table_info.rows: negative");
      const indexes = o.indexes === undefined ? [] : arr(o.indexes, "table_info.indexes").map((c) => str(c, "table_info.indexes"));
      return { rows, deleted: arr(o.deleted, "table_info.deleted").map((i) => rowId(i, "table_info.deleted")), indexes };
    });
  }

  /** Learn tables that exist on the server but not here. They are UNTRUSTED
   *  (policies came from the server): plain reads work, writes are refused
   *  unless `trustServerSchema`. Never overwrites a table already known. */
  syncSchema(): Promise<string[]> {
    return this.exclusive(async () => {
      const added: string[] = [];
      const names = arr(await this.call("tables", []), "tables").map((t) => str(t, "tables item"));
      for (const t of names) {
        if (this.#schema.has(t)) continue;
        const cols = arr(await this.call("schema", [t]), "schema").map((c) => {
          const a = arr(c, "schema column", 3);
          return { name: str(a[0], "column name"), type: normType(a[1]), policy: normPolicy(a[2]) } as Column;
        });
        this.#schema.set(t, { cols, trusted: false });
        added.push(t);
      }
      return added;
    });
  }

  /** Mark a server-learned table as trusted for writes (you vouch for its policies). */
  trustTable(table: string): void {
    const d = this.#schema.get(table);
    if (!d) throw usage(`unknown table: ${table}`);
    this.#schema.set(table, { cols: d.cols, trusted: true });
  }

  // — DDL —
  createTable(name: string, columns: Column[], opts: { ifNotExists?: boolean } = {}): Promise<void> {
    return this.exclusive(async () => {
      this.assertWritable();
      checkName("table", name);
      const seen = new Set<string>();
      for (const c of columns) {
        checkName("column", c.name);
        if (seen.has(c.name)) throw usage(`duplicate column: ${c.name}`);
        seen.add(c.name);
        if (!POLICIES.includes(c.policy)) throw usage(`bad policy for ${c.name}: ${c.policy}`);
        if (!TYPES.includes(c.type)) throw usage(`bad type for ${c.name}: ${c.type}`);
        if (c.policy === "fhe" && c.type !== "int") throw usage(`FHE columns must be INT (column ${c.name})`);
      }
      const r = await this.call("create", opts.ifNotExists
        ? [name, columns.map((c) => [c.name, c.type, c.policy]), true]    // atomic IF NOT EXISTS
        : [name, columns.map((c) => [c.name, c.type, c.policy])]);
      if (r === false) return;                     // already existed: nothing changed, nothing adopted (syncSchema learns it, untrusted)
      if (r !== null && r !== undefined) throw proto("create: unexpected reply");
      this.#schema.set(name, { cols: columns.map((c) => ({ name: c.name, type: c.type, policy: c.policy })), trusted: true });
    });
  }

  /** Drop a table (admin). Forgets its masks. */
  dropTable(name: string, opts: { ifExists?: boolean } = {}): Promise<void> {
    return this.exclusive(async () => {
      this.assertWritable();
      const r = await this.call("drop", opts.ifExists ? [name, true] : [name]);   // atomic IF EXISTS; a missing table is the server's error
      if (r === false) return;                     // did not exist: touch nothing locally
      if (r !== null && r !== undefined) throw proto("drop: unexpected reply");
      this.#schema.delete(name);
      const prefix = name + SEP;
      for (const k of [...this.#masks.keys()]) if (k.startsWith(prefix)) this.delMask(k);
    });
  }

  /** CREATE INDEX ON table (col): PLAIN columns only (role rw+; rolled back with the transaction). */
  createIndex(table: string, col: string): Promise<void> {
    return this.exclusive(async () => {
      this.assertWritable();
      if (this.col(table, col).policy !== "plain") throw usage(`indexes are only for PLAIN columns (${table}.${col})`);
      await this.call("create_index", [table, col]);
    });
  }

  /** DROP INDEX ON table (col). */
  dropIndex(table: string, col: string): Promise<void> {
    return this.exclusive(async () => {
      this.assertWritable();
      this.col(table, col);
      await this.call("drop_index", [table, col]);
    });
  }

  private def(table: string): TableDef {
    const s = this.#schema.get(table);
    if (!s) throw usage(`unknown table: ${table}`);
    return s;
  }
  private cols(table: string): Column[] { return this.def(table).cols; }
  private col(table: string, name: string): Column {
    const c = this.cols(table).find((c) => c.name === name);
    if (!c) throw usage(`no such column: ${table}.${name}`);
    return c;
  }
  private assertWritable(): void {
    if (this.#inDoubt.size) {
      throw usage(`unresolved in-doubt transaction(s) ${[...this.#inDoubt.keys()].join(", ")}: ` +
        `call resolveTransaction() before writing`);
    }
  }
  private assertTrusted(table: string): void {
    const d = this.def(table);
    if (!d.trusted && !this.#trustServerSchema) {
      throw new TorusError("UntrustedSchema",
        `refusing to write to ${table}: its encryption policies were learned from the server, ` +
        `which could mislabel an encrypted column as plain. Create the table from this client / ` +
        `load the vault that created it, or pass trustServerSchema: true (or trustTable()).`);
    }
  }

  // — mask vault with an undo journal (cheap transactions) —
  private setMask(k: string, r: bigint) {
    if (this.#undo) this.#undo.push([k, this.#masks.get(k)]);
    this.#masks.set(k, r);
  }
  private delMask(k: string) {
    if (this.#undo) this.#undo.push([k, this.#masks.get(k)]);
    this.#masks.delete(k);
  }
  private applyUndo(u: Undo) {
    for (let i = u.length - 1; i >= 0; i--) {
      const [k, prev] = u[i];
      if (prev === undefined) this.#masks.delete(k); else this.#masks.set(k, prev);
    }
  }

  // — blinding —
  private encodeCell(v: Value, table: string, c: Column): bigint {
    if (v === null || v === undefined) throw usage(`encrypted column ${table}.${c.name} cannot hold NULL`);
    if (typeof v === "string") throw usage(`cannot encrypt a string (${table}.${c.name})`);
    if (typeof v === "boolean") return v ? 1n : 0n;
    if (isRational(v)) return encodeRational(v.num, v.den);
    if (typeof v === "number" && !Number.isSafeInteger(v)) throw usage(`number ${v} is not a safe integer; pass a bigint`);
    if (typeof v !== "number" && typeof v !== "bigint") throw usage(`cannot encrypt a ${typeof v}`);
    return encodeInt(BigInt(v));
  }

  /** The blinded wire cells (value + optional MAC) and the masks to remember. */
  private blindCell(table: string, c: Column, v: Value): { cells: Array<[string, WireVal]>; masks: Array<[string, bigint]> } {
    const s = this.encodeCell(v, table, c);
    const r = randScalar();
    const cells: Array<[string, WireVal]> = [[c.name, { t: "i", v: mod(s + r).toString() }]];
    const masks: Array<[string, bigint]> = [[c.name, r]];
    if (this.#authenticated) {
      const r2 = randScalar();
      cells.push([MAC + c.name, { t: "i", v: mod(mod(this.#alpha * s) + r2).toString() }]);
      masks.push([MAC + c.name, r2]);
    }
    return { cells, masks };
  }

  // — FHE columns —
  private fheKey(): FheKey {
    if (!this.#fhe) throw usage("this table has FHE columns but no FHE key is loaded (pass fheKey to connect())");
    return this.#fhe;
  }

  /** The integer of an FHE cell: FHE columns hold integers only (no NULL, bool, string, fraction, binary). */
  private fheInt(v: Value, table: string, col: string): bigint {
    if (typeof v === "bigint") return v;
    if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
    if (isRational(v) && v.den !== 0n) {
      const r = rational(v.num, v.den);
      if (typeof r === "bigint") return r;
    }
    throw usage(`FHE column ${table}.${col} holds integers only`);
  }

  /** The encrypted wire cell of an FHE column plus (authenticated) its tag. `rowid` is unknown at INSERT
   *  time: a placeholder tag is sent and replaced by {@link writeCells} once the row id exists. */
  private fheCells(table: string, c: Column, x: bigint, nonce: bigint, rowid?: number): Array<[string, WireVal]> {
    const key = this.fheKey();
    const cells: Array<[string, WireVal]> = [[c.name, wvCell(key.encrypt(x))]];
    if (this.#authenticated) {
      cells.push([FMAC + c.name, wvCell(rowid === undefined ? key.placeholderCell() : key.tag(x, table, c.name, rowid, nonce))]);
      cells.push([FNONCE + c.name, { t: "i", v: nonce.toString() }]);   // a fresh nonce for EVERY write
    }
    return cells;
  }

  /** Several cell writes in ONE atomic `update_cells` RPC per chunk (<= 2000 items and the server's
   *  `max_items`); the caller's transaction makes the chunks atomic together. A server that does not
   *  know `update_cells` gets repeated `update_cell` calls instead, and is not asked again. */
  private async writeCells(table: string, items: Array<[number, string, WireVal]>): Promise<void> {
    const chunk = Math.min(FHE_WRITE_CHUNK, this.serverInfo.limits?.maxItems ?? FHE_WRITE_CHUNK);
    for (let i = 0; i < items.length; i += chunk) {
      const part = items.slice(i, i + chunk);
      if (this.#updateCells) {
        try {
          const n = safeInt(await this.call("update_cells", [table, part], 4096), "update_cells");
          if (n !== part.length) throw proto("update_cells: implausible count");
          continue;
        } catch (e) {
          if (!(e instanceof TorusError && e.kind === "BadRequest" && /unknown method/.test(e.message))) throw e;
          this.#updateCells = false;
        }
      }
      for (const [row, col, w] of part) await this.call("update_cell", [table, row, col, w]);
    }
  }

  private fheTagItems(table: string, rowid: number, tags: Array<[string, bigint, bigint]>): Array<[number, string, WireVal]> {
    if (tags.length === 0) return [];
    const key = this.fheKey();
    return tags.map(([col, x, nonce]) => [rowid, FMAC + col, wvCell(key.tag(x, table, col, rowid, nonce))]);
  }

  private blindRow(table: string, row: Record<string, Value>): {
    wire: Record<string, WireVal>; pending: Array<[string, bigint]>; tags: Array<[string, bigint, bigint]>;
  } {
    this.assertTrusted(table);
    const cols = this.cols(table);
    const known = new Set(cols.map((c) => c.name));
    for (const k of Object.keys(row)) {
      if (!known.has(k)) throw usage(`no such column: ${table}.${k}`);
    }
    const wire: Record<string, WireVal> = Object.create(null);
    const pending: Array<[string, bigint]> = [];
    const tags: Array<[string, bigint, bigint]> = [];
    for (const c of cols) {
      if (!hasOwn(row, c.name)) throw usage(`INSERT must provide column ${table}.${c.name}`);
      const v = row[c.name];
      if (c.policy === "plain") {
        wire[c.name] = wv(v);
      } else if (c.policy === "fhe") {
        const x = this.fheInt(v, table, c.name);
        const nonce = newNonce();
        for (const [n, w] of this.fheCells(table, c, x, nonce)) wire[n] = w;
        if (this.#authenticated) tags.push([c.name, x, nonce]);
      } else {
        const b = this.blindCell(table, c, v);
        for (const [n, w] of b.cells) wire[n] = w;
        pending.push(...b.masks);
      }
    }
    return { wire: { ...wire }, pending, tags };
  }

  // — INSERT: blind encrypted cells, keep masks locally —
  insert(table: string, row: Record<string, Value>): Promise<number> {
    return this.exclusive(async () => {
      this.assertWritable();
      const { wire, pending, tags } = this.blindRow(table, row);
      const run = async (): Promise<number> => {
        const rowid = rowId(await this.call("insert", [table, wire]), "insert");
        for (const [col, r] of pending) this.setMask(mkey(table, rowid, col), r);
        // authenticated FHE: the tag binds the row id, known only now - same transaction as the INSERT
        if (tags.length) await this.writeCells(table, this.fheTagItems(table, rowid, tags));
        return rowid;
      };
      return tags.length ? this.atomically(run) : run();
    });
  }

  /** Bulk insert: every row is blinded locally and sent in `insert_many` round
   *  trips of <= 50 000 rows (all-or-nothing: wrapped in a transaction when
   *  more than one is needed). Returns the new row ids. */
  insertMany(table: string, rows: Array<Record<string, Value>>): Promise<number[]> {
    return this.exclusive(async () => {
      this.assertWritable();
      if (rows.length === 0) return [];
      const blinded = rows.map((r) => this.blindRow(table, r));
      const tagged = blinded.some((b) => b.tags.length > 0);
      const per = 50_000;
      const send = async (): Promise<number[]> => {
        const all: number[] = [];
        for (let i = 0; i < blinded.length; i += per) {
          const part = blinded.slice(i, i + per);
          const ids = arr(await this.call("insert_many", [table, part.map((b) => b.wire)],
            part.length * 24 + 4096), "insert_many", part.length).map((x) => rowId(x, "insert_many"));
          part.forEach((b, k) => { for (const [col, r] of b.pending) this.setMask(mkey(table, ids[k], col), r); });
          const items: Array<[number, string, WireVal]> = [];
          for (let k = 0; k < part.length; k++) items.push(...this.fheTagItems(table, ids[k], part[k].tags));
          if (items.length) await this.writeCells(table, items);
          all.push(...ids);
        }
        return all;
      };
      return blinded.length > per || tagged ? this.atomically(send) : send();
    });
  }

  // — UPDATE / DELETE —
  /** UPDATE ... SET col = value WHERE pred. Atomic: wrapped in an implicit
   *  transaction when none is open. Returns the number of rows changed. */
  update(table: string, assignments: Record<string, Value>, where?: WirePred | null): Promise<number> {
    return this.exclusive(async () => {
      this.assertWritable();
      this.assertTrusted(table);
      for (const col of Object.keys(assignments)) this.col(table, col);
      const pred = wirePred(where);
      return this.atomically(async () => {
        const idxs = await this.matching(table, pred);
        const fheItems: Array<[number, string, WireVal]> = [];
        for (const i of idxs) {
          for (const [col, v] of Object.entries(assignments)) {
            const c = this.col(table, col);
            if (c.policy === "plain") {
              await this.call("update_cell", [table, i, col, wv(v)]);
            } else if (c.policy === "fhe") {
              // a fresh ciphertext (and tag) per row, never one shared cell
              for (const [n, w] of this.fheCells(table, c, this.fheInt(v, table, col), newNonce(), i)) fheItems.push([i, n, w]);
            } else {
              const b = this.blindCell(table, c, v);
              for (const [n, w] of b.cells) await this.call("update_cell", [table, i, n, w]);
              for (const [n, r] of b.masks) this.setMask(mkey(table, i, n), r);
            }
          }
        }
        if (fheItems.length) await this.writeCells(table, fheItems);   // value + tag of every row, atomically batched
        return idxs.length;
      });
    });
  }

  /** DELETE FROM table WHERE pred (tombstones the rows). Returns how many were removed. */
  deleteRows(table: string, where?: WirePred | null): Promise<number> {
    return this.exclusive(async () => {
      this.assertWritable();
      this.cols(table);
      const pred = wirePred(where);
      const idxs = await this.matching(table, pred);
      let n = 0;
      for (const part of idxs.length ? chunked(idxs) : []) {
        const k = safeInt(await this.call("delete_rows", [table, part]), "delete_rows");
        if (k < 0 || k > part.length) throw proto("delete_rows: implausible count");
        n += k;
      }
      return n;
    });
  }

  private async atomically<T>(fn: () => Promise<T>): Promise<T> {
    if (this.#inTx) return fn();
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
  get inTransaction(): boolean { return this.#inTx; }
  /** Ids of COMMITs whose outcome is still unknown. */
  get inDoubtTransactions(): string[] { return [...this.#inDoubt.keys()]; }

  /** Open a transaction (with a fresh random id, so a lost COMMIT can be
   *  settled via `tx_status`). The client journals every mask change so a
   *  rollback (or a failed commit) restores the vault exactly. */
  begin(): Promise<void> {
    return this.exclusive(async () => {
      this.assertWritable();
      if (this.#inTx) throw usage("a transaction is already open");
      const txid = randomBytes(16).toString("hex");
      await this.call("tx_begin", [txid]);       // if this throws nothing changed
      this.#txid = txid;
      this.#undo = [];
      this.#txSchema = new Map(this.#schema);
      this.#inTx = true;
    });
  }

  /** The server definitely holds no transaction for us: drop the local one. */
  private abortLocal(): void {
    if (this.#undo) this.applyUndo(this.#undo);
    if (this.#txSchema) this.#schema = this.#txSchema;
    this.#undo = null;
    this.#txSchema = null;
    this.#txid = null;
    this.#inTx = false;
  }

  /** Commit. No-op outside a transaction. If the reply is lost the outcome is
   *  settled with `tx_status` on a fresh connection; the vault is restored ONLY
   *  when the server definitely did not commit. */
  commit(): Promise<void> {
    return this.exclusive(async () => {
      if (!this.#inTx) return;
      const txid = this.#txid!;
      try {
        await Client.rawCall(this.#tr, "tx_commit", []);
      } catch (e) {
        if (e instanceof TorusError && (e.kind === "ConnectionError" || e.kind === "TimeoutError")) {
          await this.settleLostCommit(txid, e);
          return;
        }
        // the server ANSWERED with an error: it holds no committed transaction
        this.abortLocal();
        await this.bestEffortRollback();
        throw e;
      }
      this.#undo = null;
      this.#txSchema = null;
      this.#txid = null;
      this.#inTx = false;
    });
  }

  private moveToInDoubt(txid: string): void {
    this.#inDoubt.set(txid, { undo: this.#undo ?? [], schema: this.#txSchema ?? new Map(this.#schema) });
    this.#undo = null; this.#txSchema = null; this.#txid = null; this.#inTx = false;
  }

  private async askStatus(txid: string, tr: Transport): Promise<string> {
    for (let i = 0; ; i++) {
      const s = str(await Client.rawCall(tr, "tx_status", [txid]), "tx_status");
      if (s !== "open" || i >= INDOUBT_POLLS) return s;
      await new Promise((r) => setTimeout(r, 100));   // the dead session may still be unwinding
    }
  }

  private async settleLostCommit(txid: string, cause: TorusError): Promise<void> {
    this.#tr.destroy();                          // the old session (and its tx) must go first
    let fresh: { tr: Transport; info: Client["serverInfo"] };
    let status: string;
    try {
      fresh = await Client.openTransport(this.#target, this.#token);
      try {
        status = await this.askStatus(txid, fresh.tr);
      } catch (e) {
        fresh.tr.destroy();
        throw e;
      }
    } catch (e) {
      this.moveToInDoubt(txid);
      throw new TransactionInDoubt(txid,
        `COMMIT of transaction ${txid} was sent but its reply was lost (${cause.message}) and the outcome ` +
        `could not be learned (${(e as Error).message}). The client keeps both vault states; call ` +
        `reconnect() then resolveTransaction("${txid}").`);
    }
    if (status === "committed") {
      this.#tr = fresh.tr; this.serverInfo = fresh.info;
      this.#undo = null; this.#txSchema = null; this.#txid = null; this.#inTx = false;
      return;                                    // it DID commit: keep the new masks
    }
    if (status === "unknown") {
      this.#tr = fresh.tr; this.serverInfo = fresh.info;
      this.abortLocal();
      throw new TorusError(cause.kind,
        `COMMIT of transaction ${txid} did not take effect (${cause.message}); rolled back`);
    }
    fresh.tr.destroy();
    this.moveToInDoubt(txid);
    throw new TransactionInDoubt(txid, `transaction ${txid} is still ${JSON.stringify(status)} on the server`);
  }

  /** Re-open the connection (same host/port/credentials). */
  reconnect(): Promise<void> {
    return this.exclusive(async () => {
      this.#tr.destroy();
      const fresh = await Client.openTransport(this.#target, this.#token);
      this.#tr = fresh.tr;
      this.serverInfo = fresh.info;
      this.#inTx = false; this.#undo = null; this.#txSchema = null; this.#txid = null;
    });
  }

  /** Settle an in-doubt COMMIT. With `committed` given, trust the caller;
   *  otherwise ask the server (`tx_status`) over the current connection. */
  resolveTransaction(txid: string, committed?: boolean): Promise<boolean> {
    return this.exclusive(async () => {
      const rec = this.#inDoubt.get(txid);
      if (!rec) throw usage(`no in-doubt transaction ${txid}`);
      if (committed === undefined) {
        const status = await this.askStatus(txid, this.#tr);
        if (status === "open") throw new TransactionInDoubt(txid, `transaction ${txid} is still open on the server`);
        committed = status === "committed";
      }
      if (!committed) {
        this.applyUndo(rec.undo);
        this.#schema = rec.schema;
      }
      this.#inDoubt.delete(txid);
      return committed;
    });
  }

  /** Roll back server state and the local mask vault. No-op outside a transaction. */
  rollback(): Promise<void> {
    return this.exclusive(async () => {
      if (!this.#inTx) return;
      try {
        await Client.rawCall(this.#tr, "tx_rollback", []);
      } finally {
        this.abortLocal();                       // masks restored even if the RPC failed
      }
    });
  }

  /** `await db.transaction(async () => { ... })` - commit on success, roll back on throw.
   *  The whole transaction holds the client exclusively, so concurrent callers
   *  cannot interleave with it. */
  transaction<T>(fn: (db: Client) => Promise<T>): Promise<T> {
    return this.exclusive(async () => {
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
    });
  }

  // — row selection —
  private async matching(table: string, where?: WirePred | null): Promise<number[]> {
    const cols = this.cols(table);
    if (where) {
      for (const g of where.or) for (const a of g) {
        const c = cols.find((x) => x.name === a.c);
        if (c && c.policy !== "plain") throw usage(`predicates on encrypted column '${a.c}' are not supported`);
        if (c && (a.op === "like" || a.op === "not_like") && c.type !== "str") {
          throw usage(`LIKE needs a STR column ('${a.c}' is ${c.type})`);
        }
      }
    }
    return arr(await this.call("matching_rowids", [table, where ?? null]), "matching_rowids")
      .map((i) => rowId(i, "matching_rowids"));
  }

  private mask(table: string, i: number, col: string): bigint {
    const m = this.#masks.get(mkey(table, i, col));
    if (m === undefined) {
      throw usage(`no mask for ${table}[${i}].${col}: row not inserted by this vault`);
    }
    return m;
  }

  private encryptedCol(table: string, col: string): Column {
    const c = this.col(table, col);
    if (c.policy === "plain") throw usage(`${table}.${col} is a PLAIN column; nothing to unblind`);
    return c;
  }

  /** Σ blinded cells (chunked) minus Σ masks, MAC-verified when authenticated. */
  private async sumScalar(table: string, col: string, idxs: number[]): Promise<bigint> {
    const one = async (c: string): Promise<bigint> => {
      let b = 0n;
      for (const part of idxs.length ? chunked(idxs) : [[] as number[]]) {
        b = mod(b + mod(parseBig(await this.call("blinded_sum", [table, c, part], 4096), "blinded_sum")));
      }
      let m = 0n;
      for (const i of idxs) m = mod(m + this.mask(table, i, c));
      return mod(b - m);
    };
    const y = await one(col);
    if (this.#authenticated) {
      const M = await one(MAC + col);
      if (M !== mod(this.#alpha * y)) {
        throw new TorusError("IntegrityError", `MAC check failed on sum(${col}) - server returned a forged/incorrect aggregate`);
      }
    }
    return y;
  }

  // — Π_lin: SUM over the matched rows (no server key) —
  sum(table: string, col: string, where?: WirePred | null): Promise<Decoded> {
    return this.exclusive(async () => {
      this.encryptedCol(table, col);
      const idxs = await this.matching(table, wirePred(where));
      if (this.col(table, col).policy === "fhe") return this.fheSum(table, col, idxs);
      return this.sumIds(table, col, idxs);
    });
  }

  /** `k * SUM(col)` over an FHE column: the SERVER multiplies the summed ciphertext by the public scalar
   *  `k` (EC scalar multiplication, not a pairing); the result `k * sum` must lie in the key's range. */
  scaledSum(table: string, col: string, k: bigint | number, where?: WirePred | null): Promise<bigint> {
    return this.exclusive(async () => {
      this.encryptedCol(table, col);
      if (this.col(table, col).policy !== "fhe") throw usage("scaledSum is only supported on FHE columns");
      const kk = typeof k === "bigint" ? k : Number.isSafeInteger(k) ? BigInt(k) : null;
      if (kk === null || kk > FHE_MAX_K || kk < -FHE_MAX_K) throw usage("the scale must be an integer with |k| <= 2^40");
      return this.fheSum(table, col, await this.matching(table, wirePred(where)), kk);
    });
  }

  private async sumIds(table: string, col: string, idxs: number[]): Promise<Decoded> {
    this.encryptedCol(table, col);
    if (this.col(table, col).policy === "fhe") {
      throw usage(`FHE column ${table}.${col} cannot be used in a join query`);
    }
    return decode(await this.sumScalar(table, col, idxs));
  }

  /** SUM (times `k`) of an FHE column: chunked `fhe_sum` calls, partial blobs combined here by G1 addition,
   *  then opened by the key (and, when authenticated, checked against the integrity tags). */
  private async fheSum(table: string, col: string, idxs: number[], k: bigint = 1n): Promise<bigint> {
    const key = this.fheKey();
    if (idxs.length === 0) return 0n;
    let total: Buffer | null = null, tags: Buffer | null = null;
    const sumChunk = Math.min(FHE_SUM_CHUNK, this.serverInfo.limits?.fhe?.maxSumRows ?? FHE_SUM_CHUNK);
    for (let i = 0; i < idxs.length; i += sumChunk) {
      const part = idxs.slice(i, i + sumChunk);
      const args: unknown[] = k === 1n ? [table, col, part] : [table, col, part, Number(k)];
      const b = blob(await this.call("fhe_sum", args, 4096), "fhe_sum", FHE_SUM_BYTES);
      total = total === null ? b : fheAddSums(total, b);
      if (this.#authenticated) {
        let t: Buffer;
        try {
          t = blob(await this.call("fhe_sum", [table, FMAC + col, ...args.slice(2)], 4096), "fhe_sum", FHE_SUM_BYTES);
        } catch (e) {
          if (e instanceof TorusError && /integrity tag/.test(e.message)) {
            throw new TorusError("IntegrityError", `${table}.${col} has no integrity tags - it was written without authentication`);
          }
          throw e;
        }
        tags = tags === null ? t : fheAddSums(tags, t);
      }
    }
    const v = this.#authenticated
      ? key.decryptSumVerified(total!, tags!, table, col, idxs, await this.fetchNonces(table, col, idxs), k)
      : key.decryptSum(total!);
    return BigInt(v);
  }

  /** Σ aᵢ·bᵢ over two FHE columns: the server multiplies ciphertexts with the pairing-based ★_ct. */
  private async fheDot(lt: string, lc: string, lids: number[], rt: string, rc: string, rids: number[],
                       backend?: FheBackend): Promise<bigint> {
    const key = this.fheKey();
    if (backend !== undefined && backend !== "pyecc" && backend !== "mcl") throw usage("backend must be 'pyecc' or 'mcl'");
    if (lids.length === 0) return 0n;
    if (this.#fheDotMode === "local") {
      // verified: every operand cell is read (tag-checked when authenticated), the owner multiplies
      const a = await this.fheReveal(lt, lc, lids), b = await this.fheReveal(rt, rc, rids);
      return a.reduce((acc, x, k) => acc + x * b[k], 0n);
    }
    // the server's recommended size for the requested back end (unspecified = its default is "auto":
    // be conservative and size for pyecc), never above its published cap
    const lim = this.serverInfo.limits?.fhe;
    const be = backend ?? "pyecc";
    const rec = lim?.recommendedDotRows[be] ?? (be === "mcl" ? FHE_DOT_CHUNK_NATIVE : FHE_DOT_CHUNK);
    const chunk = Math.max(1, Math.min(rec, lim?.maxDotRows[be] ?? rec));
    let total: Buffer | null = null;
    for (let i = 0; i < lids.length; i += chunk) {
      const args: unknown[] = [lt, lc, lids.slice(i, i + chunk), rt, rc, rids.slice(i, i + chunk)];
      if (backend !== undefined) args.push(backend);
      const b = blob(await this.call("fhe_dot", args, 8192), "fhe_dot", FHE_DOT_BYTES);
      // `backend` is only a request: the server may use its own, and the blob's tag says which (both decrypt)
      total = total === null ? b : fheMulDots(total, b);
    }
    return BigInt(key.decryptDot(total!));
  }

  count(table: string, where?: WirePred | null): Promise<number> {
    return this.exclusive(async () => (await this.matching(table, wirePred(where))).length);
  }

  /** AVG = SUM / COUNT as an exact rational (null over zero rows). */
  avg(table: string, col: string, where?: WirePred | null): Promise<Decoded | null> {
    return this.exclusive(async () => {
      this.encryptedCol(table, col);
      const idxs = await this.matching(table, wirePred(where));
      if (idxs.length === 0) return null;
      const total = this.col(table, col).policy === "fhe"
        ? await this.fheSum(table, col, idxs) : await this.sumIds(table, col, idxs);
      return divide(total, BigInt(idxs.length));
    });
  }

  // — Π_mult: encrypted inner product sum a_i*b_i (Beaver triples) —
  dot(table: string, left: string, right: string, where?: WirePred | null, backend?: FheBackend): Promise<Decoded> {
    return this.exclusive(async () => {
      const fl = this.col(table, left).policy === "fhe", fr = this.col(table, right).policy === "fhe";
      if (fl || fr) {
        // FHE: Σ aᵢ·bᵢ by the server's pairings. `backend` picks the pairing library of the server
        // ("pyecc" slow/portable, "mcl" native); undefined = the server's default.
        if (!(fl && fr)) throw new TorusError("PlanError", "DOT cannot mix FHE and PAIRED columns");
        const idxs = await this.matching(table, wirePred(where));
        return this.fheDot(table, left, idxs, table, right, idxs, backend);
      }
      if (backend !== undefined) throw usage("the backend argument is only for FHE columns");
      this.checkDot(table, left); this.checkDot(table, right);
      const idxs = await this.matching(table, wirePred(where));
      return this.dotPairs(table, left, idxs, table, right, idxs);
    });
  }

  /** DOT needs both columns PAIRED and INT (rational inner products collapse). */
  private checkDot(table: string, col: string): void {
    const c = this.col(table, col);
    if (c.policy !== "paired") {
      throw new TorusError("PlanError", `DOT requires \`paired\` policy on column '${col}'`);
    }
    if (c.type !== "int") {
      throw new TorusError("PlanError", `DOT requires INT columns (column '${col}' is ${c.type})`);
    }
  }

  private async dotPairs(lt: string, lc: string, lids: number[],
                         rt: string, rc: string, rids: number[]): Promise<Decoded> {
    this.checkDot(lt, lc); this.checkDot(rt, rc);
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
    const egs: bigint[] = [];
    for (let i = 0; i < openings.length; i += LIST_CHUNK) {
      const part = openings.slice(i, i + LIST_CHUNK);
      arr(await this.call("mult_combine_batch", [part], part.length * (MAX_DIGITS + 8) + 4096),
        "mult_combine_batch", part.length).forEach((x) => egs.push(parseBig(x, "mult_combine_batch")));
    }
    let acc = 0n;
    for (let k = 0; k < openings.length; k++) {
      const [e, g] = openings[k].map(BigInt);
      const { u, v, w } = triples[k];
      if (this.#authenticated && mod(egs[k]) !== mod(e * g)) {
        throw new TorusError("IntegrityError", "server returned a forged product term in DOT (e*g mismatch)");
      }
      acc = mod(acc + w + e * v + g * u + egs[k]);
    }
    return decode(acc);
  }

  /** Blinded cells minus masks = the encoded scalars (not yet decoded);
   *  MAC-verified per cell when authenticated. */
  private async unblindCells(table: string, col: string, ids: number[]): Promise<bigint[]> {
    const fetch = async (c: string): Promise<bigint[]> => {
      const out: bigint[] = [];
      for (const part of ids.length ? chunked(ids) : []) {
        const ws = arr(await this.call("blinded_cells", [table, c, part], part.length * (MAX_DIGITS + 40) + 4096),
          "blinded_cells", part.length);
        ws.forEach((w, k) => out.push(mod(scalarCell(w) - this.mask(table, part[k], c))));
      }
      return out;
    };
    const ss = await fetch(col);
    if (this.#authenticated) {
      const ms = await fetch(MAC + col);
      ss.forEach((s, k) => {
        if (ms[k] !== mod(this.#alpha * s)) {
          throw new TorusError("IntegrityError",
            `MAC check failed reading ${col} (row ${ids[k]}) - the stored encrypted value was tampered with`);
        }
      });
    }
    return ss;
  }

  // — reveal columns —
  /** Plain or decrypted values of `col` for the given row ids (null id -> null). */
  column(table: string, col: string, ids: Array<number | null>): Promise<Value[]> {
    return this.exclusive(() => this.columnIn(table, col, ids));
  }

  private async columnIn(table: string, col: string, ids: Array<number | null>): Promise<Value[]> {
    const c = this.col(table, col);
    const uniq = [...new Set(ids.filter((i): i is number => i !== null))].sort((a, b) => a - b);
    const got = new Map<number, Value>();
    if (uniq.length) {
      if (c.policy === "plain") {
        for (const part of chunked(uniq)) {
          const ws = arr(await this.call("plain_cells", [table, col, part], part.length * (MAX_DIGITS * 2 + 60) + 4096),
            "plain_cells", part.length);
          ws.forEach((w, k) => got.set(part[k], uwv(w)));
        }
      } else if (c.policy === "fhe") {
        const vs = await this.fheReveal(table, col, uniq);
        vs.forEach((v, k) => got.set(uniq[k], v));
      } else {
        const ss = await this.unblindCells(table, col, uniq);
        ss.forEach((s, k) => got.set(uniq[k], decode(s)));
      }
    }
    return ids.map((i) => (i === null ? null : got.get(i) ?? null));
  }

  /** The write nonces the server reports for `ids` (`null` where absent or not an integer: the
   *  verification then fails with IntegrityError). */
  private async fetchNonces(table: string, col: string, ids: number[]): Promise<Array<bigint | null>> {
    const out: Array<bigint | null> = [];
    for (let i = 0; i < ids.length; i += FHE_READ_CHUNK) {
      const part = ids.slice(i, i + FHE_READ_CHUNK);
      const ws = arr(await this.call("plain_cells", [table, FNONCE + col, part], part.length * 120 + 4096), "plain_cells", part.length);
      for (const w of ws) {
        const o = obj(w, "plain_cells");
        out.push(o.t === "i" ? parseBig(o.v, "write nonce") : null);
      }
    }
    return out;
  }

  /** Decrypt the FHE cells of `ids` (verified against their tags when authenticated). */
  private async fheReveal(table: string, col: string, ids: number[]): Promise<bigint[]> {
    const key = this.fheKey();
    const fetch = async (c: string): Promise<Array<Buffer | null>> => {
      const out: Array<Buffer | null> = [];
      for (let i = 0; i < ids.length; i += FHE_READ_CHUNK) {
        const part = ids.slice(i, i + FHE_READ_CHUNK);
        const ws = arr(await this.call("plain_cells", [table, c, part], part.length * 700 + 4096), "plain_cells", part.length);
        for (const w of ws) out.push(binCell(w, "plain_cells"));
      }
      return out;
    };
    const cells = await fetch(col);
    if (cells.some((c) => c === null)) throw proto(`${table}.${col}: the server returned an empty FHE cell`);
    if (!this.#authenticated) return cells.map((c) => BigInt(key.decryptCell(c!)));
    const tags = await fetch(FMAC + col);
    const nonces = await this.fetchNonces(table, col, ids);
    return cells.map((c, k) => BigInt(key.decryptCellVerified(c, tags[k], table, col, ids[k], nonces[k])));
  }

  /** SELECT cols FROM table WHERE pred (plain columns as stored, encrypted ones unblinded). */
  select(table: string, columns: string[], where?: WirePred | null,
         opts: { offset?: number; limit?: number } = {}): Promise<Array<Record<string, Value>>> {
    return this.exclusive(async () => {
      const off = opts.offset ?? 0;
      if (!Number.isSafeInteger(off) || off < 0) throw usage("offset must be a non-negative integer");
      if (opts.limit !== undefined && (!Number.isSafeInteger(opts.limit) || opts.limit < 0)) {
        throw usage("limit must be a non-negative integer");
      }
      let idxs = await this.matching(table, wirePred(where));       // row-id order
      idxs = idxs.slice(off, opts.limit === undefined ? undefined : off + opts.limit);
      const vecs: Value[][] = [];
      for (const c of columns) vecs.push(await this.columnIn(table, c, idxs));
      return idxs.map((_i, k) => {
        const o: Record<string, Value> = {};
        // defineProperty: a column called "constructor" / "toString" must not collide
        columns.forEach((c, j) => Object.defineProperty(o, c,
          { value: vecs[j][k], enumerable: true, writable: true, configurable: true }));
        return o;
      });
    });
  }

  // — JOIN: client-side hash join over plaintext keys (like the Python engine) —
  /**
   * Hash join of `left` with each step in turn. Join keys must be PLAIN
   * columns (the server only ever sees plaintext keys it already stores; no
   * blinded value is touched). NULL keys never match. Returns row-id tuples.
   */
  join(left: string, steps: JoinStep[], opts: JoinOptions = {}): Promise<JoinResult> {
    return this.exclusive(async () => {
      this.cols(left);
      const firstAlias = opts.alias ?? left;
      const aliases = [firstAlias];
      const tables: Record<string, string> = Object.create(null);
      tables[firstAlias] = left;

      // split WHERE: left-table atoms go to the server, others filter the joined rows
      let push: WirePred | null = null;
      let post: WirePred | null = null;
      if (opts.where) {
        const atoms = opts.where.or.flat();
        if (atoms.every((a) => a.a === undefined || a.a === firstAlias)) {
          push = { or: opts.where.or.map((g) => g.map(({ a: _a, ...rest }) => rest as Atom)) };
        } else {
          post = opts.where;
        }
      }
      let tuples: Array<Array<number | null>> = (await this.matching(left, push)).map((i) => [i]);

      for (const st of steps) {
        const alias = st.alias ?? st.table;
        if (alias in tables) throw usage(`duplicate alias: ${alias}`);
        const leftAlias = st.leftAlias ?? firstAlias;
        if (!(leftAlias in tables)) throw usage(`unknown or later alias in ON clause: ${leftAlias}`);
        const lt = tables[leftAlias];
        if (this.col(lt, st.leftCol).policy !== "plain" || this.col(st.table, st.rightCol).policy !== "plain") {
          throw usage("JOIN keys must be PLAIN columns");
        }
        const kind = st.kind ?? "inner";
        if (kind !== "inner" && kind !== "left") throw usage(`bad join kind: ${kind}`);

        const rightIds = await this.matching(st.table, null);
        const rightKeys = await this.columnIn(st.table, st.rightCol, rightIds);
        const rightMap = new Map<string, number[]>();
        rightIds.forEach((rid, k) => {
          const key = plainKey(rightKeys[k]);
          if (key === null) return;                                // NULL never equals NULL
          const l = rightMap.get(key);
          if (l) l.push(rid); else rightMap.set(key, [rid]);
        });
        const lpos = aliases.indexOf(leftAlias);
        const lkeys = await this.columnIn(lt, st.leftCol, tuples.map((t) => t[lpos]));
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

      if (post) {
        const need = new Map<string, { alias: string; col: string }>();
        for (const g of post.or) for (const a of g) {
          const al = a.a ?? firstAlias;
          if (!(al in tables)) throw usage(`unknown alias in WHERE: ${al}`);
          if (this.col(tables[al], a.c).policy !== "plain") throw usage("WHERE may only reference PLAIN columns");
          need.set(al + SEP + a.c, { alias: al, col: a.c });
        }
        const vals = new Map<string, Value[]>();
        for (const [k, { alias, col }] of need) {
          const p = aliases.indexOf(alias);
          vals.set(k, await this.columnIn(tables[alias], col, tuples.map((t) => t[p])));
        }
        tuples = tuples.filter((_t, i) =>
          post!.or.some((g) => g.every((a) => atomMatches(vals.get((a.a ?? firstAlias) + SEP + a.c)![i], a))));
      }
      return { aliases, tables, tuples };
    });
  }

  private aliasPos(j: JoinResult, alias: string): number {
    const p = j.aliases.indexOf(alias);
    if (p < 0) throw usage(`unknown join alias: ${alias}`);
    return p;
  }

  /** Values of alias.col for every joined row (null on the NULL side). */
  joinColumn(j: JoinResult, alias: string, col: string): Promise<Value[]> {
    return this.exclusive(async () => {
      const p = this.aliasPos(j, alias);
      if (this.col(j.tables[alias], col).policy === "fhe") {
        throw usage(`FHE column ${j.tables[alias]}.${col} cannot be used in a join query`);
      }
      return this.columnIn(j.tables[alias], col, j.tuples.map((t) => t[p]));
    });
  }

  /** SUM(alias.col) over the joined rows via Π_lin; the NULL side is skipped
   *  and a row joined k times counts k times. */
  joinSum(j: JoinResult, alias: string, col: string): Promise<Decoded> {
    return this.exclusive(async () => {
      const p = this.aliasPos(j, alias);
      const ids = j.tuples.map((t) => t[p]).filter((i): i is number => i !== null);
      return this.sumIds(j.tables[alias], col, ids);
    });
  }

  /** COUNT(*) of the joined rows. */
  joinCount(j: JoinResult): number { return j.tuples.length; }

  /** DOT(a.x, b.y) over joined rows where both sides are non-null (Π_mult). */
  joinDot(j: JoinResult, aliasA: string, colA: string, aliasB: string, colB: string): Promise<Decoded> {
    return this.exclusive(async () => {
      const pa = this.aliasPos(j, aliasA), pb = this.aliasPos(j, aliasB);
      const rows = j.tuples.filter((t) => t[pa] !== null && t[pb] !== null);
      return this.dotPairs(j.tables[aliasA], colA, rows.map((t) => t[pa] as number),
                           j.tables[aliasB], colB, rows.map((t) => t[pb] as number));
    });
  }

  // — orphans: live rows on the server this vault cannot decrypt (crash between
  //   the server accepting an INSERT and the vault being saved). Driven by the
  //   live row ids the server returns, never by a server-claimed row count. —
  findOrphans(): Promise<Record<string, number[]>> {
    return this.exclusive(async () => {
      const out: Record<string, number[]> = {};
      for (const [table, d] of this.#schema) {
        // FHE columns need no mask: any client holding the key reads them
        const enc = d.cols.filter((c) => c.policy !== "plain" && c.policy !== "fhe").map((c) => c.name);
        if (!enc.length) continue;
        const live = await this.matching(table, null);
        const bad = live.filter((i) => enc.some((c) => !this.#masks.has(mkey(table, i, c))));
        if (bad.length) Object.defineProperty(out, table, { value: bad, enumerable: true, writable: true, configurable: true });
      }
      return out;
    });
  }

  // — vault persistence —
  /**
   * Write the mask vault (masks, the schema policies you created, and the MAC
   * key) to a JSON file ATOMICALLY (temp file + fsync + rename + directory
   * fsync) with mode 0600. Missing parent directories are created. The vault
   * is the owner's one long-lived secret: losing it loses the data, leaking it
   * breaks confidentiality. Refused while a COMMIT is in doubt.
   */
  saveVault(file?: string): void {
    const target = file ?? this.#vaultFile;
    if (!target) throw usage("no vault path given");
    if (this.#inDoubt.size) throw usage("cannot save the vault while a COMMIT is in doubt; resolveTransaction() first");
    if (this.#inTx) throw usage("cannot save the vault inside an open transaction");
    const entries = [...this.#masks].map(([k, r]) => {
      const [table, rowid, col] = k.split(SEP);
      return [table, Number(rowid), col, r.toString()];
    });
    const schema: Record<string, string[][]> = Object.create(null);
    for (const [t, d] of this.#schema) if (d.trusted) schema[t] = d.cols.map((c) => [c.name, c.type, c.policy]);
    const body = JSON.stringify({
      version: 2, masks: entries, schema: { ...schema },
      authenticated: this.#authenticated, alpha: this.#authenticated ? this.#alpha.toString() : undefined,
    });
    const dir = path.dirname(target);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = path.join(dir, `.${path.basename(target)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
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
    try {                                          // make the rename itself durable
      const dfd = fs.openSync(dir, "r");
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* not supported on this platform (e.g. Windows) */ }
    this.#vaultFile = this.#vaultFile ?? target;
  }

  /** Replace the in-memory mask vault (and trusted schema) with the one in `file`. */
  loadVault(file?: string): void {
    const src = file ?? this.#vaultFile;
    if (!src) throw usage("no vault path given");
    if (this.#inTx) throw usage("cannot load a vault inside an open transaction");
    const bad = (m: string) => usage(`${src} is not a valid TorusDB vault: ${m}`);
    let doc: any;
    try {
      doc = JSON.parse(fs.readFileSync(src, "utf8"));
    } catch (e) {
      throw usage(`cannot read vault ${src}: ${(e as Error).message}`);
    }
    if (!doc || typeof doc !== "object" || (doc.version !== 1 && doc.version !== 2) || !Array.isArray(doc.masks)) {
      throw bad("wrong version/shape");
    }
    const m = new Map<string, bigint>();
    for (const e of doc.masks) {
      if (!Array.isArray(e) || e.length !== 4) throw bad("corrupt mask entry");
      const [t, i, c, r] = e;
      if (typeof t !== "string" || typeof c !== "string") throw bad("corrupt mask entry");
      if (typeof i !== "number" || !Number.isSafeInteger(i) || i < 0) throw bad("bad row id");
      if (typeof r !== "string" || !/^[0-9]{1,90}$/.test(r)) throw bad("bad mask");
      const rv = BigInt(r);
      if (rv >= N) throw bad("mask out of range");
      m.set(mkey(t, i, c), rv);
    }
    const sch: SchemaMap = new Map();
    if (doc.version === 2 && doc.schema !== undefined) {
      if (doc.schema === null || typeof doc.schema !== "object") throw bad("bad schema");
      for (const [t, cols] of Object.entries(doc.schema)) {
        if (!Array.isArray(cols)) throw bad("bad schema");
        sch.set(t, { trusted: true, cols: cols.map((c: unknown) => {
          if (!Array.isArray(c) || c.length !== 3 || typeof c[0] !== "string") throw bad("bad schema column");
          return { name: c[0], type: normType(c[1]), policy: normPolicy(c[2]) };
        }) });
      }
    }
    const auth = doc.authenticated === true;
    if (auth) {
      if (typeof doc.alpha !== "string" || !/^[0-9]{1,90}$/.test(doc.alpha) || BigInt(doc.alpha) === 0n || BigInt(doc.alpha) >= N) {
        throw bad("bad MAC key");
      }
      if (!this.#authenticated) {
        throw usage(`${src} was created in authenticated (MAC) mode; connect with authenticated: true`);
      }
    } else if (this.#authenticated && m.size > 0) {
      throw usage(`${src} was created without MACs; refusing to run authenticated mode on it`);
    }
    this.#masks = m;
    for (const [t, d] of sch) this.#schema.set(t, d);       // vault policies are the trust anchor
    if (auth) this.#alpha = BigInt(doc.alpha);
    this.#vaultFile = this.#vaultFile ?? src;
  }

  /** Number of masks currently held (diagnostics/tests). */
  get maskCount(): number { return this.#masks.size; }
}

/** a / d as an exact rational (reduced; bigint when integral). */
function divide(a: Decoded, d: bigint): Decoded {
  const num = typeof a === "bigint" ? a : a.num;
  const den = typeof a === "bigint" ? 1n : a.den;
  return rational(num, den * d);
}
