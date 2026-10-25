// SPDX-License-Identifier: Apache-2.0
// Anchored table-state integrity for authenticated FHE tables (port of core/torusdb_core/fhe_anchor.py).
//
// Tags make a changed VALUE detectable; they cannot tell the owner which rows exist or whether the table
// is current. That needs a little owner-trusted state, the ANCHOR: per table {epoch, root, count, pending}.
//   leaf(row) = PRF(K_anchor, table, rowid, canonical(row)) mod n,   root = sum of the leaves of live rows.
// The server cannot compute a leaf, so the only state it can present whose leaves sum to `root` is the
// anchored one. The file format of FileAnchor is byte-compatible with the Python implementation (same JSON
// layout, 0600, temp file + fsync + rename, epoch compare-and-swap, `pending`, last 8 roots), so a Python,
// TypeScript or Rust owner can alternate on the same anchor file.

import * as fs from "fs";
import * as path from "path";
import { createHash, randomBytes } from "crypto";
import { TorusError } from "./errors";
import { FheKey, FHE_N } from "./fhe";

const N = FHE_N;
export const ANCHOR_FORMAT = "torussql-fhe-anchor";
export const ANCHOR_FORMAT_VERSION = 1;
export const ANCHOR_HISTORY = 8;
const MAX_FILE = 64 << 20;

const integrity = (m: string) => new TorusError("IntegrityError", m);
const fileErr = (m: string) => new TorusError("AnchorFileError", m);
const conflict = (m: string) => new TorusError("AnchorConflict", m);
const usage = (m: string) => new TorusError("InterfaceError", m);

/** The server presents an OLDER state than the anchor records (a lagging replica, or a rollback). */
export class StaleServerError extends TorusError {
  constructor(m: string) {
    super("StaleServerError", m);
    this.name = "StaleServerError";
    Object.setPrototypeOf(this, StaleServerError.prototype);
  }
}

// ── anchor state ─────────────────────────────────────────────────────────────
export interface Pending {
  epoch: number; root: bigint; count: number; txid: string | null; drop: boolean; created: boolean;
}
export interface Entry {
  epoch: number; root: bigint; count: number; pending: Pending | null;
  /** [epoch, root, count], newest last (at most 8) */
  history: Array<[number, bigint, number]>;
}
/** One table's part of a commit. `expectEpoch` null = the anchor must not know the table yet; `root` null drops it. */
export interface Change { expectEpoch: number | null; root: bigint | null; count: number }

/** All operations are atomic; `expect*` arguments are compare-and-swap. */
export interface Anchor {
  get(table: string): Entry | null;
  tables(): string[];
  beginCommit(changes: Map<string, Change>, txid: string | null): void;
  finishCommit(tables: string[], txid: string | null): void;
  abort(tables: string[], txid: string | null): void;
  set(table: string, root: bigint, count: number, expectEpoch: number | null): Entry;
  remove(table: string, expectEpoch?: number | null): void;
}

type State = Map<string, Entry>;
const mod = (a: bigint) => ((a % N) + N) % N;

function cloneState(st: State): State { return new Map(st); }

/** Shared logic; subclasses provide `atomic(fn, write)` (one read-modify-write over the state map). */
abstract class StateAnchor implements Anchor {
  protected abstract atomic<T>(fn: (st: State) => T, write: boolean): T;

  get(t: string) { return this.atomic((st) => st.get(t) ?? null, false); }
  tables() { return this.atomic((st) => [...st.keys()].sort(), false); }

  beginCommit(changes: Map<string, Change>, txid: string | null = null) {
    if (changes.size === 0) return;
    this.atomic((st) => {
      for (const [t, ch] of changes) {
        const e = st.get(t);
        if (e === undefined) {
          if (ch.expectEpoch !== null) throw conflict(`anchor: ${t} has no entry (expected epoch ${ch.expectEpoch})`);
        } else if (ch.expectEpoch !== e.epoch) {
          throw conflict(`anchor: ${t} is at epoch ${e.epoch}, the transaction was based on ${ch.expectEpoch} (another owner committed)`);
        } else if (e.pending !== null) {
          throw conflict(`anchor: ${t} already has a pending commit`);
        }
      }
      for (const [t, ch] of changes) {
        const old = st.get(t);
        const created = old === undefined;
        const e: Entry = old ?? { epoch: 0, root: 0n, count: 0, pending: null, history: [] };
        st.set(t, { ...e, pending: { epoch: e.epoch + 1, root: mod(ch.root ?? 0n), count: ch.count, txid, drop: ch.root === null, created } });
      }
    }, true);
  }

  finishCommit(tables: string[], txid: string | null = null) {
    this.atomic((st) => {
      const todo: string[] = [];
      for (const t of tables) {
        const e = st.get(t);
        if (e === undefined || e.pending === null) continue;            // already settled
        if (txid !== null && e.pending.txid !== txid) throw conflict(`anchor: ${t} has a pending commit of another transaction`);
        todo.push(t);
      }
      for (const t of todo) {
        const e = st.get(t)!, p = e.pending!;
        if (p.drop) { st.delete(t); continue; }
        const hist = [...e.history, [e.epoch, e.root, e.count] as [number, bigint, number]].slice(-ANCHOR_HISTORY);
        st.set(t, { epoch: p.epoch, root: p.root, count: p.count, pending: null, history: hist });
      }
    }, true);
  }

  abort(tables: string[], txid: string | null = null) {
    this.atomic((st) => {
      for (const t of tables) {
        const e = st.get(t);
        if (e === undefined || e.pending === null || (txid !== null && e.pending.txid !== txid)) continue;
        if (e.pending.created) st.delete(t); else st.set(t, { ...e, pending: null });
      }
    }, true);
  }

  set(table: string, root: bigint, count: number, expectEpoch: number | null): Entry {
    return this.atomic((st) => {
      const e = st.get(table);
      if ((e ? e.epoch : null) !== expectEpoch) throw conflict(`anchor: ${table} changed (expected epoch ${expectEpoch})`);
      if (e && e.pending !== null) throw conflict(`anchor: ${table} has a pending commit`);
      const hist = e ? [...e.history, [e.epoch, e.root, e.count] as [number, bigint, number]].slice(-ANCHOR_HISTORY) : [];
      const ne: Entry = { epoch: e ? e.epoch + 1 : 0, root: mod(root), count, pending: null, history: hist };
      st.set(table, ne);
      return ne;
    }, true);
  }

  remove(table: string, expectEpoch: number | null = null) {
    this.atomic((st) => {
      const e = st.get(table);
      if (e === undefined) return;
      if (expectEpoch !== null && e.epoch !== expectEpoch) throw conflict(`anchor: ${table} changed (expected epoch ${expectEpoch})`);
      st.delete(table);
    }, true);
  }
}

/** In-memory anchor (tests, single-process experiments). Lost with the process. */
export class MemoryAnchor extends StateAnchor {
  #st: State = new Map();
  protected atomic<T>(fn: (st: State) => T, write: boolean): T {
    const work = cloneState(this.#st);
    const out = fn(work);
    if (write) this.#st = work;
    return out;
  }
}

function encEntry(e: Entry): unknown {
  return {
    epoch: e.epoch, root: e.root.toString(), count: e.count,
    history: e.history.map(([a, b, c]) => [a, b.toString(), c]),
    pending: e.pending === null ? null : {
      epoch: e.pending.epoch, root: e.pending.root.toString(), count: e.pending.count,
      txid: e.pending.txid, drop: e.pending.drop, created: e.pending.created,
    },
  };
}
function decEntry(d: any): Entry {
  try {
    const big = (x: unknown) => mod(BigInt(x as string));
    const p = d.pending;
    const pend: Pending | null = p === null || p === undefined ? null : {
      epoch: Number(p.epoch), root: big(p.root), count: Number(p.count),
      txid: p.txid ?? null, drop: !!p.drop, created: !!p.created,
    };
    const hist = (d.history ?? []).map(([a, b, c]: [number, string, number]) => [Number(a), big(b), Number(c)] as [number, bigint, number]);
    if (!Number.isSafeInteger(Number(d.epoch)) || !Number.isSafeInteger(Number(d.count))) throw new Error("bad number");
    return { epoch: Number(d.epoch), root: big(d.root), count: Number(d.count), pending: pend, history: hist };
  } catch (e) {
    throw fileErr(`anchor entry is malformed (${(e as Error).message})`);
  }
}

function sortedJson(v: unknown, indent = 1, level = 0): string {
  // json.dumps(sort_keys=True, indent=1) of the Python implementation (ASCII-only output)
  const esc = (s: string) => JSON.stringify(s).replace(/[\u0080-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  const pad = (n: number) => " ".repeat(indent * n);
  if (v === null) return "null";
  if (typeof v === "string") return esc(v);
  if (typeof v === "number" || typeof v === "boolean") return JSON.stringify(v);
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return "[\n" + v.map((x) => pad(level + 1) + sortedJson(x, indent, level + 1)).join(",\n") + "\n" + pad(level) + "]";
  }
  const keys = Object.keys(v as object).sort();
  if (keys.length === 0) return "{}";
  return "{\n" + keys.map((k) => pad(level + 1) + esc(k) + ": " + sortedJson((v as any)[k], indent, level + 1)).join(",\n") + "\n" + pad(level) + "}";
}

function sleepMs(ms: number) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

/**
 * JSON file, mode 0600, versioned; writes are crash-safe (temp file created O_EXCL, fsync, atomic rename,
 * fsync of the directory). Refuses a symlink, a file that is not ours, lax permissions, malformed content
 * and unknown versions - it never silently starts from an empty state when the file is damaged.
 *
 * Locking: Python and Rust serialise owner PROCESSES with `flock(<path>.lock)`. Node has no flock; on
 * macOS/BSD this class takes the very same lock by opening the lock file with O_EXLOCK, so all three
 * languages exclude each other. On Linux there is no such flag: processes of this driver exclude each other
 * through an O_EXCL sidecar `<path>.lock.ts`, but a concurrent Python/Rust WRITER is not excluded - do not run
 * writers of different languages at the same moment on Linux (sequential use is fine). The epoch
 * compare-and-swap still catches the lost update at the next commit.
 */
export class FileAnchor extends StateAnchor {
  readonly path: string;
  constructor(file: string) {
    super();
    this.path = path.resolve(file.startsWith("~") ? path.join(process.env.HOME ?? "", file.slice(1)) : file);
    if (!fs.existsSync(path.dirname(this.path)) || !fs.statSync(path.dirname(this.path)).isDirectory()) {
      throw fileErr(`anchor directory ${path.dirname(this.path)} does not exist`);
    }
  }
  toString() { return `<FileAnchor ${this.path}>`; }

  private static check(fd: number, what: string): fs.Stats {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw fileErr(`${what} is not a regular file`);
    if (typeof process.geteuid === "function" && st.uid !== process.geteuid()) throw fileErr(`${what} is owned by another user`);
    if (st.mode & 0o077) throw fileErr(`${what} has lax permissions (${(st.mode & 0o777).toString(8)}); chmod 600 it (it is the owner's trust root)`);
    return st;
  }

  private read(): State {
    let fd: number;
    try {
      fd = fs.openSync(this.path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    } catch (e: any) {
      if (e.code === "ENOENT") return new Map();
      throw fileErr(`cannot open the anchor file ${this.path}: ${e.message}`);
    }
    let raw: Buffer;
    try {
      const st = FileAnchor.check(fd, `anchor file ${this.path}`);
      if (st.size > MAX_FILE) throw fileErr("anchor file is implausibly large");
      raw = fs.readFileSync(fd);
    } finally { fs.closeSync(fd); }
    try {
      const doc = JSON.parse(raw.toString("utf8"));
      if (doc.format !== ANCHOR_FORMAT) throw new Error("not an anchor file");
      if (doc.v !== ANCHOR_FORMAT_VERSION) {
        throw fileErr(`anchor file version ${JSON.stringify(doc.v)} is not supported (this build reads version ${ANCHOR_FORMAT_VERSION})`);
      }
      const out: State = new Map();
      for (const [t, e] of Object.entries(doc.tables)) out.set(t, decEntry(e));
      return out;
    } catch (e) {
      if (e instanceof TorusError) throw e;
      throw fileErr(`anchor file ${this.path} is corrupt (${(e as Error).message}); restore it from a backup - refusing to start from an empty state`);
    }
  }

  private write(st: State) {
    const tables: Record<string, unknown> = {};
    for (const [t, e] of [...st].sort(([a], [b]) => (a < b ? -1 : 1))) tables[t] = encEntry(e);
    const body = Buffer.from(sortedJson({ format: ANCHOR_FORMAT, v: ANCHOR_FORMAT_VERSION, tables }), "utf8");
    const tmp = `${this.path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
    const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fs.renameSync(tmp, this.path);
    } catch (e) {
      try { fs.closeSync(fd); } catch { /* already closed */ }
      fs.rmSync(tmp, { force: true });
      throw e;
    }
    const dfd = fs.openSync(path.dirname(this.path), "r");
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  }

  /** Take the cross-process lock; returns the release function. */
  private lock(): () => void {
    const lockPath = this.path + ".lock";
    const exlock = (fs.constants as any).O_EXLOCK as number | undefined;
    if (exlock) {                                            // BSD/macOS: same flock as Python/Rust
      let fd: number;
      try {
        fd = fs.openSync(lockPath, fs.constants.O_RDWR | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0) | exlock, 0o600);
        FileAnchor.check(fd, "anchor lock file");
      } catch (e: any) {
        throw e instanceof TorusError ? e : fileErr(`cannot lock the anchor file: ${e.message}`);
      }
      return () => fs.closeSync(fd);                         // closing releases the flock
    }
    const side = lockPath + ".ts";
    const deadline = Date.now() + 30_000;
    for (;;) {
      try {
        const fd = fs.openSync(side, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        return () => fs.rmSync(side, { force: true });
      } catch (e: any) {
        if (e.code !== "EEXIST") throw fileErr(`cannot lock the anchor file: ${e.message}`);
        try { if (Date.now() - fs.statSync(side).mtimeMs > 60_000) fs.rmSync(side, { force: true }); } catch { /* raced */ }
        if (Date.now() > deadline) throw fileErr("timed out waiting for the anchor lock");
        sleepMs(5);
      }
    }
  }

  protected atomic<T>(fn: (st: State) => T, write: boolean): T {
    if (!write) return fn(cloneState(this.read()));          // the rename is atomic: a reader needs no lock
    const release = this.lock();
    try {
      const st = this.read();
      const work = cloneState(st);
      const out = fn(work);
      if (!sameState(work, st)) this.write(work);
      return out;
    } finally { release(); }
  }
}

function sameState(a: State, b: State): boolean {
  if (a.size !== b.size) return false;
  for (const [t, e] of a) {
    const f = b.get(t);
    if (!f || JSON.stringify(encEntry(e)) !== JSON.stringify(encEntry(f))) return false;
  }
  return true;
}

// ── canonical row material (bit-for-bit the Python encoding) ─────────────────
function field(tag: string, payload: Buffer): Buffer {
  const h = Buffer.alloc(5);
  h.write(tag, 0, "latin1");
  h.writeUInt32BE(payload.length, 1);
  return Buffer.concat([h, payload]);
}

/** A PLAIN column value as decoded from the wire: null, boolean, bigint, string or a reduced fraction. */
export type AnchorValue = null | boolean | bigint | string | { num: bigint; den: bigint };

/** Unambiguous encoding of a PLAIN value; bool and int share a form, a fraction with denominator 1 is the integer. */
export function canonValue(v: AnchorValue): Buffer {
  if (v === null) return field("n", Buffer.alloc(0));
  if (typeof v === "boolean") return field("i", Buffer.from(v ? "1" : "0"));
  if (typeof v === "bigint") return field("i", Buffer.from(v.toString()));
  if (typeof v === "string") return field("s", Buffer.from(v, "utf8"));
  if (typeof v === "object" && typeof v.num === "bigint" && typeof v.den === "bigint") {
    return v.den === 1n ? field("i", Buffer.from(v.num.toString())) : field("f", Buffer.from(`${v.num}/${v.den}`));
  }
  throw integrity("cannot anchor a value of this type");
}

export const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest();

/** json.dumps(..., separators=(",", ":")) with ensure_ascii, as Python writes it. */
function pyJson(v: unknown): string {
  return JSON.stringify(v).replace(/[\u0080-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

/** Binds a leaf to the column names, types and policies. */
export function schemaDigest(table: string, cols: Array<{ name: string; type: string; policy: string }>): Buffer {
  return sha256(Buffer.from(pyJson([table, cols.map((c) => [c.name, c.type, c.policy])]), "utf8"));
}

export type FhePart = [bigint | null, Buffer | null, Buffer | null];

export function rowMaterial(sdig: Buffer, plain: AnchorValue[], parts: FhePart[]): Buffer {
  const out: Buffer[] = [Buffer.from("torussql/anchor/row/v1"), sdig];
  for (const v of plain) out.push(canonValue(v));
  for (const [nonce, hc, ht] of parts) {
    out.push(canonValue(nonce));
    out.push(field("c", hc ?? Buffer.alloc(0)));
    out.push(field("t", ht ?? Buffer.alloc(0)));
  }
  return Buffer.concat(out);
}

// ── the verified snapshot ────────────────────────────────────────────────────
export interface RowRec { vals: AnchorValue[]; fhe: FhePart[]; leaf: bigint }

export class Snapshot {
  rows = new Map<number, RowRec>();
  nslots = 0;
  epoch: number | null = null;
  baseRoot = 0n; baseCount = 0;
  root = 0n; count = 0;
  constructor(readonly table: string, readonly plainCols: string[], readonly fheCols: string[], readonly sdig: Buffer) {}

  rowDict(id: number): Record<string, AnchorValue> {
    const r = this.rows.get(id)!;
    const o: Record<string, AnchorValue> = Object.create(null);
    this.plainCols.forEach((c, i) => { o[c] = r.vals[i]; });
    return o;
  }
  liveIds(): number[] { return [...this.rows.keys()].sort((a, b) => a - b); }
  plain(col: string, ids: number[]): AnchorValue[] {
    const i = this.plainCols.indexOf(col);
    return ids.map((id) => {
      const r = this.rows.get(id);
      if (!r) throw integrity(`row ${id} of ${this.table} is not part of the anchored table state`);
      return r.vals[i];
    });
  }
  fhePart(col: string, ids: number[]): FhePart[] {
    const i = this.fheCols.indexOf(col);
    return ids.map((id) => {
      const r = this.rows.get(id);
      if (!r) throw integrity(`row ${id} of ${this.table} is not part of the anchored table state`);
      return r.fhe[i];
    });
  }
}

// ── the manager ──────────────────────────────────────────────────────────────
interface TxT { epoch: number | null; droot: bigint; dcount: number; reset: boolean; dropped: boolean }
interface Tx { txid: string | null; tables: Map<string, TxT>; undo: Array<() => void>; rescanned: Set<string> }

/** What the manager needs from the client. */
export interface AnchorHost {
  key(): FheKey;
  /** schema of an anchored table (plain / fhe column names in order, digest) or null when not anchored */
  layout(table: string): { plain: string[]; fhe: string[]; sdig: Buffer } | null;
  fheRows(table: string, start: number, count: number): Promise<unknown>;
  maxScanRows(): number | undefined;
  txStatus(txid: string): Promise<string>;
  hasSchema(table: string): boolean;
  serverTables(): Promise<string[]>;
  /** decode one wire value of a PLAIN column (throws IntegrityError for something the server may not send) */
  decodePlain(w: unknown): AnchorValue;
}

const DEFAULT_MAX_ROWS = 1_000_000;

export class AnchorManager {
  snaps = new Map<string, Snapshot>();
  tx: Tx | null = null;
  maxRows: number;
  stats = { scans: 0, scanRows: 0 };
  #pending: string[] = [];
  #expect = new Map<string, { root: bigint; count: number } | null>();
  #changes = new Map<string, Change>();

  constructor(private h: AnchorHost, readonly anchor: Anchor, maxRows?: number) {
    this.maxRows = maxRows ?? DEFAULT_MAX_ROWS;
  }

  isAnchored(table: string) { return this.h.layout(table) !== null; }

  private rec(snap: Snapshot, rid: number, vals: AnchorValue[], fp: FhePart[]): RowRec {
    if (!Array.isArray(vals) || vals.length !== snap.plainCols.length || !Array.isArray(fp) || fp.length !== snap.fheCols.length) {
      throw integrity(`${snap.table} row ${rid}: the server's row has the wrong shape`);
    }
    for (const [nonce, hc, ht] of fp) {
      if (nonce !== null && typeof nonce !== "bigint") throw integrity("the server reported a malformed write nonce");
      for (const x of [hc, ht]) if (x !== null && x.length !== 32) throw integrity(`${snap.table} row ${rid}: malformed cell hash`);
    }
    const leaf = this.h.key().anchorLeaf(snap.table, rid, rowMaterial(snap.sdig, vals, fp));
    return { vals, fhe: fp, leaf };
  }

  private parseHash(x: unknown): Buffer | null {
    if (x === null) return null;
    if (typeof x !== "string" || !/^[0-9a-f]{64}$/.test(x)) throw integrity("malformed fhe_rows reply from the server (cell hash)");
    return Buffer.from(x, "hex");
  }

  private async scan(table: string): Promise<Snapshot> {
    const lay = this.h.layout(table)!;
    const snap = new Snapshot(table, lay.plain, lay.fhe, lay.sdig);
    const step = Math.min(2000, this.h.maxScanRows() ?? 2000);
    let start = 0, root = 0n, count = 0, n = 0;
    for (;;) {
      const r = (await this.h.fheRows(table, start, step)) as any;
      const bad = (why: string) => integrity(`malformed fhe_rows reply from the server (${why})`);
      if (r === null || typeof r !== "object" || !Number.isSafeInteger(r.n) || r.n < 0 || !Array.isArray(r.rows)) throw bad("shape");
      n = r.n;
      if (n > this.maxRows) {
        throw new TorusError("InterfaceError", `${table} has ${n} slots: more than the anchored-mode limit of ${this.maxRows} rows (integrityAnchorMaxRows)`);
      }
      if (start >= n) break;
      const rows: any[] = r.rows;
      if (rows.length === 0 || rows.length > step) throw integrity(`${table}: the server's scan answer does not cover the requested slots`);
      rows.forEach((row, k) => {
        if (!Array.isArray(row) || row[0] !== start + k) throw integrity(`${table}: the server's scan skipped or repeated a slot`);
        if (row[1] === 1) return;                                         // dead slot
        if (row[1] !== 0 || !Array.isArray(row[2]) || !Array.isArray(row[3])) throw bad("row");
        const vals = (row[2] as unknown[]).map((w) => this.h.decodePlain(w));
        const fp: FhePart[] = (row[3] as unknown[]).map((e) => {
          if (!Array.isArray(e) || e.length !== 3) throw bad("fhe part");
          const nw = e[0] as any;
          let nonce: bigint | null;
          if (nw && nw.t === "n") nonce = null;
          else if (nw && nw.t === "i" && typeof nw.v === "string" && /^-?[0-9]{1,40}$/.test(nw.v)) nonce = BigInt(nw.v);
          else throw integrity("the server reported a malformed write nonce");
          return [nonce, this.parseHash(e[1]), this.parseHash(e[2])];
        });
        const rec = this.rec(snap, row[0], vals, fp);
        snap.rows.set(row[0], rec);
        root += rec.leaf; count++;
      });
      start += rows.length;
    }
    snap.nslots = n;
    snap.root = root % N; snap.count = count;
    snap.baseRoot = snap.root; snap.baseCount = snap.count;
    this.stats.scans++; this.stats.scanRows += n;
    return snap;
  }

  private missing(table: string) {
    return new TorusError("AnchorMissingError",
      `table ${table} has FHE columns but the integrity anchor has no entry for it, so its row set cannot be verified. ` +
      `If it was created before the anchor was configured, call adoptTable("${table}") once (trust on first use: only as honest ` +
      `as the server at that moment); a table created through this connection is anchored automatically`);
  }

  /** The verified table state (cached per anchor epoch). */
  async snapshot(table: string, opts: { force?: boolean; forWrite?: boolean } = {}): Promise<Snapshot> {
    const tt = this.tx?.tables.get(table);
    const snap = this.snaps.get(table);
    if (tt && tt.reset && snap) return snap;                             // created inside this transaction
    let a = this.anchor.get(table);
    if (a === null) throw this.missing(table);
    if (!opts.force && snap && snap.epoch === a.epoch && a.pending === null && snap.baseRoot === a.root && snap.baseCount === a.count) return snap;
    const fresh = await this.scan(table);
    const [dr, dc] = tt ? [tt.droot, tt.dcount] : [0n, 0];
    const got: [bigint, number] = [mod(fresh.root - dr), fresh.count - dc];
    a = this.settle(table, a, got);
    if (tt && tt.epoch !== null && a.epoch !== tt.epoch) {
      throw conflict(`anchor: ${table} moved from epoch ${tt.epoch} to ${a.epoch} during the transaction (another owner committed)`);
    }
    fresh.epoch = a.epoch; fresh.baseRoot = got[0]; fresh.baseCount = got[1];
    const volatile = a.pending !== null;
    if (volatile) {
      fresh.epoch = null;                                                // never cached while a commit is in flight
      if (opts.forWrite) throw conflict(`anchor: ${table} has a commit in flight from another owner`);
    }
    this.snaps.set(table, fresh);
    if (tt) {
      this.tx!.rescanned.add(table);
      if (tt.epoch === null && !volatile) tt.epoch = a.epoch;
    }
    return fresh;
  }

  /** Compare what the server presents with the anchor; settle a pending commit; or refuse. */
  private settle(table: string, a: Entry, got: [bigint, number]): Entry {
    const eq = (r: bigint, c: number) => r === got[0] && c === got[1];
    if (eq(a.root, a.count)) {
      // a pending commit whose new state is NOT on the server and is not in flight is dead: abort it lazily
      if (a.pending !== null && !this.inFlight.get(a.pending.txid ?? "")) {
        this.anchor.abort([table], a.pending.txid);
        return this.anchor.get(table) ?? a;
      }
      return a;
    }
    const p = a.pending;
    if (p && !p.drop && eq(p.root, p.count)) {
      try { this.anchor.finishCommit([table], p.txid); } catch (e) { if (!(e instanceof TorusError && e.kind === "AnchorConflict")) throw e; }
      const a2 = this.anchor.get(table);
      if (a2 && eq(a2.root, a2.count)) return a2;
    }
    if (a.history.some(([, r, c]) => eq(r, c))) {
      throw new StaleServerError(
        `${table}: the server is behind the anchor (its table state matches an older epoch than ${a.epoch}: a replica that has not ` +
        `caught up, or a rollback). Nothing was accepted; retry once the server has caught up`);
    }
    throw integrity(`table state of ${table} does not match the anchor: rows added, dropped, rolled back or altered ` +
      `(server presents ${got[1]} rows, the anchor records ${a.count})`);
  }

  /** txid -> true while another owner's commit may still be on its way (filled by `settleInFlight`). */
  inFlight = new Map<string, boolean>();

  /** Ask the server about the pending transaction of `table` (only "unknown" proves it dead). */
  private async probeInFlight(table: string) {
    const a = this.anchor.get(table);
    const p = a?.pending;
    if (!p || p.txid === null) return;
    try { this.inFlight.set(p.txid, (await this.h.txStatus(p.txid)) !== "unknown"); } catch { this.inFlight.set(p.txid, true); }
  }

  // — transaction state —
  begin(txid: string | null) {
    if (this.tx) throw usage("an anchor transaction is already open");
    this.tx = { txid, tables: new Map(), undo: [], rescanned: new Set() };
  }

  private tt(table: string, snap?: Snapshot): TxT {
    let t = this.tx!.tables.get(table);
    if (!t) { t = { epoch: snap ? snap.epoch : null, droot: 0n, dcount: 0, reset: false, dropped: false }; this.tx!.tables.set(table, t); }
    return t;
  }

  async writeSnapshot(table: string): Promise<Snapshot> {
    if (!this.tx) throw usage("anchored tables are written inside a transaction");
    await this.probeInFlight(table);
    const snap = await this.snapshot(table, { forWrite: true });
    this.tt(table, snap);
    return snap;
  }

  async readSnapshot(table: string): Promise<Snapshot> {
    await this.probeInFlight(table);
    return this.snapshot(table);
  }

  private apply(snap: Snapshot, tt: TxT, rid: number, nw: RowRec | null, old: RowRec | null) {
    const saved = { root: snap.root, count: snap.count, nslots: snap.nslots, droot: tt.droot, dcount: tt.dcount };
    const d = mod((nw ? nw.leaf : 0n) - (old ? old.leaf : 0n));
    const dn = (nw ? 1 : 0) - (old ? 1 : 0);
    if (nw) { snap.rows.set(rid, nw); snap.nslots = Math.max(snap.nslots, rid + 1); } else snap.rows.delete(rid);
    snap.root = mod(snap.root + d); snap.count += dn;
    tt.droot = mod(tt.droot + d); tt.dcount += dn;
    this.tx!.undo.push(() => {
      snap.root = saved.root; snap.count = saved.count; snap.nslots = saved.nslots; tt.droot = saved.droot; tt.dcount = saved.dcount;
      if (old) snap.rows.set(rid, old); else snap.rows.delete(rid);
    });
  }

  recordInsert(snap: Snapshot, rid: number, vals: AnchorValue[], fp: FhePart[]) {
    const tt = this.tt(snap.table, snap);
    if (!Number.isSafeInteger(rid) || snap.rows.has(rid) || rid < snap.nslots) {
      throw integrity(`${snap.table}: the server returned row id ${rid}, which is already in use or out of order`);
    }
    this.apply(snap, tt, rid, this.rec(snap, rid, vals, fp), null);
  }
  recordUpdate(snap: Snapshot, rid: number, vals: AnchorValue[], fp: FhePart[]) {
    const old = snap.rows.get(rid);
    if (!old) throw integrity(`row ${rid} of ${snap.table} is not part of the anchored table state`);
    this.apply(snap, this.tt(snap.table, snap), rid, this.rec(snap, rid, vals, fp), old);
  }
  recordDelete(snap: Snapshot, rid: number) {
    const old = snap.rows.get(rid);
    if (!old) throw integrity(`row ${rid} of ${snap.table} is not part of the anchored table state`);
    this.apply(snap, this.tt(snap.table, snap), rid, null, old);
  }

  // — DDL —
  ddlCreate(table: string) {
    const lay = this.h.layout(table)!;
    const a = this.anchor.get(table);
    const hadTt = this.tx!.tables.get(table), hadSnap = this.snaps.get(table);
    this.tx!.tables.set(table, { epoch: a ? a.epoch : null, droot: 0n, dcount: 0, reset: true, dropped: false });
    this.snaps.set(table, new Snapshot(table, lay.plain, lay.fhe, lay.sdig));
    const tx = this.tx!;
    tx.undo.push(() => {
      if (!hadTt) tx.tables.delete(table); else tx.tables.set(table, hadTt);
      if (!hadSnap) this.snaps.delete(table); else this.snaps.set(table, hadSnap);
    });
  }
  ddlDrop(table: string) {
    const a = this.anchor.get(table);
    const hadTt = this.tx!.tables.get(table);
    const tt: TxT = hadTt ?? { epoch: a ? a.epoch : null, droot: 0n, dcount: 0, reset: false, dropped: false };
    this.tx!.tables.set(table, tt);
    const was = tt.dropped;
    tt.dropped = true;
    const hadSnap = this.snaps.get(table);
    this.snaps.delete(table);
    const tx = this.tx!;
    tx.undo.push(() => {
      tt.dropped = was;
      if (!hadTt) tx.tables.delete(table);
      if (hadSnap) this.snaps.set(table, hadSnap);
    });
  }

  // — commit protocol —
  /** Record `pending` in the anchor BEFORE the server is asked to commit. False when nothing anchored changed. */
  prepare(): boolean {
    const tx = this.tx!;
    const changes = new Map<string, Change>();
    for (const [t, tt] of tx.tables) {
      if (tt.dropped) { changes.set(t, { expectEpoch: tt.epoch, root: null, count: 0 }); continue; }
      if (!(tt.droot !== 0n || tt.dcount !== 0 || tt.reset)) continue;
      const snap = this.snaps.get(t)!;
      const [br, bc] = tt.reset ? [0n, 0] : [snap.baseRoot, snap.baseCount];
      changes.set(t, { expectEpoch: tt.epoch, root: mod(br + tt.droot), count: bc + tt.dcount });
    }
    if (changes.size === 0) return false;
    this.anchor.beginCommit(changes, tx.txid);
    this.#pending = [...changes.keys()];
    this.#changes = changes;
    this.#expect = new Map([...changes].map(([t, ch]) => [t, ch.root === null ? null : { root: ch.root, count: ch.count }]));
    return true;
  }

  finish() {
    const tx = this.tx, pend = this.#pending;
    this.tx = null; this.#pending = [];
    if (!tx) return;
    try {
      if (pend.length) {
        this.anchor.finishCommit(pend, tx.txid);
        this.repairAborted(pend, tx.txid);
        for (const t of pend) {
          const e = this.anchor.get(t), want = this.#expect.get(t) ?? null;
          if ((want === null) !== (e === null) || (e !== null && want !== null && (e.pending !== null || e.root !== want.root || e.count !== want.count))) {
            throw conflict(`${t} is not in the state this commit recorded`);
          }
        }
      }
    } catch (e) {
      if (e instanceof TorusError && e.kind === "AnchorConflict") {
        this.snaps.clear();
        throw integrity(`the anchor does not hold this transaction's commit: ${e.message}`);
      }
      throw e;
    }
    for (const [t, tt] of tx.tables) {
      const snap = this.snaps.get(t);
      if (tt.dropped) this.snaps.delete(t);
      else if (snap && pend.includes(t)) {
        const a = this.anchor.get(t)!;
        snap.epoch = a.epoch; snap.baseRoot = snap.root; snap.baseCount = snap.count;
      }
    }
  }

  /** Our `pending` record was aborted behind our back although the server answered "committed": the anchor is still
   *  exactly at the state the transaction was based on, so record the commit again (a lie can only cause a later failure). */
  private repairAborted(pend: string[], txid: string | null) {
    const redo = new Map<string, Change>();
    for (const t of pend) {
      const ch = this.#changes.get(t)!, e = this.anchor.get(t);
      if ((e === null && ch.expectEpoch === null) || (e !== null && e.pending === null && e.epoch === ch.expectEpoch)) redo.set(t, ch);
    }
    if (redo.size) { this.anchor.beginCommit(redo, txid); this.anchor.finishCommit([...redo.keys()], txid); }
  }

  /** The transaction did not commit: discard its changes (and the pending record). */
  abort() {
    const tx = this.tx, pend = this.#pending;
    this.tx = null; this.#pending = [];
    if (!tx) return;
    try { if (pend.length) this.anchor.abort(pend, tx.txid); }
    finally {
      for (const u of [...tx.undo].reverse()) u();
      for (const t of tx.rescanned) this.snaps.delete(t);
    }
  }

  /** The outcome is unknown (in doubt): leave `pending` in the anchor for the next connect to settle by scanning. */
  detach() { this.tx = null; this.#pending = []; this.snaps.clear(); }

  // — tools —
  async adopt(table: string, replace = false) {
    if (this.tx) throw usage("adoptTable: finish the transaction first");
    if (!this.isAnchored(table)) throw usage(`${table} has no FHE columns (or the connection is not authenticated)`);
    const a = this.anchor.get(table);
    if (a !== null && !replace) throw usage(`${table} already has an anchor entry (epoch ${a.epoch}); pass replace: true to adopt the server's current state instead`);
    const snap = await this.scan(table);
    if (a !== null) this.anchor.remove(table);
    const e = this.anchor.set(table, snap.root, snap.count, null);
    snap.epoch = e.epoch;
    this.snaps.set(table, snap);
    return { table, rows: snap.count, slots: snap.nslots, epoch: e.epoch };
  }

  async verify(table: string) {
    if (!this.isAnchored(table)) throw usage(`${table} has no FHE columns (or the connection is not authenticated)`);
    await this.probeInFlight(table);
    const snap = await this.snapshot(table, { force: true });
    return { table, rows: snap.count, slots: snap.nslots, epoch: snap.epoch };
  }

  /** On connect: settle every pending commit the anchor holds by scanning the server. */
  async settlePending() {
    let onServer: Set<string> | null = null;
    for (const t of this.anchor.tables()) {
      const e = this.anchor.get(t);
      if (e === null || e.pending === null) continue;
      if (this.h.hasSchema(t)) { await this.probeInFlight(t); await this.snapshot(t, { force: true }); continue; }
      onServer ??= new Set(await this.h.serverTables());
      if (onServer.has(t)) continue;                                     // unknown schema: settled on first use
      const p = e.pending;
      if (p.drop) this.anchor.finishCommit([t], p.txid);                 // the table is gone: the drop committed
      else if (p.created) this.anchor.abort([t], p.txid);                // it was never created
      else throw integrity(`table ${t} is gone from the server but the anchor records it (pending commit that is not a drop)`);
    }
  }
}
