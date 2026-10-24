// SPDX-License-Identifier: Apache-2.0
// FHE columns (EC-FHE on BN254) for the TorusDB TypeScript driver - the owner's side.
//
// Normative spec: proto/fhe-wire.md. This module needs NO pairing: the server computes the
// pairings (DOT); the client only does G1/G2 scalar multiplication, G1 addition, Fp12 arithmetic
// (to open a DOT result) and bounded discrete logarithms. Everything is plain BigInt.
//
// NOT constant-time: BigInt arithmetic leaks timing. Do not expose decryption to an attacker who
// can measure it with high resolution (the server only ever sees ciphertexts).

import { createHmac, randomBytes, scryptSync } from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import { TorusError } from "./errors";

// ── constants ────────────────────────────────────────────────────────────────
/** BN254 base field modulus. */
export const FHE_P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
/** BN254 group order. */
export const FHE_N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const P = FHE_P;
const N = FHE_N;

export const FHE_G1_BYTES = 64;
export const FHE_G2_BYTES = 128;
export const FHE_GT_BYTES = 384;
/** One FHE cell: C1 || C2 || D1 || D2. */
export const FHE_CELL_BYTES = 384;
/** SUM blob: sum C1 || sum C2. */
export const FHE_SUM_BYTES = 128;
/** DOT blob: tag || c00 || c01 || c10 || c11. */
export const FHE_DOT_BYTES = 1 + 4 * FHE_GT_BYTES;
/** Default plaintext/result range of a key. */
export const FHE_DEFAULT_RANGE = 1_000_000;
/** Largest range a key may have (the BSGS table has about sqrt(2*range) entries). */
export const FHE_MAX_RANGE = 2 ** 40;
export type FheBackend = "pyecc" | "mcl";

const G2X0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781n;
const G2X1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634n;
const G2Y0 = 8495653923123431417604973247489272438418190587263600148770280649306958101930n;
const G2Y1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531n;

// GT generators g = e(G1, G2) of the two pairing back ends, in the canonical py_ecc polynomial
// basis (12 x 32-byte big-endian coefficients). Published in proto/fhe-vectors.json.
const GT_GEN_PYECC_HEX =
  "28c6e04df059260df7d2d2a1f9b5f77676d1939847852c4ed50d2318744c1d5f17bb74adab1705c26133af1dac87044a3833ac011018e8158da48382bbd2dcd60d3bd72f54d742f78ea9e6015c8ea2f2e7fbb728c9c905ec531dcf7de5b246f0090cb8ee97e091a667af03882b06c3ecb4e437993cbd1b05b98c7f9dfcfe9c40016b6d855b5cbf76f9829a309db52f5c442f65ae29f996af59d65f85f4afe78a0a0272204db51dadc0342bd318b9302a44faec12ff500bdd4d4b012ffe45f36f084f330485b09e866bc2f2ea2b897394deaf3f12aa31f28cb0552990967d470427ed208e7a0b55ae6e710bbfbd2fd922669c026360e37cc5b2ab8624115361042067586885c3318eeffa1938c754fe3c60224ee5ae15e66af6b5104c47c8c5d8279db296f9d479292532c7c493d8e0722b6efae42158387564889c79fc038ee32b03614464f04dd772d86df88674c270ffc8747ea13e72da95e3594468f222c4108c19d15f9446f744d0f110405d3856d6cc3bda6c4d537663729f5257628417";
const GT_GEN_MCL_HEX =
  "0c498eace9669afdb2ac004a2bc3352ff31fa2b137a520190498891a96af31fb0f7abc6cd882a79148ae975c363201b64294a69c7da04b4dc0fcc4a6b77f99801fa5477cf344c578b943985d188016c90cfed95c39da64d34f7dab3bf29053a4189cc22058b17f919c91a5da449e1130585d76d6c852c08307a7355064d0e6682e5c373f19a914ff641dc62428638e6209a0f8ca64990df7966a7cce65903e150ae359efdcdc3ff0067fb863975a0289d468186d63f62e156aec452863c445d402e02d2cc795a2000a1b1f823879abbd397c4dea0918ed66b49d34b48efb8a4a14d3d6ca72d8a950a31dc10f7b4053c9e9ad9ebb590cb4a60f8215d4b99f2b4a040ba9fa500f1a5c4b31984a74e68659c4b420bd699ce630b130b08a6ea1162b0b53320e5a6488cb98a855ffc837d2a75ab90d61ac16cc1b7ab2cd3ed5e22b971c54a530398c9064bdc662d929e645cadda9a712cc5a8243f9cddbd2d98dd1f000f97b5221474526b601f3730a3afa965ceee1b343940c383e5314859e762c97";

const usage = (m: string) => new TorusError("InterfaceError", m);
const proto = (m: string) => new TorusError("ProtocolError", m);
const budget = (m: string) => new TorusError("OutOfBudget", m);

function mod(a: bigint, m: bigint = N): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modInvP(a: bigint): bigint {
  let [r0, r1] = [mod(a, P), P];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw usage("field element is not invertible");
  return mod(s0, P);
}

function be32(x: bigint): Buffer {
  const h = x.toString(16).padStart(64, "0");
  if (h.length !== 64) throw usage("integer does not fit in 32 bytes");
  return Buffer.from(h, "hex");
}
function rd32(b: Uint8Array, off: number): bigint {
  return BigInt("0x" + Buffer.from(b.buffer, b.byteOffset + off, 32).toString("hex"));
}

/** Uniform scalar in [1, n) (512 random bits reduced: bias < 2^-250). */
function randScalar(): bigint {
  return 1n + (BigInt("0x" + randomBytes(64).toString("hex")) % (N - 1n));
}

// ── generic fields ───────────────────────────────────────────────────────────
interface Field<T> {
  readonly zero: T;
  readonly one: T;
  add(a: T, b: T): T;
  sub(a: T, b: T): T;
  mul(a: T, b: T): T;
  sqr(a: T): T;
  neg(a: T): T;
  isZero(a: T): boolean;
  eq(a: T, b: T): boolean;
  inv(a: T): T;
}

const Fp: Field<bigint> = {
  zero: 0n,
  one: 1n,
  add: (a, b) => { const r = a + b; return r >= P ? r - P : r; },
  sub: (a, b) => { const r = a - b; return r < 0n ? r + P : r; },
  mul: (a, b) => (a * b) % P,
  sqr: (a) => (a * a) % P,
  neg: (a) => (a === 0n ? 0n : P - a),
  isZero: (a) => a === 0n,
  eq: (a, b) => a === b,
  inv: modInvP,
};

type Fp2e = readonly [bigint, bigint]; // a0 + a1*i, i^2 = -1
const Fp2: Field<Fp2e> = {
  zero: [0n, 0n],
  one: [1n, 0n],
  add: (a, b) => [Fp.add(a[0], b[0]), Fp.add(a[1], b[1])],
  sub: (a, b) => [Fp.sub(a[0], b[0]), Fp.sub(a[1], b[1])],
  mul: (a, b) => {
    const t0 = a[0] * b[0], t1 = a[1] * b[1];
    const t2 = (a[0] + a[1]) * (b[0] + b[1]);
    return [mod(t0 - t1, P), mod(t2 - t0 - t1, P)];
  },
  sqr: (a) => [mod((a[0] + a[1]) * (a[0] - a[1]), P), mod(2n * a[0] * a[1], P)],
  neg: (a) => [Fp.neg(a[0]), Fp.neg(a[1])],
  isZero: (a) => a[0] === 0n && a[1] === 0n,
  eq: (a, b) => a[0] === b[0] && a[1] === b[1],
  inv: (a) => {
    const nrm = modInvP((a[0] * a[0] + a[1] * a[1]) % P);
    return [(a[0] * nrm) % P, Fp.neg((a[1] * nrm) % P)];
  },
};

// ── short Weierstrass curve y^2 = x^3 + b in Jacobian coordinates ────────────
interface Aff<T> { readonly x: T; readonly y: T }
interface Jac<T> { readonly x: T; readonly y: T; readonly z: T }

class Curve<T> {
  readonly one: T;
  constructor(readonly F: Field<T>, readonly b: T) { this.one = F.one; }

  inf(): Jac<T> { return { x: this.F.one, y: this.F.one, z: this.F.zero }; }
  isInf(p: Jac<T>): boolean { return this.F.isZero(p.z); }
  fromAff(a: Aff<T> | null): Jac<T> { return a ? { x: a.x, y: a.y, z: this.F.one } : this.inf(); }
  neg(p: Jac<T>): Jac<T> { return { x: p.x, y: this.F.neg(p.y), z: p.z }; }

  onCurve(a: Aff<T>): boolean {
    const F = this.F;
    return F.eq(F.sqr(a.y), F.add(F.mul(F.sqr(a.x), a.x), this.b));
  }

  dbl(p: Jac<T>): Jac<T> {
    const F = this.F;
    if (F.isZero(p.z) || F.isZero(p.y)) return this.inf();
    const A = F.sqr(p.x), B = F.sqr(p.y), C = F.sqr(B);
    const t = F.sqr(F.add(p.x, B));
    let D = F.sub(F.sub(t, A), C);
    D = F.add(D, D);
    const E = F.add(F.add(A, A), A);
    const Fq = F.sqr(E);
    const X3 = F.sub(Fq, F.add(D, D));
    let C8 = F.add(C, C); C8 = F.add(C8, C8); C8 = F.add(C8, C8);
    const Y3 = F.sub(F.mul(E, F.sub(D, X3)), C8);
    const YZ = F.mul(p.y, p.z);
    return { x: X3, y: Y3, z: F.add(YZ, YZ) };
  }

  add(p: Jac<T>, q: Jac<T>): Jac<T> {
    const F = this.F;
    if (F.isZero(p.z)) return q;
    if (F.isZero(q.z)) return p;
    const Z1Z1 = F.sqr(p.z), Z2Z2 = F.sqr(q.z);
    const U1 = F.mul(p.x, Z2Z2), U2 = F.mul(q.x, Z1Z1);
    const S1 = F.mul(F.mul(p.y, q.z), Z2Z2), S2 = F.mul(F.mul(q.y, p.z), Z1Z1);
    const H = F.sub(U2, U1);
    const r0 = F.sub(S2, S1);
    if (F.isZero(H)) return F.isZero(r0) ? this.dbl(p) : this.inf();
    const H2 = F.add(H, H);
    const I = F.sqr(H2), J = F.mul(H, I);
    const r = F.add(r0, r0);
    const V = F.mul(U1, I);
    const X3 = F.sub(F.sub(F.sqr(r), J), F.add(V, V));
    const S1J = F.mul(S1, J);
    const Y3 = F.sub(F.mul(r, F.sub(V, X3)), F.add(S1J, S1J));
    const Z3 = F.mul(F.sub(F.sub(F.sqr(F.add(p.z, q.z)), Z1Z1), Z2Z2), H);
    return { x: X3, y: Y3, z: Z3 };
  }

  /** p + q with q affine (not infinity). */
  addMixed(p: Jac<T>, q: Aff<T>): Jac<T> {
    const F = this.F;
    if (F.isZero(p.z)) return { x: q.x, y: q.y, z: F.one };
    const Z1Z1 = F.sqr(p.z);
    const U2 = F.mul(q.x, Z1Z1), S2 = F.mul(F.mul(q.y, p.z), Z1Z1);
    const H = F.sub(U2, p.x);
    const r0 = F.sub(S2, p.y);
    if (F.isZero(H)) return F.isZero(r0) ? this.dbl(p) : this.inf();
    const HH = F.sqr(H);
    let I = F.add(HH, HH); I = F.add(I, I);
    const J = F.mul(H, I);
    const r = F.add(r0, r0);
    const V = F.mul(p.x, I);
    const X3 = F.sub(F.sub(F.sqr(r), J), F.add(V, V));
    const YJ = F.mul(p.y, J);
    const Y3 = F.sub(F.mul(r, F.sub(V, X3)), F.add(YJ, YJ));
    const Z3 = F.sub(F.sub(F.sqr(F.add(p.z, H)), Z1Z1), HH);
    return { x: X3, y: Y3, z: Z3 };
  }

  toAffine(p: Jac<T>): Aff<T> | null {
    const F = this.F;
    if (F.isZero(p.z)) return null;
    const zi = F.inv(p.z), zi2 = F.sqr(zi);
    return { x: F.mul(p.x, zi2), y: F.mul(F.mul(p.y, zi2), zi) };
  }

  /** Montgomery batch inversion: one field inversion for the whole list. */
  batchToAffine(ps: Jac<T>[]): Array<Aff<T> | null> {
    const F = this.F;
    const out: Array<Aff<T> | null> = new Array(ps.length).fill(null);
    const idx: number[] = [];
    const pref: T[] = [];
    let acc = F.one;
    for (let i = 0; i < ps.length; i++) {
      if (F.isZero(ps[i].z)) continue;
      idx.push(i);
      acc = F.mul(acc, ps[i].z);
      pref.push(acc);
    }
    if (idx.length === 0) return out;
    let inv = F.inv(acc);
    for (let k = idx.length - 1; k >= 0; k--) {
      const p = ps[idx[k]];
      const zi = k > 0 ? F.mul(inv, pref[k - 1]) : inv;
      inv = F.mul(inv, p.z);
      const zi2 = F.sqr(zi);
      out[idx[k]] = { x: F.mul(p.x, zi2), y: F.mul(F.mul(p.y, zi2), zi) };
    }
    return out;
  }

  eqAff(a: Aff<T> | null, c: Aff<T> | null): boolean {
    if (a === null || c === null) return a === c;
    return this.F.eq(a.x, c.x) && this.F.eq(a.y, c.y);
  }

  /** Variable-base k*p, 4-bit window (k >= 0). */
  mul(p: Jac<T>, k: bigint): Jac<T> {
    if (k < 0n) return this.neg(this.mul(p, -k));
    if (k === 0n || this.isInf(p)) return this.inf();
    const tab: Jac<T>[] = new Array(16);
    tab[1] = p;
    tab[2] = this.dbl(p);
    for (let i = 3; i < 16; i++) tab[i] = this.add(tab[i - 1], p);
    const bits = k.toString(2).length;
    const top = Math.ceil(bits / 4);
    let acc = this.inf();
    for (let w = top - 1; w >= 0; w--) {
      if (w !== top - 1) { acc = this.dbl(this.dbl(this.dbl(this.dbl(acc)))); }
      const d = Number((k >> BigInt(4 * w)) & 15n);
      if (d) acc = this.add(acc, tab[d]);
    }
    return acc;
  }

  /** Precomputed table of d * 16^w * base (d = 1..15, w = 0..63), affine. */
  fixedTable(base: Aff<T>): Array<Array<Aff<T>>> {
    const tab: Array<Array<Aff<T>>> = [];
    let b = this.fromAff(base);
    for (let w = 0; w < 64; w++) {
      const row: Jac<T>[] = [b, this.dbl(b)];
      for (let d = 3; d <= 15; d++) row.push(this.add(row[d - 2], b));
      tab.push(this.batchToAffine(row) as Array<Aff<T>>);
      b = this.dbl(this.dbl(this.dbl(this.dbl(b))));
    }
    return tab;
  }

  mulFixed(tab: Array<Array<Aff<T>>>, k: bigint): Jac<T> {
    if (k < 0n) return this.neg(this.mulFixed(tab, -k));
    let acc = this.inf();
    let w = 0;
    while (k > 0n) {
      if (w >= 64) throw usage("scalar too large for the fixed-base table");
      const d = Number(k & 15n);
      if (d) acc = this.addMixed(acc, tab[w][d - 1]);
      k >>= 4n;
      w++;
    }
    return acc;
  }
}

const B2: Fp2e = (() => {
  // b' = 3 / (9 + i) = 3 (9 - i) / 82
  const inv82 = modInvP(82n);
  return [mod(27n * inv82, P), mod(-3n * inv82, P)] as Fp2e;
})();
const C1 = new Curve<bigint>(Fp, 3n);
const C2 = new Curve<Fp2e>(Fp2, B2);
const G1_AFF: Aff<bigint> = { x: 1n, y: 2n };
const G2_AFF: Aff<Fp2e> = { x: [G2X0, G2X1], y: [G2Y0, G2Y1] };

let g1Table: Array<Array<Aff<bigint>>> | undefined;
let g2Table: Array<Array<Aff<Fp2e>>> | undefined;
const g1Base = () => (g1Table ??= C1.fixedTable(G1_AFF));
const g2Base = () => (g2Table ??= C2.fixedTable(G2_AFF));

// ── point encodings ──────────────────────────────────────────────────────────
type G1 = Aff<bigint> | null;
type G2 = Aff<Fp2e> | null;

function isZero(b: Uint8Array, off: number, len: number): boolean {
  for (let i = 0; i < len; i++) if (b[off + i] !== 0) return false;
  return true;
}

/** 64 bytes -> affine G1 point (null = infinity). Coordinates < p and on the curve (cofactor 1). */
function g1From(b: Uint8Array, off = 0): G1 {
  if (isZero(b, off, 64)) return null;
  const x = rd32(b, off), y = rd32(b, off + 32);
  if (x >= P || y >= P) throw proto("G1 coordinate out of range");
  const pt = { x, y };
  if (!C1.onCurve(pt)) throw proto("G1 point is not on the curve");
  return pt;
}
function g1To(p: G1): Buffer {
  return p === null ? Buffer.alloc(64) : Buffer.concat([be32(p.x), be32(p.y)]);
}
function g2To(p: G2): Buffer {
  return p === null ? Buffer.alloc(128)
    : Buffer.concat([be32(p.x[0]), be32(p.x[1]), be32(p.y[0]), be32(p.y[1])]);
}

// ── GT = subgroup of Fp12 in the py_ecc polynomial basis w^12 = 18 w^6 - 82 ───
type Fp12 = bigint[]; // 12 coefficients in [0, p)
const FP12_ONE: Fp12 = [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

function fp12Reduce(t: bigint[]): Fp12 {
  for (let k = 22; k >= 12; k--) {
    const c = t[k] % P;
    if (c !== 0n) {
      t[k - 6] += 18n * c;
      t[k - 12] -= 82n * c;
    }
  }
  const out: Fp12 = new Array(12);
  for (let i = 0; i < 12; i++) out[i] = mod(t[i], P);
  return out;
}
function fp12Mul(a: Fp12, b: Fp12): Fp12 {
  const t: bigint[] = new Array(23).fill(0n);
  for (let i = 0; i < 12; i++) {
    const ai = a[i];
    if (ai === 0n) continue;
    for (let j = 0; j < 12; j++) t[i + j] += ai * b[j];
  }
  return fp12Reduce(t);
}
function fp12Sqr(a: Fp12): Fp12 {
  const t: bigint[] = new Array(23).fill(0n);
  for (let i = 0; i < 12; i++) {
    const ai = a[i];
    if (ai === 0n) continue;
    t[2 * i] += ai * ai;
    const a2 = 2n * ai;
    for (let j = i + 1; j < 12; j++) t[i + j] += a2 * a[j];
  }
  return fp12Reduce(t);
}
function fp12Eq(a: Fp12, b: Fp12): boolean {
  for (let i = 0; i < 12; i++) if (a[i] !== b[i]) return false;
  return true;
}
/** a^e, e >= 0 (4-bit window). */
function fp12Pow(a: Fp12, e: bigint): Fp12 {
  if (e < 0n) throw usage("negative exponent");
  if (e === 0n) return FP12_ONE;
  const tab: Fp12[] = new Array(16);
  tab[1] = a;
  tab[2] = fp12Sqr(a);
  for (let i = 3; i < 16; i++) tab[i] = fp12Mul(tab[i - 1], a);
  const top = Math.ceil(e.toString(2).length / 4);
  let acc: Fp12 = FP12_ONE;
  let started = false;
  for (let w = top - 1; w >= 0; w--) {
    if (started) { acc = fp12Sqr(acc); acc = fp12Sqr(acc); acc = fp12Sqr(acc); acc = fp12Sqr(acc); }
    const d = Number((e >> BigInt(4 * w)) & 15n);
    if (d) { acc = started ? fp12Mul(acc, tab[d]) : tab[d]; started = true; }
  }
  return acc;
}
/** a^e1 * b^e2 (Shamir's trick, 2-bit joint window). */
function fp12Pow2(a: Fp12, e1: bigint, b: Fp12, e2: bigint): Fp12 {
  const tab: Fp12[] = new Array(16);
  const pa: Fp12[] = [FP12_ONE, a, fp12Sqr(a), fp12Mul(fp12Sqr(a), a)];
  const pb: Fp12[] = [FP12_ONE, b, fp12Sqr(b), fp12Mul(fp12Sqr(b), b)];
  for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) {
    tab[i * 4 + j] = i === 0 ? pb[j] : j === 0 ? pa[i] : fp12Mul(pa[i], pb[j]);
  }
  const bits = Math.max(e1.toString(2).length, e2.toString(2).length);
  const top = Math.ceil(bits / 2);
  let acc: Fp12 = FP12_ONE;
  for (let w = top - 1; w >= 0; w--) {
    acc = fp12Sqr(fp12Sqr(acc));
    const d1 = Number((e1 >> BigInt(2 * w)) & 3n), d2 = Number((e2 >> BigInt(2 * w)) & 3n);
    if (d1 || d2) acc = fp12Mul(acc, tab[d1 * 4 + d2]);
  }
  return acc;
}
function fp12From(b: Uint8Array, off: number): Fp12 {
  const out: Fp12 = new Array(12);
  for (let i = 0; i < 12; i++) {
    const c = rd32(b, off + 32 * i);
    if (c >= P) throw proto("GT coefficient out of range");
    out[i] = c;
  }
  return out;
}
function fp12To(a: Fp12): Buffer {
  return Buffer.concat(a.map(be32));
}
function fp12Key(a: Fp12): string {
  return a[0].toString(36) + "|" + a[1].toString(36) + "|" + a[2].toString(36);
}

const GT_GEN: Record<number, Fp12> = {
  1: fp12From(Buffer.from(GT_GEN_PYECC_HEX, "hex"), 0),
  2: fp12From(Buffer.from(GT_GEN_MCL_HEX, "hex"), 0),
};

// ── bounded discrete logs (baby-step / giant-step) ───────────────────────────
function bsgsM(range: number): number {
  return Math.floor(Math.sqrt(range * 2 + 1)) + 1;
}

interface G1Table { m: number; map: Map<bigint, number> }
const g1Tables = new Map<number, G1Table>();
const g1Key = (p: Aff<bigint>) => (p.x << 1n) | (p.y & 1n);

function g1BabyTable(m: number): G1Table {
  let t = g1Tables.get(m);
  if (t) return t;
  const map = new Map<bigint, number>();
  let cur = C1.fromAff(G1_AFF);
  const BATCH = 512;
  let j = 1;
  while (j <= m) {
    const pts: Jac<bigint>[] = [];
    for (let i = 0; i < BATCH && j + i <= m; i++) { pts.push(cur); cur = C1.addMixed(cur, G1_AFF); }
    const aff = C1.batchToAffine(pts);
    aff.forEach((a, i) => { if (a && !map.has(g1Key(a))) map.set(g1Key(a), j + i); });
    j += pts.length;
  }
  t = { m, map };
  if (g1Tables.size > 4) g1Tables.clear();
  g1Tables.set(m, t);
  return t;
}

/** Discrete log of M (w.r.t. G1) over [-range, range]. */
function g1Dlog(M: G1, range: number): number {
  if (M === null) return 0;
  const m = bsgsM(range);
  const tab = g1BabyTable(m);
  const R = BigInt(range);
  let cur = C1.add(C1.fromAff(M), C1.mulFixed(g1Base(), R));
  // after the shift the answer x + R lies in [0, 2R]; j = 0 means "cur is infinity"
  const giant = C1.toAffine(C1.mulFixed(g1Base(), BigInt(m)))!;
  const negGiant: Aff<bigint> = { x: giant.x, y: Fp.neg(giant.y) };
  const BATCH = 128;
  let i = 0;
  while (i <= m) {
    const pts: Jac<bigint>[] = [];
    for (let k = 0; k < BATCH && i + k <= m; k++) { pts.push(cur); cur = C1.addMixed(cur, negGiant); }
    const aff = C1.batchToAffine(pts);
    for (let k = 0; k < aff.length; k++) {
      const a = aff[k];
      const j = a === null ? 0 : tab.map.get(g1Key(a));
      if (j !== undefined) {
        const val = (i + k) * m + j - range;
        if (Math.abs(val) > range) break;
        return val;
      }
    }
    i += pts.length;
  }
  throw budget("result is outside the key's value range (or the ciphertext is invalid)");
}

interface GtTable { m: number; map: Map<string, number> }
const gtTables = new Map<string, GtTable>();

function gtDlog(M: Fp12, tag: number, range: number): number {
  const g = GT_GEN[tag];
  const m = bsgsM(range);
  const tk = tag + ":" + m;
  let tab = gtTables.get(tk);
  if (!tab) {
    const map = new Map<string, number>();
    let cur = FP12_ONE;
    for (let j = 0; j <= m; j++) {
      const k = fp12Key(cur);
      if (!map.has(k)) map.set(k, j);
      cur = fp12Mul(cur, g);
    }
    tab = { m, map };
    if (gtTables.size > 4) gtTables.clear();
    gtTables.set(tk, tab);
  }
  const giant = fp12Pow(g, N - BigInt(m));                      // g^(-m)
  let cur = fp12Mul(M, fp12Pow(g, BigInt(range)));
  for (let i = 0; i <= m; i++) {
    const j = tab.map.get(fp12Key(cur));
    if (j !== undefined) {
      const val = i * m + j - range;
      if (Math.abs(val) > range) break;
      return val;
    }
    cur = fp12Mul(cur, giant);
  }
  throw budget("result is outside the key's value range (or the ciphertext is invalid)");
}

// ── public ciphertext helpers (no key needed) ────────────────────────────────
function checkCell(cell: Uint8Array, what = "FHE cell"): void {
  if (!(cell instanceof Uint8Array) || cell.length !== FHE_CELL_BYTES) {
    throw proto(`${what}: an FHE cell is exactly ${FHE_CELL_BYTES} bytes`);
  }
}

/** The (C1, C2) halves of a cell as a 128-byte SUM blob (validates length and both G1 points). */
export function cellToSum(cell: Uint8Array): Buffer {
  checkCell(cell);
  g1From(cell, 0); g1From(cell, 64);
  return Buffer.from(cell.subarray(0, 128));
}

/** Sum the G1 halves of cells (what the server does for SUM); optional public scalar. */
export function sumCells(cells: Uint8Array[], scale: bigint = 1n): Buffer {
  let a = C1.inf(), b = C1.inf();
  for (const c of cells) {
    checkCell(c);
    const p1 = g1From(c, 0), p2 = g1From(c, 64);
    if (p1) a = C1.addMixed(a, p1);
    if (p2) b = C1.addMixed(b, p2);
  }
  if (scale !== 1n) { const k = mod(scale); a = C1.mul(a, k); b = C1.mul(b, k); }
  const [pa, pb] = C1.batchToAffine([a, b]);
  return Buffer.concat([g1To(pa), g1To(pb)]);
}

/** Combine two partial SUM blobs (G1 addition of both halves). */
export function addSums(a: Uint8Array, b: Uint8Array): Buffer {
  if (a.length !== FHE_SUM_BYTES || b.length !== FHE_SUM_BYTES) throw proto("bad SUM ciphertext");
  const r: Jac<bigint>[] = [];
  for (const off of [0, 64]) {
    const x = g1From(a, off), y = g1From(b, off);
    r.push(C1.add(C1.fromAff(x), C1.fromAff(y)));
  }
  const aff = C1.batchToAffine(r);
  return Buffer.concat([g1To(aff[0]), g1To(aff[1])]);
}

/** Combine two partial DOT blobs of the same tag (component-wise GT multiplication). */
export function mulDots(a: Uint8Array, b: Uint8Array): Buffer {
  if (a.length !== FHE_DOT_BYTES || b.length !== FHE_DOT_BYTES || a[0] !== b[0]) {
    throw proto("bad or mismatched DOT ciphertexts");
  }
  if (a[0] !== 1 && a[0] !== 2) throw proto("unknown DOT back-end tag");
  const parts: Buffer[] = [Buffer.from([a[0]])];
  for (let i = 0; i < 4; i++) {
    parts.push(fp12To(fp12Mul(fp12From(a, 1 + i * 384), fp12From(b, 1 + i * 384))));
  }
  return Buffer.concat(parts);
}

// ── sealed key files (torussql/seal.py) ──────────────────────────────────────
const KEY_MAGIC = "TORUSFHEKEY1";
const SEAL_LABEL = Buffer.from("fhe-key");

function hmac256(key: Uint8Array, ...msg: Uint8Array[]): Buffer {
  const h = createHmac("sha256", key);
  for (const m of msg) h.update(m);
  return h.digest();
}
function passphraseKey(passphrase: string, salt: Buffer): Buffer {
  const raw = scryptSync(Buffer.from(passphrase, "utf8"), salt, 32,
    { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return hmac256(raw, Buffer.concat([Buffer.from("torussql/passphrase-label\0"), SEAL_LABEL]));
}
function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
function keystream(key: Buffer, nonce: Buffer, len: number): Buffer {
  const parts: Buffer[] = [];
  for (let c = 0, got = 0; got < len; c++, got += 32) parts.push(hmac256(key, nonce, u64be(c)));
  return Buffer.concat(parts).subarray(0, len);
}
function macInput(nonce: Buffer, ct: Buffer): Buffer {
  return Buffer.concat([nonce, Buffer.from([1]), u64be(SEAL_LABEL.length), SEAL_LABEL, ct]);
}
function seal(k: Buffer, pt: Buffer): Buffer {
  const encKey = hmac256(k, Buffer.from("enc")), macKey = hmac256(k, Buffer.from("mac"));
  const nonce = randomBytes(16);
  const ks = keystream(encKey, nonce, pt.length);
  const ct = Buffer.from(pt.map((b, i) => b ^ ks[i]));
  return Buffer.concat([nonce, hmac256(macKey, macInput(nonce, ct)), ct]);
}
function unseal(k: Buffer, sealed: Buffer): Buffer {
  if (sealed.length < 48) throw usage("sealed blob too short");
  const nonce = sealed.subarray(0, 16), tag = sealed.subarray(16, 48), ct = sealed.subarray(48);
  const want = hmac256(hmac256(k, Buffer.from("mac")), macInput(nonce, ct));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= tag[i] ^ want[i];
  if (diff !== 0) throw usage("wrong passphrase or damaged key file");
  const ks = keystream(hmac256(k, Buffer.from("enc")), nonce, ct.length);
  return Buffer.from(ct.map((b, i) => b ^ ks[i]));
}

function checkRange(range: number): number {
  if (!Number.isSafeInteger(range) || range < 1 || range > FHE_MAX_RANGE) {
    throw usage(`FHE range must be an integer in [1, 2^40], got ${range}`);
  }
  return range;
}

function toBigInt(v: bigint | number, what: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  throw usage(`${what} must be a bigint or a safe integer`);
}

// ── the key ──────────────────────────────────────────────────────────────────
/**
 * The owner's FHE secret `s` (and the derived public key). `s` never leaves this object:
 * it is a `#private` field, hidden from `console.log`, `util.inspect` and `JSON.stringify`.
 */
export class FheKey {
  #s: bigint;
  #secret: Buffer;
  #range: number;
  #qTab?: Array<Array<Aff<bigint>>>;
  #q2Tab?: Array<Array<Aff<Fp2e>>>;
  #alpha?: bigint;
  #placeholder?: Buffer;

  private constructor(s: bigint, range: number) {
    if (!(s > 0n && s < N)) throw usage("FHE secret out of range [1, n)");
    this.#s = s;
    this.#secret = be32(s);
    this.#range = checkRange(range);
  }

  /** A fresh random key. */
  static generate(range: number = FHE_DEFAULT_RANGE): FheKey {
    return new FheKey(randScalar(), range);
  }
  /** From the raw 32-byte big-endian secret. */
  static fromSecretBytes(raw: Uint8Array, range: number = FHE_DEFAULT_RANGE): FheKey {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) throw usage("an FHE secret is exactly 32 bytes");
    return new FheKey(BigInt("0x" + Buffer.from(raw).toString("hex")), range);
  }
  /** From 64 hex characters. */
  static fromHex(hex: string, range: number = FHE_DEFAULT_RANGE): FheKey {
    if (typeof hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex)) throw usage("an FHE secret is 64 hex characters");
    return new FheKey(BigInt("0x" + hex), range);
  }

  /** Load a key file written by Python `fhe.save_key` (or by {@link save}):
   *  `TORUSFHEKEY1 plain` or `TORUSFHEKEY1 sealed <salt>` (scrypt + encrypt-then-MAC). */
  static load(file: string, passphrase?: string): FheKey {
    let raw: Buffer;
    try { raw = fs.readFileSync(file); } catch (e) { throw usage(`cannot read ${file}: ${(e as Error).message}`); }
    const nl = raw.indexOf(10);
    const head = (nl < 0 ? raw : raw.subarray(0, nl)).toString("latin1").split(/\s+/).filter(Boolean);
    const rest = nl < 0 ? Buffer.alloc(0) : raw.subarray(nl + 1);
    if (head[0] !== KEY_MAGIC) throw usage(`${file}: not an FHE key file`);
    let body: Buffer;
    if (head[1] === "plain") {
      body = rest;
    } else if (head[1] === "sealed") {
      if (!passphrase) throw usage(`${file} is sealed - a passphrase is required`);
      const salt = head[2] && /^([0-9a-f]{2})+$/i.test(head[2]) ? Buffer.from(head[2], "hex") : null;
      const hex = rest.toString("latin1").trim();
      if (!salt || !/^([0-9a-f]{2})+$/i.test(hex)) throw usage(`${file}: damaged key file`);
      body = unseal(passphraseKey(passphrase, salt), Buffer.from(hex, "hex"));
    } else {
      throw usage(`${file}: unknown key file kind`);
    }
    let d: any;
    try { d = JSON.parse(body.toString("utf8")); } catch { throw usage(`${file}: damaged key file`); }
    if (!d || typeof d.s !== "string" || typeof d.range !== "number") throw usage(`${file}: damaged key file`);
    return FheKey.fromHex(d.s, d.range);
  }

  /** Write the key (mode 0600, atomic). With a passphrase it is sealed; `null`/`undefined` stores it
   *  unprotected (tests only). The format is the one of Python `fhe.save_key`. */
  save(file: string, passphrase?: string | null): void {
    const body = Buffer.from(JSON.stringify({ v: 1, range: this.#range, s: this.#secret.toString("hex") }));
    let blob: Buffer;
    if (passphrase) {
      const salt = randomBytes(16);
      const k = passphraseKey(passphrase, salt);
      blob = Buffer.concat([Buffer.from(`${KEY_MAGIC} sealed ${salt.toString("hex")}\n`),
        Buffer.from(seal(k, body).toString("hex"))]);
    } else {
      blob = Buffer.concat([Buffer.from(`${KEY_MAGIC} plain\n`), body]);
    }
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      fs.writeSync(fd, blob);
      fs.fsyncSync(fd);
    } catch (e) {
      fs.closeSync(fd); fs.rmSync(tmp, { force: true });
      throw e;
    }
    fs.closeSync(fd);
    try { fs.renameSync(tmp, file); } catch (e) { fs.rmSync(tmp, { force: true }); throw e; }
  }

  /** Plaintexts and results must lie in [-range, range]. */
  get range(): number { return this.#range; }
  /** The secret as 32 big-endian bytes (a copy). */
  secretBytes(): Buffer { return Buffer.from(this.#secret); }

  [util.inspect.custom](): string { return `FheKey { range: ${this.#range} (secret redacted) }`; }
  toJSON(): string { return "[FheKey]"; }

  // ── encryption (public data only) ──
  private qTab() { return (this.#qTab ??= C1.fixedTable(C1.toAffine(C1.mulFixed(g1Base(), this.#s))!)); }
  private q2Tab() { return (this.#q2Tab ??= C2.fixedTable(C2.toAffine(C2.mulFixed(g2Base(), this.#s))!)); }

  /** Encrypt an integer with |v| <= range: a 384-byte cell. r1 and r2 are independent random scalars. */
  encrypt(v: bigint | number): Buffer {
    const x = toBigInt(v, "an FHE plaintext");
    const R = BigInt(this.#range);
    if (x > R || x < -R) throw budget(`|value| must be <= the key's range (${this.#range})`);
    return this.encryptScalar(x);
  }

  /** Encrypt an arbitrary scalar mod n (no range limit: used for integrity tags). */
  encryptScalar(m: bigint): Buffer {
    let vm = mod(m);
    if (vm > N / 2n) vm = vm - N;                    // short representative: faster fixed-base mult
    const r1 = randScalar(), r2 = randScalar();
    const g1 = g1Base(), g2 = g2Base();
    const c1 = C1.mulFixed(g1, r1);
    const c2 = C1.add(C1.mulFixed(g1, vm), C1.mulFixed(this.qTab(), r1));
    const d1 = C2.mulFixed(g2, r2);
    const d2 = C2.add(C2.mulFixed(g2, vm), C2.mulFixed(this.q2Tab(), r2));
    const [a, b] = C1.batchToAffine([c1, c2]);
    return Buffer.concat([g1To(a), g1To(b), g2To(C2.toAffine(d1)), g2To(C2.toAffine(d2))]);
  }

  /** A valid cell that is not tied to any plaintext, used as the temporary tag of an authenticated INSERT. */
  placeholderCell(): Buffer { return (this.#placeholder ??= this.encryptScalar(0n)); }

  // ── decryption ──
  /** C2 - s*C1 of a (C1,C2) pair at `blob[off..]` as an affine point (the plaintext times G1). */
  private opened(blob: Uint8Array, off: number): G1 {
    const c1 = g1From(blob, off), c2 = g1From(blob, off + 64);
    const sc1 = c1 === null ? C1.inf() : C1.mul(C1.fromAff(c1), this.#s);
    return C1.toAffine(C1.add(C1.fromAff(c2), C1.neg(sc1)));
  }

  /** Decrypt a SUM blob (128 bytes) with a bounded discrete log. */
  decryptSum(blob: Uint8Array): number {
    if (blob.length !== FHE_SUM_BYTES) throw proto("bad SUM ciphertext");
    return g1Dlog(this.opened(blob, 0), this.#range);
  }

  /** Decrypt one cell (only its G1 half is used). */
  decryptCell(cell: Uint8Array): number {
    checkCell(cell);
    return g1Dlog(this.opened(cell, 0), this.#range);
  }

  /** Decrypt a DOT blob: `M = c11 * c01^-s * c10^-s * c00^(s^2) = g^(sum a_i b_i)`, then a bounded dlog.
   *  The four components are the server's (untrusted) answer: the two that are raised to
   *  secret-dependent powers are first checked to lie in GT (order n), which closes the
   *  small-subgroup oracle a hostile server could otherwise use against `s`. */
  decryptDot(blob: Uint8Array): number {
    if (blob.length !== FHE_DOT_BYTES) throw proto("bad DOT ciphertext");
    const tag = blob[0];
    if (tag !== 1 && tag !== 2) throw proto("unknown DOT back-end tag");
    const c00 = fp12From(blob, 1), c01 = fp12From(blob, 385), c10 = fp12From(blob, 769), c11 = fp12From(blob, 1153);
    const c0110 = fp12Mul(c01, c10);
    if (!fp12Eq(fp12Pow(c00, N), FP12_ONE) || !fp12Eq(fp12Pow(c0110, N), FP12_ONE)) {
      throw proto("DOT result is not an element of the target group (hostile or damaged server answer)");
    }
    const s = this.#s;
    const M = fp12Mul(c11, fp12Pow2(c0110, N - s, c00, (s * s) % N));
    return gtDlog(M, tag, this.#range);
  }

  // ── integrity tags (authenticated mode) ──
  private prf(label: string, ...parts: Array<string | number>): bigint {
    const h = createHmac("sha256", this.#secret).update("torussql/fhe/" + label).digest();
    const d = createHmac("sha512", h).update(parts.map(String).join("\0"), "utf8").digest("hex");
    return BigInt("0x" + d) % N;
  }
  /** The MAC key alpha = PRF("alpha") (or 1). */
  alpha(): bigint { return (this.#alpha ??= this.prf("alpha") || 1n); }
  /** The per-cell tweak gamma = PRF("gamma", table, column, row id). */
  gamma(table: string, col: string, rowid: number): bigint { return this.prf("gamma", table, col, rowid); }
  /** The tag cell Enc(alpha*v + gamma) for the cell (table, col, rowid). */
  tag(v: bigint | number, table: string, col: string, rowid: number): Buffer {
    const x = toBigInt(v, "an FHE plaintext");
    return this.encryptScalar(this.alpha() * x + this.gamma(table, col, rowid));
  }

  /** Check `tag-sum == alpha * value-sum + k * (sum gamma_i) * G1` (group elements) and return the
   *  decrypted value sum. Throws IntegrityError on any mismatch. */
  decryptSumVerified(valueBlob: Uint8Array, tagBlob: Uint8Array, table: string, col: string,
                     rowIds: number[], scale: bigint | number = 1n): number {
    if (valueBlob.length !== FHE_SUM_BYTES || tagBlob.length !== FHE_SUM_BYTES) throw proto("bad SUM ciphertext");
    let gam = 0n;
    for (const i of rowIds) gam += this.gamma(table, col, i);
    gam %= N;
    const k = toBigInt(scale, "the scale");
    const mv = this.opened(valueBlob, 0), mt = this.opened(tagBlob, 0);
    const want = C1.toAffine(C1.add(
      mv === null ? C1.inf() : C1.mul(C1.fromAff(mv), this.alpha()),
      C1.mulFixed(g1Base(), mod(k * gam))));
    if (!C1.eqAff(mt, want)) {
      throw new TorusError("IntegrityError",
        `integrity check failed for ${table}.${col}: the server's aggregate does not match the authenticated cells`);
    }
    return g1Dlog(mv, this.#range);
  }

  /** Decrypt one cell and verify it against its tag cell (`null` tag = never tagged). */
  decryptCellVerified(cell: Uint8Array | null, tag: Uint8Array | null, table: string, col: string, rowid: number): number {
    if (cell === null || tag === null) {
      throw new TorusError("IntegrityError",
        `${table}.${col} row ${rowid} has no integrity tag (written without authentication, or tampered)`);
    }
    return this.decryptSumVerified(cellToSum(cell), cellToSum(tag), table, col, [rowid]);
  }
}

/** Test/diagnostic access to the group order and generators (not part of the stable API). */
export const _internals = {
  C1, C2, G1_AFF, G2_AFF, fp12Pow, fp12From, fp12To, fp12Mul, FP12_ONE, GT_GEN, B2, g1From, g1To,
  G2_HEX: [G2X0, G2X1, G2Y0, G2Y1],
};
