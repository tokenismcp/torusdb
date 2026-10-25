// SPDX-License-Identifier: Apache-2.0
//! FHE columns (EC-FHE on BN254) - the owner's side. Normative spec: `proto/fhe-wire.md`.
//!
//! No pairing is needed here: the SERVER computes the pairings (`DOT`); the client only does
//! G1/G2 scalar multiplication, G1 addition, Fp12 arithmetic (to open a DOT result) and bounded
//! discrete logarithms, all on `num-bigint`.
//!
//! NOT constant-time (num-bigint is not): do not expose decryption to an attacker who can time
//! it with high resolution. The server only ever sees ciphertexts.

use crate::error::{Error, Kind};
use crate::hash::{hmac_sha256, hmac_sha512, scrypt, sha512};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

type Result<T> = std::result::Result<T, Error>;

pub const FHE_GT_BYTES: usize = 384;
/// One FHE cell: `C1 || C2 || D1 || D2`.
pub const FHE_CELL_BYTES: usize = 384;
/// SUM blob: `sum C1 || sum C2`.
pub const FHE_SUM_BYTES: usize = 128;
/// DOT blob: `tag || c00 || c01 || c10 || c11`.
pub const FHE_DOT_BYTES: usize = 1 + 4 * FHE_GT_BYTES;
/// Default plaintext/result range of a key.
pub const FHE_DEFAULT_RANGE: u64 = 1_000_000;
/// Largest range a key may have (the BSGS tables have about sqrt(2*range) entries).
pub const FHE_MAX_RANGE: u64 = 1 << 40;

/// The pairing library the SERVER should use for DOT (`fhe_dot`'s optional last argument).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FheBackend {
    /// Pure Python `py_ecc` (portable, about 0.2 s per row). Result tag 0x01.
    Pyecc,
    /// Native `mclbn256` (about 1 ms per row). Result tag 0x02.
    Mcl,
}

impl FheBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            FheBackend::Pyecc => "pyecc",
            FheBackend::Mcl => "mcl",
        }
    }
}

const G2X0: &str = "10857046999023057135944570762232829481370756359578518086990519993285655852781";
const G2X1: &str = "11559732032986387107991004021392285783925812861821192530917403151452391805634";
const G2Y0: &str = "8495653923123431417604973247489272438418190587263600148770280649306958101930";
const G2Y1: &str = "4082367875863433681332203403145435568316851327593401208105741076214120093531";

// GT generators g = e(G1, G2) of the two pairing back ends, canonical py_ecc polynomial basis
// (12 x 32-byte big-endian coefficients). Published in proto/fhe-vectors.json.
const GT_GEN_PYECC_HEX: &str = "28c6e04df059260df7d2d2a1f9b5f77676d1939847852c4ed50d2318744c1d5f17bb74adab1705c26133af1dac87044a3833ac011018e8158da48382bbd2dcd60d3bd72f54d742f78ea9e6015c8ea2f2e7fbb728c9c905ec531dcf7de5b246f0090cb8ee97e091a667af03882b06c3ecb4e437993cbd1b05b98c7f9dfcfe9c40016b6d855b5cbf76f9829a309db52f5c442f65ae29f996af59d65f85f4afe78a0a0272204db51dadc0342bd318b9302a44faec12ff500bdd4d4b012ffe45f36f084f330485b09e866bc2f2ea2b897394deaf3f12aa31f28cb0552990967d470427ed208e7a0b55ae6e710bbfbd2fd922669c026360e37cc5b2ab8624115361042067586885c3318eeffa1938c754fe3c60224ee5ae15e66af6b5104c47c8c5d8279db296f9d479292532c7c493d8e0722b6efae42158387564889c79fc038ee32b03614464f04dd772d86df88674c270ffc8747ea13e72da95e3594468f222c4108c19d15f9446f744d0f110405d3856d6cc3bda6c4d537663729f5257628417";
const GT_GEN_MCL_HEX: &str = "0c498eace9669afdb2ac004a2bc3352ff31fa2b137a520190498891a96af31fb0f7abc6cd882a79148ae975c363201b64294a69c7da04b4dc0fcc4a6b77f99801fa5477cf344c578b943985d188016c90cfed95c39da64d34f7dab3bf29053a4189cc22058b17f919c91a5da449e1130585d76d6c852c08307a7355064d0e6682e5c373f19a914ff641dc62428638e6209a0f8ca64990df7966a7cce65903e150ae359efdcdc3ff0067fb863975a0289d468186d63f62e156aec452863c445d402e02d2cc795a2000a1b1f823879abbd397c4dea0918ed66b49d34b48efb8a4a14d3d6ca72d8a950a31dc10f7b4053c9e9ad9ebb590cb4a60f8215d4b99f2b4a040ba9fa500f1a5c4b31984a74e68659c4b420bd699ce630b130b08a6ea1162b0b53320e5a6488cb98a855ffc837d2a75ab90d61ac16cc1b7ab2cd3ed5e22b971c54a530398c9064bdc662d929e645cadda9a712cc5a8243f9cddbd2d98dd1f000f97b5221474526b601f3730a3afa965ceee1b343940c383e5314859e762c97";

fn usage(m: impl Into<String>) -> Error {
    Error::interface(m)
}
fn proto(m: impl Into<String>) -> Error {
    Error::protocol(m)
}
fn budget(m: impl Into<String>) -> Error {
    Error::budget(m)
}

fn p() -> &'static BigUint {
    static P: OnceLock<BigUint> = OnceLock::new();
    P.get_or_init(|| {
        BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap()
    })
}
/// The BN254 group order.
pub fn group_order() -> &'static BigUint {
    static N: OnceLock<BigUint> = OnceLock::new();
    N.get_or_init(|| {
        BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap()
    })
}
fn p82() -> &'static BigUint {
    static V: OnceLock<BigUint> = OnceLock::new();
    V.get_or_init(|| p() * 82u32)
}

fn be32(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(&b);
    o
}
fn rd32(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&b[..32])
}

/// Uniform scalar in [1, n) (512 random bits reduced: bias < 2^-250). Cryptographically secure RNG.
fn rand_scalar() -> BigUint {
    let mut b = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut b);
    BigUint::from_bytes_be(&b) % (group_order() - 1u32) + 1u32
}

// ── fields ───────────────────────────────────────────────────────────────────
trait Fld: Clone + PartialEq {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, o: &Self) -> Self;
    fn sub(&self, o: &Self) -> Self;
    fn mul(&self, o: &Self) -> Self;
    fn sqr(&self) -> Self {
        self.mul(self)
    }
    fn neg(&self) -> Self;
    fn is_zero(&self) -> bool;
    fn inv(&self) -> Self;
}

#[derive(Clone, PartialEq, Debug)]
struct Fp(BigUint);

impl Fld for Fp {
    fn zero() -> Self {
        Fp(BigUint::zero())
    }
    fn one() -> Self {
        Fp(BigUint::one())
    }
    fn add(&self, o: &Self) -> Self {
        let s = &self.0 + &o.0;
        Fp(if &s >= p() { s - p() } else { s })
    }
    fn sub(&self, o: &Self) -> Self {
        Fp(if self.0 >= o.0 { &self.0 - &o.0 } else { &self.0 + p() - &o.0 })
    }
    fn mul(&self, o: &Self) -> Self {
        Fp((&self.0 * &o.0) % p())
    }
    fn neg(&self) -> Self {
        Fp(if self.0.is_zero() { BigUint::zero() } else { p() - &self.0 })
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    fn inv(&self) -> Self {
        Fp(self.0.modpow(&(p() - 2u32), p()))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct Fp2(Fp, Fp); // a0 + a1*i, i^2 = -1

impl Fld for Fp2 {
    fn zero() -> Self {
        Fp2(Fp::zero(), Fp::zero())
    }
    fn one() -> Self {
        Fp2(Fp::one(), Fp::zero())
    }
    fn add(&self, o: &Self) -> Self {
        Fp2(self.0.add(&o.0), self.1.add(&o.1))
    }
    fn sub(&self, o: &Self) -> Self {
        Fp2(self.0.sub(&o.0), self.1.sub(&o.1))
    }
    fn mul(&self, o: &Self) -> Self {
        let t0 = self.0.mul(&o.0);
        let t1 = self.1.mul(&o.1);
        let t2 = self.0.add(&self.1).mul(&o.0.add(&o.1));
        Fp2(t0.sub(&t1), t2.sub(&t0).sub(&t1))
    }
    fn sqr(&self) -> Self {
        let c0 = self.0.add(&self.1).mul(&self.0.sub(&self.1));
        let m = self.0.mul(&self.1);
        Fp2(c0, m.add(&m))
    }
    fn neg(&self) -> Self {
        Fp2(self.0.neg(), self.1.neg())
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero() && self.1.is_zero()
    }
    fn inv(&self) -> Self {
        let nrm = self.0.sqr().add(&self.1.sqr()).inv();
        Fp2(self.0.mul(&nrm), self.1.mul(&nrm).neg())
    }
}

// ── short Weierstrass curve y^2 = x^3 + b in Jacobian coordinates ────────────
#[derive(Clone)]
struct Jac<F> {
    x: F,
    y: F,
    z: F,
}
#[derive(Clone, PartialEq)]
struct Aff<F> {
    x: F,
    y: F,
}
type Table<F> = Vec<Vec<Aff<F>>>;

struct Curve<F: Fld> {
    b: F,
}

impl<F: Fld> Curve<F> {
    fn inf(&self) -> Jac<F> {
        Jac { x: F::one(), y: F::one(), z: F::zero() }
    }
    fn is_inf(&self, p: &Jac<F>) -> bool {
        p.z.is_zero()
    }
    fn lift(&self, a: &Aff<F>) -> Jac<F> {
        Jac { x: a.x.clone(), y: a.y.clone(), z: F::one() }
    }
    fn neg(&self, p: &Jac<F>) -> Jac<F> {
        Jac { x: p.x.clone(), y: p.y.neg(), z: p.z.clone() }
    }
    fn on_curve(&self, a: &Aff<F>) -> bool {
        a.y.sqr() == a.x.sqr().mul(&a.x).add(&self.b)
    }

    fn dbl(&self, p: &Jac<F>) -> Jac<F> {
        if p.z.is_zero() || p.y.is_zero() {
            return self.inf();
        }
        let a = p.x.sqr();
        let b = p.y.sqr();
        let c = b.sqr();
        let t = p.x.add(&b).sqr();
        let d0 = t.sub(&a).sub(&c);
        let d = d0.add(&d0);
        let e = a.add(&a).add(&a);
        let f = e.sqr();
        let x3 = f.sub(&d.add(&d));
        let c2 = c.add(&c);
        let c4 = c2.add(&c2);
        let c8 = c4.add(&c4);
        let y3 = e.mul(&d.sub(&x3)).sub(&c8);
        let yz = p.y.mul(&p.z);
        Jac { x: x3, y: y3, z: yz.add(&yz) }
    }

    fn add(&self, p: &Jac<F>, q: &Jac<F>) -> Jac<F> {
        if p.z.is_zero() {
            return q.clone();
        }
        if q.z.is_zero() {
            return p.clone();
        }
        let z1z1 = p.z.sqr();
        let z2z2 = q.z.sqr();
        let u1 = p.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = p.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&p.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r0 = s2.sub(&s1);
        if h.is_zero() {
            return if r0.is_zero() { self.dbl(p) } else { self.inf() };
        }
        let h2 = h.add(&h);
        let i = h2.sqr();
        let j = h.mul(&i);
        let r = r0.add(&r0);
        let v = u1.mul(&i);
        let x3 = r.sqr().sub(&j).sub(&v.add(&v));
        let s1j = s1.mul(&j);
        let y3 = r.mul(&v.sub(&x3)).sub(&s1j.add(&s1j));
        let z3 = p.z.add(&q.z).sqr().sub(&z1z1).sub(&z2z2).mul(&h);
        Jac { x: x3, y: y3, z: z3 }
    }

    /// p + q with q affine (not infinity).
    fn add_mixed(&self, p: &Jac<F>, q: &Aff<F>) -> Jac<F> {
        if p.z.is_zero() {
            return self.lift(q);
        }
        let z1z1 = p.z.sqr();
        let u2 = q.x.mul(&z1z1);
        let s2 = q.y.mul(&p.z).mul(&z1z1);
        let h = u2.sub(&p.x);
        let r0 = s2.sub(&p.y);
        if h.is_zero() {
            return if r0.is_zero() { self.dbl(p) } else { self.inf() };
        }
        let hh = h.sqr();
        let i0 = hh.add(&hh);
        let i = i0.add(&i0);
        let j = h.mul(&i);
        let r = r0.add(&r0);
        let v = p.x.mul(&i);
        let x3 = r.sqr().sub(&j).sub(&v.add(&v));
        let yj = p.y.mul(&j);
        let y3 = r.mul(&v.sub(&x3)).sub(&yj.add(&yj));
        let z3 = p.z.add(&h).sqr().sub(&z1z1).sub(&hh);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn to_affine(&self, p: &Jac<F>) -> Option<Aff<F>> {
        if p.z.is_zero() {
            return None;
        }
        let zi = p.z.inv();
        let zi2 = zi.sqr();
        Some(Aff { x: p.x.mul(&zi2), y: p.y.mul(&zi2).mul(&zi) })
    }

    /// Montgomery batch inversion: one field inversion for the whole list.
    fn batch_to_affine(&self, ps: &[Jac<F>]) -> Vec<Option<Aff<F>>> {
        let mut out: Vec<Option<Aff<F>>> = vec![None; ps.len()];
        let mut idx = vec![];
        let mut pref: Vec<F> = vec![];
        let mut acc = F::one();
        for (i, p) in ps.iter().enumerate() {
            if p.z.is_zero() {
                continue;
            }
            idx.push(i);
            acc = acc.mul(&p.z);
            pref.push(acc.clone());
        }
        if idx.is_empty() {
            return out;
        }
        let mut inv = acc.inv();
        for k in (0..idx.len()).rev() {
            let p = &ps[idx[k]];
            let zi = if k > 0 { inv.mul(&pref[k - 1]) } else { inv.clone() };
            inv = inv.mul(&p.z);
            let zi2 = zi.sqr();
            out[idx[k]] = Some(Aff { x: p.x.mul(&zi2), y: p.y.mul(&zi2).mul(&zi) });
        }
        out
    }

    /// Variable-base k*p, 4-bit window.
    fn mul(&self, p: &Jac<F>, k: &BigUint) -> Jac<F> {
        if k.is_zero() || self.is_inf(p) {
            return self.inf();
        }
        let mut tab: Vec<Jac<F>> = vec![self.inf(), p.clone(), self.dbl(p)];
        for i in 3..16 {
            let n = self.add(&tab[i - 1], p);
            tab.push(n);
        }
        let digits = k.to_radix_le(16);
        let mut acc = self.inf();
        for (pos, d) in digits.iter().enumerate().rev() {
            if pos != digits.len() - 1 {
                acc = self.dbl(&self.dbl(&self.dbl(&self.dbl(&acc))));
            }
            if *d != 0 {
                acc = self.add(&acc, &tab[*d as usize]);
            }
        }
        acc
    }

    /// Table of d * 16^w * base (d = 1..15, w = 0..63), affine.
    fn fixed_table(&self, base: &Aff<F>) -> Table<F> {
        let mut tab = Vec::with_capacity(64);
        let mut b = self.lift(base);
        for _ in 0..64 {
            let mut row = vec![b.clone(), self.dbl(&b)];
            for d in 3..=15 {
                let n = self.add(&row[d - 2], &b);
                row.push(n);
            }
            tab.push(self.batch_to_affine(&row).into_iter().map(|a| a.unwrap()).collect());
            b = self.dbl(&self.dbl(&self.dbl(&self.dbl(&b))));
        }
        tab
    }

    fn mul_fixed(&self, tab: &Table<F>, k: &BigUint) -> Result<Jac<F>> {
        let digits = k.to_radix_le(16);
        if k.is_zero() {
            return Ok(self.inf());
        }
        if digits.len() > 64 {
            return Err(usage("scalar too large for the fixed-base table"));
        }
        let mut acc = self.inf();
        for (w, d) in digits.iter().enumerate() {
            if *d != 0 {
                acc = self.add_mixed(&acc, &tab[w][*d as usize - 1]);
            }
        }
        Ok(acc)
    }
}

fn dec(s: &str) -> Fp {
    Fp(BigUint::parse_bytes(s.as_bytes(), 10).unwrap())
}

fn c1() -> &'static Curve<Fp> {
    static C: OnceLock<Curve<Fp>> = OnceLock::new();
    C.get_or_init(|| Curve { b: Fp(BigUint::from(3u32)) })
}
fn c2() -> &'static Curve<Fp2> {
    static C: OnceLock<Curve<Fp2>> = OnceLock::new();
    C.get_or_init(|| {
        // b' = 3 / (9 + i) = 3 (9 - i) / 82 = (27 - 3i) / 82
        let inv82 = Fp(BigUint::from(82u32)).inv();
        let b0 = Fp(BigUint::from(27u32)).mul(&inv82);
        let b1 = Fp(BigUint::from(3u32)).neg().mul(&inv82);
        Curve { b: Fp2(b0, b1) }
    })
}
fn g1_gen() -> Aff<Fp> {
    Aff { x: Fp(BigUint::one()), y: Fp(BigUint::from(2u32)) }
}
fn g2_gen() -> Aff<Fp2> {
    Aff { x: Fp2(dec(G2X0), dec(G2X1)), y: Fp2(dec(G2Y0), dec(G2Y1)) }
}
fn g1_base() -> &'static Table<Fp> {
    static T: OnceLock<Table<Fp>> = OnceLock::new();
    T.get_or_init(|| c1().fixed_table(&g1_gen()))
}
fn g2_base() -> &'static Table<Fp2> {
    static T: OnceLock<Table<Fp2>> = OnceLock::new();
    T.get_or_init(|| c2().fixed_table(&g2_gen()))
}

// ── point encodings ──────────────────────────────────────────────────────────
type G1 = Option<Aff<Fp>>;

/// 64 bytes -> affine G1 point (`None` = infinity). Coordinates < p and on the curve (cofactor 1).
fn g1_from(b: &[u8]) -> Result<G1> {
    if b.len() != 64 {
        return Err(proto("a G1 point is 64 bytes"));
    }
    if b.iter().all(|x| *x == 0) {
        return Ok(None);
    }
    let (x, y) = (rd32(&b[..32]), rd32(&b[32..]));
    if &x >= p() || &y >= p() {
        return Err(proto("G1 coordinate out of range"));
    }
    let pt = Aff { x: Fp(x), y: Fp(y) };
    if !c1().on_curve(&pt) {
        return Err(proto("G1 point is not on the curve"));
    }
    Ok(Some(pt))
}
fn g1_to(p_: &G1) -> Vec<u8> {
    match p_ {
        None => vec![0u8; 64],
        Some(a) => [be32(&a.x.0), be32(&a.y.0)].concat(),
    }
}
fn g2_to(p_: &Option<Aff<Fp2>>) -> Vec<u8> {
    match p_ {
        None => vec![0u8; 128],
        Some(a) => [be32(&a.x.0 .0), be32(&a.x.1 .0), be32(&a.y.0 .0), be32(&a.y.1 .0)].concat(),
    }
}

// ── GT = subgroup of Fp12 in the py_ecc polynomial basis w^12 = 18 w^6 - 82 ───
#[derive(Clone, PartialEq, Debug)]
struct Fp12(Vec<BigUint>); // 12 coefficients in [0, p)

impl Fp12 {
    fn one() -> Fp12 {
        let mut v = vec![BigUint::zero(); 12];
        v[0] = BigUint::one();
        Fp12(v)
    }
    fn reduce(mut t: Vec<BigUint>) -> Fp12 {
        for k in (12..23).rev() {
            let c = &t[k] % p();
            if !c.is_zero() {
                t[k - 6] += &c * 18u32;
                t[k - 12] += p82() - &c * 82u32;
            }
        }
        Fp12(t.into_iter().take(12).map(|x| x % p()).collect())
    }
    fn mul(&self, o: &Fp12) -> Fp12 {
        let mut t = vec![BigUint::zero(); 23];
        for i in 0..12 {
            if self.0[i].is_zero() {
                continue;
            }
            for j in 0..12 {
                t[i + j] += &self.0[i] * &o.0[j];
            }
        }
        Fp12::reduce(t)
    }
    fn sqr(&self) -> Fp12 {
        let mut t = vec![BigUint::zero(); 23];
        for i in 0..12 {
            if self.0[i].is_zero() {
                continue;
            }
            t[2 * i] += &self.0[i] * &self.0[i];
            let a2 = &self.0[i] * 2u32;
            for j in i + 1..12 {
                t[i + j] += &a2 * &self.0[j];
            }
        }
        Fp12::reduce(t)
    }
    /// a^e (4-bit window).
    fn pow(&self, e: &BigUint) -> Fp12 {
        if e.is_zero() {
            return Fp12::one();
        }
        let mut tab = vec![Fp12::one(), self.clone(), self.sqr()];
        for i in 3..16 {
            let n = tab[i - 1].mul(self);
            tab.push(n);
        }
        let digits = e.to_radix_le(16);
        let mut acc: Option<Fp12> = None;
        for d in digits.iter().rev() {
            if let Some(a) = &acc {
                let mut x = a.sqr();
                x = x.sqr();
                x = x.sqr();
                x = x.sqr();
                acc = Some(x);
            }
            if *d != 0 {
                acc = Some(match acc {
                    Some(a) => a.mul(&tab[*d as usize]),
                    None => tab[*d as usize].clone(),
                });
            }
        }
        acc.unwrap_or_else(Fp12::one)
    }
    /// a^e1 * b^e2 (Shamir's trick, 2-bit joint window).
    fn pow2(a: &Fp12, e1: &BigUint, b: &Fp12, e2: &BigUint) -> Fp12 {
        let one = Fp12::one();
        let a2 = a.sqr();
        let b2 = b.sqr();
        let pa = [one.clone(), a.clone(), a2.clone(), a2.mul(a)];
        let pb = [one, b.clone(), b2.clone(), b2.mul(b)];
        let mut tab: Vec<Fp12> = Vec::with_capacity(16);
        for (i, pai) in pa.iter().enumerate() {
            for (j, pbj) in pb.iter().enumerate() {
                tab.push(if i == 0 {
                    pbj.clone()
                } else if j == 0 {
                    pai.clone()
                } else {
                    pai.mul(pbj)
                });
            }
        }
        let bits = e1.bits().max(e2.bits()) as usize;
        let top = bits.div_ceil(2);
        let d1 = e1.to_radix_le(4);
        let d2 = e2.to_radix_le(4);
        let mut acc = Fp12::one();
        for w in (0..top).rev() {
            acc = acc.sqr().sqr();
            let x = *d1.get(w).unwrap_or(&0) as usize;
            let y = *d2.get(w).unwrap_or(&0) as usize;
            if x != 0 || y != 0 {
                acc = acc.mul(&tab[x * 4 + y]);
            }
        }
        acc
    }
    fn from_bytes(b: &[u8]) -> Result<Fp12> {
        if b.len() != FHE_GT_BYTES {
            return Err(proto("a GT element is 384 bytes"));
        }
        let mut v = Vec::with_capacity(12);
        for i in 0..12 {
            let c = rd32(&b[32 * i..]);
            if &c >= p() {
                return Err(proto("GT coefficient out of range"));
            }
            v.push(c);
        }
        Ok(Fp12(v))
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(be32).collect()
    }
    fn key(&self) -> Vec<u8> {
        [be32(&self.0[0]), be32(&self.0[1]), be32(&self.0[2])].concat()
    }
}

fn gt_gen(tag: u8) -> &'static Fp12 {
    static G: OnceLock<[Fp12; 2]> = OnceLock::new();
    let g = G.get_or_init(|| {
        let f = |h: &str| Fp12::from_bytes(&hex_decode(h).unwrap()).unwrap();
        [f(GT_GEN_PYECC_HEX), f(GT_GEN_MCL_HEX)]
    });
    &g[(tag - 1) as usize]
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() & 1 == 1 || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub(crate) fn b64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Strict base64: only the canonical encoding (what `b64_encode` produces) is accepted.
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() & 3 != 0 || !s.is_ascii() {
        return None;
    }
    let val = |c: u8| B64.iter().position(|x| *x == c).map(|v| v as u32);
    let mut out = vec![];
    for q in s.as_bytes().chunks(4) {
        let pad = q.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in q.iter().enumerate() {
            n <<= 6;
            if i < 4 - pad {
                n |= val(*c)?;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    if b64_encode(&out) != s {
        return None;
    }
    Some(out)
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ── bounded discrete logs (baby-step / giant-step) ───────────────────────────
fn bsgs_m(range: u64) -> u64 {
    ((range * 2 + 1) as f64).sqrt().floor() as u64 + 1
}

struct G1Table {
    map: HashMap<Vec<u8>, u32>,
}
fn g1_key(a: &Aff<Fp>) -> Vec<u8> {
    let mut k = be32(&a.x.0).to_vec();
    k.push(if a.y.0.is_odd() { 1 } else { 0 });
    k
}
fn g1_baby_table(m: u64) -> Arc<G1Table> {
    static TABLES: OnceLock<Mutex<HashMap<u64, Arc<G1Table>>>> = OnceLock::new();
    let tabs = TABLES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = tabs.lock().unwrap().get(&m) {
        return t.clone();
    }
    let c = c1();
    let g = g1_gen();
    let mut map = HashMap::with_capacity(m as usize + 1);
    let mut cur = c.lift(&g);
    let mut j = 1u64;
    while j <= m {
        let mut pts = vec![];
        let mut i = 0;
        while i < 512 && j + i <= m {
            pts.push(cur.clone());
            cur = c.add_mixed(&cur, &g);
            i += 1;
        }
        for (i, a) in c.batch_to_affine(&pts).into_iter().enumerate() {
            if let Some(a) = a {
                map.entry(g1_key(&a)).or_insert((j + i as u64) as u32);
            }
        }
        j += pts.len() as u64;
    }
    let t = Arc::new(G1Table { map });
    let mut guard = tabs.lock().unwrap();
    if guard.len() > 4 {
        guard.clear();
    }
    guard.insert(m, t.clone());
    t
}

/// Discrete log of `target` (w.r.t. G1) over [-range, range].
fn g1_dlog(target: &G1, range: u64) -> Result<i64> {
    let c = c1();
    let m = bsgs_m(range);
    let tab = g1_baby_table(m);
    let shift = c.mul_fixed(g1_base(), &BigUint::from(range))?;
    let tj = target.as_ref().map(|a| c.lift(a)).unwrap_or_else(|| c.inf());
    let base = c.add(&tj, &shift);
    let giant = c.to_affine(&c.mul_fixed(g1_base(), &BigUint::from(m))?).unwrap();
    let neg_giant = Aff { x: giant.x.clone(), y: giant.y.neg() };
    // Start the giant-step walk at a RANDOM position and wrap around: the number of steps until a hit
    // is then uniform and independent of the plaintext (a fixed start leaks the value through timing).
    let steps = m + 1;
    let i0 = rand_index(steps);
    let back = c.mul_fixed(g1_base(), &(BigUint::from(i0) * m))?;
    let mut cur = c.add(&base, &c.neg(&back));
    let mut t = 0u64;
    while t < steps {
        let (mut pts, mut idx) = (vec![], vec![]);
        let mut k = 0;
        while k < 128 && t + k < steps {
            let i = (i0 + t + k) % steps;
            if i == 0 && t + k > 0 {
                cur = base.clone(); // wrapped around
            }
            pts.push(cur.clone());
            idx.push(i);
            cur = c.add_mixed(&cur, &neg_giant);
            k += 1;
        }
        for (k, a) in c.batch_to_affine(&pts).into_iter().enumerate() {
            let j = match &a {
                None => Some(0u32),
                Some(a) => tab.map.get(&g1_key(a)).copied(),
            };
            if let Some(j) = j {
                let val = (idx[k] * m + j as u64) as i64 - range as i64;
                if val.unsigned_abs() > range {
                    return Err(out_of_range());
                }
                return Ok(val);
            }
        }
        t += pts.len() as u64;
    }
    Err(out_of_range())
}

fn rand_index(n: u64) -> u64 {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    u64::from_be_bytes(b) % n
}

/// A fresh per-write number (1 <= n < 2^120) that individualises an integrity tag.
pub fn new_nonce() -> BigInt {
    let mut b = [0u8; 15];
    rand::thread_rng().fill_bytes(&mut b);
    BigInt::from(BigUint::from_bytes_be(&b) | BigUint::one())
}

fn out_of_range() -> Error {
    budget("result is outside the key's value range (or the ciphertext is invalid)")
}

struct GtTable {
    map: HashMap<Vec<u8>, u32>,
}
fn gt_dlog(mm: &Fp12, tag: u8, range: u64) -> Result<i64> {
    type Cache = Mutex<HashMap<(u8, u64), Arc<GtTable>>>;
    static TABLES: OnceLock<Cache> = OnceLock::new();
    let g = gt_gen(tag);
    let m = bsgs_m(range);
    let tabs = TABLES.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = tabs.lock().unwrap().get(&(tag, m)).cloned();
    let tab = match cached {
        Some(t) => t,
        None => {
            let mut map = HashMap::with_capacity(m as usize + 1);
            let mut cur = Fp12::one();
            for j in 0..=m {
                map.entry(cur.key()).or_insert(j as u32);
                cur = cur.mul(g);
            }
            let t = Arc::new(GtTable { map });
            let mut guard = tabs.lock().unwrap();
            if guard.len() > 4 {
                guard.clear();
            }
            guard.insert((tag, m), t.clone());
            t
        }
    };
    let giant = g.pow(&(group_order() - BigUint::from(m)));
    let base = mm.mul(&g.pow(&BigUint::from(range)));
    let steps = m + 1;
    let i0 = rand_index(steps); // random start: see g1_dlog
    let mut cur = base.mul(&giant.pow(&BigUint::from(i0)));
    for t in 0..steps {
        let i = (i0 + t) % steps;
        if i == 0 && t > 0 {
            cur = base.clone(); // wrapped around
        }
        if let Some(j) = tab.map.get(&cur.key()) {
            let val = (i * m + *j as u64) as i64 - range as i64;
            if val.unsigned_abs() > range {
                return Err(out_of_range());
            }
            return Ok(val);
        }
        cur = cur.mul(&giant);
    }
    Err(out_of_range())
}

// ── public ciphertext helpers (no key needed) ────────────────────────────────
fn check_cell(cell: &[u8]) -> Result<()> {
    if cell.len() != FHE_CELL_BYTES {
        return Err(proto(format!("an FHE cell is exactly {} bytes, got {}", FHE_CELL_BYTES, cell.len())));
    }
    Ok(())
}

/// The `(C1, C2)` halves of a cell as a 128-byte SUM blob (validates length and both G1 points).
pub fn cell_to_sum(cell: &[u8]) -> Result<Vec<u8>> {
    check_cell(cell)?;
    g1_from(&cell[..64])?;
    g1_from(&cell[64..128])?;
    Ok(cell[..128].to_vec())
}

/// Sum the G1 halves of cells (what the server does for SUM); optional public scalar.
pub fn sum_cells<C: AsRef<[u8]>>(cells: &[C], scale: &BigInt) -> Result<Vec<u8>> {
    let c = c1();
    let (mut a, mut b) = (c.inf(), c.inf());
    for cell in cells {
        let cell = cell.as_ref();
        check_cell(cell)?;
        if let Some(p1) = g1_from(&cell[..64])? {
            a = c.add_mixed(&a, &p1);
        }
        if let Some(p2) = g1_from(&cell[64..128])? {
            b = c.add_mixed(&b, &p2);
        }
    }
    if !scale.is_one() {
        let k = to_scalar(scale);
        a = c.mul(&a, &k);
        b = c.mul(&b, &k);
    }
    let r = c.batch_to_affine(&[a, b]);
    Ok([g1_to(&r[0]), g1_to(&r[1])].concat())
}

/// Combine two partial SUM blobs (G1 addition of both halves).
pub fn add_sums(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != FHE_SUM_BYTES || b.len() != FHE_SUM_BYTES {
        return Err(proto("bad SUM ciphertext"));
    }
    let c = c1();
    let mut r = vec![];
    for off in [0usize, 64] {
        let x = g1_from(&a[off..off + 64])?;
        let y = g1_from(&b[off..off + 64])?;
        let xj = x.map(|v| c.lift(&v)).unwrap_or_else(|| c.inf());
        let yj = y.map(|v| c.lift(&v)).unwrap_or_else(|| c.inf());
        r.push(c.add(&xj, &yj));
    }
    let aff = c.batch_to_affine(&r);
    Ok([g1_to(&aff[0]), g1_to(&aff[1])].concat())
}

/// Combine two partial DOT blobs of the same tag (component-wise GT multiplication).
pub fn mul_dots(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != FHE_DOT_BYTES || b.len() != FHE_DOT_BYTES || a[0] != b[0] {
        return Err(proto("bad or mismatched DOT ciphertexts"));
    }
    if a[0] != 1 && a[0] != 2 {
        return Err(proto("unknown DOT back-end tag"));
    }
    let mut out = vec![a[0]];
    for i in 0..4 {
        let s = 1 + i * FHE_GT_BYTES;
        let x = Fp12::from_bytes(&a[s..s + FHE_GT_BYTES])?;
        let y = Fp12::from_bytes(&b[s..s + FHE_GT_BYTES])?;
        out.extend(x.mul(&y).to_bytes());
    }
    Ok(out)
}

/// A (possibly negative) integer reduced mod n.
fn to_scalar(v: &BigInt) -> BigUint {
    v.mod_floor(&BigInt::from(group_order().clone())).to_biguint().unwrap()
}

// ── sealed key files (torussql/seal.py) ──────────────────────────────────────
const KEY_MAGIC: &str = "TORUSFHEKEY1";
const SEAL_LABEL: &[u8] = b"fhe-key";

fn passphrase_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let raw = scrypt(passphrase.as_bytes(), salt, 1 << 15, 8, 1, 32);
    let mut msg = b"torussql/passphrase-label\0".to_vec();
    msg.extend_from_slice(SEAL_LABEL);
    hmac_sha256(&raw, &msg)
}
fn keystream(key: &[u8], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![];
    let mut c = 0u64;
    while out.len() < len {
        let mut m = nonce.to_vec();
        m.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&hmac_sha256(key, &m));
        c += 1;
    }
    out.truncate(len);
    out
}
fn mac_input(nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut m = nonce.to_vec();
    m.push(1);
    m.extend_from_slice(&(SEAL_LABEL.len() as u64).to_be_bytes());
    m.extend_from_slice(SEAL_LABEL);
    m.extend_from_slice(ct);
    m
}
fn seal(k: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let enc_key = hmac_sha256(k, b"enc");
    let mac_key = hmac_sha256(k, b"mac");
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ks = keystream(&enc_key, &nonce, pt.len());
    let ct: Vec<u8> = pt.iter().zip(&ks).map(|(a, b)| a ^ b).collect();
    let tag = hmac_sha256(&mac_key, &mac_input(&nonce, &ct));
    [nonce.to_vec(), tag.to_vec(), ct].concat()
}
fn unseal(k: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 48 {
        return Err(usage("sealed blob too short"));
    }
    let (nonce, tag, ct) = (&sealed[..16], &sealed[16..48], &sealed[48..]);
    let want = hmac_sha256(&hmac_sha256(k, b"mac"), &mac_input(nonce, ct));
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= tag[i] ^ want[i];
    }
    if diff != 0 {
        return Err(usage("wrong passphrase or damaged key file"));
    }
    let ks = keystream(&hmac_sha256(k, b"enc"), nonce, ct.len());
    Ok(ct.iter().zip(&ks).map(|(a, b)| a ^ b).collect())
}

fn check_range(range: u64) -> Result<u64> {
    if !(1..=FHE_MAX_RANGE).contains(&range) {
        return Err(usage(format!("FHE range must be an integer in [1, 2^40], got {}", range)));
    }
    Ok(range)
}

// ── the key ──────────────────────────────────────────────────────────────────
struct KeyInner {
    s: BigUint,
    s2: BigUint, // second secret: Q2 = s2*G2 (NEVER s*G2, that is a value oracle)
    secret: [u8; 32],
    range: u64,
    q_tab: OnceLock<Table<Fp>>,
    q2_tab: OnceLock<Table<Fp2>>,
    alpha: OnceLock<BigUint>,
    placeholder: OnceLock<Vec<u8>>,
}

/// The owner's FHE secret `s` and the derived public key. Cheap to clone (shared), never printed
/// by `Debug`, and the secret is only reachable through [`FheKey::secret_bytes`].
#[derive(Clone)]
pub struct FheKey(Arc<KeyInner>);

impl fmt::Debug for FheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FheKey {{ range: {} (secret redacted) }}", self.0.range)
    }
}

impl FheKey {
    fn new(s: BigUint, range: u64) -> Result<FheKey> {
        if s.is_zero() || &s >= group_order() {
            return Err(usage("FHE secret out of range [1, n)"));
        }
        let range = check_range(range)?;
        let secret = be32(&s);
        // s2 = int(SHA-512("torussql/fhe/v2/g2-secret\0" || s as 32 big-endian bytes)) mod (n-1) + 1
        let mut seed = b"torussql/fhe/v2/g2-secret\0".to_vec();
        seed.extend_from_slice(&secret);
        let s2 = BigUint::from_bytes_be(&sha512(&seed)) % (group_order() - 1u32) + 1u32;
        Ok(FheKey(Arc::new(KeyInner {
            s,
            s2,
            secret,
            range,
            q_tab: OnceLock::new(),
            q2_tab: OnceLock::new(),
            alpha: OnceLock::new(),
            placeholder: OnceLock::new(),
        })))
    }

    /// A fresh random key.
    pub fn generate(range: u64) -> Result<FheKey> {
        FheKey::new(rand_scalar(), range)
    }
    /// From the raw 32-byte big-endian secret.
    pub fn from_secret_bytes(raw: &[u8], range: u64) -> Result<FheKey> {
        if raw.len() != 32 {
            return Err(usage("an FHE secret is exactly 32 bytes"));
        }
        FheKey::new(BigUint::from_bytes_be(raw), range)
    }
    /// From 64 hex characters.
    pub fn from_hex(h: &str, range: u64) -> Result<FheKey> {
        match hex_decode(h) {
            Some(b) if h.len() == 64 => FheKey::from_secret_bytes(&b, range),
            _ => Err(usage("an FHE secret is 64 hex characters")),
        }
    }

    /// Load a key file written by Python `fhe.save_key` (or by [`FheKey::save`]):
    /// `TORUSFHEKEY1 plain` or `TORUSFHEKEY1 sealed <salt>` (scrypt + encrypt-then-MAC).
    pub fn load(file: &Path, passphrase: Option<&str>) -> Result<FheKey> {
        let raw = std::fs::read(file).map_err(|e| usage(format!("cannot read {}: {}", file.display(), e)))?;
        let (head, rest) = match raw.iter().position(|b| *b == b'\n') {
            Some(i) => (&raw[..i], &raw[i + 1..]),
            None => (&raw[..], &raw[raw.len()..]),
        };
        let head = String::from_utf8_lossy(head).to_string();
        let parts: Vec<&str> = head.split_whitespace().collect();
        let damaged = || usage(format!("{}: damaged key file", file.display()));
        if parts.first() != Some(&KEY_MAGIC) {
            return Err(usage(format!("{}: not an FHE key file", file.display())));
        }
        let body: Vec<u8> = match parts.get(1).copied() {
            Some("plain") => rest.to_vec(),
            Some("sealed") => {
                let pw = passphrase
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| usage(format!("{} is sealed - a passphrase is required", file.display())))?;
                let salt = parts.get(2).and_then(|s| hex_decode(s)).ok_or_else(damaged)?;
                let blob = hex_decode(String::from_utf8_lossy(rest).trim()).ok_or_else(damaged)?;
                unseal(&passphrase_key(pw, &salt), &blob)?
            }
            _ => return Err(usage(format!("{}: unknown key file kind", file.display()))),
        };
        let d: serde_json::Value = serde_json::from_slice(&body).map_err(|_| damaged())?;
        let s = d["s"].as_str().ok_or_else(damaged)?;
        let range = d["range"].as_u64().ok_or_else(damaged)?;
        FheKey::from_hex(s, range)
    }

    /// Write the key (mode 0600, atomic). With a passphrase it is sealed; `None` stores it
    /// unprotected (tests only). The format is the one of Python `fhe.save_key`.
    pub fn save(&self, file: &Path, passphrase: Option<&str>) -> Result<()> {
        let body = format!("{{\"v\": 1, \"range\": {}, \"s\": \"{}\"}}", self.0.range, hex_encode(&self.0.secret));
        let blob: Vec<u8> = match passphrase.filter(|p| !p.is_empty()) {
            Some(pw) => {
                let mut salt = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut salt);
                let k = passphrase_key(pw, &salt);
                format!("{} sealed {}\n{}", KEY_MAGIC, hex_encode(&salt), hex_encode(&seal(&k, body.as_bytes()))).into_bytes()
            }
            None => format!("{} plain\n{}", KEY_MAGIC, body).into_bytes(),
        };
        let dir = file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let tmp = dir.join(format!(
            ".{}.{}.{:08x}.tmp",
            file.file_name().and_then(|s| s.to_str()).unwrap_or("fhe.key"),
            std::process::id(),
            rand::random::<u32>()
        ));
        let io = |e: std::io::Error| usage(format!("key write failed: {}", e));
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
            std::fs::rename(&tmp, file)
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(io(e));
        }
        Ok(())
    }

    /// The public key: `(q_g1 = s*G1 (64 bytes), q2_g2 = s2*G2 (128 bytes))`.
    pub fn public_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let q1 = c1().to_affine(&c1().mul_fixed(g1_base(), &self.0.s)?);
        let q2 = c2().to_affine(&c2().mul_fixed(g2_base(), &self.0.s2)?);
        Ok((g1_to(&q1), g2_to(&q2)))
    }
    /// The second secret `s2` as 32 big-endian bytes (for known-answer tests).
    pub fn s2_bytes(&self) -> [u8; 32] {
        be32(&self.0.s2)
    }

    /// Plaintexts and results must lie in `[-range, range]`.
    pub fn range(&self) -> u64 {
        self.0.range
    }
    /// The secret as 32 big-endian bytes (a copy).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.secret
    }

    // ── encryption (public data only) ──
    fn q_tab(&self) -> Result<&Table<Fp>> {
        if self.0.q_tab.get().is_none() {
            let q = c1().to_affine(&c1().mul_fixed(g1_base(), &self.0.s)?).unwrap();
            let _ = self.0.q_tab.set(c1().fixed_table(&q));
        }
        Ok(self.0.q_tab.get().unwrap())
    }
    fn q2_tab(&self) -> Result<&Table<Fp2>> {
        if self.0.q2_tab.get().is_none() {
            let q = c2().to_affine(&c2().mul_fixed(g2_base(), &self.0.s2)?).unwrap();
            let _ = self.0.q2_tab.set(c2().fixed_table(&q));
        }
        Ok(self.0.q2_tab.get().unwrap())
    }

    /// Encrypt an integer with `|v| <= range`: a 384-byte cell. r1 and r2 are independent random scalars.
    pub fn encrypt(&self, v: i64) -> Result<Vec<u8>> {
        if v.unsigned_abs() > self.0.range {
            return Err(budget(format!("|value| must be <= the key's range ({})", self.0.range)));
        }
        self.encrypt_scalar(&BigInt::from(v))
    }

    /// Encrypt an arbitrary scalar mod n (no range limit: used for integrity tags).
    pub fn encrypt_scalar(&self, m: &BigInt) -> Result<Vec<u8>> {
        let n = group_order();
        let mut vm = to_scalar(m);
        let neg = &vm * 2u32 > *n;
        if neg {
            vm = n - &vm; // short representative: faster fixed-base multiplication
        }
        let (r1, r2) = (rand_scalar(), rand_scalar());
        let (a, b) = (c1(), c2());
        let sg = |j: Jac<Fp>| if neg { a.neg(&j) } else { j };
        let sg2 = |j: Jac<Fp2>| if neg { b.neg(&j) } else { j };
        let cc1 = a.mul_fixed(g1_base(), &r1)?;
        let cc2 = a.add(&sg(a.mul_fixed(g1_base(), &vm)?), &a.mul_fixed(self.q_tab()?, &r1)?);
        let dd1 = b.mul_fixed(g2_base(), &r2)?;
        let dd2 = b.add(&sg2(b.mul_fixed(g2_base(), &vm)?), &b.mul_fixed(self.q2_tab()?, &r2)?);
        let aff = a.batch_to_affine(&[cc1, cc2]);
        Ok([g1_to(&aff[0]), g1_to(&aff[1]), g2_to(&b.to_affine(&dd1)), g2_to(&b.to_affine(&dd2))].concat())
    }

    /// A valid cell that is not tied to any plaintext, used as the temporary tag of an authenticated INSERT.
    pub(crate) fn placeholder_cell(&self) -> Result<Vec<u8>> {
        if self.0.placeholder.get().is_none() {
            let _ = self.0.placeholder.set(self.encrypt_scalar(&BigInt::zero())?);
        }
        Ok(self.0.placeholder.get().unwrap().clone())
    }

    // ── decryption ──
    /// `C2 - s*C1` of the `(C1, C2)` pair at the start of `blob` (the plaintext times G1).
    fn opened(&self, blob: &[u8]) -> Result<G1> {
        let c = c1();
        let p1 = g1_from(&blob[..64])?;
        let p2 = g1_from(&blob[64..128])?;
        let sc1 = match &p1 {
            None => c.inf(),
            Some(a) => c.mul(&c.lift(a), &self.0.s),
        };
        let c2j = p2.map(|v| c.lift(&v)).unwrap_or_else(|| c.inf());
        Ok(c.to_affine(&c.add(&c2j, &c.neg(&sc1))))
    }

    /// Decrypt a SUM blob (128 bytes) with a bounded discrete log.
    pub fn decrypt_sum(&self, blob: &[u8]) -> Result<i64> {
        if blob.len() != FHE_SUM_BYTES {
            return Err(proto("bad SUM ciphertext"));
        }
        g1_dlog(&self.opened(blob)?, self.0.range)
    }

    /// Decrypt one cell (only its G1 half is used).
    pub fn decrypt_cell(&self, cell: &[u8]) -> Result<i64> {
        check_cell(cell)?;
        g1_dlog(&self.opened(cell)?, self.0.range)
    }

    /// Decrypt a DOT blob: `M = c11 * c01^-s2 * c10^-s * c00^(s*s2) = g^(sum a_i b_i)`, then a bounded
    /// dlog. The four components are the server's (untrusted) answer: those raised to secret-dependent
    /// powers (all but c11) are first checked to lie in GT (order n), which closes the small-subgroup
    /// oracle a hostile server could otherwise use against `s` and `s2`.
    pub fn decrypt_dot(&self, blob: &[u8]) -> Result<i64> {
        if blob.len() != FHE_DOT_BYTES {
            return Err(proto("bad DOT ciphertext"));
        }
        let tag = blob[0];
        if tag != 1 && tag != 2 {
            return Err(proto("unknown DOT back-end tag"));
        }
        let comp = |i: usize| Fp12::from_bytes(&blob[1 + i * FHE_GT_BYTES..1 + (i + 1) * FHE_GT_BYTES]);
        let (c00, c01, c10, c11) = (comp(0)?, comp(1)?, comp(2)?, comp(3)?);
        let n = group_order();
        for c in [&c00, &c01, &c10] {
            if c.pow(n) != Fp12::one() {
                return Err(proto("DOT result is not an element of the target group (hostile or damaged server answer)"));
            }
        }
        let (s, s2) = (&self.0.s, &self.0.s2);
        let mm = c11.mul(&Fp12::pow2(&c01, &(n - s2), &c10, &(n - s))).mul(&c00.pow(&((s * s2) % n)));
        gt_dlog(&mm, tag, self.0.range)
    }

    // ── integrity tags (authenticated mode) ──
    fn prf(&self, label: &str, parts: &[String]) -> BigUint {
        let h = hmac_sha256(&self.0.secret, format!("torussql/fhe/{}", label).as_bytes());
        let d = hmac_sha512(&h, parts.join("\0").as_bytes());
        BigUint::from_bytes_be(&d) % group_order()
    }
    fn alpha_u(&self) -> &BigUint {
        self.0.alpha.get_or_init(|| {
            let a = self.prf("alpha", &[]);
            if a.is_zero() {
                BigUint::one()
            } else {
                a
            }
        })
    }
    /// The MAC key `alpha = PRF("alpha")` (or 1).
    pub fn alpha(&self) -> BigInt {
        BigInt::from(self.alpha_u().clone())
    }
    /// Leaf of one row for the anchored table state (`anchor.rs`): a PRF of the table, the row id and the
    /// canonical row material, under a key derived from the MAC secret with its own label ("anchor-leaf").
    pub fn anchor_leaf(&self, table: &str, rowid: i64, material: &[u8]) -> BigInt {
        let k = hmac_sha256(&self.0.secret, b"torussql/fhe/anchor-leaf");
        let mut msg = (table.len() as u32).to_be_bytes().to_vec();
        msg.extend_from_slice(table.as_bytes());
        msg.extend_from_slice(&(rowid as u64).to_be_bytes());
        msg.extend_from_slice(material);
        BigInt::from(BigUint::from_bytes_be(&hmac_sha512(&k, &msg)) % group_order())
    }
    /// The per-cell tweak `gamma = PRF("gamma", table, column, row id)`.
    pub fn gamma(&self, table: &str, col: &str, rowid: i64, nonce: &BigInt) -> BigInt {
        BigInt::from(self.prf(
            "gamma",
            &[table.to_string(), col.to_string(), rowid.to_string(), nonce.to_string()],
        ))
    }
    /// The tag cell `Enc(alpha*v + gamma)` for the cell `(table, col, rowid)`.
    pub fn tag(&self, v: i64, table: &str, col: &str, rowid: i64, nonce: &BigInt) -> Result<Vec<u8>> {
        let m = self.alpha() * BigInt::from(v) + self.gamma(table, col, rowid, nonce);
        self.encrypt_scalar(&m)
    }

    /// Check `tag-sum == alpha * value-sum + k * (sum gamma_i) * G1` (group elements) and return the
    /// decrypted value sum. Fails with `Kind::Integrity` on any mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_sum_verified(
        &self,
        value_blob: &[u8],
        tag_blob: &[u8],
        table: &str,
        col: &str,
        row_ids: &[i64],
        nonces: &[Option<BigInt>],
        scale: &BigInt,
    ) -> Result<i64> {
        if value_blob.len() != FHE_SUM_BYTES || tag_blob.len() != FHE_SUM_BYTES {
            return Err(proto("bad SUM ciphertext"));
        }
        if nonces.len() != row_ids.len() {
            return Err(Error::new(
                Kind::Integrity,
                format!("{}.{}: write nonces missing for the requested rows", table, col),
            ));
        }
        let n = BigInt::from(group_order().clone());
        let mut gam = BigInt::zero();
        for (i, nonce) in row_ids.iter().zip(nonces) {
            let nonce = nonce.as_ref().ok_or_else(|| {
                Error::new(
                    Kind::Integrity,
                    format!("{}.{} row {} has no write nonce (written without authentication, or tampered)", table, col, i),
                )
            })?;
            gam += self.gamma(table, col, *i, nonce);
        }
        gam = gam.mod_floor(&n);
        let c = c1();
        let mv = self.opened(value_blob)?;
        let mt = self.opened(tag_blob)?;
        let am = match &mv {
            None => c.inf(),
            Some(a) => c.mul(&c.lift(a), self.alpha_u()),
        };
        let kg = to_scalar(&(scale * gam));
        let want = c.to_affine(&c.add(&am, &c.mul_fixed(g1_base(), &kg)?));
        if mt != want {
            return Err(Error::new(
                Kind::Integrity,
                format!(
                    "integrity check failed for {}.{}: the server's aggregate does not match the authenticated cells",
                    table, col
                ),
            ));
        }
        g1_dlog(&mv, self.0.range)
    }

    /// Decrypt one cell and verify it against its tag cell (`None` tag = never tagged).
    pub fn decrypt_cell_verified(
        &self,
        cell: Option<&[u8]>,
        tag: Option<&[u8]>,
        table: &str,
        col: &str,
        rowid: i64,
        nonce: Option<&BigInt>,
    ) -> Result<i64> {
        let (cell, tag) = match (cell, tag) {
            (Some(c), Some(t)) => (c, t),
            _ => {
                return Err(Error::new(
                    Kind::Integrity,
                    format!(
                        "{}.{} row {} has no integrity tag (written without authentication, or tampered)",
                        table, col, rowid
                    ),
                ))
            }
        };
        self.decrypt_sum_verified(&cell_to_sum(cell)?, &cell_to_sum(tag)?, table, col, &[rowid], &[nonce.cloned()], &BigInt::one())
    }
}

/// Parse helpers re-exported for tests (not part of the stable API).
#[doc(hidden)]
pub mod internals {
    use super::*;
    pub fn gt_generator_bytes(tag: u8) -> Vec<u8> {
        gt_gen(tag).to_bytes()
    }
    pub fn gt_generator_has_order_n(tag: u8) -> bool {
        gt_gen(tag).pow(group_order()) == Fp12::one() && gt_gen(tag).pow(&(group_order() / 3u32)) != Fp12::one()
    }
    pub fn curves_ok() -> bool {
        let (a, b) = (c1(), c2());
        a.on_curve(&g1_gen())
            && b.on_curve(&g2_gen())
            && a.is_inf(&a.mul(&a.lift(&g1_gen()), group_order()))
            && b.is_inf(&b.mul(&b.lift(&g2_gen()), group_order()))
    }
    /// base64 decode (test helper)
    pub fn unb64(s: &str) -> Vec<u8> {
        b64_decode(s).unwrap()
    }
    /// `a*A + b*B` on the two G1 halves (C1 || C2, 128 bytes each) - what a keyless server can do (test helper)
    pub fn g1_affine_combo(a_blob: &[u8], a: i64, b_blob: &[u8], b: i64) -> Vec<u8> {
        let c = c1();
        let k = |x: i64| to_scalar(&BigInt::from(x));
        let mut out = vec![];
        for off in [0usize, 64] {
            let pa = g1_from(&a_blob[off..off + 64]).unwrap().map(|p| c.lift(&p)).unwrap_or_else(|| c.inf());
            let pb = g1_from(&b_blob[off..off + 64]).unwrap().map(|p| c.lift(&p)).unwrap_or_else(|| c.inf());
            let r = c.add(&c.mul(&pa, &k(a)), &c.mul(&pb, &k(b)));
            out.extend(g1_to(&c.to_affine(&r)));
        }
        out
    }
    pub fn hex(b: &[u8]) -> String {
        hex_encode(b)
    }
    pub fn unhex(s: &str) -> Vec<u8> {
        hex_decode(s).unwrap()
    }
}
