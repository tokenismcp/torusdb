// SPDX-License-Identifier: Apache-2.0
//! Z/nZ arithmetic and the int/rational encoding (matches the Python reference
//! `ecfhe.nokey`, including its exact-representability budget).

use crate::error::Error;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand::RngCore;
use std::sync::OnceLock;

/// BN254 group order - the modulus of the no-key scalar ring Z/nZ.
pub fn n() -> &'static BigInt {
    static N: OnceLock<BigInt> = OnceLock::new();
    N.get_or_init(|| {
        BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    })
}

/// Wang bound on |num| and den: isqrt(N/2), about 2^126.
fn bound() -> &'static BigInt {
    static B: OnceLock<BigInt> = OnceLock::new();
    B.get_or_init(|| (n() / 2u32).sqrt())
}

/// Range for |num|*den: N >> 64, about 2^189.
fn range() -> &'static BigInt {
    static R: OnceLock<BigInt> = OnceLock::new();
    R.get_or_init(|| n() >> 64u32)
}

pub(crate) fn md(a: &BigInt) -> BigInt {
    a.mod_floor(n())
}

pub(crate) fn mod_inv(a: &BigInt) -> BigInt {
    let m = n();
    let (mut old_r, mut r) = (md(a), m.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    while !r.is_zero() {
        let q = &old_r / &r;
        let nr = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, nr);
        let ns = &old_s - &q * &s;
        old_s = std::mem::replace(&mut s, ns);
    }
    md(&old_s)
}

/// Exactly uniform in [0, N): 254 random bits, rejected when >= N (N is just under 2^254; acceptance ~ 0.76).
/// (Reducing 256 random bits mod N would NOT be uniform: 2^256 / N ~ 5.3, so the lowest ~29% of the residues
/// would be ~20% more likely - a bias the wire audit's chi-square test detects.)
pub(crate) fn rand_scalar() -> BigInt {
    loop {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b[0] &= 0x3f;
        let v = BigInt::from_bytes_be(Sign::Plus, &b);
        if v < *n() {
            return v;
        }
    }
}

/// A decoded value: either an integer or an exact rational in lowest terms.
#[derive(Debug, Clone, PartialEq)]
pub enum Decoded {
    Int(BigInt),
    Rational(BigInt, BigInt),
}

/// Reduce num/den (den != 0) to lowest terms with den > 0.
pub fn reduce(num: &BigInt, den: &BigInt) -> Decoded {
    let (mut a, mut b) = (num.clone(), den.clone());
    if b.is_negative() {
        a = -a;
        b = -b;
    }
    let g = a.gcd(&b);
    if g > BigInt::one() {
        a /= &g;
        b /= &g;
    }
    if b.is_one() {
        Decoded::Int(a)
    } else {
        Decoded::Rational(a, b)
    }
}

/// enc(int). Rejects |v| > ~2^126 (OutOfBudget).
pub fn encode_int(v: &BigInt) -> Result<BigInt, Error> {
    if v.abs() > *bound() {
        return Err(Error::budget(format!(
            "integer of {} bits exceeds the encodable range (|v| <= ~2^126)",
            v.abs().bits()
        )));
    }
    Ok(md(v))
}

/// enc(a/b). Needs |a|, b <= ~2^126 and |a|*b < ~2^189.
pub fn encode_rational(num: &BigInt, den: &BigInt) -> Result<BigInt, Error> {
    if den.is_zero() {
        return Err(Error::interface("zero denominator"));
    }
    let (a, b) = match reduce(num, den) {
        Decoded::Int(a) => (a, BigInt::one()),
        Decoded::Rational(a, b) => (a, b),
    };
    if a.abs() > *bound() || b > *bound() || a.abs() * &b >= *range() {
        return Err(Error::budget(format!(
            "fraction {}/{} exceeds the encodable range",
            a, b
        )));
    }
    Ok(md(&(md(&a) * mod_inv(&md(&b)))))
}

/// dec: Wang rational reconstruction, strict like the Python reference - a
/// result outside the exactly-representable range is an `OutOfBudget` error
/// rather than a wrong number.
pub fn decode(s: &BigInt) -> Result<Decoded, Error> {
    let bound = bound();
    let (mut r0, mut r1) = (n().clone(), md(s));
    let (mut t0, mut t1) = (BigInt::zero(), BigInt::one());
    while r1 > *bound {
        let q = &r0 / &r1;
        let nr = &r0 - &q * &r1;
        r0 = std::mem::replace(&mut r1, nr);
        let nt = &t0 - &q * &t1;
        t0 = std::mem::replace(&mut t1, nt);
    }
    let (mut a, mut b) = (r1, t1);
    if b.is_negative() {
        a = -a;
        b = -b;
    }
    if b.is_zero() {
        return Err(Error::budget("rational reconstruction failed (out of budget)"));
    }
    if a.abs() * &b >= *range() {
        return Err(Error::budget(
            "decoded value is outside the exactly-representable range - an aggregate \
             probably overflowed; the result cannot be trusted",
        ));
    }
    Ok(reduce(&a, &b))
}
