// SPDX-License-Identifier: Apache-2.0
//! Cross-language known-answer tests from ../vectors.json (no server needed).
use num_bigint::BigInt;
use torusdb::{decode, encode_int, encode_rational, n, Decoded, Kind};

mod common;

fn vec_json() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(common::vectors_path()).unwrap()).unwrap()
}
fn b(s: &str) -> BigInt {
    s.parse().unwrap()
}

#[test]
fn modulus_matches() {
    assert_eq!(n().to_string(), vec_json()["N"].as_str().unwrap());
}

#[test]
fn every_encode_vector() {
    let v = vec_json();
    let list = v["encode"].as_array().unwrap();
    assert!(list.len() >= 9);
    for e in list {
        let val = BigInt::from(e["value"].as_i64().unwrap());
        let enc = encode_int(&val).unwrap();
        assert_eq!(enc.to_string(), e["encoded"].as_str().unwrap());
        assert_eq!(decode(&enc).unwrap(), Decoded::Int(val));
    }
}

#[test]
fn every_rational_vector() {
    let v = vec_json();
    let list = v["rational_reconstruct"].as_array().unwrap();
    assert!(list.len() >= 5);
    for e in list {
        let frac = e["frac"].as_str().unwrap();
        let (num, den) = frac.split_once('/').unwrap();
        let (num, den) = (b(num), b(den));
        let enc = encode_rational(&num, &den).unwrap();
        assert_eq!(enc.to_string(), e["encoded"].as_str().unwrap(), "{}", frac);
        assert_eq!(decode(&b(e["encoded"].as_str().unwrap())).unwrap(), Decoded::Rational(num, den));
    }
}

#[test]
fn sums_of_encodings_decode_to_sums() {
    let s = encode_rational(&b("1"), &b("2")).unwrap() + encode_rational(&b("1"), &b("3")).unwrap();
    assert_eq!(decode(&s).unwrap(), Decoded::Rational(b("5"), b("6")));
    assert_eq!(decode(&(encode_int(&b("5")).unwrap() + encode_int(&b("-5")).unwrap())).unwrap(), Decoded::Int(b("0")));
}

#[test]
fn budget_edges() {
    let two126: BigInt = BigInt::from(1) << 126;
    let two127: BigInt = BigInt::from(1) << 127;
    assert_eq!(decode(&encode_int(&two126).unwrap()).unwrap(), Decoded::Int(two126.clone()));
    assert_eq!(decode(&encode_int(&-two126.clone()).unwrap()).unwrap(), Decoded::Int(-two126.clone()));
    assert_eq!(encode_int(&two127).unwrap_err().kind, Kind::OutOfBudget);
    assert_eq!(encode_int(&-two127.clone()).unwrap_err().kind, Kind::OutOfBudget);
    // the sum of two 2^126 values overflows the representable range
    let s = encode_int(&two126).unwrap() + encode_int(&two126).unwrap();
    assert_eq!(decode(&s).unwrap_err().kind, Kind::OutOfBudget);
    // fractions: each of num/den within the bound and |num|*den < 2^189
    assert_eq!(encode_rational(&b("1"), &two127).unwrap_err().kind, Kind::OutOfBudget);
    assert_eq!(encode_rational(&two126, &(two126.clone() - 1)).unwrap_err().kind, Kind::OutOfBudget);
    let den: BigInt = BigInt::from(1) << 90;
    assert_eq!(decode(&encode_rational(&b("3"), &den).unwrap()).unwrap(), Decoded::Rational(b("3"), den));
    assert!(encode_rational(&b("1"), &b("0")).is_err());
}

#[test]
fn uniform_random_scalars_always_raise() {
    use rand::RngCore;
    for _ in 0..500 {
        let mut by = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut by);
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &by) % n();
        assert_eq!(decode(&s).unwrap_err().kind, Kind::OutOfBudget);
    }
}
