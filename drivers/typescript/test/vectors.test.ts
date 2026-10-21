// SPDX-License-Identifier: Apache-2.0
// Cross-language known-answer tests from drivers/vectors.json (no server needed).
import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import { N, encodeInt, encodeRational, decode, TorusError } from "../src/torusdb";
import { VECTORS } from "./helpers";

const vec = JSON.parse(fs.readFileSync(VECTORS, "utf8"));

test("modulus matches vectors.json", () => {
  assert.equal(N.toString(), vec.N);
});

for (const e of vec.encode) {
  test(`encode(${e.value}) == ${String(e.encoded).slice(0, 12)}`, () => {
    assert.equal(encodeInt(BigInt(e.value)).toString(), e.encoded);
    // and round-trips
    assert.equal(decode(BigInt(e.encoded)), BigInt(e.value));
  });
}

for (const e of vec.rational_reconstruct) {
  test(`rational ${e.frac}`, () => {
    const [n, d] = (e.frac as string).split("/").map(BigInt);
    assert.equal(encodeRational(n, d).toString(), e.encoded);
    const back = decode(BigInt(e.encoded));
    assert.deepEqual(back, { num: n, den: d });
  });
}

test("sum of encodings decodes to the sum", () => {
  const s = encodeRational(1n, 2n) + encodeRational(1n, 3n);
  assert.deepEqual(decode(s), { num: 5n, den: 6n });
  assert.equal(decode(encodeInt(5n) + encodeInt(-5n)), 0n);
});

test("out-of-budget values are rejected loudly", () => {
  assert.throws(() => encodeInt(1n << 200n), (e: any) => e instanceof TorusError && e.kind === "OutOfBudget");
  // a random element is (overwhelmingly) not a small rational
  assert.throws(() => decode((7n ** 100n) % N),
    (e: any) => e instanceof TorusError && e.kind === "OutOfBudget");
});

test("budget: 2^126 round-trips, 2^127 is rejected, sum of two 2^126 raises", () => {
  const e = (f: () => unknown) => assert.throws(f, (x: any) => x instanceof TorusError && x.kind === "OutOfBudget");
  const b = 1n << 126n;
  assert.equal(decode(encodeInt(b)), b);
  assert.equal(decode(encodeInt(-b)), -b);
  e(() => encodeInt(1n << 127n));
  e(() => encodeInt(-(1n << 127n)));
  e(() => decode(encodeInt(b) + encodeInt(b)));
  // fractions: num and den each <= bound and |num|*den < 2^189
  e(() => encodeRational(1n, 1n << 127n));
  e(() => encodeRational(1n << 126n, (1n << 126n) - 1n));
  assert.deepEqual(decode(encodeRational(3n, 1n << 90n)), { num: 3n, den: 1n << 90n });
});

test("uniform random scalars always raise OutOfBudget", () => {
  const { randomBytes } = require("crypto");
  for (let i = 0; i < 500; i++) {
    const s = BigInt("0x" + randomBytes(32).toString("hex")) % N;
    assert.throws(() => decode(s), (x: any) => x instanceof TorusError && x.kind === "OutOfBudget");
  }
});

test("zero denominator rejected", () => {
  assert.throws(() => encodeRational(1n, 0n), TorusError);
});
