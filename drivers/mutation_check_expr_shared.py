#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutation checks for the shared-wire evaluators of the TypeScript and Rust drivers.

Each mutation breaks the evaluator ON PURPOSE (drops the e*g term of the tag, reuses a triple, skips a MAC
check, fixes rho = 1, ...) by patching one source file, runs the shared-wire test file, and requires that

  * the patched driver still BUILDS (a mutation that does not compile proves nothing), and
  * at least one test FAILS, and one of the failing tests is the one that is meant to catch it.

The source file is restored afterwards, whatever happens. Usage (from drivers/):

    TORUSDB_REQUIRE_INTEGRATION=1 TORUSDB_PYTHON=<venv python> python3 mutation_check_expr_shared.py [ts] [rust] [name ...]

It needs a free machine for a few minutes (one test build per mutation) and must not run while another
process builds or tests the same driver directory.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (name, [(old, new), ...], [keywords of the test names that must be among the failures])
TS_FILE = os.path.join(HERE, "typescript/src/exprShared.ts")
TS_MUTATIONS = [
    ("drop the alpha*e*g term of the product tag",
     [("g * O.mu![j] + al * e % N * g) % N", "g * O.mu![j]) % N")], ["authenticated"]),
    ("add e*g to the owner's value share (double counting)",
     [("(O.w[j] + e * O.v[j] + g * O.u[j]) % N", "(O.w[j] + e * O.v[j] + g * O.u[j] + e * g) % N")], ["vectors", "agree", "depth 2"]),
    ("reuse the same triple at every level",
     [("const uS = rb(), uO = rb(), vS = rb(), vO = rb(), wS = rb();",
       "const uS = BigInt(j + 1), uO = BigInt(j + 7), vS = BigInt(j + 13), vO = BigInt(j + 29), wS = BigInt(j + 31);")], ["audit"]),
    ("skip the MAC check of the openings",
     [('throw integrity("MAC check failed on a multiplication opening -- the server tampered with a wire share");', "void 0;")],
     ["tampered reveal", "computing with other shares"]),
    ("skip the MAC check of the revealed result",
     [("if (this.m(sink.m[j] + v.ownm![j] - this.alpha * z) !== 0n) {", "if (false) {")],
     ["tampered reveal", "denominator", "computing with other shares"]),
    ("fix rho = 1 (the server would see y^-1)",
     [("const nz = () => 1n + this.ring.rand() % (N - 1n);", "const nz = () => 1n;")], ["audit", "multiplier"]),
    ("the dealer does not mask its triple share (uO = 0)",
     [("const uS = rb(), uO = rb(),", "const uS = rb(), uO = 0n,")], ["audit"]),
    ("abort at the first zero denominator (an abort oracle)",
     [("t = nz();", 'throw new TorusError("DivisionByZero", "division by zero (early abort)");')], ["zero denominator", "vectors", "agree"]),
    ("never wire_free after an abort",
     [("private async cleanup(): Promise<void> {", "private async cleanup(): Promise<void> {\n    if (Date.now() > 0) return;")],
     ["freed after every query", "malformed wire_exec"]),
    ("keep a zero t instead of a fresh non-zero dummy",
     [("t = nz();", "void 0;")], ["multiplier", "vectors", "agree"]),
    ("the last request does not free the live wires",
     [("this.tofree = [...new Set([...this.tofree, ...this.liveIds])];", "this.tofree = [...this.tofree];")], ["freed after every query", "vectors"]),
    ("accept any server vector (no length / range check)",
     [("x.length !== k || x.some((v) => v >= this.NN)", "false")], ["malformed wire replies"]),
    ("forget to free the negated wire of a flipped subtraction (trace drift)",
     [('      this.freeAfter(s.wid);\n    } else if (op === "sub") {', '    } else if (op === "sub") {')], ["vectors", "agree"]),
]

RS_FILE = os.path.join(HERE, "rust/src/expr_shared.rs")
RS_MUTATIONS = [
    ("drop the alpha*e*g term of the product tag",
     [("+ &g * &o.mu[j] + &al * &e % &nn * &g) % &nn;", "+ &g * &o.mu[j]) % &nn;")], ["authenticated"]),
    ("add e*g to the owner's value share (double counting)",
     [("let own = (&o.w[j] + &e * &o.v[j] + &g * &o.u[j]) % &nn;", "let own = (&o.w[j] + &e * &o.v[j] + &g * &o.u[j] + &e * &g) % &nn;")],
     ["vectors", "agree", "products"]),
    ("reuse the same triple at every level",
     [("for _ in 0..k {\n            let (u_s, u_o, v_s, v_o, w_s) = (rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar());",
       "for jj in 0..k {\n            let (u_s, u_o, v_s, v_o, w_s) = (BigInt::from(jj + 1), BigInt::from(jj + 7), BigInt::from(jj + 13), BigInt::from(jj + 29), BigInt::from(jj + 31));")],
     ["audit"]),
    ("skip the MAC check of the openings",
     [("if !md(&((&me_s[j] + &am", "if false && !md(&((&me_s[j] + &am")], ["tampered_reveal", "other_shares"]),
    ("skip the MAC check of the revealed result",
     [("if !md(&(m - &self.alpha * &z)).is_zero() {", "if false {")], ["tampered_reveal", "denominator", "other_shares"]),
    ("fix rho = 1 (the server would see y^-1)",
     [("BigInt::one() + rand_scalar() % (&self.nn - BigInt::one()) // uniform NON-ZERO", "BigInt::one()")], ["audit", "multiplier"]),
    ("the dealer does not mask its triple share (u_o = 0)",
     [("let (u_s, u_o, v_s, v_o, w_s) = (rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar(), rand_scalar());",
       "let (u_s, u_o, v_s, v_o, w_s) = (rand_scalar(), BigInt::zero(), rand_scalar(), rand_scalar(), rand_scalar());")], ["audit"]),
    ("abort at the first zero denominator (an abort oracle)",
     [("t = self.nonzero(); // dummy: the server must not learn it",
       'return Err(Error::new(Kind::DivisionByZero, "division by zero (early abort)"));')], ["zero_denominator", "vectors", "agree"]),
    ("never wire_free after an abort",
     [("fn cleanup(&mut self) {\n        self.pending.clear();", "fn cleanup(&mut self) {\n        if true {\n            return;\n        }\n        self.pending.clear();")],
     ["freed_after_every_query", "malformed_wire_exec"]),
    ("keep a zero t instead of a fresh non-zero dummy",
     [("t = self.nonzero(); // dummy: the server must not learn it", "// no dummy")], ["multiplier", "vectors", "agree"]),
    ("the last request does not free the live wires",
     [("all.extend(self.live_ids.iter().cloned());", "")], ["freed_after_every_query", "vectors"]),
    ("accept any server vector (no length / range check)",
     [("Some(v) if v.len() == k && v.iter().all(|e| *e < self.nn) => Ok(v),", "Some(v) => Ok(v),")], ["malformed_wire_replies"]),
    ("forget to free the negated wire of a flipped subtraction (trace drift)",
     [('            let wid = self.arena[s].wid.clone();\n            self.free_after(&wid);\n        } else if op == "sub" {', '        } else if op == "sub" {')],
     ["vectors", "agree"]),
]


def run(cmd, cwd, env, timeout=1800):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def ts_test(env):
    cwd = os.path.join(HERE, "typescript")
    rc, out = run(["npx", "tsc", "-p", "tsconfig.test.json"], cwd, env)
    if rc != 0:
        return "build", [], out
    rc, out = run(["node", "--test", "--test-force-exit", "--test-timeout=120000", "build-test/test/expr_shared.test.js"], cwd, env)
    failed = sorted({m.group(1) for m in re.finditer(r"^✖ (.+?) \(\d+(?:\.\d+)?ms\)$", out, re.M)})
    return ("fail" if failed or rc != 0 else "pass"), failed, out


def rs_test(env):
    cwd = os.path.join(HERE, "rust")
    rc, out = run(["cargo", "test", "--test", "expr_shared"], cwd, env)
    if re.search(r"^error(\[E\d+\])?:", out, re.M) and "could not compile" in out:
        return "build", [], out
    failed = sorted({m.group(1) for m in re.finditer(r"^test (\S+) \.\.\. FAILED$", out, re.M)})
    return ("fail" if failed or rc != 0 else "pass"), failed, out


def check(label, path, muts, runner, env, only):
    orig = open(path, encoding="utf8").read()
    bad = 0
    try:
        for name, patches, keywords in muts:
            if only and not any(o in name for o in only):
                continue
            src = orig
            for old, new in patches:
                if src.count(old) != 1:
                    print(f"[{label}] {name}: PATCH DOES NOT APPLY ({src.count(old)} occurrences of {old[:60]!r})")
                    bad += 1
                    break
                src = src.replace(old, new)
            else:
                open(path, "w", encoding="utf8").write(src)
                status, failed, out = runner(env)
                open(path, "w", encoding="utf8").write(orig)
                caught = [f for f in failed if any(k.lower() in f.lower() for k in keywords)]
                if status == "build":
                    verdict = "INVALID (does not build)"
                    bad += 1
                elif status == "pass":
                    verdict = "SURVIVED -- no test failed"
                    bad += 1
                elif not caught:
                    verdict = f"CAUGHT, but not by the intended test ({keywords}); failures: {failed[:4]}"
                    bad += 1
                else:
                    verdict = f"killed ({len(failed)} failing; e.g. {caught[0][:90]})"
                print(f"[{label}] {name}: {verdict}", flush=True)
    finally:
        open(path, "w", encoding="utf8").write(orig)
    return bad


def main():
    args = sys.argv[1:]
    langs = [a for a in args if a in ("ts", "rust")] or ["ts", "rust"]
    only = [a for a in args if a not in ("ts", "rust")]
    env = dict(os.environ)
    env.setdefault("TORUSDB_REQUIRE_INTEGRATION", "1")
    bad = 0
    if "ts" in langs:
        bad += check("ts", TS_FILE, TS_MUTATIONS, ts_test, env, only)
    if "rust" in langs:
        bad += check("rust", RS_FILE, RS_MUTATIONS, rs_test, env, only)
    # leave the driver built from the restored (unmutated) sources
    if "ts" in langs:
        ts_test(env)
    print("ALL MUTATIONS KILLED" if bad == 0 else f"{bad} PROBLEM(S)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
