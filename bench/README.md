# TorusDB no-key benchmarks

Reproducible micro-benchmarks for the no-key engine. The hot path is **pure
mod-n integer arithmetic** — no elliptic curve, no pairing, no BSGS — so
encrypted aggregation is sub-millisecond at thousands of rows.

## Run

```bash
# from the repository root (Python >= 3.11, packages installed or the source tree importable)
python bench/bench.py --rows 100,1000,5000 --repeat 3
python bench/bench.py --rows 1000,5000 --authenticated   # with integrity MAC
python bench/net_bench.py --rows 20000 [--auth]          # real TCP, server + driver
python bench/tpch.py --rows 1000                         # TPC-H-style queries
python bench/storage_bench.py --rows 200000 --cache-rows 5000 --kind disk   # or --kind memory
```

Deterministic row values; one-time-pad masks use the OS RNG (timings vary, not
results). `--json out.json` dumps machine-readable results.

## Headline numbers (in-process, no network; Apple-silicon, Python ref impl)

**Confidential only** (server holds no key, one-time-pad confidentiality):

| rows | insert µs/row | SUM ms | SUM+WHERE ms | DOT ms | COUNT ms | plain SUM µs |
|------|---------------|--------|--------------|--------|----------|--------------|
| 100  | 28.8 | 0.028 | 0.068 | 0.56 | 0.012 | 0.37 |
| 1000 | 29.0 | 0.117 | 0.431 | 5.0  | 0.016 | 2.25 |
| 5000 | 29.9 | 0.708 | 2.40  | 25.5 | 0.053 | 11.9 |

**Authenticated** (adds the §IX integrity MAC — a parallel MAC column):

| rows | insert µs/row | SUM ms | DOT ms |
|------|---------------|--------|--------|
| 1000 | 36.6 | 0.267 | 6.4  |
| 5000 | 36.5 | 1.22  | 31.0 |

## Reading the results

- **Encrypted SUM** is linear in rows and stays **sub-millisecond** to a few
  thousand rows — roughly 60× a plaintext `sum()` but in the same ballpark for
  practical workloads, and with no key on the server.
- **DOT** (encrypted inner product) costs ~5 µs/row: one Beaver triple +
  reconstruction per row (Π_mult). It dominates because each row is a
  multiplication; aggregation itself is free.
- **Integrity (MAC)** adds ~1.3–1.7× (a parallel MAC column and one extra
  affine pass) — the price of catching a cheating server unconditionally.
- **COUNT / plaintext WHERE** are essentially free (plaintext columns).

These are reference-implementation numbers in pure Python; the `mcl` pairing
backend and a compiled core are **not** on the no-key hot path, so the figures
reflect plain big-integer modular arithmetic.
