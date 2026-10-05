# Performance

This document describes how to measure `sha256mb`, how to interpret the numbers,
the staged-vs-fused HASH160 analysis, and the acceptance criteria that gate a
performance release.

The arm64 `sha2x4` backend delivers ~2.6x the throughput of scalar on Apple M3
(about 57.6M vs 21.6M hashes/s at `n = 6144`, `GOMAXPROCS=1`; 2.57–2.67x across
thermal states) with zero allocations, verified bit-for-bit against
`crypto/sha256`. amd64 SIMD is not yet implemented and runs scalar; the criteria
below apply to any new vector backend before it ships.

## What to measure

The hot paths are `Hash33` (SHA-256) and `hash160mb.FromPubkeys33` (HASH160).
The benchmarks report four quantities per case:

- `ns/op` — wall-clock time for one call.
- `MB/s` — input throughput, via `b.SetBytes(n*33)`.
- `hashes/s` — messages hashed per second (the metric that matters for HASH160
  pipelines), via a custom `b.ReportMetric`.
- `allocs/op` — must be `0`; a regression here is a correctness bug in the
  zero-alloc contract, not just a slowdown.

Batch sizes deliberately include the lane boundaries (`lanes-1`, `lanes`,
`lanes+1`) so regressions in either the vectorized body or the scalar tail are
visible, plus larger batches (`64`, `1024`, `6144`) that amortize call overhead.
`6144` is the batch the downstream bruteforcer uses.

## Running benchmarks

```sh
# All Hash33 cases, native backend, with allocation stats.
go test -run '^$' -bench '^BenchmarkHash33$' -benchmem ./

# The HASH160 pipeline (active vs staged vs fused sub-benchmarks).
go test -run '^$' -bench '^BenchmarkFromPubkeys33$' -benchmem ./hash160mb

# A single backend, comparable across runs (pin GOMAXPROCS and force a backend).
GOMAXPROCS=1 GOSHA256MB_FORCE=scalar \
	go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=10 ./ | tee scalar.txt
GOMAXPROCS=1 GOSHA256MB_FORCE=sha2x4 \
	go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=10 ./ | tee sha2x4.txt
```

Use `-count=10` (or more) and a quiet machine so the noise is small enough for
`benchstat` to draw conclusions. On a thermally constrained laptop, measure A/B
pairs back-to-back: absolute ns/op drifts with chip temperature, but a ratio of
two adjacent runs stays fair.

## Comparing with benchstat

```sh
go install golang.org/x/perf/cmd/benchstat@latest
benchstat scalar.txt sha2x4.txt
```

A change is only meaningful when `benchstat` reports it outside the noise band
(it prints `~` when the delta is not statistically significant).

## Profiling

```sh
go test -run '^$' -bench '^BenchmarkHash33$' -cpuprofile=cpu.out ./
go tool pprof -top cpu.out
```

For the scalar path, `crypto/sha256`'s block function dominates; for `sha2x4`,
look at the interleave width and the per-lane `SHA256H` dependency chains in
[`internal/shagen`](internal/shagen).

## Staged vs fused HASH160

`hash160mb` ships two bit-identical paths (see [SPEC.md](SPEC.md)). The fused
arm64 kernel keeps each lane group's SHA-256 digests in registers and feeds them
straight into RIPEMD-160 with no intermediate buffer; the staged path runs a full
SHA-256 pass into a pooled buffer, then a full RIPEMD-160 pass.

Measured on Apple M3 (`GOMAXPROCS=1`, `n = 6144`):

| Path   | ns/op  | hashes/s   | allocs/op |
| ------ | ------ | ---------- | --------- |
| staged | 586181 | ~10.5M     | 0         |
| fused  | 585607 | ~10.5M     | 0         |

Single-threaded the two are within noise; at 8 threads the staged path is ~3%
faster. Both halves are throughput-bound, and the staged path lets each kernel
run in its own deeply pipelined loop, whereas fusing four messages at a time
starves the SHA-256 pipeline of independent work. A true software-pipelined
SHA∥RIPEMD overlap is register-infeasible at 4+4 lanes (the two states do not fit
in 32 vector registers simultaneously).

**Conclusion:** the staged path is the arm64 default. The fused kernel is kept,
fully tested, and selectable with `GOHASH160MB_FORCE=fused` — it removes the
batch-sized digest buffer entirely, which can win on cores with a slower SHA
pipeline or tighter cache.

## Acceptance criteria for a vector backend

A vector backend ships as a default when, for the same GOARCH and a documented
reference CPU:

1. It remains bit-for-bit correct (`go test ./...` and the fuzz targets pass on
   that backend).
2. It is zero-allocation (`allocs/op == 0`) on the hot path.
3. `benchstat` shows a statistically significant `hashes/s` improvement over the
   incumbent default at the large-batch case, with no regression at the
   small/`lanes`-sized cases.

The `sha2x4` SHA-256 backend meets all three and is the default on arm64. A
backend that does not meet criterion 3 must not be wired as a default; it may
still be kept behind `GOSHA256MB_FORCE` / `GOHASH160MB_FORCE`, but `Backend()`
must never report a kernel that is not the one actually running.

## Apple M5 Pro local tuning (2026-10-04)

The final original-to-optimized comparison, Go 1.22.5, `GOMAXPROCS=1`, 6144
messages, six paired measurements, includes the feature-gated fused SHA3
kernel and the safe integer bounds checks:

| Fused revision | Median time | Hashes/s | allocs/op |
| -------------- | ----------- | -------- | --------- |
| original NEON  | 470.9 µs    | 13.05M   | 0         |
| final SHA3     | 346.2 µs    | 17.75M   | 0         |

The final improvement is **36.02% higher throughput** and 26.48% less time
(`p = 0.002`, six samples per revision). The [raw original](benchmarks/2026-10-04-m5-pro/hash160-fused-original.txt),
[raw final](benchmarks/2026-10-04-m5-pro/hash160-fused-final.txt), and
[benchstat comparison](benchmarks/2026-10-04-m5-pro/hash160-fused-benchstat.txt)
are archived with this library. The following measurements record the
intermediate candidates and explain the default-path choice.

### NEON instruction and dependency tuning

With Go 1.22.5 on `darwin/arm64`, `GOMAXPROCS=1`, eight alternating A/B pairs,
and 500 ms per case, two changes improved the embedded four-message HASH160
kernel: simplify the RIPEMD-160 Boolean expressions with NEON bit selection,
and add the message/round constants to A independently of the Boolean function.
The latter lets the core overlap these dependency chains before the rotation:

| Messages | Before ns/op | After ns/op | Time change | allocs/op |
| -------- | ------------ | ----------- | ----------- | --------- |
| 6144     | 471914.5     | 368009.5    | -22.02%     | 0         |

These are per-case medians; `benchstat` reports `p < 0.001` for this comparison.
At 6144 messages the throughput moves from 13.02M to 16.70M hashes/s, a 28.23%
increase. An earlier Boolean-only candidate had favorable medians but failed
the significance check (`p = 0.065` at 6144), so it was not accepted on that
evidence alone. Both final executables contain the original SHA4 kernel; forcing
the fused path keeps these measurements independent of changes to the sibling
RIPEMD library. The staged default remains available and uses that library's
runtime-selected backend. `Backend()` now names the fused kernel's embedded
SHA4/NEON implementation accurately, including when the sibling library is
forced to a different backend.

The same tuning run rejected two standalone SHA candidates: keeping the IV in
vector registers and sharing the saved state produced no consistent gain, and
a five-message interleave increased median time by 0.49% at 6144 messages and
7.62% at 64 messages. The original four-message SHA kernel remains unchanged.

Reproduce the fused measurement on the revisions being compared with:

```sh
GOMAXPROCS=1 GOHASH160MB_FORCE=fused \
  go test -run '^$' \
  -bench '^BenchmarkFromPubkeys33$/active/n=6144$' \
  -benchmem -benchtime=500ms -count=8 ./hash160mb
```

The benchmark matrix also runs a named `fused` case wherever the hardware SHA
backend is available; previously the fused runner was registered but omitted
from the iteration list.

### Feature-gated fused SHA3 comparison

A second fused kernel uses EOR3 and BCAX in the RIPEMD half, with the same
independent additions and adjusted round constants for complemented Boolean
functions. It is selected only when the sibling RIPEMD library reports
`neon-sha3`, which requires a positive hardware probe; other arm64 machines
retain the NEON fused kernel. Both keep the original SHA4 half.

Six alternating 500 ms measurements of the same Go 1.22.5 executable on Apple
M5 Pro, `GOMAXPROCS=1`, 6144 messages, compare the public entry point:

| Path               | Median ns/op | Hashes/s | allocs/op |
| ------------------ | ------------ | -------- | --------- |
| fused NEON         | 364041.5     | 16.88M   | 0         |
| fused SHA3         | 342794.5     | 17.92M   | 0         |
| staged SHA4 + SHA3 | 329902.5     | 18.62M   | 0         |

Fused SHA3 improves throughput by 6.20% over fused NEON (`p = 0.002`). The staged
pipeline is 3.91% faster than fused SHA3 (`p = 0.002`) and is still the default.
Force each path with
`GOHASH160MB_FORCE=fused` or `staged` and `GORIPEMD160MB_FORCE=neon` or
`neon-sha3` when reproducing this comparison. The named benchmark matrix also
exposes both fused kernels separately on supported hardware.

### Final downstream staged versus fused choice

The complete downstream key-generation/HASH160 pipeline was then compared with
the same final executable, Go 1.27.1, changing only `GOHASH160MB_FORCE`:

| Concurrency | Staged | Fused SHA3 | Statistical result |
| ----------- | ------ | ---------- | ------------------ |
| one thread  | 71.96 ns/key | 74.16 ns/key | fused +3.07% time, `p = 0.002` |
| 18 threads  | 215.4M keys/s | 210.6M keys/s | no significant difference, `p = 0.065` |

Both comparisons use six measurements per path. These whole-pipeline results
are separate from the Go 1.22.5 HASH160-only measurements above. They support
retaining staged as the default; the 18-thread medians do not establish a
statistically significant winner. See the archived [single-thread comparison](benchmarks/2026-10-04-m5-pro/root-final-single-benchstat.txt)
and [18-thread comparison](benchmarks/2026-10-04-m5-pro/root-final-mode-benchstat.txt).

## Recording results

When you capture a new baseline, update the smoke-benchmark table in
[README.md](README.md) with the GOARCH, CPU model, Go version, and the relevant
`Hash33` rows so the documented numbers stay reproducible.
