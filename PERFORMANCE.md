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

## Recording results

When you capture a new baseline, update the smoke-benchmark table in
[README.md](README.md) with the GOARCH, CPU model, Go version, and the relevant
`Hash33` rows so the documented numbers stay reproducible.
