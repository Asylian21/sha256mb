# sha256mb

[Go Reference](https://pkg.go.dev/github.com/Asylian21/sha256mb)
[CI](https://github.com/Asylian21/sha256mb/actions/workflows/ci.yml)
[Go Report Card](https://goreportcard.com/report/github.com/Asylian21/sha256mb)
[License: MIT](LICENSE)
[Free & Open Source](LICENSE)

`sha256mb` is a high-performance, multi-buffer SHA-256 implementation for Go,
built for Bitcoin-style HASH160 pipelines that need to hash many independent
33-byte compressed public keys at once.

The library pairs a portable `crypto/sha256` scalar oracle with a real
Go-assembly SIMD backend. On arm64 the hand-tuned 4-lane hardware-SHA kernel is
the default and runs about **2.6x faster than scalar** on Apple M3, while keeping
the hot path zero-allocation. The `hash160mb` subpackage builds the full Bitcoin
`RIPEMD160(SHA256(x))` on top of it.

This is free and open-source software released under the permissive MIT license.

```go
src := make([]byte, n*64) // n compressed pubkeys, 33 bytes each, 64-byte slots
dst := make([]byte, n*sha256mb.Size)

sha256mb.Hash33(dst, src, n, 64)
fmt.Println(sha256mb.Backend(), sha256mb.Lanes())
```

## Why This Exists

Bitcoin address tooling spends most of its time on HASH160:

```text
HASH160(x) = RIPEMD160(SHA256(x))
```

Most Go code computes SHA-256 one message at a time. The ARMv8 SHA-256
instructions (`SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1`) are *latency-bound*:
a single-message hash cannot keep the crypto pipeline full. When the workload is
naturally batched — public-key analysis, wallet tooling, address derivation,
indexers, brute-force research, benchmark suites — hashing several independent
messages in lockstep hides that latency and multiplies throughput.

`sha256mb` focuses on that exact hot path: many fixed 33-byte inputs, strided
memory, no per-message allocations, runtime backend reporting, and correctness
checked against the standard-library `crypto/sha256` oracle.

It is a performance library, not a shortcut around Bitcoin security. Faster
hashing makes experiments and benchmarks better; it does not make brute force a
business model.

## Highlights

- **Multi-buffer SHA-256 for Go** through `Hash33(dst, src, n, stride)`.
- **Bitcoin HASH160 ready** via the `hash160mb` subpackage.
- **arm64 hardware-SHA backend** (`sha2x4`) that interleaves 4 messages, with
  runtime dispatch.
- **Portable scalar fallback** (`crypto/sha256`) on every Go architecture.
- **Zero allocations** on the `Hash33` and `FromPubkeys33` hot paths.
- **Concurrent-safe API** with no package-level mutable hashing state.
- **33-byte-exact reads**: the kernel never touches the inter-message stride, so
  any `stride >= 33` is safe.
- **Differential, property, race, and fuzz tests** against `crypto/sha256` and
  `golang.org/x/crypto/ripemd160`.
- **Free and open source** under the permissive MIT license.

## Install

```sh
go get github.com/Asylian21/sha256mb
```

```go
import "github.com/Asylian21/sha256mb"            // multi-buffer SHA-256
import "github.com/Asylian21/sha256mb/hash160mb"  // batched RIPEMD160(SHA256(x))
```

To build against a local checkout before a release tag is available, add a
temporary `replace` directive to the consumer's `go.mod`:

```go
require github.com/Asylian21/sha256mb v0.0.0

replace github.com/Asylian21/sha256mb => /path/to/sha256mb
```

## Quick Start

`Hash33` hashes `n` compressed public keys laid out `stride` bytes apart. Only
the first 33 bytes of each slot are read, so padding the slot to 64 keeps each
message inside a single cache line for the vector loads:

```go
package main

import (
	"fmt"

	"github.com/Asylian21/sha256mb"
)

func main() {
	const (
		n      = 1024
		stride = 64 // 33-byte pubkey + 31 bytes of (unread) slack
	)

	src := make([]byte, n*stride) // msg i: src[i*stride : i*stride+33]
	dst := make([]byte, n*sha256mb.Size)

	// Fill each slot's first 33 bytes with a compressed pubkey, then hash.
	sha256mb.Hash33(dst, src, n, stride)

	fmt.Printf("backend=%s lanes=%d first=%x\n",
		sha256mb.Backend(), sha256mb.Lanes(), dst[:sha256mb.Size])
}
```

`Hash33` panics on programmer errors (`n < 0`, `stride < 33`, short input, or
short output). For `n == 0` it is a no-op that accepts nil buffers.

## HASH160 Subpackage

`hash160mb` computes Bitcoin `RIPEMD160(SHA256(x))` for a whole batch of 33-byte
messages, fusing this package's SHA-256 with the multi-buffer RIPEMD-160 from
[`github.com/Asylian21/ripemd160-asm`](https://github.com/Asylian21/ripemd160-asm):

```go
import "github.com/Asylian21/sha256mb/hash160mb"

src := make([]byte, n*64) // 33-byte pubkeys in 64-byte slots
dst := make([]byte, n*hash160mb.Size)

hash160mb.FromPubkeys33(dst, src, n, 64)
fmt.Println(hash160mb.Backend()) // e.g. staged(sha256mb=sha2x4, ripemd160mb=neon)
```

`FromPubkeys33` is allocation-free after a one-time per-goroutine warm-up and is
safe for concurrent use. Each 20-byte digest is byte-identical to
`btcutil.Hash160` of that message.

## API

```go
// package sha256mb
const (
	Size      = 32 // SHA-256 digest size in bytes
	BlockSize = 64 // SHA-256 block size in bytes
	MsgLen    = 33 // fixed message length: compressed secp256k1 public key
)

func Hash33(dst, src []byte, n, stride int)
func Lanes() int
func Backend() string

// package sha256mb/hash160mb
const (
	Size   = 20 // HASH160 digest size in bytes
	MsgLen = 33
)

func FromPubkeys33(dst, src []byte, n, stride int)
func Backend() string
func Fused() bool
```

`Hash33` is the fast path. It reads message `i` from `src[i*stride:i*stride+33]`
and writes digest `i` to `dst[i*Size:(i+1)*Size]`, byte-identical to
`crypto/sha256.Sum256`. It allocates nothing, keeps no state between calls, and
is safe for concurrent use.

## Backends

Runtime dispatch selects the fastest implemented backend once during package
initialization. `Backend()` always reports the kernel that actually executes:

| Backend  | GOARCH  | Lanes | Status                          |
| -------- | ------- | ----- | ------------------------------- |
| `sha2x4` | `arm64` | 4     | implemented, default on arm64   |
| `scalar` | all     | 1     | implemented, portable fallback  |

Set `GOSHA256MB_FORCE=scalar` or `GOSHA256MB_FORCE=sha2x4` to pin a backend for
testing or benchmarking. Unknown or unsupported values fall back to scalar.

amd64 SIMD kernels (AVX-512 / SHA-NI) are planned but not yet implemented, so
amd64 currently runs scalar. The hardware-SHA generator in
[`internal/shagen`](internal/shagen) is the reference template for adding new
kernels, and every new backend is verified bit-for-bit against the scalar oracle
before it is wired into dispatch.

### Apple-silicon feature detection

`golang.org/x/sys/cpu` does not populate ARM64 feature flags on Darwin, so a
naive `cpu.ARM64.HasSHA2` check would *silently* disable the hardware kernel on
every Apple M-series Mac. `sha256mb` detects support per platform: it assumes the
ARMv8 crypto extension on `darwin/arm64` (every Apple-silicon core implements it,
exactly as the Go standard library's own `crypto/sha256` does) and reads HWCAP
via `x/sys/cpu` on other arm64 platforms.

## Performance

Latest local Apple M3 smoke benchmark (`GOMAXPROCS=1`, Go 1.22.5, `n = 6144` —
the batch size the downstream bruteforcer uses, `-count=8` median):

| Backend  | ns/op  | MB/s   | hashes/s   | allocs/op |
| -------- | ------ | ------ | ---------- | --------- |
| `scalar` | 285100 | 711.8  | 21,550,000 | 0         |
| `sha2x4` | 106700 | 1899.4 | 57,580,000 | 0         |

The `sha2x4` backend delivers about **2.6x** the scalar throughput at large
batches (2.57–2.67x across thermal states), with zero allocations on both paths
and no regression at the lane/tail boundary counts.

Reproduce with:

```sh
GOMAXPROCS=1 GOSHA256MB_FORCE=scalar \
	go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=8 ./ | tee scalar.txt
GOMAXPROCS=1 GOSHA256MB_FORCE=sha2x4 \
	go test -run '^$' -bench '^BenchmarkHash33$' -benchmem -count=8 ./ | tee sha2x4.txt
benchstat scalar.txt sha2x4.txt
```

The full methodology, the staged-vs-fused HASH160 analysis, and the release
criteria live in [PERFORMANCE.md](PERFORMANCE.md).

## Correctness and Security Posture

This repository treats performance claims as secondary to correctness:

- Known vectors, differential tests, and fuzzing compare `Hash33` against
  `crypto/sha256` and `FromPubkeys33` against `crypto/sha256` +
  `golang.org/x/crypto/ripemd160` (the `btcutil.Hash160` algorithm).
- Every implemented backend — scalar, `sha2x4`, and the fused HASH160 kernel —
  passes the same contract tests, including lane boundaries, the scalar tail,
  and poisoned inter-message padding that catches any read past byte 33.
- `Hash33` and `FromPubkeys33` are tested for zero allocations, bounds safety,
  and concurrent use, including under the race detector.

SHA-256 is a standard primitive; this package is a faster way to compute it in
bulk, not a new cryptographic construction. For new protocol design, prefer
primitives selected for that protocol's threat model.

## Testing

```sh
go test ./...                              # all packages, native backend
GOSHA256MB_FORCE=scalar go test ./...      # force the scalar oracle
go test -race ./...                        # data-race detector
```

Fuzzing:

```sh
go test -run '^$' -fuzz '^FuzzHash33$'        -fuzztime=30s .
go test -run '^$' -fuzz '^FuzzFromPubkeys33$' -fuzztime=30s ./hash160mb
```

Contribution guidelines, generator rules, and the pull-request checklist are in
[CONTRIBUTING.md](CONTRIBUTING.md). The precise API contract is in
[SPEC.md](SPEC.md).

## Roadmap

- Add amd64 SIMD backends (AVX-512 / SHA-NI) only when a real kernel beats
  scalar and passes the same bit-for-bit verification suite.
- Keep `Hash33` and `FromPubkeys33` zero-allocation and stable for
  high-throughput callers.
- Expand benchmark coverage across more CPUs and Go releases.

## License

`sha256mb` is free and open-source software under the MIT license. You may use,
copy, modify, and redistribute it under the terms in [`LICENSE`](LICENSE).
