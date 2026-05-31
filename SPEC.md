# sha256mb Specification

This repository implements a pure-Go plus Go-assembler multi-buffer SHA-256
library. The primary API is `Hash33`, which hashes many independent 33-byte
messages from a strided input buffer into contiguous 32-byte digests. The
`hash160mb` subpackage builds Bitcoin `RIPEMD160(SHA256(x))` on top of it.

## Public API

```go
// package sha256mb
const (
	Size      = 32 // SHA-256 digest size in bytes
	BlockSize = 64 // SHA-256 internal block size in bytes
	MsgLen    = 33 // fixed message length: compressed secp256k1 public key
)

func Hash33(dst, src []byte, n, stride int)
func Lanes() int
func Backend() string
```

The `hash160mb` subpackage exposes:

```go
// package sha256mb/hash160mb
const (
	Size   = 20 // HASH160 digest size in bytes
	MsgLen = 33
)

func FromPubkeys33(dst, src []byte, n, stride int) // RIPEMD160(SHA256(x)) batched
func Backend() string
func Fused() bool
```

## Contract

### Hash33

- Reads `n` messages of exactly 33 bytes: message `i` is
  `src[i*stride : i*stride+33]`. Only those 33 bytes are read; the kernel never
  touches the inter-message stride padding, so any `stride >= 33` is safe.
- Writes `n` digests of exactly `Size` bytes: digest `i` is
  `dst[i*Size:(i+1)*Size]`.
- Requires `stride >= 33`, `len(src) >= (n-1)*stride+33`, and `len(dst) >= n*Size`.
- Allocates nothing, keeps no state between calls, and is safe for concurrent
  use by multiple goroutines.
- For all inputs, lane `i` equals `crypto/sha256.Sum256(src[i*stride:i*stride+33])`.
  The scalar backend is the reference; every other backend must match it
  bit-for-bit.

### FromPubkeys33 (hash160mb)

- Reads `n` 33-byte messages at `stride` and writes `n` 20-byte digests
  contiguously: digest `i` is `dst[i*Size:(i+1)*Size]`.
- Each digest equals `RIPEMD160(SHA256(message))`, byte-identical to
  `btcutil.Hash160`.
- Same buffer, stride, allocation, and concurrency contract as `Hash33`.

### Padding (fixed single block)

A 33-byte message is exactly one padded SHA-256 block, computed without a
length-dependent branch:

```text
W[0..7] = message bytes 0..31 (8 big-endian words)
W[8]    = msg[32]<<24 | 0x00800000   (final byte + the 0x80 padding bit)
W[9..14]= 0
W[15]   = 0x108                       (264 = 33*8, the message bit length)
```

The 32-byte SHA-256 digest is in turn exactly one padded RIPEMD-160 block, whose
little-endian schedule words are the byte-reversed SHA-256 state words — the
endianness boundary the fused HASH160 kernel crosses entirely in registers.

### Panics

The following are programming errors and panic rather than returning an error:

- `Hash33` / `FromPubkeys33`: `n < 0`, `stride < 33`,
  `len(src) < (n-1)*stride+33`, or `len(dst) < n*Size`.

A count of `n == 0` is always a valid no-op and tolerates nil buffers.

## Backends

Implemented backends:

- `scalar`: pure `crypto/sha256` fallback and correctness oracle (1 lane).
  Default off arm64.
- `sha2x4`: arm64 4-lane hardware-SHA backend (`SHA256H`/`SHA256H2`/`SHA256SU0`/
  `SHA256SU1`), four independent messages interleaved per loop. Default on arm64.

amd64 SIMD kernels (AVX-512 / SHA-NI) are planned but not yet implemented; amd64
currently runs the scalar backend. A backend is only advertised — and only
selectable — once it has a real kernel verified bit-for-bit against the scalar
oracle, so `Backend()` never reports a SIMD name while secretly running scalar.

The active backend is chosen once at package initialization. `GOSHA256MB_FORCE`
may be set to `scalar` or `sha2x4`. Selection rules:

- empty string or `auto`: choose the fastest backend implemented for the current
  architecture.
- an implemented backend name: use it.
- an unknown name, or a backend not implemented for the current architecture
  (for example `sha2x4` on amd64): fall back to `scalar`. Selection never panics.

`Backend()` returns the active backend name and `Lanes()` returns its lane count
(always `1` for scalar, `4` for `sha2x4`). The two always agree, and the reported
backend is always the kernel that actually executes.

On `darwin/arm64` the hardware backend is assumed available (every Apple-silicon
core implements the ARMv8 crypto extension, as `crypto/sha256` itself assumes);
on other arm64 platforms it is gated on the HWCAP `SHA2` bit via
`golang.org/x/sys/cpu`.

## HASH160 path selection

`hash160mb` ships two bit-identical implementations:

- **staged**: a full `Hash33` pass into a pooled digest buffer, then a full
  `ripemd160mb.Hash32` pass. The default on every architecture.
- **fused** (arm64): a single kernel that hashes four messages with hardware
  SHA-256, hands the digests to a 4-lane NEON RIPEMD-160 entirely in registers
  (no intermediate buffer), and stores the four HASH160 results.

On Apple M3 the two measure within noise single-threaded and the staged path is
~3% faster at 8 threads (both halves are throughput-bound and the staged path
gives each its own deeply pipelined loop), so **staged is the default**. The
fused kernel is validated, benchmarked, and selectable with `GOHASH160MB_FORCE=fused`
for reproducibility and for cores where eliminating the digest buffer wins.
`Backend()` reports `staged(...)` or `fused(...)` accordingly, and `Fused()`
agrees.

## Quality bar

"Well tested" for this repository means all of the following hold:

- Correctness is validated against the independent standard-library oracles:
  `crypto/sha256` for `Hash33`, and `crypto/sha256` + `golang.org/x/crypto/ripemd160`
  for `FromPubkeys33`, via known vectors, differential tests, and fuzzing
  (`FuzzHash33`, `FuzzFromPubkeys33`).
- Every available backend (scalar, `sha2x4`, staged, fused) is exercised through
  the same correctness suite, including the lane/tail boundary counts and
  poisoned inter-message padding.
- `Hash33` and `FromPubkeys33` are asserted to be zero-allocation and to respect
  their buffer bounds.
- Tests pass under the race detector and under forced-scalar / forced-staged
  execution.
- `gofmt` and `go vet` are clean, and `go generate ./...` produces no diff.

The assembly generators (`internal/shagen`, `hash160mb/internal/fusedgen`) are
validated by the `go generate` + clean-tree check rather than by statement
coverage.
