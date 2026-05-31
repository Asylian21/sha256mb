// Package sha256mb computes SHA-256 digests of many independent fixed-length
// messages in one call, with a multi-buffer fast path designed for
// Bitcoin-style HASH160 pipelines (RIPEMD160(SHA256(compressed-pubkey))).
//
// The primary API is [Hash33], which hashes n independent 33-byte messages —
// exactly one SHA-256 block each after padding — from a single strided source
// buffer into n contiguous 32-byte digests. 33 bytes is the length of a
// compressed secp256k1 public key (a 0x02/0x03 prefix plus the 32-byte
// x-coordinate), the input to a Bitcoin P2PKH HASH160.
//
// # Hash33 buffer layout
//
// Message i occupies src[i*stride : i*stride+33]; only the first 33 bytes of
// each stride are read, so a caller may pad the stride (for example to 64 for
// aligned vector loads) and leave the trailing bytes uninitialized. Digest i
// occupies dst[i*Size:(i+1)*Size]:
//
//	src: | msg 0 (33B) | pad | msg 1 (33B) | pad | ... |   (stride bytes apart)
//	dst: | dig 0 (32B) | dig 1 (32B) | ...           |   (contiguous)
//
// Each digest is byte-identical to crypto/sha256.Sum256(src[i*stride:i*stride+33]).
// Hash33 does not allocate, holds no state between calls, and is safe for
// concurrent use by multiple goroutines.
//
// # Panics
//
// Hash33 panics if n is negative, if stride < 33, if src is shorter than
// (n-1)*stride+33 bytes, or if dst is shorter than n*[Size] bytes. These
// indicate a caller bug rather than a runtime error. A count of n == 0 is a
// valid no-op that tolerates nil buffers.
//
// # Backend selection
//
// At package initialization the implementation selects the fastest backend
// available in this build for the current architecture. The scalar backend is a
// pure crypto/sha256 implementation that also serves as the correctness oracle
// for the vector backends. [Backend] reports the active backend name and
// [Lanes] reports how many messages it processes in parallel.
//
// On arm64 the default is a hardware-SHA backend that interleaves several
// independent messages through the ARMv8 SHA-256 instructions to keep the
// latency-bound crypto pipeline full; the portable scalar fallback is the
// default everywhere else. amd64 SIMD kernels (AVX-512 / SHA-NI) are planned
// but not yet implemented, so amd64 currently runs the scalar backend.
//
// The environment variable GOSHA256MB_FORCE may be set to pin a backend
// (scalar, or an architecture-specific kernel name such as sha2x4). An unknown
// value, or a backend not implemented for the current architecture, falls back
// to scalar rather than failing; the value reported by [Backend] always names
// the kernel that actually runs and is never a SIMD name for a scalar run.
package sha256mb
