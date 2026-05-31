// Package hash160mb computes the Bitcoin HASH160 — RIPEMD160(SHA256(x)) — of
// many independent 33-byte messages (compressed secp256k1 public keys) in one
// call, fusing the multi-buffer SHA-256 from
// [github.com/Asylian21/sha256mb] with the multi-buffer RIPEMD-160 from
// [github.com/Asylian21/ripemd160-asm].
//
// [FromPubkeys33] is the hot-path primitive: it is allocation-free (after a
// one-time per-goroutine scratch warm-up) and safe for concurrent use, which is
// what Bitcoin address-collision brute-forcers need on their inner loop.
//
// On arm64 a fused kernel keeps each lane group's SHA-256 digests in registers
// and feeds them straight into RIPEMD-160 without a large intermediate buffer;
// where no fused kernel is built the package falls back to a staged path
// (sha256mb.Hash33 into a pooled scratch, then ripemd160mb.Hash32) that is
// bit-identical and still allocation-free. [Backend] reports which path runs.
package hash160mb

import (
	"fmt"
	"sync"

	ripemd160mb "github.com/Asylian21/ripemd160-asm"
	"github.com/Asylian21/sha256mb"
)

const (
	// Size is the size, in bytes, of a HASH160 digest.
	Size = ripemd160mb.Size // 20

	// MsgLen is the fixed input message length: a compressed secp256k1 public
	// key (1-byte 0x02/0x03 prefix + 32-byte x-coordinate).
	MsgLen = sha256mb.MsgLen // 33
)

// scratchPool hands each goroutine a reusable SHA-256 digest buffer for the
// staged path so FromPubkeys33 allocates nothing after warm-up. The buffer
// grows to the largest n a caller has used and is then reused indefinitely. A
// single batch-sized buffer (rather than small tiles) lets the SHA-256 pass
// stream digests out and the RIPEMD-160 pass stream them back sequentially —
// the access pattern the hardware prefetcher handles best, and measured faster
// than L1-sized tiling on Apple M-series.
var scratchPool = sync.Pool{New: func() any { b := make([]byte, 0); return &b }}

// FromPubkeys33 computes RIPEMD160(SHA256(msg)) for n independent 33-byte
// messages.
//
// Message i is src[i*stride : i*stride+33]; only the first 33 bytes of each
// stride are read. Result i (20 bytes) is written to dst[i*Size:(i+1)*Size] and
// is byte-identical to btcutil.Hash160 of that message.
//
// stride must be >= 33. src must contain at least (n-1)*stride+33 bytes and dst
// at least n*Size bytes. FromPubkeys33 does not allocate after a one-time
// per-goroutine scratch warm-up and is safe for concurrent use.
//
// FromPubkeys33 panics if n is negative, if stride < 33, if len(src) <
// (n-1)*stride+33, or if len(dst) < n*Size. A count of zero is a no-op that
// tolerates nil buffers.
func FromPubkeys33(dst, src []byte, n, stride int) {
	if n < 0 {
		panic("hash160mb: negative message count")
	}
	if n == 0 {
		return
	}
	if stride < MsgLen {
		panic(fmt.Sprintf("hash160mb: stride %d < %d", stride, MsgLen))
	}
	if len(src) < (n-1)*stride+MsgLen {
		panic(fmt.Sprintf("hash160mb: src too short for %d %d-byte messages at stride %d", n, MsgLen, stride))
	}
	if len(dst) < n*Size {
		panic(fmt.Sprintf("hash160mb: dst too short for %d HASH160 digests", n))
	}

	if fromPubkeys33Fused(dst, src, n, stride) {
		return
	}
	stagedFromPubkeys33(dst, src, n, stride)
}

// stagedFromPubkeys33 is the portable two-phase path and the correctness oracle
// for the fused kernel: a full multi-buffer SHA-256 pass into a pooled scratch,
// then a full multi-buffer RIPEMD-160 pass over those digests.
func stagedFromPubkeys33(dst, src []byte, n, stride int) {
	need := n * sha256mb.Size
	bp := scratchPool.Get().(*[]byte)
	if cap(*bp) < need {
		*bp = make([]byte, need)
	}
	buf := (*bp)[:need]
	sha256mb.Hash33(buf, src, n, stride)
	ripemd160mb.Hash32(dst[:n*Size], buf, n)
	scratchPool.Put(bp)
}

// Backend returns a human-readable description of the active HASH160 path,
// naming the underlying SHA-256 and RIPEMD-160 backends.
func Backend() string {
	if name, ok := fusedBackend(); ok {
		return name
	}
	return fmt.Sprintf("staged(sha256mb=%s, ripemd160mb=%s)", sha256mb.Backend(), ripemd160mb.Backend())
}

// Fused reports whether a fused single-pass kernel is active (true) or the
// staged two-phase fallback is in use (false).
func Fused() bool {
	_, ok := fusedBackend()
	return ok
}
