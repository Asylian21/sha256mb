package sha256mb

import "fmt"

const (
	// Size is the size, in bytes, of a SHA-256 digest.
	Size = 32

	// BlockSize is SHA-256's internal block size in bytes.
	BlockSize = 64

	// MsgLen is the fixed message length accepted by Hash33: a compressed
	// secp256k1 public key (1-byte 0x02/0x03 prefix + 32-byte x-coordinate).
	MsgLen = 33
)

// hash33Func hashes n independent MsgLen-byte messages, message i taken from
// src[i*stride:], writing digest i to dst[i*Size:]. A backend's function is only
// ever invoked by Hash33 with n a positive multiple of its lane count.
type hash33Func func(dst, src []byte, n, stride int)

type backend struct {
	name   string
	lanes  int
	hash33 hash33Func
}

// active is the backend chosen at init (see cpu.go). It defaults to scalar so
// the package is usable even before init runs (e.g. from another package's
// init) and on any architecture without a vector kernel.
var active = backend{
	name:   "scalar",
	lanes:  1,
	hash33: scalarHash33,
}

// Hash33 hashes n independent 33-byte messages from src into dst.
//
// Message i is src[i*stride : i*stride+33]; only the first 33 bytes of each
// stride are read. Digest i is written to dst[i*Size:(i+1)*Size] and is
// byte-identical to crypto/sha256.Sum256(src[i*stride : i*stride+33]).
//
// stride must be >= 33. src must contain at least (n-1)*stride+33 bytes and dst
// at least n*Size bytes. Hash33 does not allocate and is safe for concurrent
// use by multiple goroutines.
//
// Hash33 panics if n is negative, if stride < 33, if len(src) < (n-1)*stride+33,
// or if len(dst) < n*Size. A count of zero is a no-op that tolerates nil
// buffers.
func Hash33(dst, src []byte, n, stride int) {
	if n < 0 {
		panic("sha256mb: negative message count")
	}
	if n == 0 {
		return
	}
	if stride < MsgLen {
		panic(fmt.Sprintf("sha256mb: stride %d < %d", stride, MsgLen))
	}
	needSrc := (n-1)*stride + MsgLen
	needDst := n * Size
	if len(src) < needSrc {
		panic(fmt.Sprintf("sha256mb: src too short for %d %d-byte messages at stride %d", n, MsgLen, stride))
	}
	if len(dst) < needDst {
		panic(fmt.Sprintf("sha256mb: dst too short for %d SHA-256 digests", n))
	}

	b := active
	if b.lanes <= 1 {
		scalarHash33(dst[:needDst], src, n, stride)
		return
	}

	// Vectorized body over whole lane groups, then a scalar tail for the
	// remainder. The library handles the split so callers never align n.
	vecN := n - n%b.lanes
	if vecN > 0 {
		b.hash33(dst[:vecN*Size], src, vecN, stride)
	}
	if vecN != n {
		scalarHash33(dst[vecN*Size:needDst], src[vecN*stride:], n-vecN, stride)
	}
}

// Lanes returns the number of messages processed in parallel by the active
// backend. It returns 1 for the scalar backend.
func Lanes() int { return active.lanes }

// Backend returns the active backend name.
func Backend() string { return active.name }
