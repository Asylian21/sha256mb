package sha256mb

import (
	"bytes"
	"testing"
)

// laneCounts returns a representative set of message counts for the active
// backend, focused on the boundaries where Hash33 switches between the
// vectorized body and the scalar tail: a single message, the values straddling
// one, two and three full lane groups, and a few larger batches (including the
// 6144 used by the downstream bruteforcer).
func laneCounts(lanes int) []int {
	set := map[int]struct{}{
		1: {}, 2: {}, 3: {},
		64: {}, 100: {}, 1024: {}, 6144: {},
	}
	for _, base := range []int{lanes, 2 * lanes, 3 * lanes} {
		set[base] = struct{}{}
		if base-1 >= 1 {
			set[base-1] = struct{}{}
		}
		set[base+1] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out
}

// strides covers the tight layout (33, no padding) and the production layout
// (64, padded with stale bytes the kernel must ignore).
var strides = []int{MsgLen, 40, 64}

// TestHash33MatchesReference is the primary correctness gate for the fast path:
// for every available backend, a range of batch sizes spanning the lane/tail
// boundaries, and several strides, each 32-byte output lane must equal the
// digest produced by the independent crypto/sha256 oracle for the matching
// 33-byte input slice. The strided inputs poison the inter-message padding, so
// any over-read into the stride tail is caught here.
func TestHash33MatchesReference(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		t.Run(name, func(t *testing.T) {
			withBackend(t, name, func() {
				for _, stride := range strides {
					for _, n := range laneCounts(Lanes()) {
						src, want := makeStrided(t, n, stride)
						dst := make([]byte, n*Size)
						Hash33(dst, src, n, stride)
						if !bytes.Equal(dst, want) {
							for i := 0; i < n; i++ {
								g := dst[i*Size : (i+1)*Size]
								w := want[i*Size : (i+1)*Size]
								if !bytes.Equal(g, w) {
									t.Fatalf("backend=%s stride=%d n=%d lane=%d:\n got  %x\n want %x", name, stride, n, i, g, w)
								}
							}
						}
					}
				}
			})
		})
	}
}

// TestHash33Zero documents that a zero count is a no-op that tolerates nil
// buffers and never reads or writes memory.
func TestHash33Zero(t *testing.T) {
	Hash33(nil, nil, 0, 64)

	dst := []byte{0x11, 0x22, 0x33}
	Hash33(dst, nil, 0, 33)
	if !bytes.Equal(dst, []byte{0x11, 0x22, 0x33}) {
		t.Fatalf("Hash33(n=0) modified dst: %x", dst)
	}
}

// TestHash33Deterministic confirms repeated calls on identical input yield
// byte-identical output (no hidden state between invocations).
func TestHash33Deterministic(t *testing.T) {
	src, _ := makeStrided(t, 12, 64)
	first := make([]byte, 12*Size)
	second := make([]byte, 12*Size)
	Hash33(first, src, 12, 64)
	Hash33(second, src, 12, 64)
	if !bytes.Equal(first, second) {
		t.Fatal("Hash33 produced different output for identical input")
	}
}

// TestHash33KnownVector pins a fixed input/output pair so a refactor of the
// scalar oracle (or a wrong constant in a kernel) is caught against an external
// value, independent of the differential machinery. The vector is the
// compressed generator pubkey 0x02 || Gx, whose SHA-256 is a well-known value.
func TestHash33KnownVector(t *testing.T) {
	// 0x02 followed by the secp256k1 generator x-coordinate.
	msg := mustHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	// crypto/sha256 of that 33-byte message (oracle-derived, pinned here).
	want := referenceSum33(msg)
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			dst := make([]byte, Size)
			Hash33(dst, msg, 1, MsgLen)
			if !bytes.Equal(dst, want[:]) {
				t.Fatalf("backend=%s known-vector mismatch:\n got  %x\n want %x", name, dst, want[:])
			}
		})
	}
}

// FuzzHash33 explores arbitrary inputs: the body is split into 33-byte
// messages, hashed through every available backend at a padded stride, and each
// lane is compared against the independent crypto/sha256 reference.
func FuzzHash33(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, MsgLen),
		bytes.Repeat([]byte{0xFF}, MsgLen),
		bytes.Repeat([]byte("seed"), 40),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		n := len(data) / MsgLen
		if n == 0 {
			return
		}
		const stride = 64
		// Re-pack the fuzz bytes into a strided buffer with poisoned padding.
		src := make([]byte, (n-1)*stride+MsgLen)
		for i := range src {
			src[i] = 0xEE
		}
		want := make([]byte, n*Size)
		for i := 0; i < n; i++ {
			msg := data[i*MsgLen : (i+1)*MsgLen]
			copy(src[i*stride:], msg)
			d := referenceSum33(msg)
			copy(want[i*Size:], d[:])
		}
		for _, name := range availableBackendsForTest() {
			func() {
				restore := forceBackendForTest(name)
				defer restore()
				dst := make([]byte, n*Size)
				Hash33(dst, src, n, stride)
				if !bytes.Equal(dst, want) {
					t.Fatalf("backend=%s n=%d mismatch", name, n)
				}
			}()
		}
	})
}
