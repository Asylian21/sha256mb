package hash160mb

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	//lint:ignore SA1019 x/crypto/ripemd160 is intentionally the independent reference oracle
	"golang.org/x/crypto/ripemd160"
)

// referenceHash160 computes RIPEMD160(SHA256(msg)) using crypto/sha256 and the
// independent golang.org/x/crypto/ripemd160 implementation. This is exactly the
// algorithm of btcutil.Hash160, used here as an external oracle without pulling
// in the heavy btcd/btcutil dependency tree.
func referenceHash160(msg []byte) [Size]byte {
	s := sha256.Sum256(msg)
	h := ripemd160.New()
	_, _ = h.Write(s[:])
	var out [Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return b
}

// makeStrided builds n random 33-byte messages spaced stride bytes apart with
// poisoned inter-message padding (so any over-read corrupts the digest) and the
// matching n*Size expected HASH160 buffer from the oracle.
func makeStrided(t testing.TB, n, stride int) (src, want []byte) {
	t.Helper()
	src = make([]byte, (n-1)*stride+MsgLen)
	for i := range src {
		src[i] = 0xEE
	}
	want = make([]byte, n*Size)
	for i := 0; i < n; i++ {
		msg := randomBytes(t, MsgLen)
		copy(src[i*stride:], msg)
		d := referenceHash160(msg)
		copy(want[i*Size:], d[:])
	}
	return src, want
}

// runners is the set of code paths every correctness test exercises: the
// public entry point (whichever backend is active) and the staged fallback
// (forced via the test hook), so the staged path is covered even when a fused
// kernel is the default.
var runners = map[string]func(dst, src []byte, n, stride int){
	"active": FromPubkeys33,
	"staged": StagedForTest,
}

var strides = []int{MsgLen, 40, 64}

func counts() []int {
	return []int{1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 64, 100, 1024, 6144}
}

// TestFromPubkeys33MatchesReference is the primary correctness gate: every path,
// stride and batch size must produce HASH160 digests byte-identical to the
// independent oracle. Poisoned padding catches any read past the 33rd byte.
func TestFromPubkeys33MatchesReference(t *testing.T) {
	for name, run := range runners {
		t.Run(name, func(t *testing.T) {
			for _, stride := range strides {
				for _, n := range counts() {
					src, want := makeStrided(t, n, stride)
					dst := make([]byte, n*Size)
					run(dst, src, n, stride)
					if !bytes.Equal(dst, want) {
						for i := 0; i < n; i++ {
							g := dst[i*Size : (i+1)*Size]
							w := want[i*Size : (i+1)*Size]
							if !bytes.Equal(g, w) {
								t.Fatalf("path=%s stride=%d n=%d lane=%d:\n got  %x\n want %x", name, stride, n, i, g, w)
							}
						}
					}
				}
			}
		})
	}
}

// TestFromPubkeys33KnownVector pins the HASH160 of the compressed secp256k1
// generator public key against the independent oracle, guarding the whole
// pipeline against a refactor that breaks both our paths the same way.
func TestFromPubkeys33KnownVector(t *testing.T) {
	gen, err := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		t.Fatal(err)
	}
	want := referenceHash160(gen)
	for name, run := range runners {
		dst := make([]byte, Size)
		run(dst, gen, 1, MsgLen)
		if !bytes.Equal(dst, want[:]) {
			t.Fatalf("path=%s known-vector mismatch:\n got  %x\n want %x", name, dst, want[:])
		}
	}
}

// TestFromPubkeys33Zero documents that a zero count is a no-op tolerating nil.
func TestFromPubkeys33Zero(t *testing.T) {
	FromPubkeys33(nil, nil, 0, 64)
	dst := []byte{1, 2, 3}
	FromPubkeys33(dst, nil, 0, 33)
	if !bytes.Equal(dst, []byte{1, 2, 3}) {
		t.Fatalf("n=0 modified dst: %x", dst)
	}
}

// TestFromPubkeys33ZeroAlloc asserts the documented allocation-free contract on
// the active path after warm-up.
func TestFromPubkeys33ZeroAlloc(t *testing.T) {
	const n = 6144
	src, _ := makeStrided(t, n, 64)
	dst := make([]byte, n*Size)
	if allocs := testing.AllocsPerRun(50, func() { FromPubkeys33(dst, src, n, 64) }); allocs != 0 {
		t.Fatalf("FromPubkeys33 allocated %v times per run, want 0", allocs)
	}
}

// TestFromPubkeys33RespectsBounds checks no write past dst[:n*Size]; the src is
// sized to the exact minimum so any over-read trips the runtime bounds check.
func TestFromPubkeys33RespectsBounds(t *testing.T) {
	const (
		n      = 9
		stride = 64
		guard  = 16
	)
	src, want := makeStrided(t, n, stride)
	dst := make([]byte, n*Size+guard)
	for i := range dst {
		dst[i] = 0xCD
	}
	FromPubkeys33(dst[:n*Size], src, n, stride)
	for i := n * Size; i < len(dst); i++ {
		if dst[i] != 0xCD {
			t.Fatalf("wrote past dst[:%d] at index %d", n*Size, i)
		}
	}
	if !bytes.Equal(dst[:n*Size], want) {
		t.Fatal("wrong digests")
	}
}

// TestFromPubkeys33Concurrent proves the documented thread-safety: many
// goroutines hashing the same input concurrently all match the reference (run
// under -race this also proves no shared mutable state on the hot path).
func TestFromPubkeys33Concurrent(t *testing.T) {
	const (
		workers  = 16
		iters    = 32
		messages = 200
		stride   = 64
	)
	src, want := makeStrided(t, messages, stride)
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst := make([]byte, messages*Size)
			for it := 0; it < iters; it++ {
				FromPubkeys33(dst, src, messages, stride)
				if !bytes.Equal(dst, want) {
					errs <- "incorrect concurrent digest"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if msg, bad := <-errs; bad {
		t.Fatal(msg)
	}
}

// TestFromPubkeys33Panics covers the documented programming-error preconditions.
func TestFromPubkeys33Panics(t *testing.T) {
	cases := []struct {
		name   string
		dst    []byte
		src    []byte
		n      int
		stride int
	}{
		{"negative n", make([]byte, Size), make([]byte, 64), -1, 64},
		{"stride too small", make([]byte, Size), make([]byte, 64), 1, MsgLen - 1},
		{"src too short", make([]byte, 2*Size), make([]byte, 64+MsgLen-1), 2, 64},
		{"dst too short", make([]byte, Size), make([]byte, 64+MsgLen), 2, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic for %s", tc.name)
				}
			}()
			FromPubkeys33(tc.dst, tc.src, tc.n, tc.stride)
		})
	}
}

// TestBackendDescribed checks Backend() is non-empty and consistent with Fused().
func TestBackendDescribed(t *testing.T) {
	if Backend() == "" {
		t.Fatal("Backend() is empty")
	}
	// Fused() and Backend() must agree about whether a fused kernel runs.
	if Fused() && bytes.HasPrefix([]byte(Backend()), []byte("staged(")) {
		t.Fatalf("Fused()=true but Backend()=%q looks staged", Backend())
	}
}

// FuzzFromPubkeys33 hashes arbitrary inputs split into 33-byte messages through
// both paths and compares each lane against the oracle.
func FuzzFromPubkeys33(f *testing.F) {
	f.Add(make([]byte, MsgLen))
	f.Add(bytes.Repeat([]byte{0xFF}, MsgLen))
	f.Add(bytes.Repeat([]byte("k"), 5*MsgLen))
	f.Fuzz(func(t *testing.T, data []byte) {
		n := len(data) / MsgLen
		if n == 0 {
			return
		}
		const stride = 64
		src := make([]byte, (n-1)*stride+MsgLen)
		for i := range src {
			src[i] = 0xEE
		}
		want := make([]byte, n*Size)
		for i := 0; i < n; i++ {
			msg := data[i*MsgLen : (i+1)*MsgLen]
			copy(src[i*stride:], msg)
			d := referenceHash160(msg)
			copy(want[i*Size:], d[:])
		}
		for name, run := range runners {
			dst := make([]byte, n*Size)
			run(dst, src, n, stride)
			if !bytes.Equal(dst, want) {
				t.Fatalf("path=%s n=%d mismatch", name, n)
			}
		}
	})
}
