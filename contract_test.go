package sha256mb

import (
	"bytes"
	"sync"
	"testing"
)

// The tests in this file pin the contract that downstream multi-threaded
// pipelines (Bitcoin HASH160 brute-forcers) rely on: Hash33 is the hot path, it
// is zero-allocation on every backend, it is safe for concurrent use by many
// worker goroutines, the library transparently handles message counts that are
// not a multiple of the lane width, and it never reads past the 33rd byte of a
// message or writes past n*Size of the destination.

// TestHash33ZeroAllocEveryBackend asserts the zero-allocation contract for each
// implemented backend, not just whichever one happens to be active, so a future
// kernel cannot silently start allocating on the hot path.
func TestHash33ZeroAllocEveryBackend(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			const n = 96 // spans several lane groups plus a tail for every backend
			src, _ := makeStrided(t, n, 64)
			dst := make([]byte, n*Size)
			if allocs := testing.AllocsPerRun(200, func() { Hash33(dst, src, n, 64) }); allocs != 0 {
				t.Fatalf("backend %q: Hash33 allocated %v times per run, want 0", name, allocs)
			}
		})
	}
}

// TestHash33TailHandling verifies the library itself splits a batch into the
// vectorized body and a scalar tail when n is not a multiple of the lane width:
// callers never have to align n. Every lane, body or tail, must match the
// independent reference.
func TestHash33TailHandling(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			lanes := Lanes()
			for _, n := range []int{1, lanes - 1, lanes, lanes + 1, 2*lanes - 1, 2 * lanes, 2*lanes + 1, 3*lanes + 2} {
				if n < 1 {
					continue
				}
				src, want := makeStrided(t, n, 64)
				dst := make([]byte, n*Size)
				Hash33(dst, src, n, 64)
				if !bytes.Equal(dst, want) {
					t.Fatalf("backend %q n=%d tail mismatch", name, n)
				}
			}
		})
	}
}

// TestHash33RespectsBounds guarantees Hash33 writes exactly n*Size bytes and
// reads at most (n-1)*stride+33 bytes, leaving surrounding sentinel bytes
// untouched even when the caller passes larger backing arrays. The src buffer
// is sized to the exact minimum so any over-read trips the runtime bounds
// check, and the inter-message padding is poisoned so any in-bounds over-read
// corrupts the digest.
func TestHash33RespectsBounds(t *testing.T) {
	const (
		n      = 9
		stride = 64
		guard  = 16
	)
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			body, want := makeStrided(t, n, stride) // exact length (n-1)*stride+33

			// dst with trailing guard bytes that must stay untouched.
			dst := make([]byte, n*Size+guard)
			for i := range dst {
				dst[i] = 0xCD
			}

			Hash33(dst[:n*Size], body, n, stride)

			for i := n * Size; i < len(dst); i++ {
				if dst[i] != 0xCD {
					t.Fatalf("backend %q wrote past dst[:%d] at index %d", name, n*Size, i)
				}
			}
			if !bytes.Equal(dst[:n*Size], want) {
				t.Fatalf("backend %q produced wrong digests", name)
			}
		})
	}
}

// TestHash33ConcurrentWorkers stresses the documented thread-safety guarantee:
// many goroutines call the shared, stateless Hash33 simultaneously and every
// digest must still match the reference. Under -race this also proves the hot
// path holds no shared mutable state.
func TestHash33ConcurrentWorkers(t *testing.T) {
	const (
		workers    = 16
		iterations = 64
		messages   = 50 // not a multiple of any lane width, to exercise tails
		stride     = 64
	)
	src, want := makeStrided(t, messages, stride)

	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst := make([]byte, messages*Size) // each worker owns its output
			for it := 0; it < iterations; it++ {
				Hash33(dst, src, messages, stride)
				if !bytes.Equal(dst, want) {
					errs <- "concurrent Hash33 produced an incorrect digest"
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

// TestHash33Panics covers the documented programming-error preconditions.
func TestHash33Panics(t *testing.T) {
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
			Hash33(tc.dst, tc.src, tc.n, tc.stride)
		})
	}
}

// TestHash33MetadataConstants pins the advertised sizes.
func TestHash33MetadataConstants(t *testing.T) {
	if Size != 32 {
		t.Fatalf("Size = %d, want 32", Size)
	}
	if BlockSize != 64 {
		t.Fatalf("BlockSize = %d, want 64", BlockSize)
	}
	if MsgLen != 33 {
		t.Fatalf("MsgLen = %d, want 33", MsgLen)
	}
}
