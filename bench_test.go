package sha256mb

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// benchCounts returns batch sizes spanning the lane/tail boundaries (one short
// of a lane group, exactly aligned, and one over) plus larger batches that
// amortize call overhead, including the 6144 used by the downstream
// bruteforcer.
func benchCounts(lanes int) []int {
	ns := []int{1}
	if lanes > 1 {
		ns = append(ns, lanes-1, lanes, lanes+1)
	}
	return append(ns, 64, 1024, 6144)
}

// BenchmarkHash33 measures Hash33 across every available backend and a range of
// batch sizes, at the production stride of 64. It reports MB/s, hashes/s (the
// metric that matters for HASH160 pipelines) and allocs/op (must be 0).
func BenchmarkHash33(b *testing.B) {
	const stride = 64
	for _, backendName := range availableBackendsForTest() {
		restore := forceBackendForTest(backendName)
		lanes := Lanes()
		restore()

		for _, n := range benchCounts(lanes) {
			b.Run(fmt.Sprintf("%s/n=%d", backendName, n), func(b *testing.B) {
				restore := forceBackendForTest(backendName)
				defer restore()
				src := make([]byte, (n-1)*stride+MsgLen)
				dst := make([]byte, n*Size)
				if _, err := rand.Read(src); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(n * MsgLen))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					Hash33(dst, src, n, stride)
				}
				b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "hashes/s")
			})
		}
	}
}
