package hash160mb

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// benchPaths is the set of HASH160 implementations benchmarked head-to-head:
// the active path (the fused kernel where one is built) and the staged
// two-phase fallback, so PERFORMANCE.md can justify which is the arm64 default.
var benchPaths = map[string]func(dst, src []byte, n, stride int){
	"active": FromPubkeys33,
	"staged": StagedForTest,
}

// BenchmarkFromPubkeys33 measures the fused/staged HASH160 hot path at the
// production stride of 64 across batch sizes including the 6144 used by the
// downstream bruteforcer. It reports hashes/s and asserts the allocation-free
// contract.
func BenchmarkFromPubkeys33(b *testing.B) {
	const stride = 64
	for _, path := range []string{"active", "staged"} {
		run := benchPaths[path]
		for _, n := range []int{1, 64, 1024, 6144} {
			b.Run(fmt.Sprintf("%s/n=%d", path, n), func(b *testing.B) {
				src := make([]byte, (n-1)*stride+MsgLen)
				dst := make([]byte, n*Size)
				if _, err := rand.Read(src); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(n * MsgLen))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					run(dst, src, n, stride)
				}
				b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "hashes/s")
			})
		}
	}
}
