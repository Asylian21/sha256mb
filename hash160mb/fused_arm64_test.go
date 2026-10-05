//go:build arm64

package hash160mb

import (
	"testing"

	"github.com/Asylian21/sha256mb"
)

func TestFusedBackendDescribesEmbeddedKernel(t *testing.T) {
	if sha256mb.Lanes() != fusedLanes {
		t.Skip("hardware SHA4 backend unavailable")
	}
	previous := mode
	mode = fusePrefer
	defer func() { mode = previous }()
	name, ok := fusedBackend()
	want := "fused(sha256mb=sha2x4, ripemd160mb=neon)"
	if useFusedSHA3 {
		want = "fused(sha256mb=sha2x4, ripemd160mb=neon-sha3)"
	}
	if !ok || name != want {
		t.Fatalf("fusedBackend() = %q, %t, want %q", name, ok, want)
	}
}

// FusedForTest exposes the fused single-pass kernel directly, so the
// correctness, fuzz and benchmark suites cover it on arm64 even though the
// default (and the "active" runner) is the staged path. It is only meaningful
// when hardware SHA-256 is present; the init below registers it conditionally.
func FusedForTest(dst, src []byte, n, stride int) { fusedHashN(dst, src, n, stride) }

func FusedNEONForTest(dst, src []byte, n, stride int) {
	fusedHashNKernel(dst, src, n, stride, false)
}

func FusedSHA3ForTest(dst, src []byte, n, stride int) {
	fusedHashNKernel(dst, src, n, stride, true)
}

// init wires the fused kernel into the shared correctness and benchmark tables
// whenever this build can actually run it (hardware SHA-256 available), so a
// regression in the fused path fails the suite regardless of GOHASH160MB_FORCE.
func init() {
	if sha256mb.Lanes() == fusedLanes {
		runners["fused"] = FusedForTest
		benchPaths["fused"] = FusedForTest
		runners["fused-neon"] = FusedNEONForTest
		benchPaths["fused-neon"] = FusedNEONForTest
		if useFusedSHA3 {
			runners["fused-sha3"] = FusedSHA3ForTest
			benchPaths["fused-sha3"] = FusedSHA3ForTest
		}
	}
}
