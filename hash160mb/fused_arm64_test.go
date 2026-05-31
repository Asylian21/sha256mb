//go:build arm64

package hash160mb

import "github.com/Asylian21/sha256mb"

// FusedForTest exposes the fused single-pass kernel directly, so the
// correctness, fuzz and benchmark suites cover it on arm64 even though the
// default (and the "active" runner) is the staged path. It is only meaningful
// when hardware SHA-256 is present; the init below registers it conditionally.
func FusedForTest(dst, src []byte, n, stride int) { fusedHashN(dst, src, n, stride) }

// init wires the fused kernel into the shared correctness and benchmark tables
// whenever this build can actually run it (hardware SHA-256 available), so a
// regression in the fused path fails the suite regardless of GOHASH160MB_FORCE.
func init() {
	if sha256mb.Lanes() == fusedLanes {
		runners["fused"] = FusedForTest
		benchPaths["fused"] = FusedForTest
	}
}
