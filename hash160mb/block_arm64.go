//go:build arm64

package hash160mb

import (
	"fmt"
	"os"
	"strings"

	ripemd160mb "github.com/Asylian21/ripemd160-asm"
	"github.com/Asylian21/sha256mb"
)

// fusedLanes is the number of messages the fused kernel consumes per loop
// iteration. It must equal the SHA half's interleave width.
const fusedLanes = 4

// forceEnv selects the HASH160 path at init, overriding the automatic choice.
// Recognized values (case-insensitive): "" or "auto" (default), "staged"/"off"
// (the two-phase fallback), "fused"/"on" (the fused single-pass kernel). It
// mirrors GOSHA256MB_FORCE / GORIPEMD160MB_FORCE and exists for A/B benchmarking
// and for selecting the fused kernel on microarchitectures where it wins.
const forceEnv = "GOHASH160MB_FORCE"

type fuseMode int

const (
	fuseAuto   fuseMode = iota // pick the measured-faster path for this build
	fuseStaged                 // always staged
	fusePrefer                 // fused where hardware SHA-256 is available
)

// mode is resolved once at init; the hot path never touches the environment.
var mode = resolveMode(os.Getenv(forceEnv))

func resolveMode(s string) fuseMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "staged", "off", "scalar":
		return fuseStaged
	case "fused", "on":
		return fusePrefer
	default: // "", "auto", or anything unrecognized: pick automatically
		return fuseAuto
	}
}

// fusedActive reports whether the fused single-pass kernel runs.
//
// The default (fuseAuto) is the STAGED path: on Apple M-series the fused kernel
// measures within noise of staged single-threaded and ~3% slower at 8 threads,
// because both halves are throughput-bound and the staged path gives each its
// own deeply-pipelined loop (see PERFORMANCE.md). The fused kernel is validated,
// benchmarked and selectable via GOHASH160MB_FORCE=fused for reproducibility and
// for cores where removing the intermediate digest buffer pays off.
//
// The fused kernel hard-codes the ARMv8 SHA-256 instructions, so it is only ever
// enabled when sha256mb selected its hardware backend — a condition that already
// folds in both the CPU feature probe and GOSHA256MB_FORCE. Gating on sha256mb's
// lane count also keeps the packages' reported backends consistent: force
// sha256mb to scalar (or run on a core without the SHA-256 extension) and
// HASH160 falls back to staged instead of issuing an illegal instruction.
func fusedActive() bool {
	if mode != fusePrefer {
		return false
	}
	return sha256mb.Lanes() == fusedLanes
}

// fromPubkeys33Fused runs the fused kernel over whole lane groups and finishes
// any short tail through the staged path, which on this architecture also uses
// the hardware SHA backend. It returns true when it handled the batch and false
// when the fused kernel is inactive so the caller takes the staged path.
//
// Bounds were validated by FromPubkeys33 before dispatch.
func fromPubkeys33Fused(dst, src []byte, n, stride int) bool {
	if !fusedActive() {
		return false
	}
	fusedHashN(dst, src, n, stride)
	return true
}

// fusedHashN applies the fused kernel to the whole lane groups and the staged
// path to the remaining tail. It is also the test entry point (FusedForTest) so
// the fused kernel is covered even when GOHASH160MB_FORCE pins another mode.
func fusedHashN(dst, src []byte, n, stride int) {
	vecN := n - n%fusedLanes
	if vecN > 0 {
		hash160From33SHA2(dst[:vecN*Size], src, vecN, stride)
	}
	if vecN != n {
		stagedFromPubkeys33(dst[vecN*Size:n*Size], src[vecN*stride:], n-vecN, stride)
	}
}

// fusedBackend names the fused kernel when it is active.
func fusedBackend() (string, bool) {
	if fusedActive() {
		return fmt.Sprintf("fused(sha256mb=%s, ripemd160mb=%s)", sha256mb.Backend(), ripemd160mb.Backend()), true
	}
	return "", false
}
