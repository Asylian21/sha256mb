//go:build !arm64

package hash160mb

// This file provides the non-fused hooks for architectures without a fused
// single-pass kernel (everything except arm64). FromPubkeys33 always takes the
// staged fallback, and Backend() honestly reports "staged(...)". The arm64
// fused kernel lives in block_arm64.go + block_arm64.s.

// fromPubkeys33Fused runs the fused kernel and returns true when it handled the
// whole batch. This stub returns false so the caller takes the staged path.
func fromPubkeys33Fused(dst, src []byte, n, stride int) bool { return false }

// fusedBackend names the fused kernel when one is active.
func fusedBackend() (string, bool) { return "", false }
