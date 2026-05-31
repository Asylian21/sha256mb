//go:build arm64 && darwin

package sha256mb

// hasSHA2 reports whether the ARMv8 SHA-256 instructions are available. Every
// Apple Silicon core (the only arm64 Darwin target) implements the ARMv8
// cryptography extension, so detection is unconditional here — matching the Go
// standard library, whose crypto/sha256 also assumes hardware SHA on
// darwin/arm64. golang.org/x/sys/cpu does NOT populate ARM64 feature flags on
// Darwin (it has no sysctl path and falls back to a minimal feature set), so it
// must not be consulted here.
func hasSHA2() bool { return true }
