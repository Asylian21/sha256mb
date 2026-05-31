//go:build arm64

package sha256mb

// armLanes and armName describe the generated arm64 hardware-SHA kernel and MUST
// match the lane count in internal/shagen (the generator of block_arm64.s).
const (
	armLanes = 4
	armName  = "sha2x4"
)

// bestBackend selects the hardware-SHA kernel when the CPU implements the ARMv8
// SHA-256 instructions (see hasSHA2: always true on Apple Silicon, HWCAP-gated
// elsewhere). NEON is mandatory on ARMv8-A, but the SHA-256 extension is
// optional, so on the rare core without it the package honestly falls back to
// the scalar oracle.
func bestBackend() backend {
	if hasSHA2() {
		return shaBackend()
	}
	return scalarBackend()
}

func shaBackend() backend {
	return backend{name: armName, lanes: armLanes, hash33: hash33SHA2}
}

// vectorBackend reports the named vector backend implemented on this
// architecture. Only the generated multi-buffer hardware-SHA kernel is
// implemented on arm64, and only when the CPU supports the SHA-256 extension.
func vectorBackend(name string) (backend, bool) {
	if name == armName && hasSHA2() {
		return shaBackend(), true
	}
	return backend{}, false
}
