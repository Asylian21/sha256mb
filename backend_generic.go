//go:build !arm64

package sha256mb

// On architectures without a vector kernel in this build, the portable scalar
// implementation is the only backend. amd64 SIMD kernels (AVX-512 16-lane and
// SHA-NI 2-way) are planned but not yet implemented; the arm64 hardware-SHA
// generator in internal/shagen is the reference template for adding them.

func bestBackend() backend { return scalarBackend() }

// vectorBackend reports no implemented vector backends on these architectures,
// so any named request falls back to scalar.
func vectorBackend(string) (backend, bool) { return backend{}, false }
