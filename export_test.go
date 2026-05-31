package sha256mb

import "runtime"

func forceBackendForTest(name string) (restore func()) {
	prev := active
	active = selectBackend(name)
	return func() { active = prev }
}

// availableBackendsForTest lists the backends that are actually implemented and
// runnable on the current build, so the matrix tests only exercise real
// kernels. Scalar is always present; the arm64 hardware-SHA backend is added
// here once its kernel is wired in (see block_arm64.go / internal/shagen).
func availableBackendsForTest() []string {
	names := []string{"scalar"}
	if runtime.GOARCH == "arm64" {
		for _, n := range []string{"sha2x2", "sha2x4"} {
			if _, ok := vectorBackend(n); ok {
				names = append(names, n)
			}
		}
	}
	return names
}
