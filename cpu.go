package sha256mb

import "os"

// forceEnv is the environment variable that pins a specific backend, primarily
// for testing and benchmarking. See selectBackend for the accepted values.
const forceEnv = "GOSHA256MB_FORCE"

func init() {
	active = selectBackend(os.Getenv(forceEnv))
}

// selectBackend resolves a backend from a force string. The empty string and
// "auto" choose the fastest backend the current build implements for this CPU;
// "scalar" always selects the portable oracle; any other value names a specific
// vector backend and is honored only if this build actually implements it on
// the current architecture. Unknown or unavailable names fall back to scalar
// rather than failing, so selection never panics and Backend() never reports a
// SIMD name for a kernel that is really the scalar fallback.
func selectBackend(force string) backend {
	switch force {
	case "", "auto":
		return bestBackend()
	case "scalar":
		return scalarBackend()
	default:
		if b, ok := vectorBackend(force); ok {
			return b
		}
		return scalarBackend()
	}
}

func scalarBackend() backend {
	return backend{name: "scalar", lanes: 1, hash33: scalarHash33}
}
