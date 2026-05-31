package sha256mb

import (
	"bytes"
	"testing"
)

// knownLanes maps every backend name the library may report to its required
// lane count. Backend() and Lanes() must always agree with this table.
var knownLanes = map[string]int{
	"scalar": 1,
	"sha2x2": 2,
	"sha2x4": 4,
}

// TestBackendAndLanesConsistent checks that the reported backend name is one of
// the known backends and that its lane count is positive and consistent with
// the name. The scalar backend must always report a single lane.
func TestBackendAndLanesConsistent(t *testing.T) {
	name := Backend()
	lanes := Lanes()
	if lanes < 1 {
		t.Fatalf("Lanes() = %d, want >= 1", lanes)
	}
	want, ok := knownLanes[name]
	if !ok {
		t.Fatalf("Backend() = %q, not a known backend", name)
	}
	if lanes != want {
		t.Fatalf("backend %q reports %d lanes, want %d", name, lanes, want)
	}
}

// TestActiveBackendIsImplemented guards against the class of bug where the
// dispatch advertises a vector backend that secretly runs the scalar oracle:
// every backend the package can report must be one this build actually
// implements, so Backend() never lies about running SIMD.
func TestActiveBackendIsImplemented(t *testing.T) {
	if !backendAvailable(Backend()) {
		t.Fatalf("active backend %q is not in the implemented set %v", Backend(), availableBackendsForTest())
	}
}

// TestSelectBackendDefaults verifies that the empty string and "auto" both
// resolve to the platform's best backend, matching the package init behavior.
func TestSelectBackendDefaults(t *testing.T) {
	best := bestBackend()
	for _, force := range []string{"", "auto"} {
		got := selectBackend(force)
		if got.name != best.name || got.lanes != best.lanes {
			t.Fatalf("selectBackend(%q) = %q/%d, want %q/%d", force, got.name, got.lanes, best.name, best.lanes)
		}
	}
}

// TestSelectBackendInvalidFallsBackToScalar verifies that an unrecognized force
// value never panics and always degrades safely to the scalar oracle.
func TestSelectBackendInvalidFallsBackToScalar(t *testing.T) {
	for _, force := range []string{"unknown", "AVX2", "scalar ", "sha", "0"} {
		got := selectBackend(force)
		if got.name != "scalar" || got.lanes != 1 {
			t.Fatalf("selectBackend(%q) = %q/%d, want scalar/1", force, got.name, got.lanes)
		}
	}
}

// TestSelectBackendUnimplementedFallsBackToScalar verifies that the names of
// vector backends that are not implemented in this build (the amd64 SIMD
// families and any unbuilt arm64 variant) always resolve to scalar rather than
// a backend that lies about its width.
func TestSelectBackendUnimplementedFallsBackToScalar(t *testing.T) {
	for _, name := range []string{"sse2", "avx2", "avx512"} {
		got := selectBackend(name)
		if got.name != "scalar" || got.lanes != 1 {
			t.Fatalf("selectBackend(%q) = %q/%d, want scalar/1", name, got.name, got.lanes)
		}
		if _, ok := vectorBackend(name); ok {
			t.Fatalf("vectorBackend(%q) unexpectedly reports an implementation", name)
		}
	}
}

// TestSelectBackendForcedScalar confirms scalar can always be requested
// explicitly on any architecture.
func TestSelectBackendForcedScalar(t *testing.T) {
	got := selectBackend("scalar")
	if got.name != "scalar" || got.lanes != 1 || got.hash33 == nil {
		t.Fatalf("selectBackend(\"scalar\") = %+v", got)
	}
}

// TestSelectBackendForcedAvailable confirms that any backend reported as
// available can actually be forced and yields a usable, correctly-named backend
// with a lane count matching the canonical table.
func TestSelectBackendForcedAvailable(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		got := selectBackend(name)
		if got.name != name {
			t.Fatalf("selectBackend(%q) = %q, want %q", name, got.name, name)
		}
		if got.hash33 == nil {
			t.Fatalf("selectBackend(%q) returned a nil hash function", name)
		}
		if got.lanes != knownLanes[name] {
			t.Fatalf("selectBackend(%q) = %d lanes, want %d", name, got.lanes, knownLanes[name])
		}
	}
}

// TestBestBackendIsUsable enforces that the default backend constructor always
// returns a backend with a non-nil hash function, a sane lane count, and a
// known name on every architecture.
func TestBestBackendIsUsable(t *testing.T) {
	for label, b := range map[string]backend{"scalar": scalarBackend(), "best": bestBackend()} {
		if b.hash33 == nil {
			t.Fatalf("%s backend has a nil hash function", label)
		}
		if b.lanes < 1 {
			t.Fatalf("%s backend reports %d lanes, want >= 1", label, b.lanes)
		}
		if _, ok := knownLanes[b.name]; !ok {
			t.Fatalf("%s backend has unknown name %q", label, b.name)
		}
	}
}

// TestForcedBackendHashWorks invokes each available backend's wired hash33
// function pointer directly, hashing exactly one full lane group at the
// production stride of 64, to ensure the constructor is wired to a kernel that
// produces correct digests. A full lane group is used because the public
// dispatch only ever calls a backend with a multiple of its lane count.
func TestForcedBackendHashWorks(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			b := active
			src, want := makeStrided(t, b.lanes, 64)
			dst := make([]byte, b.lanes*Size)
			b.hash33(dst, src, b.lanes, 64)
			if !bytes.Equal(dst, want) {
				t.Fatalf("backend %q hash33 mismatch:\n got  %x\n want %x", name, dst, want)
			}
		})
	}
}
