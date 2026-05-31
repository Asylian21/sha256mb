package sha256mb

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string into bytes, failing the test on malformed input.
func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// referenceSum33 returns SHA-256(msg) computed by the standard library
// crypto/sha256, used as the independent oracle for the differential tests so
// they do not merely compare the package against itself.
func referenceSum33(msg []byte) [Size]byte {
	return sha256.Sum256(msg)
}

// randomBytes returns n cryptographically random bytes, failing the test on a
// reader error instead of forcing every caller to handle it.
func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return b
}

// makeStrided builds a source buffer of exactly (n-1)*stride+MsgLen bytes
// holding n random 33-byte messages spaced stride bytes apart, with every
// inter-message gap byte POISONED (0xEE). A backend that reads past the 33-byte
// message into the stride padding therefore produces a wrong digest and is
// caught by the differential comparison. It also returns the expected n*Size
// digest buffer computed by the crypto/sha256 oracle.
func makeStrided(t testing.TB, n, stride int) (src, want []byte) {
	t.Helper()
	if stride < MsgLen {
		t.Fatalf("makeStrided: stride %d < %d", stride, MsgLen)
	}
	src = make([]byte, (n-1)*stride+MsgLen)
	for i := range src {
		src[i] = 0xEE // poison: leaks into the digest if a kernel over-reads
	}
	want = make([]byte, n*Size)
	for i := 0; i < n; i++ {
		msg := randomBytes(t, MsgLen)
		copy(src[i*stride:], msg)
		d := referenceSum33(msg)
		copy(want[i*Size:], d[:])
	}
	return src, want
}

// withBackend forces the named backend for the duration of fn and always
// restores the previously active backend. It skips the test when the backend is
// not implemented on the current CPU so the matrix tests stay portable.
func withBackend(t *testing.T, name string, fn func()) {
	t.Helper()
	if !backendAvailable(name) {
		t.Skipf("backend %q not available on %s", name, Backend())
	}
	restore := forceBackendForTest(name)
	defer restore()
	fn()
}

// backendAvailable reports whether name appears in the set of backends that can
// be exercised on the current CPU.
func backendAvailable(name string) bool {
	for _, n := range availableBackendsForTest() {
		if n == name {
			return true
		}
	}
	return false
}
