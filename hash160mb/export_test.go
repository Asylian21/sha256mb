package hash160mb

// StagedForTest exposes the staged two-phase path so tests can verify it
// directly even on an architecture where a fused kernel is the default. Both
// paths must match the independent reference oracle bit-for-bit.
func StagedForTest(dst, src []byte, n, stride int) { stagedFromPubkeys33(dst, src, n, stride) }
