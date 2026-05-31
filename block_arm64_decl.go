//go:build arm64

package sha256mb

// hash33SHA2 is the generated arm64 hardware-SHA kernel (block_arm64.s). It
// hashes n independent 33-byte messages, message i at src[i*stride:], writing
// digest i to dst[i*Size:]. The caller (Hash33) guarantees n is a positive
// multiple of the lane count; the scalar tail is handled in Go.
//
//go:noescape
func hash33SHA2(dst, src []byte, n, stride int)
