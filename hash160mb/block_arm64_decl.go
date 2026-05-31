//go:build arm64

package hash160mb

// hash160From33SHA2 is the generated arm64 fused kernel (block_arm64.s). It
// computes RIPEMD160(SHA256(msg)) for n 33-byte messages, message i at
// src[i*stride:], writing the 20-byte digest i to dst[i*Size:]. The intermediate
// SHA-256 digests never leave registers. The caller (fromPubkeys33Fused)
// guarantees n is a positive multiple of the lane count; the short tail is
// handled in Go. Only bytes 0..32 of each message are read.
//
//go:noescape
func hash160From33SHA2(dst, src []byte, n, stride int)
