package sha256mb

import "crypto/sha256"

// scalarHash33 is the portable correctness oracle: it hashes n independent
// 33-byte messages with the standard library crypto/sha256, one at a time.
// Every vector backend must match it bit-for-bit.
//
// It reads exactly MsgLen bytes per message (src[i*stride : i*stride+MsgLen]),
// never the inter-message stride padding, and writes exactly Size bytes per
// digest. It allocates nothing and is safe for concurrent use.
func scalarHash33(dst, src []byte, n, stride int) {
	for i := 0; i < n; i++ {
		sum := sha256.Sum256(src[i*stride : i*stride+MsgLen])
		copy(dst[i*Size:(i+1)*Size], sum[:])
	}
}
