//go:build darwin || linux

package sha256mb

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Asylian21/sha256mb/internal/testutil"
)

// A wrong assembly load/store width must fault, including when digest bytes
// happen to be correct. Place exact-size buffers against protected pages in
// both directions, at tight, odd and production strides and all four tails.
func TestHash33GuardPages(t *testing.T) {
	for _, name := range availableBackendsForTest() {
		withBackend(t, name, func() {
			for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
				for _, stride := range []int{33, 34, 47, 64} {
					for _, atEnd := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/n=%d/stride=%d/end=%t", name, n, stride, atEnd), func(t *testing.T) {
							src, want := makeStrided(t, n, stride)
							guardedSrc := testutil.GuardedBytes(t, len(src), atEnd)
							copy(guardedSrc, src)
							dst := testutil.GuardedBytes(t, n*Size, atEnd)
							Hash33(dst, guardedSrc, n, stride)
							if !bytes.Equal(dst, want) {
								t.Fatal("guarded digest differs from independent reference")
							}
						})
					}
				}
			}
		})
	}
}
