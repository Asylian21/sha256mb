//go:build darwin || linux

package hash160mb

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Asylian21/sha256mb/internal/testutil"
)

func TestFromPubkeys33GuardPages(t *testing.T) {
	for name, run := range runners {
		for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
			for _, stride := range []int{33, 34, 47, 64} {
				for _, atEnd := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/n=%d/stride=%d/end=%t", name, n, stride, atEnd), func(t *testing.T) {
						src, want := makeStrided(t, n, stride)
						guardedSrc := testutil.GuardedBytes(t, len(src), atEnd)
						copy(guardedSrc, src)
						dst := testutil.GuardedBytes(t, n*Size, atEnd)
						run(dst, guardedSrc, n, stride)
						if !bytes.Equal(dst, want) {
							t.Fatal("guarded HASH160 differs from independent reference")
						}
					})
				}
			}
		}
	}
}
