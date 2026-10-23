//go:build darwin || linux

// Package testutil supplies memory-boundary fixtures for the assembly tests.
package testutil

import (
	"testing"

	"golang.org/x/sys/unix"
)

// GuardedBytes returns a buffer abutting an inaccessible page at its beginning
// or end. Slice bounds alone cannot detect assembly reads beyond a buffer.
func GuardedBytes(t testing.TB, size int, atEnd bool) []byte {
	t.Helper()
	page := unix.Getpagesize()
	if size <= 0 || size > page {
		t.Fatalf("guarded buffer size %d outside 1..%d", size, page)
	}
	mem, err := unix.Mmap(-1, 0, 3*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Munmap(mem); err != nil {
			t.Error(err)
		}
	})
	if err := unix.Mprotect(mem[:page], unix.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mprotect(mem[2*page:], unix.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	start := page
	if atEnd {
		start = 2*page - size
	}
	return mem[start : start+size : start+size]
}
