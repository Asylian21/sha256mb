//go:build arm64 && !darwin

package sha256mb

import "golang.org/x/sys/cpu"

// hasSHA2 reports whether the ARMv8 SHA-256 instructions are available, read
// from the kernel-provided HWCAP / system registers via golang.org/x/sys/cpu.
// This path covers Linux, the BSDs and other arm64 platforms where the SHA-256
// extension is genuinely optional.
func hasSHA2() bool { return cpu.ARM64.HasSHA2 }
