// Command fusedgen emits the arm64 fused HASH160 kernel block_arm64.s.
//
// The kernel computes RIPEMD160(SHA256(msg)) for four independent 33-byte
// messages per loop iteration WITHOUT ever writing the intermediate SHA-256
// digests to memory. It is the register-level fusion of two proven kernels:
//
//   - the SHA-256 half mirrors github.com/Asylian21/sha256mb's hardware-SHA
//     kernel (SHA256H/H2/SU0/SU1), running four messages as register-disjoint
//     streams in lockstep so the out-of-order core hides SHA256H latency;
//   - the RIPEMD-160 half mirrors github.com/Asylian21/ripemd160-asm's NEON
//     kernel (two pipelines, one 32-bit lane per message).
//
// Why fuse. The SHA-256 instructions execute on the dedicated cryptographic
// pipes; the RIPEMD-160 round body is plain NEON integer/logical work on the
// vector ALUs. Running them back-to-back in one loop lets the core overlap the
// next group's SHA with the current group's RIPEMD across the two execution
// domains — an overlap the staged (all-SHA-then-all-RIPEMD) path cannot get —
// and removes the batch-sized digest buffer from the memory hierarchy entirely.
//
// The endianness boundary (SHA-256 emits a big-endian digest; RIPEMD-160 reads
// it as little-endian words) collapses to nothing here: the SHA finalize's
// VREV32 of the state words yields exactly the little-endian schedule words
// x0..x7 the RIPEMD transpose expects, handed over in registers.
//
// Per-iteration data flow (V = NEON register):
//
//	SHA setup/rounds/finalize  -> lane m digest in (abcd_rev[m], efgh_rev[m])
//	gather                     -> V0..V7 = m0[x0..3],m0[x4..7],m1[x0..3],...
//	RIPEMD transpose           -> V0..V7 = word-major (lane = message)
//	RIPEMD 80 rounds + combine -> V0..V4 = digest words 0..4 (lane = message)
//	store                      -> four contiguous 20-byte HASH160 digests
//
// Message preprocessing matches sha256mb exactly: a fixed 33-byte single SHA
// block (W[8]=msg[32]<<24|0x00800000, W[15]=0x108) and a fixed 32-byte single
// RIPEMD block (x8=0x80, x14=256). Only bytes 0..32 of each message are read,
// so the kernel is safe at any stride >= 33 and never over-reads the caller's
// buffer.
//
// The generator is the single source of truth for block_arm64.s; do not edit
// the assembly by hand (see CONTRIBUTING.md).
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// modulePath is the import path of the module that owns the generated file. The
// generated kernel lives in the hash160mb subpackage of that module.
const modulePath = "github.com/Asylian21/sha256mb"

// lanes is the number of independent messages processed per loop iteration. It
// is fixed at four: the SHA half wants enough independent streams to hide
// SHA256H latency, and the RIPEMD half is intrinsically four-lane (one 32-bit
// lane per message in a 128-bit vector).
const lanes = 4

// ---------------------------------------------------------------------------
// SHA-256 constants and register plan (mirrors sha256mb/internal/shagen).
// ---------------------------------------------------------------------------

var shaK = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var shaIV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// SHA per-lane register roles, packed seven registers per lane (V0..V27 for the
// four lanes), with K/IV scratch and the W+K pool above them.
func shaSched(m, w int) int { return m*7 + w }
func shaAbcd(m int) int     { return m*7 + 4 }
func shaEfgh(m int) int     { return m*7 + 5 }
func shaSaved(m int) int    { return m*7 + 6 }

var (
	shaRegK   = 7*lanes + 0                     // V28: current round group's K
	shaRegIV  = 7*lanes + 1                     // V29: IV scratch (setup/finalize only)
	shaWKPool = []int{7*lanes + 2, 7*lanes + 3} // V30, V31: per-lane W+K scratch
)

func shaWK(m int) int { return shaWKPool[m%len(shaWKPool)] }

// ---------------------------------------------------------------------------
// RIPEMD-160 constants and register plan (mirrors ripemd160-asm/internal/neongen).
// ---------------------------------------------------------------------------

var rl = [80]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var rr = [80]int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var sl = [80]int{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var sr = [80]int{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

var ripeIV = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
var leftK = [5]uint32{0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e}
var rightK = [5]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0}

const (
	regX8   = 8  // schedule word x8  = 0x80
	regLK   = 9  // current round's left additive constant
	regRK   = 10 // current round's right additive constant
	regX14  = 14 // schedule word x14 = 256
	regOnes = 31 // 0xffffffff, for the bitwise-NOT in f3/f5
)

func main() {
	root := repoRoot()
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	p("// Code generated by internal/fusedgen; DO NOT EDIT.")
	p("//go:build arm64")
	p("")
	p("#include \"textflag.h\"")
	p("")
	p("// func hash160From33SHA2(dst, src []byte, n, stride int)")
	p("//")
	p("// Computes RIPEMD160(SHA256(msg)) for n 33-byte messages, %d per loop", lanes)
	p("// iteration. The caller guarantees n is a positive multiple of %d; the", lanes)
	p("// short tail is handled in Go. Only bytes 0..32 of each message are read.")
	p("TEXT ·hash160From33SHA2(SB), NOSPLIT, $0-64")
	p("\tMOVD\tdst_base+0(FP), R0")
	p("\tMOVD\tsrc_base+24(FP), R1")
	p("\tMOVD\tn+48(FP), R2")
	p("\tMOVD\tstride+56(FP), R5")
	p("\tCBZ\tR2, done")
	p("")
	p("loop:")

	// --- SHA-256 of the four messages -------------------------------------
	p("\t// Per-lane message base pointers (lane m = R1 + m*stride).")
	for m := 1; m < lanes; m++ {
		p("\tADD\tR5, %s, %s", baseReg(m-1), baseReg(m))
	}
	p("")
	p("\t// SHA-256: load each message, build its schedule, seed state from IV.")
	p("\tMOVD\t$\u00b7fuseSHAIV(SB), R4")
	p("\tVLD1\t(R4), [V%d.S4]", shaRegIV)
	for m := 0; m < lanes; m++ {
		shaSetupLane(&b, m)
	}
	p("")
	p("\t// SHA-256: 16 round groups, K loaded once per group, applied to every lane.")
	p("\tMOVD\t$\u00b7fuseSHAK(SB), R4")
	for g := 0; g < 16; g++ {
		p("\t// --- SHA round group %d ---", g)
		p("\tVLD1.P\t16(R4), [V%d.S4]", shaRegK)
		for m := 0; m < lanes; m++ {
			shaGroupBody(&b, m, g)
		}
	}
	p("")
	p("\t// SHA-256 finalize (no store): digest[m] = REV32(state[m] + IV), held in")
	p("\t// (abcd[m], efgh[m]) as the little-endian words x0..x7 RIPEMD consumes.")
	p("\tMOVD\t$\u00b7fuseSHAIV(SB), R4")
	for m := 0; m < lanes; m++ {
		shaFinalizeLane(&b, m)
	}
	p("")

	// --- hand the digests to the RIPEMD input slots -----------------------
	gatherDigests(&b)
	p("")

	// --- RIPEMD-160 of the four digests ------------------------------------
	p("\t// RIPEMD-160 call-invariant constants (re-materialized: the SHA half")
	p("\t// clobbers V%d/V%d/V%d).", regX8, regX14, regOnes)
	bcast(&b, 0x80, regX8)
	bcast(&b, 0x100, regX14)
	bcast(&b, 0xffffffff, regOnes)
	p("")
	ripeTranspose(&b)

	leftState := [5]int{16, 17, 18, 19, 20}
	rightState := [5]int{21, 22, 23, 24, 25}
	p("\t// Broadcast the RIPEMD initial chaining value into both pipelines.")
	for i, r := range leftState {
		bcast(&b, ripeIV[i], r)
	}
	for i := range rightState {
		p("\tVMOV\tV%d.B16, V%d.B16", leftState[i], rightState[i])
	}

	for j := 0; j < 80; j++ {
		if j%16 == 0 {
			round := j / 16
			p("\t// RIPEMD round %d additive constants", round)
			if leftK[round] != 0 {
				bcast(&b, leftK[round], regLK)
			}
			if rightK[round] != 0 {
				bcast(&b, rightK[round], regRK)
			}
		}
		ripeStep(&b, true, j, &leftState, freeReg(leftState, rightState))
		ripeStep(&b, false, j, &rightState, freeReg(leftState, rightState))
	}

	ripeCombine(&b, leftState, rightState)
	ripeStore(&b)
	p("")

	p("\t// Advance src past this lane group; dst already advanced by the store.")
	p("\tADD\tR5, %s, R1", baseReg(lanes-1))
	p("\tSUBS\t$%d, R2, R2", lanes)
	p("\tBNE\tloop")
	p("done:")
	p("\tRET")
	p("")

	emitConstants(&b)

	write(filepath.Join(root, "hash160mb", "block_arm64.s"), []byte(b.String()))
}

// baseReg returns the general register holding lane m's message base pointer.
func baseReg(m int) string {
	if m == 0 {
		return "R1"
	}
	return fmt.Sprintf("R%d", 5+m) // R6, R7, R8 for lanes 1..3
}

// ---------------------------------------------------------------------------
// SHA-256 emit helpers (verbatim from shagen, minus the digest store).
// ---------------------------------------------------------------------------

func shaSetupLane(b *strings.Builder, m int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	base := baseReg(m)
	p("\t// SHA lane %d: load message, build schedule, seed state", m)
	p("\tVLD1\t(%s), [V%d.B16]", base, shaSched(m, 0))
	p("\tADD\t$16, %s, R3", base)
	p("\tVLD1\t(R3), [V%d.B16]", shaSched(m, 1))
	p("\tVREV32\tV%d.B16, V%d.B16", shaSched(m, 0), shaSched(m, 0))
	p("\tVREV32\tV%d.B16, V%d.B16", shaSched(m, 1), shaSched(m, 1))
	p("\tMOVBU\t32(%s), R3", base)
	p("\tLSL\t$24, R3, R3")
	p("\tMOVD\t$0x00800000, R10")
	p("\tORR\tR10, R3, R3")
	p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", shaSched(m, 2), shaSched(m, 2), shaSched(m, 2))
	p("\tVMOV\tR3, V%d.S[0]", shaSched(m, 2))
	p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", shaSched(m, 3), shaSched(m, 3), shaSched(m, 3))
	p("\tMOVD\t$0x108, R3")
	p("\tVMOV\tR3, V%d.S[3]", shaSched(m, 3))
	p("\tVMOV\tV%d.B16, V%d.B16", shaRegIV, shaAbcd(m))
	p("\tMOVD\t$\u00b7fuseSHAIV(SB), R3")
	p("\tADD\t$16, R3, R3")
	p("\tVLD1\t(R3), [V%d.S4]", shaEfgh(m))
	p("\tVMOV\tV%d.B16, V%d.B16", shaAbcd(m), shaSaved(m))
}

func shaGroupBody(b *strings.Builder, m, g int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	cur := shaSched(m, g%4)
	w := shaWK(m)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", shaRegK, cur, w)
	if g <= 11 {
		next := shaSched(m, (g+1)%4)
		p("\tSHA256SU0\tV%d.S4, V%d.S4", next, cur)
	}
	if g >= 1 && g <= 12 {
		u := (g - 1) % 4
		p("\tSHA256SU1\tV%d.S4, V%d.S4, V%d.S4", shaSched(m, (u+3)%4), shaSched(m, (u+2)%4), shaSched(m, u))
	}
	p("\tSHA256H\tV%d.S4, V%d, V%d", w, shaEfgh(m), shaAbcd(m))
	p("\tSHA256H2\tV%d.S4, V%d, V%d", w, shaSaved(m), shaEfgh(m))
	p("\tVMOV\tV%d.B16, V%d.B16", shaAbcd(m), shaSaved(m))
}

// shaFinalizeLane adds the IV back, byte-reverses each word to the big-endian
// digest (which, read as little-endian words, is exactly RIPEMD's x0..x7), and
// leaves the result in (abcd[m], efgh[m]). It does NOT store to memory.
func shaFinalizeLane(b *strings.Builder, m int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// SHA lane %d: state += IV, byte-swap; digest stays in V%d/V%d", m, shaAbcd(m), shaEfgh(m))
	p("\tVLD1\t(R4), [V%d.S4]", shaRegIV)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", shaRegIV, shaAbcd(m), shaAbcd(m))
	p("\tADD\t$16, R4, R3")
	p("\tVLD1\t(R3), [V%d.S4]", shaRegIV)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", shaRegIV, shaEfgh(m), shaEfgh(m))
	p("\tVREV32\tV%d.B16, V%d.B16", shaAbcd(m), shaAbcd(m))
	p("\tVREV32\tV%d.B16, V%d.B16", shaEfgh(m), shaEfgh(m))
}

// gatherDigests moves the four lanes' digests from their scattered SHA state
// registers into V0..V7 — the contiguous layout the RIPEMD transpose expects:
// V0=m0[x0..3], V1=m0[x4..7], V2=m1[x0..3], ... V7=m3[x4..7]. The move order is
// chosen so a destination is never written before its source has been read
// (only V4/V5 are both source and destination, copied out first).
func gatherDigests(b *strings.Builder) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// Gather the four digests into V0..V7 (RIPEMD input order).")
	type mov struct{ dst, src int }
	moves := []mov{
		{0, shaAbcd(0)}, {1, shaEfgh(0)}, // V0,V1 <- lane0 (frees V4,V5)
		{2, shaAbcd(1)}, {3, shaEfgh(1)}, // V2,V3 <- lane1
		{6, shaAbcd(3)}, {7, shaEfgh(3)}, // V6,V7 <- lane3
		{4, shaAbcd(2)}, {5, shaEfgh(2)}, // V4,V5 <- lane2 (after V4,V5 freed)
	}
	for _, mv := range moves {
		if mv.dst == mv.src {
			continue
		}
		p("\tVMOV\tV%d.B16, V%d.B16", mv.src, mv.dst)
	}
}

// ---------------------------------------------------------------------------
// RIPEMD-160 emit helpers (verbatim from neongen; the transpose drops the
// memory load because the digests are handed over in registers).
// ---------------------------------------------------------------------------

func bcast(b *strings.Builder, imm uint32, dst int) {
	fmt.Fprintf(b, "\tMOVD\t$%#x, R3\n", imm)
	fmt.Fprintf(b, "\tVMOV\tR3, V%d.S4\n", dst)
}

// ripeTranspose shuffles V0..V7 so lane k of Vw holds word w of message k. The
// digests are already in V0..V7 (see gatherDigests); unlike the standalone
// RIPEMD kernel there is no message load here.
func ripeTranspose(b *strings.Builder) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// Transpose the in-register digests to word-major (lane = message).")
	transpose4x4(b, 0, 2, 4, 6, 20, 21, 22, 23)
	transpose4x4(b, 1, 3, 5, 7, 24, 25, 26, 27)
	for i := 0; i <= 7; i++ {
		p("\tVMOV\tV%d.B16, V%d.B16", 20+i, i)
	}
}

func transpose4x4(b *strings.Builder, p0, p1, p2, p3, q0, q1, q2, q3 int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\tVZIP1\tV%d.S4, V%d.S4, V16.S4", p1, p0)
	p("\tVZIP2\tV%d.S4, V%d.S4, V17.S4", p1, p0)
	p("\tVZIP1\tV%d.S4, V%d.S4, V18.S4", p3, p2)
	p("\tVZIP2\tV%d.S4, V%d.S4, V19.S4", p3, p2)
	p("\tVZIP1\tV18.D2, V16.D2, V%d.D2", q0)
	p("\tVZIP2\tV18.D2, V16.D2, V%d.D2", q1)
	p("\tVZIP1\tV19.D2, V17.D2, V%d.D2", q2)
	p("\tVZIP2\tV19.D2, V17.D2, V%d.D2", q3)
}

func xreg(idx int) (reg int, skip bool) {
	switch {
	case idx <= 7:
		return idx, false
	case idx == 8:
		return regX8, false
	case idx == 14:
		return regX14, false
	default:
		return 0, true
	}
}

func ripeStep(b *strings.Builder, left bool, j int, st *[5]int, tmp int) {
	a, bb, c, d, e := st[0], st[1], st[2], st[3], st[4]
	var idx, rot, fn, kreg int
	var hasK bool
	if left {
		idx, rot, fn = rl[j], sl[j], j/16
		kreg, hasK = regLK, leftK[j/16] != 0
	} else {
		idx, rot, fn = rr[j], sr[j], 4-j/16
		kreg, hasK = regRK, rightK[j/16] != 0
	}

	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// RIPEMD %s step %d", side(left), j)
	emitF(b, fn, bb, c, d, tmp)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", a, tmp, tmp)
	if xr, skip := xreg(idx); !skip {
		p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", xr, tmp, tmp)
	}
	if hasK {
		p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", kreg, tmp, tmp)
	}
	rotl(b, tmp, a, rot)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", e, a, a)
	rotl(b, c, tmp, 10)
	*st = [5]int{e, a, bb, tmp, d}
}

func emitF(b *strings.Builder, fn, bb, c, d, out int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	switch fn {
	case 0: // f1 = B ^ C ^ D
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", c, bb, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", d, out, out)
	case 1: // f2 = D ^ (B & (C ^ D))
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", c, d, out)
		p("\tVAND\tV%d.B16, V%d.B16, V%d.B16", bb, out, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", d, out, out)
	case 2: // f3 = (B | ~C) ^ D
		p("\tVMOV\tV%d.B16, V%d.B16", c, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", regOnes, out, out)
		p("\tVORR\tV%d.B16, V%d.B16, V%d.B16", out, bb, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", d, out, out)
	case 3: // f4 = C ^ (D & (B ^ C))
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", bb, c, out)
		p("\tVAND\tV%d.B16, V%d.B16, V%d.B16", d, out, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", c, out, out)
	case 4: // f5 = B ^ (C | ~D)
		p("\tVMOV\tV%d.B16, V%d.B16", d, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", regOnes, out, out)
		p("\tVORR\tV%d.B16, V%d.B16, V%d.B16", out, c, out)
		p("\tVEOR\tV%d.B16, V%d.B16, V%d.B16", bb, out, out)
	default:
		panic(fn)
	}
}

func rotl(b *strings.Builder, src, dst, n int) {
	fmt.Fprintf(b, "\tVSHL\t$%d, V%d.S4, V%d.S4\n", n, src, dst)
	fmt.Fprintf(b, "\tVSRI\t$%d, V%d.S4, V%d.S4\n", 32-n, src, dst)
}

func ripeCombine(b *strings.Builder, l, r [5]int) {
	al, bl, cl, dl, el := l[0], l[1], l[2], l[3], l[4]
	ar, br, cr, dr, er := r[0], r[1], r[2], r[3], r[4]
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// RIPEMD finalize: digest word w -> V[w]; V5 holds the IV term.")
	emitCombineWord(b, 0, ripeIV[1], cl, dr)
	emitCombineWord(b, 1, ripeIV[2], dl, er)
	emitCombineWord(b, 2, ripeIV[3], el, ar)
	emitCombineWord(b, 3, ripeIV[4], al, br)
	emitCombineWord(b, 4, ripeIV[0], bl, cr)
}

func emitCombineWord(b *strings.Builder, out int, ivTerm uint32, left, right int) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	bcast(b, ivTerm, 5)
	p("\tVADD\tV%d.S4, V5.S4, V%d.S4", left, out)
	p("\tVADD\tV%d.S4, V%d.S4, V%d.S4", right, out, out)
}

func ripeStore(b *strings.Builder) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("\t// Transpose digests back to message-major order and store 4x20 bytes.")
	p("\tVZIP1\tV1.S4, V0.S4, V26.S4")
	p("\tVZIP2\tV1.S4, V0.S4, V27.S4")
	p("\tVZIP1\tV3.S4, V2.S4, V28.S4")
	p("\tVZIP2\tV3.S4, V2.S4, V29.S4")
	p("\tVZIP1\tV28.D2, V26.D2, V5.D2")
	p("\tVZIP2\tV28.D2, V26.D2, V6.D2")
	p("\tVZIP1\tV29.D2, V27.D2, V7.D2")
	p("\tVZIP2\tV29.D2, V27.D2, V15.D2")
	for lane, vreg := range []int{5, 6, 7, 15} {
		p("\tVST1.P\t[V%d.B16], 16(R0)", vreg)
		p("\tVMOV\tV4.S[%d], R3", lane)
		p("\tMOVWU.P\tR3, 4(R0)")
	}
}

func freeReg(left, right [5]int) int {
	used := map[int]bool{regOnes: true}
	for _, r := range left {
		used[r] = true
	}
	for _, r := range right {
		used[r] = true
	}
	for r := 26; r <= 30; r++ {
		if !used[r] {
			return r
		}
	}
	for r := 16; r <= 30; r++ {
		if !used[r] {
			return r
		}
	}
	panic("fusedgen: no free vector register")
}

func side(left bool) string {
	if left {
		return "left"
	}
	return "right"
}

func emitConstants(b *strings.Builder) {
	p := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	p("// SHA-256 round constants K[0..63].")
	for i, v := range shaK {
		p("DATA\t\u00b7fuseSHAK+%#04x(SB)/4, $%#08x", i*4, v)
	}
	p("GLOBL\t\u00b7fuseSHAK(SB), RODATA|NOPTR, $256")
	p("")
	p("// SHA-256 initial hash value H0..H7.")
	for i, v := range shaIV {
		p("DATA\t\u00b7fuseSHAIV+%#04x(SB)/4, $%#08x", i*4, v)
	}
	p("GLOBL\t\u00b7fuseSHAIV(SB), RODATA|NOPTR, $32")
}

func repoRoot() string {
	// go:generate runs this as "cd hash160mb/internal/fusedgen && go run .", so
	// the working directory is <root>/hash160mb/internal/fusedgen.
	root := filepath.Dir(filepath.Dir(filepath.Dir(must(os.Getwd()))))
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		panic(fmt.Errorf("fusedgen: cannot read go.mod at resolved root %q: %w", root, err))
	}
	if !bytes.Contains(data, []byte("module "+modulePath)) {
		panic(fmt.Errorf("fusedgen: resolved root %q is not module %q", root, modulePath))
	}
	return root
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func write(path string, b []byte) {
	old, _ := os.ReadFile(path)
	if bytes.Equal(old, b) {
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(fmt.Errorf("write %s: %w", path, err))
	}
}
