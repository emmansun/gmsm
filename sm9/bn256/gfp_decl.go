//go:build (amd64 || arm64) && !purego

package bn256

// This file contains forward declarations for the architecture-specific
// assembly implementations of these functions, provided that they exist.

import (
	"golang.org/x/sys/cpu"
)

// amd64 assembly uses ADCX/ADOX/MULX if ADX is available to run two carry
// chains in the flags in parallel across the whole operation, and aggressively
// unrolls loops. arm64 processes four words at a time.
var supportADX = cpu.X86.HasADX && cpu.X86.HasBMI2

// Set c = p - a, if c == p, then c = 0
// It seems this function's performance is worse than gfpSub with zero.
//
//go:noescape
func gfpNeg(c, a *gfP)

// Set c = a + b, if c >= p, then c = c - p
//
//go:noescape
func gfpAdd(c, a, b *gfP)

// Set c = a + a
//
//go:noescape
func gfpDouble(c, a *gfP)

// Set c = a + a + a
//
//go:noescape
func gfpTriple(c, a *gfP)

// Set c = a - b, if c is negative, then c = c + p
//
//go:noescape
func gfpSub(c, a, b *gfP)

// Montgomery multiplication. Sets res = in1 * in2 * R⁻¹ mod p.
//
//go:noescape
func gfpMul(c, a, b *gfP)

// Montgomery square, repeated n times (n >= 1).
//
//go:noescape
func gfpSqr(res, in *gfP, n int)

// Montgomery multiplication by R⁻¹, or 1 outside the domain.
// Sets res = in * R⁻¹, bringing res out of the Montgomery domain.
//
//go:noescape
func gfpFromMont(res, in *gfP)

// Marshal gfP into big endian form
//
//go:noescape
func gfpMarshal(out *[32]byte, in *gfP)

// Unmarshal the bytes into little endian form
//
//go:noescape
func gfpUnmarshal(out *gfP, in *[32]byte)
