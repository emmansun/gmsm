//go:build (amd64 && !purego) || (arm64 && !purego)
// +build amd64,!purego arm64,!purego

package bn256

// This file contains forward declarations for the architecture-specific
// assembly implementations of these functions, provided that they exist.

import (
	"golang.org/x/sys/cpu"
)

var hasBMI2 = cpu.X86.HasBMI2

// Set c = p - a, if c == p, then c = 0
//
// go:noescape
func gfpNeg(c, a *gfP)

// Set c = a + b, if c >= p, then c = c - p
//
//go:noescape
func gfpAdd(c, a, b *gfP)

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
