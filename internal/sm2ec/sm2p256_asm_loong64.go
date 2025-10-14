package sm2ec

import (
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// p256Element is a P-256 base field element in [0, P-1] in the Montgomery
// domain (with R 2²⁵⁶) as four limbs in little-endian order value.
type p256Element [4]uint64

type SM2P256Point1 struct {
	// (X:Y:Z) are Jacobian coordinates where x = X/Z² and y = Y/Z³. The point
	// at infinity can be represented by any set of coordinates with Z = 0.
	x, y, z p256Element
}

var supportLSX = cpu.Loong64.HasLSX
var supportLASX = cpu.Loong64.HasLASX

//go:noescape
func p256BigToLittle(res *p256Element, in *[32]byte)

//go:noescape
func p256LittleToBig(res *[32]byte, in *p256Element)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func p256MovCond(res, a, b *SM2P256Point1, cond int)

// If cond is not 0, sets val = -val mod p.
//
//go:noescape
func p256NegCond(val *p256Element, cond int)

// Montgomery multiplication. Sets res = in1 * in2 * R⁻¹ mod p.
//
//go:noescape
func p256Mul(res, in1, in2 *p256Element)

// Montgomery square, repeated n times (n >= 1).
//
//go:noescape
func p256Sqr(res, in *p256Element, n int)

// Montgomery multiplication by R⁻¹, or 1 outside the domain.
// Sets res = in * R⁻¹, bringing res out of the Montgomery domain.
//
//go:noescape
func p256FromMont(res, in *p256Element)

// p256OrdReduce ensures s is in the range [0, ord(G)-1].
//
//go:noescape
func p256OrdReduce(s *p256OrdElement)

//go:noescape
func p256Sub(res, in1, in2 *p256Element)

//go:noescape
func p256MulBy2(res, in *p256Element)
