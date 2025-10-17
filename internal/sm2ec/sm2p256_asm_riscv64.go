//go:build riscv64 && !purego

package sm2ec

// SM2P256Point1 is a SM2 P-256 point. The zero value should not be assumed to be valid
// (although it is in this implementation).
type SM2P256Point1 struct {
	// (X:Y:Z) are Jacobian coordinates where x = X/Z² and y = Y/Z³. The point
	// at infinity can be represented by any set of coordinates with Z = 0.
	x, y, z p256Element
}

// p256Element is a P-256 base field element in [0, P-1] in the Montgomery
// domain (with R 2²⁵⁶) as four limbs in little-endian order value.
type p256Element [4]uint64

//go:noescape
func p256BigToLittle(res *p256Element, in *[32]byte)

//go:noescape
func p256LittleToBig(res *[32]byte, in *p256Element)

// If cond is not 0, sets val = -val mod p.
//
//go:noescape
func p256NegCond(val *p256Element, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func p256MovCond(res, a, b *SM2P256Point1, cond int)

// Montgomery multiplication. Sets res = in1 * in2 * R⁻¹ mod p.
//
//go:noescape
func p256Mul(res, in1, in2 *p256Element)
