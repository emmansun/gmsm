//go:build !purego

package sm2ec


// p256Element is a P-256 base field element in [0, P-1] in the Montgomery
// domain (with R 2²⁵⁶) as four limbs in little-endian order value.
type p256Element [4]uint64

// p256OrdElement is a P-256 scalar field element in [0, ord(G)-1] in the
// Montgomery domain (with R 2²⁵⁶) as four uint64 limbs in little-endian order.
type p256OrdElement [4]uint64

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

// If cond is not 0, sets val = -val mod p.
//
//go:noescape
func p256NegCond(val *p256Element, cond int)

// If cond is 0, sets res = b, otherwise sets res = a.
//
//go:noescape
func p256MovCond(res, a, b *SM2P256Point, cond int)

//go:noescape
func p256BigToLittle(res *p256Element, in *[32]byte)

//go:noescape
func p256LittleToBig(res *[32]byte, in *p256Element)

//go:noescape
func p256OrdBigToLittle(res *p256OrdElement, in *[32]byte)

//go:noescape
func p256OrdLittleToBig(res *[32]byte, in *p256OrdElement)

// p256OrdReduce ensures s is in the range [0, ord(G)-1].
//
//go:noescape
func p256OrdReduce(s *p256OrdElement)
