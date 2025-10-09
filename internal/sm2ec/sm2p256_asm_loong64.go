package sm2ec

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
