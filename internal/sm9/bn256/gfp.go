package bn256

import (
	"errors"
	"fmt"
	"math/bits"
)

type gfP [4]uint64

var zero = newGFp(0)
var one = newGFp(1)
var two = newGFp(2)

// newGFp creates a new gfP element from the given int64 value.
// If the input value is non-negative, it directly converts it to uint64.
// If the input value is negative, it converts the absolute value to uint64
// and then negates the resulting gfP element.
// The resulting gfP element is then encoded in Montgomery form.
func newGFp(x int64) (out *gfP) {
	if x >= 0 {
		out = &gfP{uint64(x)}
	} else {
		out = &gfP{uint64(-x)}
		gfpNeg(out, out)
	}

	montEncode(out, out)
	return out
}

// newGFpFromBytes creates a new gfP element from a byte slice.
// It unmarshals the byte slice into a gfP element, then encodes it in Montgomery form.
func newGFpFromBytes(in []byte) (out *gfP) {
	out = &gfP{}
	gfpUnmarshal(out, (*[32]byte)(in))
	montEncode(out, out)
	return out
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) *gfP {
	gfpCopy(e, f)
	return e
}

// exp calculates the exponentiation of a given gfP element `f` raised to the power
// represented by the 256-bit integer `bits`. The result is stored in the gfP element `e`.
//
// The function uses a square-and-multiply algorithm to perform the exponentiation.
// It iterates over each bit of the 256-bit integer `bits`, and for each bit, it squares
// the current power and multiplies it to the result if the bit is set.
//
// Parameters:
// - f: The base gfP element to be exponentiated.
// - bits: A 256-bit integer represented as an array of 4 uint64 values, where bits[0]
//         contains the least significant 64 bits and bits[3] contains the most significant 64 bits.
func (e *gfP) exp(f *gfP, bits [4]uint64) {
	sum, power := &gfP{}, &gfP{}
	sum.Set(rN1)
	power.Set(f)

	for word := range 4 {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				gfpMul(sum, sum, power)
			}
			gfpSqr(power, power, 1)
		}
	}

	gfpMul(sum, sum, r3)
	e.Set(sum)
}

func (e *gfP) Mul(a, b *gfP) *gfP {
	gfpMul(e, a, b)
	return e
}

func (e *gfP) Square(a *gfP, n int) *gfP {
	gfpSqr(e, a, n)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *gfP) Equal(t *gfP) int {
	var acc uint64
	for i := range e {
		acc |= e[i] ^ t[i]
	}
	return uint64IsZero(acc)
}

func (e *gfP) Sqrt(f *gfP) {
	// Since p = 8k+5,
	// Atkin algorithm
	// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.896.6057&rep=rep1&type=pdf
	// https://eprint.iacr.org/2012/685.pdf
	//
	a1, b, i := &gfP{}, &gfP{}, &gfP{}
	sqrtCandidate(a1, f)
	gfpMul(b, twoExpPMinus5Over8, a1) // b=ta1
	gfpMul(a1, f, b)                  // a1=fb
	gfpMul(i, two, a1)                // i=2(fb)
	gfpMul(i, i, b)                   // i=2(fb)b
	gfpSub(i, i, one)                 // i=2(fb)b-1
	gfpMul(i, a1, i)                  // i=(fb)(2(fb)b-1)
	e.Set(i)
}

// Marshal serializes the gfP element into the provided byte slice.
// The output byte slice must be at least 32 bytes long.
func (e *gfP) Marshal(out []byte) {
	if len(out) < 32 {
		panic("sm9: invalid out length")
	}
	gfpMarshal((*[32]byte)(out), e)
}

// uint64IsZero returns 1 if x is zero and zero otherwise.
func uint64IsZero(x uint64) int {
	x = ^x
	x &= x >> 32
	x &= x >> 16
	x &= x >> 8
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}

// lessThanP returns 1 if the given gfP element x is less than the prime modulus p2,
// and 0 otherwise. It performs a subtraction of x from p2 and checks the borrow bit
// to determine if x is less than p2.
func lessThanP(x *gfP) int {
	var b uint64
	_, b = bits.Sub64(x[0], p2[0], b)
	_, b = bits.Sub64(x[1], p2[1], b)
	_, b = bits.Sub64(x[2], p2[2], b)
	_, b = bits.Sub64(x[3], p2[3], b)
	return int(b)
}

// Unmarshal decodes a 32-byte big-endian representation of a gfP element.
// It returns an error if the input length is not 32 bytes or if the decoded
// value is not a valid gfP element (i.e., greater than or equal to the field prime).
func (e *gfP) Unmarshal(in []byte) error {
	if len(in) < 32 {
		return errors.New("sm9: invalid input length")
	}
	gfpUnmarshal(e, (*[32]byte)(in))
	if lessThanP(e) == 0 {
		return errors.New("sm9: invalid gfP encoding")
	}
	return nil
}

func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpFromMont(c, a) }

// cmovznzU64 is a single-word conditional move.
//
// Postconditions:
//
//	out1 = (if arg1 = 0 then arg2 else arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [0x0 ~> 0xffffffffffffffff]
//	arg3: [0x0 ~> 0xffffffffffffffff]
//
// Output Bounds:
//
//	out1: [0x0 ~> 0xffffffffffffffff]
func cmovznzU64(out1 *uint64, arg1 uint64, arg2 uint64, arg3 uint64) {
	x1 := (uint64(arg1) * 0xffffffffffffffff)
	x2 := ((x1 & arg3) | ((^x1) & arg2))
	*out1 = x2
}

// Select sets e to p1 if cond == 1, and to p2 if cond == 0.
func (e *gfP) Select(p1, p2 *gfP, cond int) *gfP {
	var x1 uint64
	cmovznzU64(&x1, uint64(cond), p2[0], p1[0])
	var x2 uint64
	cmovznzU64(&x2, uint64(cond), p2[1], p1[1])
	var x3 uint64
	cmovznzU64(&x3, uint64(cond), p2[2], p1[2])
	var x4 uint64
	cmovznzU64(&x4, uint64(cond), p2[3], p1[3])
	e[0] = x1
	e[1] = x2
	e[2] = x3
	e[3] = x4
	return e
}
