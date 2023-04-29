package bn256

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

type gfP [4]uint64

var zero = newGFp(0)
var one = newGFp(1)
var two = newGFp(2)

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

func fromBigInt(x *big.Int) (out *gfP) {
	out = &gfP{}
	var a *big.Int
	if x.Sign() >= 0 {
		a = x
	} else {
		a = new(big.Int).Neg(x)
	}
	bytes := a.Bytes()
	if len(bytes) > 32 {
		panic("sm9: invalid byte length")
	} else if len(bytes) < 32 {
		fixedBytes := make([]byte, 32)
		copy(fixedBytes[32-len(bytes):], bytes)
		bytes = fixedBytes
	}
	for i := 0; i < 4; i++ {
		start := len(bytes) - 8
		out[i] = binary.BigEndian.Uint64(bytes[start:])
		bytes = bytes[:start]
	}
	if x.Sign() < 0 {
		gfpNeg(out, out)
	}
	if x.Sign() != 0 {
		montEncode(out, out)
	}
	return out
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) *gfP {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]

	return e
}

func (e *gfP) exp(f *gfP, bits [4]uint64) {
	sum, power := &gfP{}, &gfP{}
	sum.Set(rN1)
	power.Set(f)

	for word := 0; word < 4; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				gfpMul(sum, sum, power)
			}
			gfpMul(power, power, power)
		}
	}

	gfpMul(sum, sum, r3)
	e.Set(sum)
}

func (e *gfP) Mul(a, b *gfP) *gfP {
	gfpMul(e, a, b)
	return e
}

func (e *gfP) Square(a *gfP) *gfP {
	gfpMul(e, a, a)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *gfP) Equal(t *gfP) int {
	if *e == *t {
		return 1
	}
	return 0
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

func (e *gfP) Marshal(out []byte) {
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			out[8*w+b] = byte(e[3-w] >> (56 - 8*b))
		}
	}
}

func (e *gfP) Unmarshal(in []byte) error {
	// Unmarshal the bytes into little endian form
	for w := uint(0); w < 4; w++ {
		e[3-w] = 0
		for b := uint(0); b < 8; b++ {
			e[3-w] += uint64(in[8*w+b]) << (56 - 8*b)
		}
	}
	// Ensure the point respects the curve modulus
	for i := 3; i >= 0; i-- {
		if e[i] < p2[i] {
			return nil
		}
		if e[i] > p2[i] {
			return errors.New("sm9: coordinate exceeds modulus")
		}
	}
	return errors.New("sm9: coordinate equals modulus")
}

func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpMul(c, a, &gfP{1}) }

// cmovznzU64 is a single-word conditional move.
//
// Postconditions:
//   out1 = (if arg1 = 0 then arg2 else arg3)
//
// Input Bounds:
//   arg1: [0x0 ~> 0x1]
//   arg2: [0x0 ~> 0xffffffffffffffff]
//   arg3: [0x0 ~> 0xffffffffffffffff]
// Output Bounds:
//   out1: [0x0 ~> 0xffffffffffffffff]
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
