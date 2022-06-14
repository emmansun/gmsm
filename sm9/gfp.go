package sm9

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/hkdf"
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
	for i, v := range a.Bits() {
		out[i] = uint64(v)
	}
	if x.Sign() < 0 {
		gfpNeg(out, out)
	}
	if x.Sign() != 0 {
		montEncode(out, out)
	}
	return out
}

// hashToBase implements hashing a message to an element of the field.
//
// L = ceil((256+128)/8)=48, ctr = 0, i = 1
func hashToBase(msg, dst []byte) *gfP {
	var t [48]byte
	info := []byte{'H', '2', 'C', byte(0), byte(1)}
	r := hkdf.New(sha256.New, msg, dst, info)
	if _, err := r.Read(t[:]); err != nil {
		panic(err)
	}
	var x big.Int
	v := x.SetBytes(t[:]).Mod(&x, p).Bytes()
	v32 := [32]byte{}
	for i := len(v) - 1; i >= 0; i-- {
		v32[len(v)-1-i] = v[i]
	}
	u := &gfP{
		binary.LittleEndian.Uint64(v32[0*8 : 1*8]),
		binary.LittleEndian.Uint64(v32[1*8 : 2*8]),
		binary.LittleEndian.Uint64(v32[2*8 : 3*8]),
		binary.LittleEndian.Uint64(v32[3*8 : 4*8]),
	}
	montEncode(u, u)
	return u
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]
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

func (e *gfP) exp2(f *gfP, power *big.Int) *gfP {
	sum := &gfP{}
	sum.Set(one)
	t := &gfP{}

	for i := power.BitLen() - 1; i >= 0; i-- {
		gfpMul(t, sum, sum)
		if power.Bit(i) != 0 {
			gfpMul(sum, t, f)
		} else {
			sum.Set(t)
		}
	}

	e.Set(sum)
	return e
}

func (e *gfP) Invert(f *gfP) {
	e.exp(f, pMinus2)
}

func (e *gfP) Sqrt(f *gfP) {
	// Since p = 8k+5,
	// Atkin algorithm
	// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.896.6057&rep=rep1&type=pdf
	// https://eprint.iacr.org/2012/685.pdf
	//
	a1, b, i := &gfP{}, &gfP{}, &gfP{}
	a1.exp(f, pMinus5Over8)
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

func sign0(e *gfP) int {
	x := &gfP{}
	montDecode(x, e)
	for w := 3; w >= 0; w-- {
		if x[w] > pMinus1Over2[w] {
			return 1
		} else if x[w] < pMinus1Over2[w] {
			return -1
		}
	}
	return 1
}

func legendre(e *gfP) int {
	f := &gfP{}
	// Since p = 8k+5, then e^(4k+2) is the Legendre symbol of e.
	f.exp(e, pMinus1Over2)

	montDecode(f, f)

	if *f != [4]uint64{} {
		return 2*int(f[0]&1) - 1
	}

	return 0
}

func (e *gfP) Div2(f *gfP) *gfP {
	ret := &gfP{}
	gfpMul(ret, f, twoInvert)
	e.Set(ret)
	return e
}

var twoInvert = &gfP{}

func init() {
	t1 := newGFp(2)
	twoInvert.Invert(t1)
}

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
