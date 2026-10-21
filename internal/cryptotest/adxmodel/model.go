// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package adxmodel contains a flag-accurate model of the AMD64 BMI2/ADX
// field-multiplication kernels and the tooling that generates boundary test
// vectors from it.
//
// The model exists because random differential testing cannot reach the
// failure modes of these kernels: the ADOX chain bug fixed in issue #560
// needed a reduction intermediate to land in a 2^31-wide window around the
// sign boundary, roughly a 2^-33 event per multiplication. Constructed
// inputs are the only practical way to pin the behaviour, and a simulator
// that tracks CF/OF exactly is the only way to construct them.
//
// The instruction semantics modelled here were validated bit-for-bit against
// hardware RFLAGS captures in the issue #560 analysis: ADCX/ADOX are unsigned
// additions that write only their own flag, while SUB/SBB/SHL write the
// signed-overflow OF, which is why an ADOX placed after a subtraction chain
// consumes a flag it never produced.
package adxmodel

import "math/bits"

// Channel selects which flag channel the reduction add-back chain uses.
type Channel int

const (
	// ADOX models the pre-fix code: the reduction chain reads OF, which the
	// preceding SUB/SBB block overwrote with signed-overflow semantics.
	ADOX Channel = iota
	// ADCX models the fixed code: the reduction chain reads CF, which the
	// SBB borrow chain produces with the semantics the reduction needs.
	ADCX
)

// Step records the state of one reduction step of the model.
type Step struct {
	// Index is the reduction step k (0..3).
	Index int
	// Acc is the low accumulator limb r[k] at entry to the step.
	Acc uint64
	// InOF is the OF value consumed by the first add-back instruction of
	// the step: for ADOX this is the stale SBB overflow, for ADCX the
	// channel is CF and InOF is not consumed.
	InOF uint64
	// HeadOF is the OF produced by the first add-back instruction (ADOX
	// only), which shows whether the corrupting carry was propagated.
	HeadOF uint64
}

// Mul is the result of one modelled multiplication.
type Mul struct {
	// R is the 256-bit result in Montgomery form (a*b*2^-256 mod q), limbs
	// least significant first.
	R [4]uint64
	// Steps traces every reduction step.
	Steps []Step
}

// p256P is the SM2 field prime q = 2^256 - 2^224 - 2^96 + 2^64 - 1 in limb
// order, matching p256P in internal/sm2ec. It is not the SM2 group order
// n = 0xfffffffe...7203df6b21c6052b53bbf40939d54123; only the field prime has
// the shape the shift-and-subtract reduction relies on (low limb -1).
var p256P = [4]uint64{
	0xffffffffffffffff, 0xffffffff00000000,
	0xffffffffffffffff, 0xfffffffeffffffff,
}

// MontgomeryMul models p256Mul (mulBMI2 in p256_common_amd64.s) on the given
// reduction channel. Inputs and outputs are four little-endian limbs.
func MontgomeryMul(a, b [4]uint64, ch Channel) Mul {
	var r [6]uint64
	var cf, of uint64
	steps := make([]Step, 0, 4)

	mulxStep := func(x, y uint64) (lo, hi uint64) { return mulx(x, y) }

	// x * y[0]: pure ADCX chain, OF untouched (zeroed by XORQ at entry).
	dx := b[0]
	var ax, hi, bx, t0 uint64
	r[0], r[1] = mulxStep(a[0], dx)
	ax, hi = mulxStep(a[1], dx)
	r[2] = hi
	r[1], cf = adc(r[1], ax, cf)
	ax, hi = mulxStep(a[2], dx)
	r[3] = hi
	r[2], cf = adc(r[2], ax, cf)
	ax, hi = mulxStep(a[3], dx)
	r[4] = hi
	r[3], cf = adc(r[3], ax, cf)
	r[4], cf = adc(r[4], r[5], cf)

	redStep := func(k int) {
		l := r[k]
		ax := l << 32
		dx := l >> 32

		// SUBQ/SBBQ write CF (borrow) and OF (signed overflow).
		r[(k+1)%6], cf, of = sub(r[(k+1)%6], ax)
		r[(k+2)%6], cf, of = sbb(r[(k+2)%6], dx, cf)
		r[(k+3)%6], cf, of = sbb(r[(k+3)%6], ax, cf)
		ax = r[k] // MOVQ acc[k], AX does not write flags
		r[k], cf, of = sbb(r[k], dx, cf)

		step := Step{Index: k, Acc: l, InOF: of}
		if ch == ADOX {
			r[(k+1)%6], of = adox(r[(k+1)%6], ax, of)
			step.HeadOF = of
			r[(k+2)%6], of = adox(r[(k+2)%6], 0, of)
			r[(k+3)%6], of = adox(r[(k+3)%6], 0, of)
			r[(k+4)%6], of = adox(r[(k+4)%6], r[k], of)
			r[(k+5)%6], of = adox(r[(k+5)%6], 0, of)
		} else {
			r[(k+1)%6], cf = adc(r[(k+1)%6], ax, cf)
			r[(k+2)%6], cf = adc(r[(k+2)%6], 0, cf)
			r[(k+3)%6], cf = adc(r[(k+3)%6], 0, cf)
			r[(k+4)%6], cf = adc(r[(k+4)%6], r[k], cf)
			r[(k+5)%6], cf = adc(r[(k+5)%6], 0, cf)
		}
		steps = append(steps, step)
	}

	redStep(0)
	r[0], cf, of = 0, 0, 0 // XORQ acc0, acc0

	// x * y[1] .. y[3]: ADCX for the high-word chain, ADOX for the
	// accumulator; the fix consumed the pending ADCX carry at each tail.
	// The six accumulator limbs form a sliding window, so every index is
	// taken modulo 6 exactly as the register names in the kernel do.
	for k := 1; k <= 3; k++ {
		dx = b[k]
		ax, t0 = mulxStep(a[0], dx)
		r[k], of = adox(r[k], ax, of)
		ax, bx = mulxStep(a[1], dx)
		ax, cf = adc(ax, t0, cf)
		r[(k+1)%6], of = adox(r[(k+1)%6], ax, of)
		ax, t0 = mulxStep(a[2], dx)
		ax, cf = adc(ax, bx, cf)
		r[(k+2)%6], of = adox(r[(k+2)%6], ax, of)
		ax, bx = mulxStep(a[3], dx)
		ax, cf = adc(ax, t0, cf)
		r[(k+3)%6], of = adox(r[(k+3)%6], ax, of)

		bx, cf = adc(bx, 0, cf) // ADCXQ res_ptr, BX
		r[(k+4)%6], of = adox(r[(k+4)%6], bx, of)
		if ch == ADCX {
			r[k-1], cf = adc(r[k-1], 0, cf) // fix: ADCXQ res_ptr, acc(k-1)
		}
		r[k-1], of = adox(r[k-1], 0, of)

		if k < 3 {
			redStep(k)
			r[k], cf, of = 0, 0, 0
		}
	}

	redStep(3)

	return Mul{R: primReduce(r[4], r[5], r[0], r[1], r[2]), Steps: steps}
}

// primReduce models p256PrimReduce: a single conditional subtraction of the
// field prime q over the five-limb intermediate (a0..a4).
func primReduce(a0, a1, a2, a3, a4 uint64) [4]uint64 {
	b0, b1, b2, b3 := a0, a1, a2, a3
	var cf uint64
	a0, cf = bits.Sub64(a0, ^uint64(0), cf)
	a1, cf = bits.Sub64(a1, p256P[1], cf)
	a2, cf = bits.Sub64(a2, ^uint64(0), cf)
	a3, cf = bits.Sub64(a3, p256P[3], cf)
	a4, cf = bits.Sub64(a4, 0, cf)
	if cf != 0 {
		return [4]uint64{b0, b1, b2, b3}
	}
	return [4]uint64{a0, a1, a2, a3}
}

func mulx(a, b uint64) (lo, hi uint64) {
	hi, lo = bits.Mul64(a, b)
	return lo, hi
}

// adc models ADCXQ and ADDQ/ADCQ: unsigned addition with carry out.
func adc(a, b, carry uint64) (uint64, uint64) {
	s, c := bits.Add64(a, b, carry)
	return s, c
}

// adox models ADOXQ: unsigned addition on the OF channel. The carry out is
// the same as ADCX; only the destination flag differs.
func adox(a, b, of uint64) (uint64, uint64) {
	return bits.Add64(a, b, of)
}

// sub models SUBQ: CF is the borrow, OF is the signed-subtract overflow.
func sub(a, b uint64) (r, cf, of uint64) {
	r, borrow := bits.Sub64(a, b, 0)
	return r, borrow, ofSub(a, b, 0)
}

// sbb models SBBQ.
func sbb(a, b, cf uint64) (r, outCF, of uint64) {
	r, borrow := bits.Sub64(a, b, cf)
	return r, borrow, ofSub(a, b, cf)
}

// ofSub returns the OF written by SUBQ/SBBQ: the signed overflow of
// a - b - cf, computed as c64 XOR c63 where c64 is the unsigned carry out of
// a + ^b + (1-cf) and c63 is the carry into bit 63 of the same addition.
func ofSub(a, b, cf uint64) uint64 {
	inv := 1 - cf
	_, c64 := bits.Add64(a, ^b, inv)
	low, _ := bits.Add64(a&(1<<63-1), (^b)&(1<<63-1), inv)
	return c64 ^ (low >> 63)
}

// LimbsFromBigEndian converts a 32-byte big-endian value to little-endian
// limbs, the representation used by every 256-bit kernel in this repository.
func LimbsFromBigEndian(in *[32]byte) [4]uint64 {
	var out [4]uint64
	for i := 0; i < 4; i++ {
		base := 24 - 8*i
		out[i] = uint64(in[base])<<56 | uint64(in[base+1])<<48 |
			uint64(in[base+2])<<40 | uint64(in[base+3])<<32 |
			uint64(in[base+4])<<24 | uint64(in[base+5])<<16 |
			uint64(in[base+6])<<8 | uint64(in[base+7])
	}
	return out
}

// BigEndianFromLimbs is the inverse of LimbsFromBigEndian.
func BigEndianFromLimbs(in [4]uint64) [32]byte {
	var out [32]byte
	for i := 0; i < 4; i++ {
		v := in[i]
		base := 24 - 8*i
		out[base] = byte(v >> 56)
		out[base+1] = byte(v >> 48)
		out[base+2] = byte(v >> 40)
		out[base+3] = byte(v >> 32)
		out[base+4] = byte(v >> 24)
		out[base+5] = byte(v >> 16)
		out[base+6] = byte(v >> 8)
		out[base+7] = byte(v)
	}
	return out
}
