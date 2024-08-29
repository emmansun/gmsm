//go:build (amd64 || arm64 || s390x || ppc64le) && !purego

package sm2ec

import "errors"

// Montgomery multiplication modulo org(G). Sets res = in1 * in2 * R⁻¹.
//
//go:noescape
func p256OrdMul(res, in1, in2 *p256OrdElement)

// Montgomery square modulo org(G), repeated n times (n >= 1).
//
//go:noescape
func p256OrdSqr(res, in *p256OrdElement, n int)

// This code operates in the Montgomery domain where R = 2²⁵⁶ mod n and n is
// the order of the scalar field. Elements in the Montgomery domain take the
// form a×R and p256OrdMul calculates (a × b × R⁻¹) mod n. RR is R in the
// domain, or R×R mod n, thus p256OrdMul(x, RR) gives x×R, i.e. converts x
// into the Montgomery domain.
var RR = &p256OrdElement{0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b}

// P256OrdInverse, sets out to in⁻¹ mod org(G). If in is zero, out will be zero.
// n-2 =
// 1111111111111111111111111111111011111111111111111111111111111111
// 1111111111111111111111111111111111111111111111111111111111111111
// 0111001000000011110111110110101100100001110001100000010100101011
// 0101001110111011111101000000100100111001110101010100000100100001
func P256OrdInverse(k []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	x := new(p256OrdElement)
	p256OrdBigToLittle(x, (*[32]byte)(k))
	p256OrdMul(x, x, RR)
	// Inversion is implemented as exponentiation with exponent p − 2.
	// The sequence of 41 multiplications and 253 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_100     = 1 + _11
	//	_101     = 1 + _100
	//	_111     = _10 + _101
	//	_1001    = _10 + _111
	//	_1101    = _100 + _1001
	//	_1111    = _10 + _1101
	//	_11110   = 2*_1111
	//	_11111   = 1 + _11110
	//	_111110  = 2*_11111
	//	_111111  = 1 + _111110
	//	_1111110 = 2*_111111
	//	i20      = _1111110 << 6 + _1111110
	//	x18      = i20 << 5 + _111111
	//	x31      = x18 << 13 + i20 + 1
	//	i42      = 2*x31
	//	i44      = i42 << 2
	//	i140     = ((i44 << 32 + i44) << 29 + i42) << 33
	//	i150     = ((i44 + i140 + _111) << 4 + _111) << 3
	//	i170     = ((1 + i150) << 11 + _1111) << 6 + _11111
	//	i183     = ((i170 << 5 + _1101) << 3 + _11) << 3
	//	i198     = ((1 + i183) << 7 + _111) << 5 + _11
	//	i219     = ((i198 << 9 + _101) << 5 + _101) << 5
	//	i231     = ((_1101 + i219) << 5 + _1001) << 4 + _1101
	//	i244     = ((i231 << 2 + _11) << 7 + _111111) << 2
	//	i262     = ((1 + i244) << 10 + _1001) << 5 + _111
	//	i277     = ((i262 << 5 + _111) << 4 + _101) << 4
	//	return     ((_101 + i277) << 9 + _1001) << 5 + 1
	//
	var z = new(p256OrdElement)
	var t0 = new(p256OrdElement)
	var t1 = new(p256OrdElement)
	var t2 = new(p256OrdElement)
	var t3 = new(p256OrdElement)
	var t4 = new(p256OrdElement)
	var t5 = new(p256OrdElement)
	var t6 = new(p256OrdElement)
	var t7 = new(p256OrdElement)
	var t8 = new(p256OrdElement)
	var t9 = new(p256OrdElement)

	p256OrdSqr(t3, x, 1)
	p256OrdMul(z, x, t3)
	p256OrdMul(t4, x, z)
	p256OrdMul(t1, x, t4)
	p256OrdMul(t2, t3, t1)
	p256OrdMul(t0, t3, t2)
	p256OrdMul(t4, t4, t0)
	p256OrdMul(t6, t3, t4)
	p256OrdSqr(t3, t6, 1)
	p256OrdMul(t5, x, t3)
	p256OrdSqr(t3, t5, 1)
	p256OrdMul(t3, x, t3)
	p256OrdSqr(t7, t3, 1)
	p256OrdSqr(t8, t7, 6)
	p256OrdMul(t7, t7, t8)
	p256OrdSqr(t8, t7, 5)
	p256OrdMul(t8, t3, t8)
	p256OrdSqr(t8, t8, 13)
	p256OrdMul(t7, t7, t8)
	p256OrdMul(t7, x, t7)
	p256OrdSqr(t8, t7, 1)
	p256OrdSqr(t7, t8, 2)
	p256OrdSqr(t9, t7, 32)
	p256OrdMul(t9, t7, t9)
	p256OrdSqr(t9, t9, 29)
	p256OrdMul(t8, t8, t9)
	p256OrdSqr(t8, t8, 33)
	p256OrdMul(t7, t7, t8)
	p256OrdMul(t7, t2, t7)
	p256OrdSqr(t7, t7, 4)
	p256OrdMul(t7, t2, t7)
	p256OrdSqr(t7, t7, 3)
	p256OrdMul(t7, x, t7)
	p256OrdSqr(t7, t7, 11)
	p256OrdMul(t6, t6, t7)
	p256OrdSqr(t6, t6, 6)
	p256OrdMul(t5, t5, t6)
	p256OrdSqr(t5, t5, 5)
	p256OrdMul(t5, t4, t5)
	p256OrdSqr(t5, t5, 3)
	p256OrdMul(t5, z, t5)
	p256OrdSqr(t5, t5, 3)
	p256OrdMul(t5, x, t5)
	p256OrdSqr(t5, t5, 7)
	p256OrdMul(t5, t2, t5)
	p256OrdSqr(t5, t5, 5)
	p256OrdMul(t5, z, t5)
	p256OrdSqr(t5, t5, 9)
	p256OrdMul(t5, t1, t5)
	p256OrdSqr(t5, t5, 5)
	p256OrdMul(t5, t1, t5)
	p256OrdSqr(t5, t5, 5)
	p256OrdMul(t5, t4, t5)
	p256OrdSqr(t5, t5, 5)
	p256OrdMul(t5, t0, t5)
	p256OrdSqr(t5, t5, 4)
	p256OrdMul(t4, t4, t5)
	p256OrdSqr(t4, t4, 2)
	p256OrdMul(t4, z, t4)
	p256OrdSqr(t4, t4, 7)
	p256OrdMul(t3, t3, t4)
	p256OrdSqr(t3, t3, 2)
	p256OrdMul(t3, x, t3)
	p256OrdSqr(t3, t3, 10)
	p256OrdMul(t3, t0, t3)
	p256OrdSqr(t3, t3, 5)
	p256OrdMul(t3, t2, t3)
	p256OrdSqr(t3, t3, 5)
	p256OrdMul(t2, t2, t3)
	p256OrdSqr(t2, t2, 4)
	p256OrdMul(t2, t1, t2)
	p256OrdSqr(t2, t2, 4)
	p256OrdMul(t1, t1, t2)
	p256OrdSqr(t1, t1, 9)
	p256OrdMul(t0, t0, t1)
	p256OrdSqr(t0, t0, 5)
	p256OrdMul(z, x, t0)
	return p256OrderFromMont(z), nil
}

// P256OrdMul multiplication modulo org(G).
func P256OrdMul(in1, in2 []byte) ([]byte, error) {
	if len(in1) != 32 || len(in2) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	x1 := new(p256OrdElement)
	p256OrdBigToLittle(x1, (*[32]byte)(in1))
	p256OrdMul(x1, x1, RR)

	x2 := new(p256OrdElement)
	p256OrdBigToLittle(x2, (*[32]byte)(in2))
	p256OrdMul(x2, x2, RR)

	res := new(p256OrdElement)
	p256OrdMul(res, x1, x2)

	return p256OrderFromMont(res), nil
}

func p256OrderFromMont(in *p256OrdElement) []byte {
	// Montgomery multiplication by R⁻¹, or 1 outside the domain as R⁻¹×R = 1,
	// converts a Montgomery value out of the domain.
	one := &p256OrdElement{1}
	p256OrdMul(in, in, one)

	var xOut [32]byte
	p256OrdLittleToBig(&xOut, in)
	return xOut[:]
}
