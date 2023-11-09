//go:build (amd64 && !purego) || (arm64 && !purego)

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
//
func P256OrdInverse(k []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	x := new(p256OrdElement)
	p256OrdBigToLittle(x, (*[32]byte)(k))

	// Inversion is implemented as exponentiation by n - 2, per Fermat's little theorem.
	//
	// The sequence of 43 multiplications and 254 squarings is derived from
	// https://briansmith.org/ecc-inversion-addition-chains-01#p256_scalar_inversion
	_1 := new(p256OrdElement)
	_11 := new(p256OrdElement)
	_101 := new(p256OrdElement)
	_111 := new(p256OrdElement)
	_1111 := new(p256OrdElement)
	_10101 := new(p256OrdElement)
	_101111 := new(p256OrdElement)
	t := new(p256OrdElement)
	m := new(p256OrdElement)

	p256OrdMul(_1, x, RR)      // _1 , 2^0
	p256OrdSqr(m, _1, 1)       // _10, 2^1
	p256OrdMul(_11, m, _1)     // _11, 2^1 + 2^0
	p256OrdMul(_101, m, _11)   // _101, 2^2 + 2^0
	p256OrdMul(_111, m, _101)  // _111, 2^2 + 2^1 + 2^0
	p256OrdSqr(x, _101, 1)     // _1010, 2^3 + 2^1
	p256OrdMul(_1111, _101, x) // _1111, 2^3 + 2^2 + 2^1 + 2^0

	p256OrdSqr(t, x, 1)          // _10100, 2^4 + 2^2
	p256OrdMul(_10101, t, _1)    // _10101, 2^4 + 2^2 + 2^0
	p256OrdSqr(x, _10101, 1)     // _101010, 2^5 + 2^3 + 2^1
	p256OrdMul(_101111, _101, x) // _101111, 2^5 + 2^3 + 2^2 + 2^1 + 2^0
	p256OrdMul(x, _10101, x)     // _111111 = x6, 2^5 + 2^4 + 2^3 + 2^2 + 2^1 + 2^0
	p256OrdSqr(t, x, 2)          // _11111100, 2^7 + 2^6 + 2^5 + 2^4 + 2^3 + 2^2

	p256OrdMul(m, t, m)   // _11111110 = x8, , 2^7 + 2^6 + 2^5 + 2^4 + 2^3 + 2^2 + 2^1
	p256OrdMul(t, t, _11) // _11111111 = x8, , 2^7 + 2^6 + 2^5 + 2^4 + 2^3 + 2^2 + 2^1 + 2^0
	p256OrdSqr(x, t, 8)   // _ff00, 2^15 + 2^14 + 2^13 + 2^12 + 2^11 + 2^10 + 2^9 + 2^8
	p256OrdMul(m, x, m)   //  _fffe
	p256OrdMul(x, x, t)   // _ffff = x16, 2^15 + 2^14 + 2^13 + 2^12 + 2^11 + 2^10 + 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	p256OrdSqr(t, x, 16) // _ffff0000, 2^31 + 2^30 + 2^29 + 2^28 + 2^27 + 2^26 + 2^25 + 2^24 + 2^23 + 2^22 + 2^21 + 2^20 + 2^19 + 2^18 + 2^17 + 2^16
	p256OrdMul(m, t, m)  // _fffffffe
	p256OrdMul(t, t, x)  // _ffffffff = x32

	p256OrdSqr(x, m, 32) // _fffffffe00000000
	p256OrdMul(x, x, t)  // _fffffffeffffffff
	p256OrdSqr(x, x, 32) // _fffffffeffffffff00000000
	p256OrdMul(x, x, t)  // _fffffffeffffffffffffffff
	p256OrdSqr(x, x, 32) // _fffffffeffffffffffffffff00000000
	p256OrdMul(x, x, t)  // _fffffffeffffffffffffffffffffffff

	sqrs := []uint8{
		4, 3, 11, 5, 3, 5, 1,
		3, 7, 5, 9, 7, 5, 5,
		4, 5, 2, 2, 7, 3, 5,
		5, 6, 2, 6, 3, 5,
	}
	muls := []*p256OrdElement{
		_111, _1, _1111, _1111, _101, _10101, _1,
		_1, _111, _11, _101, _10101, _10101, _111,
		_111, _1111, _11, _1, _1, _1, _111,
		_111, _10101, _1, _1, _1, _1}

	for i, s := range sqrs {
		p256OrdSqr(x, x, int(s))
		p256OrdMul(x, x, muls[i])
	}
	return p256OrderFromMont(x), nil
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
