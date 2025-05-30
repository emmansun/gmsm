// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"crypto/subtle"
)

// fieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type fieldElement uint32

// fieldCheckReduced checks that a value a is < q.
//func fieldCheckReduced(a uint32) (fieldElement, error) {
//	if a >= q {
//		return 0, errors.New("unreduced field element")
//	}
//	return fieldElement(a), nil
//}

// fieldReduceOnce reduces a value a < 2q.
func fieldReduceOnce(a uint32) fieldElement {
	x := a - q
	// If x underflowed, then x >= 2^32 - q > 2^31, so the top bit is set.
	x += (x >> 31) * q
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint32(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint32(a - b + q)
	return fieldReduceOnce(x)
}

const (
	qInv    = 58728449   // q^-1 satisfies: q^-1 * q = 1 mod 2^32
	qNegInv = 4236238847 // inverse of -q modulo 2^32
	r       = 4193792    // 2^32 mod q
)

func fieldReduce(a uint64) fieldElement {
	t := uint32(a) * qNegInv
	return fieldReduceOnce(uint32((a + uint64(t)*q) >> 32))
}

func fieldMul(a, b fieldElement) fieldElement {
	x := uint64(a) * uint64(b)
	return fieldReduce(x)
}

// fieldMulSub returns a * (b - c). This operation is fused to save a
// fieldReduceOnce after the subtraction.
func fieldMulSub(a, b, c fieldElement) fieldElement {
	x := uint64(a) * uint64(b-c+q)
	return fieldReduce(x)
}

// ringElement is a polynomial, an element of R_q, represented as an array.
type ringElement [n]fieldElement

// polyAdd adds two ringElements or nttElements.
func polyAdd[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

// polySub subtracts two ringElements or nttElements.
func polySub[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

// nttElement is an NTT representation, an element of T_q, represented as an array.
type nttElement [n]fieldElement

// The table in FIPS 204 Appendix B uses the following formula
// zeta[k]= 1753^bitrev(k) mod q for (k = 1..255) (The first value is not used).
//
// As this implementation uses montgomery form with a multiplier of 2^32.
// The values need to be transformed i.e.
//
// zetasMontgomery[k] = fieldReduce(zeta[k] * (2^32 * 2^32 mod(q))) = (zeta[k] * r^2) mod q
var zetasMontgomery = [n]fieldElement{
	4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
	1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
	2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
	6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
	2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
	4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
	6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
	811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
	4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
	7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
	3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
	7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
	5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
	4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
	189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
	1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
	2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
	266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
	900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
	7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
	342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
	2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
	4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
	7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
	7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
	7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
	6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
	5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
	5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
	7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
	5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
	7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
}

// ntt maps a ringElement to its nttElement representation.
//
// It implements NTT, according to FIPS 204, Algorithm 41.
func ntt(f ringElement) nttElement {
	k := 1
	// len: 128, 64, 32, ..., 1
	for len := 128; len >= 1; len /= 2 {
		// start
		for start := 0; start < n; start += 2 * len {
			zeta := zetasMontgomery[k]
			k++
			// Bounds check elimination hint.
			f, flen := f[start:start+len], f[start+len:start+len+len]
			for j := range len {
				t := fieldMul(zeta, flen[j])
				flen[j] = fieldSub(f[j], t)
				f[j] = fieldAdd(f[j], t)
			}
		}
	}
	return nttElement(f)
}

// inverseNTT maps a nttElement back to the ringElement it represents.
//
// It implements NTT⁻¹, according to FIPS 204, Algorithm 42.
func inverseNTT(f nttElement) ringElement {
	k := 255
	for len := 1; len < n; len *= 2 {
		for start := 0; start < n; start += 2 * len {
			zeta := q - zetasMontgomery[k]
			k--
			// Bounds check elimination hint.
			f, flen := f[start:start+len], f[start+len:start+len+len]
			for j := range len {
				t := f[j]
				f[j] = fieldAdd(t, flen[j])
				flen[j] = fieldMulSub(zeta, t, flen[j])
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 41978) // 41978 = ((256⁻¹ mod q) * (2^64 mode q)) mode q
	}
	return ringElement(f)
}

func nttMul(f, g nttElement) nttElement {
	var ret nttElement
	for i, v := range f {
		ret[i] = fieldMul(v, g[i])
	}
	return ret
}

// infinityNorm returns the absolute value modulo q in constant time
//
//	i.e return x > (q - 1) / 2 ? q - x : x;
func infinityNorm(a fieldElement) uint32 {
	ret := subtle.ConstantTimeLessOrEq(int(a), qMinus1Div2)
	return uint32(subtle.ConstantTimeSelect(ret, int(a), int(q-a)))
}

func polyInfinityNorm[T ~[n]fieldElement](a T, norm int) int {
	for i := range a {
		left := int(infinityNorm(a[i]))
		right := int(norm)
		norm = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(left, right), right, left)
	}
	return norm
}

func vectorInfinityNorm[T ~[n]fieldElement](a []T, norm int) int {
	for i := range a {
		left := int(polyInfinityNorm(a[i], norm))
		right := int(norm)
		norm = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(left, right), right, left)
	}
	return norm
}

func infinityNormSigned(a int32) int {
	ret := subtle.ConstantTimeLessOrEq(0x80000000, int(a))
	return subtle.ConstantTimeSelect(ret, int(-a), int(a))
}

func polyInfinityNormSigned(a []int32, norm int) int {
	for i := range a {
		left := int(infinityNormSigned(a[i]))
		right := norm
		norm = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(left, right), right, left)
	}
	return norm
}

func vectorInfinityNormSigned(a [][n]int32, norm int) int {
	for i := range a {
		left := int(polyInfinityNormSigned(a[i][:], norm))
		right := norm
		norm = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(left, right), right, left)
	}
	return norm
}

func vectorCountOnes(a []ringElement) int {
	var oneCount int
	for i := range a {
		for j := range a[i] {
			oneCount += int(a[i][j])
		}
	}
	return oneCount
}

