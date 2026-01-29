// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"crypto/subtle"
)

// power2Round decomposes r into (r1, r0) such that r == r1 * 2¹³ + r0 mod q, See FIPS 204, Algorithm 35, Power2Round()
//
// r mod +- 2¹³ is defined as having a range of -4095..4096
//
// i.e for r = 0..4096 r1 = 0 and r0 = 0..4096
// at r = 4097..8191 r1 = 1 and r0 = -4095..-1
// (but since r0 is kept positive it effectively adds q and then reduces by q if needed)
// Similarly for the range r = 8192..8192+4096 r1=1 and r0=0..4096
// & 12289..16383 r1=2 and r0=-4095..-1
func power2Round(r fieldElement) (r1, r0 fieldElement) {
	// Add 2¹² - 1 to round up r1 by one if r0 > 2¹².
	// r is at most 2²³ - 2¹³ + 1, so rr + (2¹² - 1) won't overflow 23 bits.
	r1 = (r + 1<<(d-1) - 1) >> d
	r0 = fieldSub(r, r1<<d)
	return
}

// compressHighBits decomposes r into r1 and r0 such that r == r1 * (2 * gamma2) + r0 mod q.
// See FIPS 204, Algorithm 37, HighBits.
//
// r: The input value to decompose, in the range [0, q-1].
// gamma2: Depending on the algorithm, gamma2 is either (q-1)/32 or (q-1)/88.
// Returns: r1 (the high-order bits).
func compressHighBits(r fieldElement, gamma2 uint32) uint32 {
	// Initial computation of r1
	r1 := int32((r + 127) >> 7)

	if gamma2 == gamma2QMinus1Div32 {
		// returns ((ceil(r / 2^7) * (2^10 + 1) + 2^21) / 2^22) mod 2^4
		r1 = (r1*1025 + (1 << 21)) >> 22
		r1 &= 15 // r1 mod 2^4
		return uint32(r1)
	} else {
		// Adjust r1 for gamma2 = (q-1)/88
		r1 = (r1*11275 + (1 << 23)) >> 24
		// Ensure r1 is within the valid range
		r1 ^= ((43 - r1) >> 31) & r1
		return uint32(r1)
	}
}

func decompose(r fieldElement, gamma2 uint32) (r1 uint32, r0 int32) {
	r1 = compressHighBits(r, gamma2)
	r0 = int32(r) - int32(r1)*int32(gamma2)*2
	r0 -= ((int32(qMinus1Div2) - r0) >> 31) & q
	return
}

// See FIPS 204, Algorithm 40, UseHint(h, r)
func useHint(h, r fieldElement, gamma2 uint32) fieldElement {
	r1, r0 := decompose(r, gamma2)
	if int(h) == 0 {
		return fieldElement(r1)
	}
	if gamma2 == gamma2QMinus1Div32 {
		// m = 16, thus |mod m| in the spec turns into |& 15|
		if r0 > 0 {
			return fieldElement((r1 + 1) & 15)
		}
		return fieldElement((r1 - 1) & 15)
	} else {
		// m = 44 if gamma2 = ((q - 1) / 88)
		if r0 > 0 {
			if r1 == 43 {
				return 0
			}
			return fieldElement(r1 + 1)
		} else if r1 == 0 {
			return 43
		}
		return fieldElement(r1 - 1)
	}
}

func vectorMakeHint(ct0, cs2, w, hint []ringElement, gamma2 uint32) {
	_ = hint[len(ct0)-1] // Bounds check elimination hint.
	_ = cs2[len(ct0)-1]  // Bounds check elimination hint.
	_ = w[len(ct0)-1]    // Bounds check elimination hint.
	for i := range ct0 {
		for j := range n {
			hint[i][j] = makeHint(ct0[i][j], cs2[i][j], w[i][j], gamma2)
		}
	}
}

func makeHint(ct0, cs2, w fieldElement, gamma2 uint32) fieldElement {
	rPlusZ := fieldSub(w, cs2)
	r := fieldAdd(rPlusZ, ct0)

	return fieldElement(1 ^ uint32(subtle.ConstantTimeEq(int32(compressHighBits(r, gamma2)), int32(compressHighBits(rPlusZ, gamma2)))))
}
