// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import "github.com/emmansun/gmsm/internal/byteorder"

const (
	ghashBlockSize = 16
)

// ghashFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
type ghashFieldElement struct {
	low, high uint64
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// hctrAdd adds two elements of GF(2¹²⁸) and returns the sum.
func ghashAdd(x, y *ghashFieldElement) ghashFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return ghashFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// hctrDouble returns the result of doubling an element of GF(2¹²⁸).
func ghashDouble(x *ghashFieldElement) (double ghashFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

// ghashReductionTable is stored irreducible polynomial's double & add precomputed results.
// 0000 - 0
// 0001 - irreducible polynomial >> 3
// 0010 - irreducible polynomial >> 2
// 0011 - (irreducible polynomial >> 3 xor irreducible polynomial >> 2)
// ...
// 1000 - just the irreducible polynomial
var ghashReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// ghashMul sets y to y*H, where H is the GHASH key, fixed during New.
func ghashMul(productTable *[16]ghashFieldElement, y *ghashFieldElement) {
	var z ghashFieldElement

	// Eliminate bounds checks in the loop.
	_ = ghashReductionTable[0xf]

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of hash key.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(ghashReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions.
			t := &productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func updateBlocks(productTable *[16]ghashFieldElement, y *ghashFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= byteorder.BEUint64(blocks)
		y.high ^= byteorder.BEUint64(blocks[8:])
		ghashMul(productTable, y)
		blocks = blocks[blockSize:]
	}
}

// ghashUpdate extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func ghashUpdate(productTable *[16]ghashFieldElement, y *ghashFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	updateBlocks(productTable, y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [blockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		updateBlocks(productTable, y, partialBlock[:])
	}
}
