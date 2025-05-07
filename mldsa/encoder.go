// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
)

// simpleBitPack10Bits encodes a polynomial f into a byte slice
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 10 bits
// i.e. Use 10 bits from each coefficient and pack them into bytes
// So every 4 coefficients (c0..c3) fit into 5 bytes.
//
//	|c0||c1||c2||c3|
//	 |\  |\  |\  |\
//	|8|2 6|4 4|6 2|8|
func simpleBitPack10Bits(s []byte, f ringElement) []byte {
	s, b := alias.SliceForAppend(s, encodingSize10)
	for i := 0; i < n; i += 4 {
		var x uint64
		x |= uint64(f[i])
		x |= uint64(f[i+1]) << 10
		x |= uint64(f[i+2]) << 20
		x |= uint64(f[i+3]) << 30
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b[3] = uint8(x >> 24)
		b[4] = uint8(x >> 32)
		b = b[5:]
	}
	return s
}

// simpleBitUnpack10Bits decodes a byte slice into a polynomial f
// See FIPS 204, Algorithm 18, SimpleBitUnpack(w, b) where b = 10 bits
func simpleBitUnpack10Bits(b []byte, f *ringElement) {
	const mask = 0x3FF
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) | (uint64(b[4]) << 32)
		b = b[5:]
		f[i] = fieldElement(x & mask)
		f[i+1] = fieldElement((x >> 10) & mask)
		f[i+2] = fieldElement((x >> 20) & mask)
		f[i+3] = fieldElement((x >> 30) & mask)
	}
}

// simpleBitPack4Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..15 (4 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 4 bits
//
// i.e. Use 4 bits from each coefficient and pack them into bytes
// So every 2 coefficients fit into 1 byte.
//
// This is used to encode w1 when signing with ML-DSA-65 and ML-DSA-87
func simpleBitPack4Bits(s []byte, f ringElement) []byte {
	s, b := alias.SliceForAppend(s, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[0] = uint8(f[i]) | (uint8(f[i+1]) << 4)
		b = b[1:]
	}
	return s
}

// simpleBitPack6Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..43 (6 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 43
//
// i.e. Use 6 bits from each coefficient and pack them into bytes
// So every 4 coefficients fit into 3 bytes.
//
//  |c0||c1||c2||c3|
//   |  /|  /\  /
//  |6 2|4 4|2 6|
//
// This is used to encode w1 when signing with ML-DSA-44
func simpleBitPack6Bits(s []byte, f ringElement) []byte {
	s, b := alias.SliceForAppend(s, encodingSize6)
	for i := 0; i < n; i += 4 {
		var x uint64
		x = uint64(f[i])
		x |= uint64(f[i+1]) << 6
		x |= uint64(f[i+2]) << 12
		x |= uint64(f[i+3]) << 18
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)

		b = b[3:]
	}
	return s
}

// bitPackSigned2 encodes a polynomial f into a byte slice, assuming that all
// coefficients are in the range -2..2.
// See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = b = 2.
//
// This is used to encode the private key polynomial elements of s1 and s2
// for ML-DSA-44 and ML-DSA-87 (i.e. eta = 2)
// Use 3 bits from each coefficient and pack them into bytes
// So every 8 coefficients fit into 3 bytes.
//
//	|c0 c1 c2 c3 c4 c5 c6 c7|
//	 | /  / | |  / / | |  /
//	|3 3 2| 1 3 3 1| 2 3 3|
func bitPackSigned2(s []byte, f ringElement) []byte {
	s, b := alias.SliceForAppend(s, encodingSize3)
	for i := 0; i < n; i += 8 {
		var x uint32
		x |= uint32(fieldSub(2, f[i]))
		x |= uint32(fieldSub(2, f[i+1])) << 3
		x |= uint32(fieldSub(2, f[i+2])) << 6
		x |= uint32(fieldSub(2, f[i+3])) << 9
		x |= uint32(fieldSub(2, f[i+4])) << 12
		x |= uint32(fieldSub(2, f[i+5])) << 15
		x |= uint32(fieldSub(2, f[i+6])) << 18
		x |= uint32(fieldSub(2, f[i+7])) << 21
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b = b[3:]
	}
	return s
}

// bitUnpackSigned2 decodes a byte slice into a polynomial f
// See FIPS 204, Algorithm 19, BitUnpack(w, a, b). where a = b = 2.
func bitUnpackSigned2(b []byte) (ringElement, error) {
	const bitsMask = 0x7
	var f ringElement
	for i := 0; i < n; i += 8 {
		x := uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16)
		msbs := x & 0o44444444
		mask := (msbs >> 1) | (msbs >> 2)
		if subtle.ConstantTimeEq(int32(mask&x), 0) == 0 {
			return ringElement{}, errors.New("mldsa: invalid encoding")
		}

		b = b[3:]
		f[i] = fieldSub(2, fieldElement(x&bitsMask))
		f[i+1] = fieldSub(2, fieldElement((x>>3)&bitsMask))
		f[i+2] = fieldSub(2, fieldElement((x>>6)&bitsMask))
		f[i+3] = fieldSub(2, fieldElement((x>>9)&bitsMask))
		f[i+4] = fieldSub(2, fieldElement((x>>12)&bitsMask))
		f[i+5] = fieldSub(2, fieldElement((x>>15)&bitsMask))
		f[i+6] = fieldSub(2, fieldElement((x>>18)&bitsMask))
		f[i+7] = fieldSub(2, fieldElement((x>>21)&bitsMask))
	}
	return f, nil
}


// bitPackSigned4 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range -4..4.
// See FIPS 204, Algorithm 17, BitPack(w, a, b). (a = 4, b = 4)
//
// It uses a nibble from each coefficient and packs them into bytes
// So every 2 coefficients fit into 1 byte.
//
// This is used to encode the private key polynomial elements of s1 and s2
// for ML-DSA-65 (i.e. eta = 4)
func bitPackSigned4(s []byte, f ringElement) []byte {
	s, b := alias.SliceForAppend(s, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[0] = uint8(fieldSub(4, f[i])) | (uint8(fieldSub(4, f[i+1])) << 4)
		b = b[1:]
	}
	return s
}

// bitUnpackSigned4 reverses the procedure of bitPackSigned4().
// See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = b = 4.
func bitUnpackSigned4(b []byte) (ringElement, error) {
	const bitsMask = 0xF
	var f ringElement
	for i := 0; i < n; i += 8 {
		x := uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
		// None of the nibbles may be >= 9. So if the MSB of any nibble is set,
		// none of the other bits may be set. First, select all the MSBs.
		msbs := x & 0x88888888
		// For each nibble where the MSB is set, form a mask of all the other bits.
		mask := (msbs >> 1) | (msbs >> 2) | (msbs >> 3)
		if subtle.ConstantTimeEq(int32(mask&x), 0) == 0 {
			return ringElement{}, errors.New("mldsa: invalid encoding")
		}

		b = b[4:]
		f[i] = fieldSub(4, fieldElement(x&bitsMask))
		f[i+1] = fieldSub(4, fieldElement((x>>4)&bitsMask))
		f[i+2] = fieldSub(4, fieldElement((x>>8)&bitsMask))
		f[i+3] = fieldSub(4, fieldElement((x>>12)&bitsMask))
		f[i+4] = fieldSub(4, fieldElement((x>>16)&bitsMask))
		f[i+5] = fieldSub(4, fieldElement((x>>20)&bitsMask))
		f[i+6] = fieldSub(4, fieldElement((x>>24)&bitsMask))
		f[i+7] = fieldSub(4, fieldElement((x>>28)&bitsMask))
	}
	return f, nil
}


// bitPackSigned4196 encodes a polynomial f into a byte slice, assuming that all
// coefficients are in the range (-2^12 + 1)..2^12.
// See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^12 - 1, b = 2^12.
//
// This is used to encode the LSB of the public key polynomial elements of t0
// which are encoded as part of the encoded private key.
//
// The code below packs them into 2 64 bits blocks by doing..
//
//	z0 z1 z2 z3  z4  z5 z6  z7 0
//	|   |  | |   / \  |  |  |  |
//
// |13 13 13 13 12 |1 13 13 13 24
func bitPackSigned4096(s []byte, f ringElement) []byte {
	const r = 4096 // 2^12
	s, b := alias.SliceForAppend(s, encodingSize13)
	for i := 0; i < n; i += 8 {
		var x1, x2, a uint64
		x1 = uint64(fieldSub(r, f[i]))
		x1 |= uint64(fieldSub(r, f[i+1])) << 13
		x1 |= uint64(fieldSub(r, f[i+2])) << 26
		x1 |= uint64(fieldSub(r, f[i+3])) << 39
		a = uint64(fieldSub(r, f[i+4]))
		x1 |= a << 52
		x2 = a >> 12
		x2 |= uint64(fieldSub(r, f[i+5])) << 1
		x2 |= uint64(fieldSub(r, f[i+6])) << 14
		x2 |= uint64(fieldSub(r, f[i+7])) << 27
		b[0] = uint8(x1)
		b[1] = uint8(x1 >> 8)
		b[2] = uint8(x1 >> 16)
		b[3] = uint8(x1 >> 24)
		b[4] = uint8(x1 >> 32)
		b[5] = uint8(x1 >> 40)
		b[6] = uint8(x1 >> 48)
		b[7] = uint8(x1 >> 56)
		b[8] = uint8(x2)
		b[9] = uint8(x2 >> 8)
		b[10] = uint8(x2 >> 16)
		b[11] = uint8(x2 >> 24)
		b[12] = uint8(x2 >> 32)

		b = b[13:]
	}
	return s
}

// bitUnpackSigned4096 decodes a byte slice into a polynomial f
// See FIPS 204, Algorithm 19, BitUnpack(w, a, b). where a = 2^12 - 1, b = 2^12.
func bitUnpackSigned4096(b []byte, f *ringElement) error {
	const bitsMask = 0x1FFF // 2^13-1
	const r = 4096          // 2^12
	for i := 0; i < n; i += 8 {
		x1 := uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) | (uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
		x2 := uint64(b[8]) | (uint64(b[9]) << 8) | (uint64(b[10]) << 16) | (uint64(b[11]) << 24) | (uint64(b[12]) << 32)
		b = b[13:]
		f[i] = fieldSub(r, fieldElement(x1&bitsMask))
		f[i+1] = fieldSub(r, fieldElement((x1>>13)&bitsMask))
		f[i+2] = fieldSub(r, fieldElement((x1>>26)&bitsMask))
		f[i+3] = fieldSub(r, fieldElement((x1>>39)&bitsMask))
		f[i+4] = fieldSub(r, fieldElement((x1>>52 | (x2 << 12 & bitsMask))))
		f[i+5] = fieldSub(r, fieldElement((x2>>1)&bitsMask))
		f[i+6] = fieldSub(r, fieldElement((x2>>14)&bitsMask))
		f[i+7] = fieldSub(r, fieldElement((x2>>27)&bitsMask))
	}
	return nil
}

// bitPackSignedTwoPower17 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^17 + 1)..2^17.
// See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^17 - 1, b = 2^17.
//
// This is used to encode signatures for ML-DSA-44 (where gamma1 = 2^17)
//
// # Use 18 bits from each coefficient and pack them into bytes
//
// The code below packs every 4 (18 bit) coefficients into 9 bytes
//
//	z0  z1  z2 z3
//	|   |\  |  | \
//
// |18 14|4 18 10| 8
func bitPackSignedTwoPower17(s []byte, f ringElement) []byte {
	const r = 131072 // 2^17
	s, b := alias.SliceForAppend(s, encodingSize18)
	for i := 0; i < n; i += 4 {
		var x1, x2 uint64
		x1 = uint64(fieldSub(r, f[i]))
		x1 |= uint64(fieldSub(r, f[i+1])) << 18
		x1 |= uint64(fieldSub(r, f[i+2])) << 36
		x2 = uint64(fieldSub(r, f[i+3]))
		x1 |= x2 << 54
		x2 >>= 10
		b[0] = uint8(x1)
		b[1] = uint8(x1 >> 8)
		b[2] = uint8(x1 >> 16)
		b[3] = uint8(x1 >> 24)
		b[4] = uint8(x1 >> 32)
		b[5] = uint8(x1 >> 40)
		b[6] = uint8(x1 >> 48)
		b[7] = uint8(x1 >> 56)
		b[8] = uint8(x2)

		b = b[9:]
	}
	return s
}

// bitUnpackSignedTwoPower17 decodes a byte slice into a polynomial f
// See FIPS 204, Algorithm 19, BitUnpack(w, a, b). where a = 2^17 - 1, b = 2^17.
func bitUnpackSignedTwoPower17(b []byte, f *ringElement) {
	const bitsMask = 0x3FFFF // 2^18-1
	const r = 131072         // 2^17
	for i := 0; i < n; i += 4 {
		x1 := uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) | (uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
		x2 := uint64(b[8])
		b = b[9:]
		f[i] = fieldSub(r, fieldElement(x1&bitsMask))
		f[i+1] = fieldSub(r, fieldElement((x1>>18)&bitsMask))
		f[i+2] = fieldSub(r, fieldElement((x1>>36)&bitsMask))
		f[i+3] = fieldSub(r, fieldElement((x1>>54 | (x2 << 10 & bitsMask))))
	}
}

// bitPackSignedTwoPower19 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^19 + 1)..2^19.
// See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^19 - 1, b = 2^19.
//
// This is used to encode signatures for ML-DSA-65 & ML-DSA-87 (gamma1 = 2^19)
//
// # Use 20 bits from each coefficient and pack them into bytes
//
// The code below packs every 4 (20 bit) coefficients into 10 bytes
//
//	z0  z1  z2 z3
//	|   |\  |  | \
//
// |20 12|8 20 4|16
func bitPackSignedTwoPower19(s []byte, f ringElement) []byte {
	const r = 524288 // 2^19
	s, b := alias.SliceForAppend(s, encodingSize20)
	for i := 0; i < n; i += 4 {
		var x1, x2 uint64
		x1 = uint64(fieldSub(r, f[i]))
		x1 |= uint64(fieldSub(r, f[i+1])) << 20
		x1 |= uint64(fieldSub(r, f[i+2])) << 40
		x2 = uint64(fieldSub(r, f[i+3]))
		x1 |= x2 << 60
		x2 >>= 4
		b[0] = uint8(x1)
		b[1] = uint8(x1 >> 8)
		b[2] = uint8(x1 >> 16)
		b[3] = uint8(x1 >> 24)
		b[4] = uint8(x1 >> 32)
		b[5] = uint8(x1 >> 40)
		b[6] = uint8(x1 >> 48)
		b[7] = uint8(x1 >> 56)
		b[8] = uint8(x2)
		b[9] = uint8(x2 >> 8)

		b = b[10:]
	}
	return s
}

// bitUnpackSignedTwoPower19 decodes a byte slice into a polynomial f
// See FIPS 204, Algorithm 19, BitUnpack(w, a, b). where a = 2^19 - 1, b = 2^19.
// The coefficients are in the range (-2^19 + 1)..2^19
// and are represented as 20 bits.
func bitUnpackSignedTwoPower19(b []byte, f *ringElement) {
	const bitsMask = 0xFFFFF // 2^20-1
	const r = 524288         // 2^19
	for i := 0; i < n; i += 4 {
		x1 := uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) | (uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
		x2 := uint64(b[8]) | (uint64(b[9]) << 8)
		b = b[10:]
		f[i] = fieldSub(r, fieldElement(x1&bitsMask))
		f[i+1] = fieldSub(r, fieldElement((x1>>20)&bitsMask))
		f[i+2] = fieldSub(r, fieldElement((x1>>40)&bitsMask))
		f[i+3] = fieldSub(r, fieldElement((x1>>60 | (x2 << 4 & bitsMask))))
	}
}

// See FIPS 204, Algorithm 20, HintBitPack().
func hintBitPack(s []byte, hint []ringElement, omega int) []byte {
	k := len(hint)
	s, b := alias.SliceForAppend(s, omega+k)
	index := 0
	for i := range k {
		for j := 0; j < n; j++ {
			if hint[i][j] != 0 {
				b[index] = byte(j)
				index++
			}
		}
		b[omega+i] = byte(index)
	}
	return s
}

// See FIPS 204, Algorithm 21, HintBitUnpack().
func hintBitUnpack(b []byte, hint []ringElement, omega int) bool {
	k := len(hint)
	index := 0
	first := 0
	for i := range k {
		limit := int(b[omega+i])
		if limit < index || limit > omega {
			return false
		}
		first = index
		for ; index < limit; index++ {
			bi := b[index]
			if index > first && b[index-1] >= bi {
				return false
			}
			hint[i][bi] = 1
		}
	}
	for i := index; i < omega; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
