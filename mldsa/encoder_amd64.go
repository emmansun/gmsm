// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package mldsa

import "github.com/emmansun/gmsm/internal/alias"

//go:noescape
func simpleBitPack4BitsAVX2(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack4BitsHighBitsGamma32AVX2(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsAVX2(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsHighBitsGamma88AVX2(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower17AVX2(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower19AVX2(dst *byte, f *fieldElement)

//go:noescape
func bitUnpackSignedTwoPower17AVX2(b *byte, f *ringElement)

//go:noescape
func bitUnpackSignedTwoPower19AVX2(b *byte, f *ringElement)

// simpleBitPack4Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..15 (4 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 4 bits
//
// i.e. Use 4 bits from each coefficient and pack them into bytes
// So every 2 coefficients fit into 1 byte.
//
// This is used to encode w1 when signing with ML-DSA-65 and ML-DSA-87
func simpleBitPack4Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize4)
	if useAVX2 {
		simpleBitPack4BitsAVX2(&dst[0], &f[0])
		return s
	}
	simpleBitPack4BitsGeneric(dst, f)
	return s
}

// simpleBitPack4BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize4 bytes.
func simpleBitPack4BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if useAVX2 && gamma2 == gamma2QMinus1Div32 {
		simpleBitPack4BitsHighBitsGamma32AVX2(&dst[0], &f[0])
		return
	}
	simpleBitPack4BitsHighBitsGeneric(dst, f, gamma2)
}

// simpleBitPack6Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..43 (6 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 43
//
// i.e. Use 6 bits from each coefficient and pack them into bytes
// So every 4 coefficients fit into 3 bytes.
//
//	|c0||c1||c2||c3|
//	 |  /|  /\  /
//	|6 2|4 4|2 6|
//
// This is used to encode w1 when signing with ML-DSA-44
func simpleBitPack6Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize6)
	if useAVX2 {
		simpleBitPack6BitsAVX2(&dst[0], &f[0])
		return s
	}
	simpleBitPack6BitsGeneric(dst, f)
	return s
}

// simpleBitPack6BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize6 bytes.
func simpleBitPack6BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if useAVX2 && gamma2 == gamma2QMinus1Div88 {
		simpleBitPack6BitsHighBitsGamma88AVX2(&dst[0], &f[0])
		return
	}
	simpleBitPack6BitsHighBitsGeneric(dst, f, gamma2)
}

// bitPackSignedTwoPower17 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^17 + 1)..2^17.
func bitPackSignedTwoPower17(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize18)
	if useAVX2 {
		bitPackSignedTwoPower17AVX2(&dst[0], &f[0])
		return s
	}
	bitPackSignedTwoPower17Generic(dst, f)
	return s
}

// bitPackSignedTwoPower19 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^19 + 1)..2^19.
func bitPackSignedTwoPower19(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize20)
	if useAVX2 {
		bitPackSignedTwoPower19AVX2(&dst[0], &f[0])
		return s
	}
	bitPackSignedTwoPower19Generic(dst, f)
	return s
}

func bitUnpackSignedTwoPower17(b []byte, f *ringElement) {
	if useAVX2 {
		bitUnpackSignedTwoPower17AVX2(&b[0], f)
		return
	}
	bitUnpackSignedTwoPower17Generic(b, f)
}

func bitUnpackSignedTwoPower19(b []byte, f *ringElement) {
	if useAVX2 {
		bitUnpackSignedTwoPower19AVX2(&b[0], f)
		return
	}
	bitUnpackSignedTwoPower19Generic(b, f)
}
