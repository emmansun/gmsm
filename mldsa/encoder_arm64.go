// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package mldsa

import "github.com/emmansun/gmsm/internal/alias"

//go:noescape
func simpleBitPack4BitsARM64(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack4BitsHighBitsGamma32NEON(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsARM64(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsHighBitsGamma88NEON(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower17NEON(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower19NEON(dst *byte, f *fieldElement)

// simpleBitPack4Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..15 (4 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 4 bits
func simpleBitPack4Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize4)
	simpleBitPack4BitsARM64(&dst[0], &f[0])
	return s
}

// simpleBitPack4BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize4 bytes.
func simpleBitPack4BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if gamma2 == gamma2QMinus1Div32 {
		simpleBitPack4BitsHighBitsGamma32NEON(&dst[0], &f[0])
		return
	}
	simpleBitPack4BitsHighBitsGeneric(dst, f, gamma2)
}

// simpleBitPack6Bits encodes a polynomial into a byte string, assuming that all coefficients are
// in the range 0..43 (6 bits).
//
// See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 43
func simpleBitPack6Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize6)
	simpleBitPack6BitsARM64(&dst[0], &f[0])
	return s
}

// simpleBitPack6BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize6 bytes.
func simpleBitPack6BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if gamma2 == gamma2QMinus1Div88 {
		simpleBitPack6BitsHighBitsGamma88NEON(&dst[0], &f[0])
		return
	}
	simpleBitPack6BitsHighBitsGeneric(dst, f, gamma2)
}

// bitPackSignedTwoPower17 encodes a polynomial into a byte string using 18 bits
// per coefficient (FIPS 204 BitPack with eta = 2^17).
func bitPackSignedTwoPower17(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize18)
	bitPackSignedTwoPower17NEON(&dst[0], &f[0])
	return s
}

// bitPackSignedTwoPower19 encodes a polynomial into a byte string using 20 bits
// per coefficient (FIPS 204 BitPack with eta = 2^19).
func bitPackSignedTwoPower19(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize20)
	bitPackSignedTwoPower19NEON(&dst[0], &f[0])
	return s
}

func bitUnpackSignedTwoPower17(b []byte, f *ringElement) {
	bitUnpackSignedTwoPower17Generic(b, f)
}

func bitUnpackSignedTwoPower19(b []byte, f *ringElement) {
	bitUnpackSignedTwoPower19Generic(b, f)
}
