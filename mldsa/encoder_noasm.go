// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package mldsa

import "github.com/emmansun/gmsm/internal/alias"

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
	simpleBitPack4BitsGeneric(dst, f)
	return s
}

// simpleBitPack4BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize4 bytes.
func simpleBitPack4BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
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
	simpleBitPack6BitsGeneric(dst, f)
	return s
}

// simpleBitPack6BitsHighBits packs HighBits(f, gamma2) directly into dst.
// dst must be exactly encodingSize6 bytes.
func simpleBitPack6BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	simpleBitPack6BitsHighBitsGeneric(dst, f, gamma2)
}

// bitPackSignedTwoPower17 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^17 + 1)..2^17.
func bitPackSignedTwoPower17(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize18)
	bitPackSignedTwoPower17Generic(dst, f)
	return s
}

// bitPackSignedTwoPower19 encodes a polynomial into a byte string, assuming that all
// coefficients are in the range (-2^19 + 1)..2^19.
func bitPackSignedTwoPower19(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize20)
	bitPackSignedTwoPower19Generic(dst, f)
	return s
}

func bitUnpackSignedTwoPower17(b []byte, f *ringElement) {
	bitUnpackSignedTwoPower17Generic(b, f)
}

func bitUnpackSignedTwoPower19(b []byte, f *ringElement) {
	bitUnpackSignedTwoPower19Generic(b, f)
}
