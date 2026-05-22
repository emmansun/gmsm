// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import "github.com/emmansun/gmsm/internal/alias"

//go:noescape
func simpleBitPack4BitsLASX(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack4BitsHighBitsGamma32LASX(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsLASX(dst *byte, f *fieldElement)

//go:noescape
func simpleBitPack6BitsHighBitsGamma88LASX(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower17LASX(dst *byte, f *fieldElement)

//go:noescape
func bitPackSignedTwoPower19LASX(dst *byte, f *fieldElement)

//go:noescape
func bitUnpackSignedTwoPower17LASX(b *byte, f *ringElement)

//go:noescape
func bitUnpackSignedTwoPower19LASX(b *byte, f *ringElement)

func simpleBitPack4Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize4)
	if useLASX {
		simpleBitPack4BitsLASX(&dst[0], &f[0])
		return s
	}
	simpleBitPack4BitsGeneric(dst, f)
	return s
}

func simpleBitPack4BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if useLASX && gamma2 == gamma2QMinus1Div32 {
		simpleBitPack4BitsHighBitsGamma32LASX(&dst[0], &f[0])
		return
	}
	simpleBitPack4BitsHighBitsGeneric(dst, f, gamma2)
}

func simpleBitPack6Bits(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize6)
	if useLASX {
		simpleBitPack6BitsLASX(&dst[0], &f[0])
		return s
	}
	simpleBitPack6BitsGeneric(dst, f)
	return s
}

func simpleBitPack6BitsHighBits(dst []byte, f *ringElement, gamma2 uint32) {
	if useLASX && gamma2 == gamma2QMinus1Div88 {
		simpleBitPack6BitsHighBitsGamma88LASX(&dst[0], &f[0])
		return
	}
	simpleBitPack6BitsHighBitsGeneric(dst, f, gamma2)
}

func bitPackSignedTwoPower17(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize18)
	if useLASX {
		bitPackSignedTwoPower17LASX(&dst[0], &f[0])
		return s
	}
	bitPackSignedTwoPower17Generic(dst, f)
	return s
}

func bitPackSignedTwoPower19(s []byte, f *ringElement) []byte {
	s, dst := alias.SliceForAppend(s, encodingSize20)
	if useLASX {
		bitPackSignedTwoPower19LASX(&dst[0], &f[0])
		return s
	}
	bitPackSignedTwoPower19Generic(dst, f)
	return s
}

func bitUnpackSignedTwoPower17(b []byte, f *ringElement) {
	if useLASX {
		bitUnpackSignedTwoPower17LASX(&b[0], f)
		return
	}
	bitUnpackSignedTwoPower17Generic(b, f)
}

func bitUnpackSignedTwoPower19(b []byte, f *ringElement) {
	if useLASX {
		bitUnpackSignedTwoPower19LASX(&b[0], f)
		return
	}
	bitUnpackSignedTwoPower19Generic(b, f)
}
