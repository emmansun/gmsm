// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mlkem

import (
	"crypto/sha3"
)

// NEON is mandatory on all ARMv8-A (arm64) cores; no runtime detection needed.

// nttZetasL5L6Packed stores prepacked zetas for forward NTT tail layers.
// Layout:
//
//	[0..15]  -> L5 vectors: [z0 x4, z1 x4]
//	[16..31] -> L6 vectors: [z0,z0,z1,z1,z2,z2,z3,z3]
var nttZetasL5L6Packed = [32][8]fieldElement{
	{1223, 1223, 1223, 1223, 652, 652, 652, 652},
	{2777, 2777, 2777, 2777, 1015, 1015, 1015, 1015},
	{2036, 2036, 2036, 2036, 1491, 1491, 1491, 1491},
	{3047, 3047, 3047, 3047, 1785, 1785, 1785, 1785},
	{516, 516, 516, 516, 3321, 3321, 3321, 3321},
	{3009, 3009, 3009, 3009, 2663, 2663, 2663, 2663},
	{1711, 1711, 1711, 1711, 2167, 2167, 2167, 2167},
	{126, 126, 126, 126, 1469, 1469, 1469, 1469},
	{2476, 2476, 2476, 2476, 3239, 3239, 3239, 3239},
	{3058, 3058, 3058, 3058, 830, 830, 830, 830},
	{107, 107, 107, 107, 1908, 1908, 1908, 1908},
	{3082, 3082, 3082, 3082, 2378, 2378, 2378, 2378},
	{2931, 2931, 2931, 2931, 961, 961, 961, 961},
	{1821, 1821, 1821, 1821, 2604, 2604, 2604, 2604},
	{448, 448, 448, 448, 2264, 2264, 2264, 2264},
	{677, 677, 677, 677, 2054, 2054, 2054, 2054},

	{2226, 2226, 430, 430, 555, 555, 843, 843},
	{2078, 2078, 871, 871, 1550, 1550, 105, 105},
	{422, 422, 587, 587, 177, 177, 3094, 3094},
	{3038, 3038, 2869, 2869, 1574, 1574, 1653, 1653},
	{3083, 3083, 778, 778, 1159, 1159, 3182, 3182},
	{2552, 2552, 1483, 1483, 2727, 2727, 1119, 1119},
	{1739, 1739, 644, 644, 2457, 2457, 349, 349},
	{418, 418, 329, 329, 3173, 3173, 3254, 3254},
	{817, 817, 1097, 1097, 603, 603, 610, 610},
	{1322, 1322, 2044, 2044, 1864, 1864, 384, 384},
	{2114, 2114, 3193, 3193, 1218, 1218, 1994, 1994},
	{2455, 2455, 220, 220, 2142, 2142, 1670, 1670},
	{2144, 2144, 1799, 1799, 2051, 2051, 794, 794},
	{1819, 1819, 2475, 2475, 2459, 2459, 478, 478},
	{3221, 3221, 3021, 3021, 996, 996, 991, 991},
	{958, 958, 1869, 1869, 1522, 1522, 1628, 1628},
}

// inttZetasL6L5Packed stores prepacked zetas for inverse NTT tail layers.
// Layout:
//
//	[0..15]  -> L6 vectors: [z0,z0,z1,z1,z2,z2,z3,z3] in descending-k order
//	[16..31] -> L5 vectors: [z0 x4, z1 x4] in descending-k order
var inttZetasL6L5Packed = [32][8]fieldElement{
	{1628, 1628, 1522, 1522, 1869, 1869, 958, 958},
	{991, 991, 996, 996, 3021, 3021, 3221, 3221},
	{478, 478, 2459, 2459, 2475, 2475, 1819, 1819},
	{794, 794, 2051, 2051, 1799, 1799, 2144, 2144},
	{1670, 1670, 2142, 2142, 220, 220, 2455, 2455},
	{1994, 1994, 1218, 1218, 3193, 3193, 2114, 2114},
	{384, 384, 1864, 1864, 2044, 2044, 1322, 1322},
	{610, 610, 603, 603, 1097, 1097, 817, 817},
	{3254, 3254, 3173, 3173, 329, 329, 418, 418},
	{349, 349, 2457, 2457, 644, 644, 1739, 1739},
	{1119, 1119, 2727, 2727, 1483, 1483, 2552, 2552},
	{3182, 3182, 1159, 1159, 778, 778, 3083, 3083},
	{1653, 1653, 1574, 1574, 2869, 2869, 3038, 3038},
	{3094, 3094, 177, 177, 587, 587, 422, 422},
	{105, 105, 1550, 1550, 871, 871, 2078, 2078},
	{843, 843, 555, 555, 430, 430, 2226, 2226},

	{2054, 2054, 2054, 2054, 677, 677, 677, 677},
	{2264, 2264, 2264, 2264, 448, 448, 448, 448},
	{2604, 2604, 2604, 2604, 1821, 1821, 1821, 1821},
	{961, 961, 961, 961, 2931, 2931, 2931, 2931},
	{2378, 2378, 2378, 2378, 3082, 3082, 3082, 3082},
	{1908, 1908, 1908, 1908, 107, 107, 107, 107},
	{830, 830, 830, 830, 3058, 3058, 3058, 3058},
	{3239, 3239, 3239, 3239, 2476, 2476, 2476, 2476},
	{1469, 1469, 1469, 1469, 126, 126, 126, 126},
	{2167, 2167, 2167, 2167, 1711, 1711, 1711, 1711},
	{2663, 2663, 2663, 2663, 3009, 3009, 3009, 3009},
	{3321, 3321, 3321, 3321, 516, 516, 516, 516},
	{1785, 1785, 1785, 1785, 3047, 3047, 3047, 3047},
	{1491, 1491, 1491, 1491, 2036, 2036, 2036, 2036},
	{1015, 1015, 1015, 1015, 2777, 2777, 2777, 2777},
	{652, 652, 652, 652, 1223, 1223, 1223, 1223},
}

//go:noescape
func internalNTTNEON(f *ringElement)

//go:noescape
func internalInverseNTTNEON(f *nttElement)

//go:noescape
func internalNTTMulNEON(out, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccNEON(acc, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccKeyGenNEON(acc, lhs, rhs *nttElement)

//go:noescape
func samplePolyCBD2NEON(dst *ringElement, buf *[128]byte)

//go:noescape
func samplePolyCBD3NEON(dst *ringElement, buf *[192]byte)

//go:noescape
func decodeAndDecompressU10NEON(dst []ringElement, c []byte)

//go:noescape
func decodeAndDecompressU11NEON(dst []ringElement, c []byte)

//go:noescape
func polyAddAssignNEON(dst, src *ringElement)

//go:noescape
func polySubAssignNEON(dst, src *ringElement)

//go:noescape
func ringCompressAndEncode4NEON(out []byte, f *ringElement)

//go:noescape
func ringCompressAndEncode5NEON(out []byte, f *ringElement)

func nttMul(out, lhs, rhs *nttElement) {
	internalNTTMulNEON(out, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	internalNTTMulAccNEON(acc, lhs, rhs)
}

func internalNTT(f *ringElement) {
	internalNTTNEON(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	internalNTTMulAccKeyGenNEON(acc, lhs, rhs)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTNEON(f)
}

func decodeAndDecompressU10(dst []ringElement, c []byte) {
	decodeAndDecompressU10NEON(dst, c)
}

func decodeAndDecompressU11(dst []ringElement, c []byte) {
	decodeAndDecompressU11NEON(dst, c)
}

// samplePolyCBD draws a ringElement from the Dη distribution given a stream of
// random bytes generated by the PRF function, according to FIPS 203, Algorithm 8.
func samplePolyCBD(s []byte, b, η byte) ringElement {
	prf := sha3.NewSHAKE256()
	prf.Write(s)
	prf.Write([]byte{b})
	var B [maxBytesOf64Mulη]byte
	switch η {
	case 2:
		prf.Read(B[:128])
		var f ringElement
		samplePolyCBD2NEON(&f, (*[128]byte)(B[:128]))
		return f
	case 3:
		prf.Read(B[:192])
		var f ringElement
		samplePolyCBD3NEON(&f, (*[192]byte)(B[:192]))
		return f
	default:
		prf.Read(B[:64*η])
		return samplePolyCBDGeneric(B[:], η)
	}
}

func polyAddAssign(dst *ringElement, src *ringElement) {
	polyAddAssignNEON(dst, src)
}

func polySubAssign(dst *ringElement, src *ringElement) {
	polySubAssignNEON(dst, src)
}

// ringCompressAndEncode4 appends a 128-byte encoding of a ring element to s,
// compressing two coefficients per byte.
//
// It implements Compress₄, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₄, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode4(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	ringCompressAndEncode4NEON(b, f)
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₄, according to FIPS 203, Algorithm 6,
// followed by Decompress₄, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress4(b *[encodingSize4]byte, f *ringElement) {
	ringDecodeAndDecompress4Generic(b, f)
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s,
// compressing eight coefficients per five bytes.
//
// It implements Compress₅, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₅, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode5(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize5)
	ringCompressAndEncode5NEON(b, f)
	return s
}

// ringDecodeAndDecompress5 decodes a 160-byte encoding of a ring element where
// each five bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₅, according to FIPS 203, Algorithm 6,
// followed by Decompress₅, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress5(bb *[encodingSize5]byte) ringElement {
	return ringDecodeAndDecompress(bb[:], 5)
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s,
// compressing four coefficients per five bytes.
//
// It implements Compress₁₀, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₀, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode10(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	ringCompressAndEncode10Generic(b, &f)
	return s
}

// ringCompressAndEncode11 appends a 352-byte encoding of a ring element to s,
// compressing eight coefficients per eleven bytes.
//
// It implements Compress₁₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode11(s []byte, f *ringElement) []byte {
	return ringCompressAndEncode(s, f, 11)
}

// sampleNTT draws a uniformly random nttElement from a stream of uniformly
// random bytes generated by the XOF function, according to FIPS 203,
// Algorithm 7.
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewSHAKE128()
	B.Write(rho)
	var domain [2]byte
	domain[0] = ii
	domain[1] = jj
	B.Write(domain[:])

	var a nttElement
	var j int        // index into a
	var buf [24]byte // buffered reads from B

	for j < n {
		B.Read(buf[:])
		j += rejUniformGeneric(buf[:], &a, j)
	}
	return a
}
