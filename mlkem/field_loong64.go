// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
	"crypto/sha3"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var useLASX = cpu.Loong64.HasLASX

// qVecLASX stores q=3329 broadcast to 16 int16 lanes for LASX operations.
var qVecLASX [16]fieldElement

// qInvVecLASX stores qInv=62209 broadcast to 16 int16 lanes for Montgomery reduction.
var qInvVecLASX [16]fieldElement

// gammaMulTableLASX stores [r, gamma[0], r, gamma[1], ..., r, gamma[127]] as int16 lanes.
// It is consumed directly by LASX assembly in internalNTTMul*.
var gammaMulTableLASX [256]fieldElement

// nttTwiddleL8Precomp stores 8 YMM-equivalent vectors, each as [z0 x8 | z1 x8].
var nttTwiddleL8PrecompLASX [128]fieldElement

// nttTwiddleL4Precomp stores 8 vectors, each as [z0 x4, z1 x4, z2 x4, z3 x4].
var nttTwiddleL4PrecompLASX [128]fieldElement

// nttTwiddleL2Precomp stores 8 vectors with interleaved pairs.
var nttTwiddleL2PrecompLASX [128]fieldElement

// inttTwiddleL8Precomp stores 8 vectors for inverse NTT layer 5.
var inttTwiddleL8PrecompLASX [128]fieldElement

// inttTwiddleL4Precomp stores 8 vectors for inverse NTT layer 6.
var inttTwiddleL4PrecompLASX [128]fieldElement

// inttTwiddleL2Precomp stores 8 vectors for inverse NTT layer 7.
var inttTwiddleL2PrecompLASX [128]fieldElement

func init() {
	for i := range qVecLASX {
		qVecLASX[i] = q
	}
	for i := range qInvVecLASX {
		qInvVecLASX[i] = 62209
	}

	const montOne fieldElement = 2285
	for i, g := range gammasMontgomery {
		gammaMulTableLASX[2*i] = montOne
		gammaMulTableLASX[2*i+1] = g
	}

	for block := 0; block < 8; block++ {
		base8 := block * 16
		z8 := 16 + block*2
		for i := 0; i < 8; i++ {
			nttTwiddleL8PrecompLASX[base8+i] = zetasMontgomery[z8]
			nttTwiddleL8PrecompLASX[base8+8+i] = zetasMontgomery[z8+1]
		}

		base4 := block * 16
		z4 := 32 + block*4
		// LASX layout: after XVILVLV/XVILVHV split, lane0=[g0_a,g2_a], lane1=[g1_a,g3_a]
		// So twiddle must be [z0×4, z2×4 | z1×4, z3×4] (even groups in lane0, odd in lane1)
		for i := 0; i < 4; i++ {
			nttTwiddleL4PrecompLASX[base4+i] = zetasMontgomery[z4]      // z0 (g0), lane0 lo
			nttTwiddleL4PrecompLASX[base4+4+i] = zetasMontgomery[z4+2]  // z2 (g2), lane0 hi
			nttTwiddleL4PrecompLASX[base4+8+i] = zetasMontgomery[z4+1]  // z1 (g1), lane1 lo
			nttTwiddleL4PrecompLASX[base4+12+i] = zetasMontgomery[z4+3] // z3 (g3), lane1 hi
		}

		base2 := block * 16
		z2 := 64 + block*8
		z0 := zetasMontgomery[z2+0]
		z1 := zetasMontgomery[z2+1]
		z2v := zetasMontgomery[z2+2]
		z3 := zetasMontgomery[z2+3]
		z4v := zetasMontgomery[z2+4]
		z5 := zetasMontgomery[z2+5]
		z6 := zetasMontgomery[z2+6]
		z7 := zetasMontgomery[z2+7]
		nttTwiddleL2PrecompLASX[base2+0] = z0
		nttTwiddleL2PrecompLASX[base2+1] = z0
		nttTwiddleL2PrecompLASX[base2+2] = z1
		nttTwiddleL2PrecompLASX[base2+3] = z1
		nttTwiddleL2PrecompLASX[base2+4] = z4v
		nttTwiddleL2PrecompLASX[base2+5] = z4v
		nttTwiddleL2PrecompLASX[base2+6] = z5
		nttTwiddleL2PrecompLASX[base2+7] = z5
		nttTwiddleL2PrecompLASX[base2+8] = z2v
		nttTwiddleL2PrecompLASX[base2+9] = z2v
		nttTwiddleL2PrecompLASX[base2+10] = z3
		nttTwiddleL2PrecompLASX[base2+11] = z3
		nttTwiddleL2PrecompLASX[base2+12] = z6
		nttTwiddleL2PrecompLASX[base2+13] = z6
		nttTwiddleL2PrecompLASX[base2+14] = z7
		nttTwiddleL2PrecompLASX[base2+15] = z7

		iz8 := 31 - block*2
		for i := 0; i < 8; i++ {
			inttTwiddleL8PrecompLASX[base8+i] = zetasMontgomery[iz8]
			inttTwiddleL8PrecompLASX[base8+8+i] = zetasMontgomery[iz8-1]
		}

		iz4 := 63 - block*4
		// LASX layout: same split as forward NTT, even groups in lane0, odd in lane1
		for i := 0; i < 4; i++ {
			inttTwiddleL4PrecompLASX[base4+i] = zetasMontgomery[iz4]      // z0, lane0 lo
			inttTwiddleL4PrecompLASX[base4+4+i] = zetasMontgomery[iz4-2]  // z2, lane0 hi
			inttTwiddleL4PrecompLASX[base4+8+i] = zetasMontgomery[iz4-1]  // z1, lane1 lo
			inttTwiddleL4PrecompLASX[base4+12+i] = zetasMontgomery[iz4-3] // z3, lane1 hi
		}

		iz2 := 127 - block*8
		iz0 := zetasMontgomery[iz2]
		iz1 := zetasMontgomery[iz2-1]
		iz2v := zetasMontgomery[iz2-2]
		iz3 := zetasMontgomery[iz2-3]
		iz4v := zetasMontgomery[iz2-4]
		iz5 := zetasMontgomery[iz2-5]
		iz6 := zetasMontgomery[iz2-6]
		iz7 := zetasMontgomery[iz2-7]
		inttTwiddleL2PrecompLASX[base2+0] = iz0
		inttTwiddleL2PrecompLASX[base2+1] = iz0
		inttTwiddleL2PrecompLASX[base2+2] = iz1
		inttTwiddleL2PrecompLASX[base2+3] = iz1
		inttTwiddleL2PrecompLASX[base2+4] = iz4v
		inttTwiddleL2PrecompLASX[base2+5] = iz4v
		inttTwiddleL2PrecompLASX[base2+6] = iz5
		inttTwiddleL2PrecompLASX[base2+7] = iz5
		inttTwiddleL2PrecompLASX[base2+8] = iz2v
		inttTwiddleL2PrecompLASX[base2+9] = iz2v
		inttTwiddleL2PrecompLASX[base2+10] = iz3
		inttTwiddleL2PrecompLASX[base2+11] = iz3
		inttTwiddleL2PrecompLASX[base2+12] = iz6
		inttTwiddleL2PrecompLASX[base2+13] = iz6
		inttTwiddleL2PrecompLASX[base2+14] = iz7
		inttTwiddleL2PrecompLASX[base2+15] = iz7
	}
}

//go:noescape
func polyAddAssignLASX(dst, src *ringElement)

//go:noescape
func polySubAssignLASX(dst, src *ringElement)

//go:noescape
func internalNTTLASX(f *ringElement)

//go:noescape
func internalInverseNTTLASX(f *nttElement)

func nttMul(acc, lhs, rhs *nttElement) {
	nttMulGeneric(acc, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	nttMulAccGeneric(acc, lhs, rhs)
}

func internalNTT(f *ringElement) {
	if useLASX {
		internalNTTLASX(f)
		return
	}
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	if useLASX {
		internalInverseNTTLASX(f)
		return
	}
	internalInverseNTTGeneric(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	nttMulAccGeneric(acc, lhs, rhs)
}

func decodeAndDecompressU10(dst []ringElement, c []byte) {
	decodeAndDecompressU10Generic(dst, c)
}

func decodeAndDecompressU11(dst []ringElement, c []byte) {
	decodeAndDecompressU11Generic(dst, c)
}

// samplePolyCBD draws a ringElement from the Dη distribution given a stream of
// random bytes generated by the PRF function, according to FIPS 203, Algorithm 8.
func samplePolyCBD(s []byte, b, η byte) ringElement {
	prf := sha3.NewSHAKE256()
	prf.Write(s)
	prf.Write([]byte{b})
	var B [maxBytesOf64Mulη]byte
	prf.Read(B[:64*η])
	return samplePolyCBDGeneric(B[:], η)
}

func polyAddAssign(dst *ringElement, src *ringElement) {
	if useLASX {
		polyAddAssignLASX(dst, src)
		return
	}
	polyAddAssignGeneric(dst, src)
}

func polySubAssign(dst *ringElement, src *ringElement) {
	if useLASX {
		polySubAssignLASX(dst, src)
		return
	}
	polySubAssignGeneric(dst, src)
}

// ringCompressAndEncode4 appends a 128-byte encoding of a ring element to s,
// compressing two coefficients per byte.
//
// It implements Compress₄, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₄, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode4(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	ringCompressAndEncode4Generic(b, f)
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
	return ringCompressAndEncode(s, f, 5)
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
func ringCompressAndEncode10(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	ringCompressAndEncode10Generic(b, f)
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

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s,
// compressing one coefficients per bit.
//
// It implements Compress₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode1(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	clear(b)
	ringCompressAndEncode1Generic(b, f)
	return s
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
	var j int // index into a

	var batch [168]byte

	for j < n {
		B.Read(batch[:])
		for off := 0; off < len(batch) && j < n; off += 24 {
			j += rejUniformGeneric(batch[off:off+24], &a, j)
		}
	}
	return a
}
