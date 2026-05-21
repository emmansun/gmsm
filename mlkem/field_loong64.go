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
		// LASX layout after XVILVLV X10, X9, X0 / XVILVHV X10, X9, X1:
		//   X0[63:0]   = g2_a (from X10.lane0 low)  → needs z4+2
		//   X0[127:64] = g0_a (from X9.lane0 low)   → needs z4+0
		//   X0[191:128]= g3_a (from X10.lane1 low)  → needs z4+3
		//   X0[255:192]= g1_a (from X9.lane1 low)   → needs z4+1
		// Twiddle table layout: [z2×4, z0×4 | z3×4, z1×4]
		for i := 0; i < 4; i++ {
			nttTwiddleL4PrecompLASX[base4+i] = zetasMontgomery[z4+2]    // g2, [63:0]
			nttTwiddleL4PrecompLASX[base4+4+i] = zetasMontgomery[z4]    // g0, [127:64]
			nttTwiddleL4PrecompLASX[base4+8+i] = zetasMontgomery[z4+3]  // g3, [191:128]
			nttTwiddleL4PrecompLASX[base4+12+i] = zetasMontgomery[z4+1] // g1, [255:192]
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
		// LASX layout after XVSHUF4IW+XVILVLV/XVILVHV split:
		//   [63:0]   → g4,g5 (from X10.lane0 low) → needs z4,z5
		//   [127:64] → g0,g1 (from X9.lane0 low)  → needs z0,z1
		//   [191:128]→ g6,g7 (from X10.lane1 low) → needs z6,z7
		//   [255:192]→ g2,g3 (from X9.lane1 low)  → needs z2,z3
		nttTwiddleL2PrecompLASX[base2+0] = z4v
		nttTwiddleL2PrecompLASX[base2+1] = z4v
		nttTwiddleL2PrecompLASX[base2+2] = z5
		nttTwiddleL2PrecompLASX[base2+3] = z5
		nttTwiddleL2PrecompLASX[base2+4] = z0
		nttTwiddleL2PrecompLASX[base2+5] = z0
		nttTwiddleL2PrecompLASX[base2+6] = z1
		nttTwiddleL2PrecompLASX[base2+7] = z1
		nttTwiddleL2PrecompLASX[base2+8] = z6
		nttTwiddleL2PrecompLASX[base2+9] = z6
		nttTwiddleL2PrecompLASX[base2+10] = z7
		nttTwiddleL2PrecompLASX[base2+11] = z7
		nttTwiddleL2PrecompLASX[base2+12] = z2v
		nttTwiddleL2PrecompLASX[base2+13] = z2v
		nttTwiddleL2PrecompLASX[base2+14] = z3
		nttTwiddleL2PrecompLASX[base2+15] = z3

		iz8 := 31 - block*2
		for i := 0; i < 8; i++ {
			inttTwiddleL8PrecompLASX[base8+i] = zetasMontgomery[iz8]
			inttTwiddleL8PrecompLASX[base8+8+i] = zetasMontgomery[iz8-1]
		}

		iz4 := 63 - block*4
		// Same data layout as forward NTT (XVILVLV/XVILVHV split):
		//   [63:0]   → group 2 data → needs iz4-2
		//   [127:64] → group 0 data → needs iz4
		//   [191:128]→ group 3 data → needs iz4-3
		//   [255:192]→ group 1 data → needs iz4-1
		for i := 0; i < 4; i++ {
			inttTwiddleL4PrecompLASX[base4+i] = zetasMontgomery[iz4-2]    // g2, [63:0]
			inttTwiddleL4PrecompLASX[base4+4+i] = zetasMontgomery[iz4]    // g0, [127:64]
			inttTwiddleL4PrecompLASX[base4+8+i] = zetasMontgomery[iz4-3]  // g3, [191:128]
			inttTwiddleL4PrecompLASX[base4+12+i] = zetasMontgomery[iz4-1] // g1, [255:192]
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
		// Same LASX data layout as forward NTT Layer 6:
		//   [63:0]   → g4,g5 → needs iz4v,iz5
		//   [127:64] → g0,g1 → needs iz0,iz1
		//   [191:128]→ g6,g7 → needs iz6,iz7
		//   [255:192]→ g2,g3 → needs iz2v,iz3
		inttTwiddleL2PrecompLASX[base2+0] = iz4v
		inttTwiddleL2PrecompLASX[base2+1] = iz4v
		inttTwiddleL2PrecompLASX[base2+2] = iz5
		inttTwiddleL2PrecompLASX[base2+3] = iz5
		inttTwiddleL2PrecompLASX[base2+4] = iz0
		inttTwiddleL2PrecompLASX[base2+5] = iz0
		inttTwiddleL2PrecompLASX[base2+6] = iz1
		inttTwiddleL2PrecompLASX[base2+7] = iz1
		inttTwiddleL2PrecompLASX[base2+8] = iz6
		inttTwiddleL2PrecompLASX[base2+9] = iz6
		inttTwiddleL2PrecompLASX[base2+10] = iz7
		inttTwiddleL2PrecompLASX[base2+11] = iz7
		inttTwiddleL2PrecompLASX[base2+12] = iz2v
		inttTwiddleL2PrecompLASX[base2+13] = iz2v
		inttTwiddleL2PrecompLASX[base2+14] = iz3
		inttTwiddleL2PrecompLASX[base2+15] = iz3
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

//go:noescape
func internalNTTMulLASX(out, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccLASX(acc, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccKeyGenLASX(acc, lhs, rhs *nttElement)

//go:noescape
func ringCompressAndEncode1LASX(out []byte, f *ringElement)

//go:noescape
func ringCompressAndEncode4LASX(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress4LASX(b *[encodingSize4]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode5LASX(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress5LASX(b *[encodingSize5]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode10LASX(out []byte, f *ringElement)

//go:noescape
func ringCompressAndEncode11LASX(out []byte, f *ringElement)

//go:noescape
func decodeAndDecompressU10LASX(dst []ringElement, c []byte)

//go:noescape
func decodeAndDecompressU11LASX(dst []ringElement, c []byte)

func nttMul(acc, lhs, rhs *nttElement) {
	if useLASX {
		internalNTTMulLASX(acc, lhs, rhs)
		return
	}
	nttMulGeneric(acc, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	if useLASX {
		internalNTTMulAccLASX(acc, lhs, rhs)
		return
	}
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
	if useLASX {
		internalNTTMulAccKeyGenLASX(acc, lhs, rhs)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}

func decodeAndDecompressU10(dst []ringElement, c []byte) {
	if useLASX {
		decodeAndDecompressU10LASX(dst, c)
		return
	}
	decodeAndDecompressU10Generic(dst, c)
}

func decodeAndDecompressU11(dst []ringElement, c []byte) {
	if useLASX {
		decodeAndDecompressU11LASX(dst, c)
		return
	}
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
	if useLASX {
		ringCompressAndEncode4LASX(b, f)
		return s
	}
	ringCompressAndEncode4Generic(b, f)
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₄, according to FIPS 203, Algorithm 6,
// followed by Decompress₄, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress4(b *[encodingSize4]byte, f *ringElement) {
	if useLASX {
		ringDecodeAndDecompress4LASX(b, f)
		return
	}
	ringDecodeAndDecompress4Generic(b, f)
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s,
//
// It implements Compress₅, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₅, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode5(s []byte, f *ringElement) []byte {
	if useLASX {
		s, b := sliceForAppend(s, encodingSize5)
		ringCompressAndEncode5LASX(b, f)
		return s
	}
	return ringCompressAndEncode(s, f, 5)
}

// ringDecodeAndDecompress5 decodes a 160-byte encoding of a ring element where
// each five bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₅, according to FIPS 203, Algorithm 6,
// followed by Decompress₅, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress5(bb *[encodingSize5]byte) ringElement {
	if useLASX {
		var f ringElement
		ringDecodeAndDecompress5LASX(bb, &f)
		return f
	}
	return ringDecodeAndDecompress(bb[:], 5)
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s,
// compressing four coefficients per five bytes.
//
// It implements Compress₁₀, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₀, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode10(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	if useLASX {
		ringCompressAndEncode10LASX(b, f)
		return s
	}
	ringCompressAndEncode10Generic(b, f)
	return s
}

// ringCompressAndEncode11 appends a 352-byte encoding of a ring element to s,
// compressing eight coefficients per eleven bytes.
//
// It implements Compress₁₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode11(s []byte, f *ringElement) []byte {
	if useLASX {
		s, b := sliceForAppend(s, encodingSize11)
		ringCompressAndEncode11LASX(b, f)
		return s
	}
	return ringCompressAndEncode(s, f, 11)
}

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s,
// compressing one coefficients per bit.
//
// It implements Compress₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode1(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	if useLASX {
		ringCompressAndEncode1LASX(b, f)
		return s
	}
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
