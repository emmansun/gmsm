// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mlkem

import (
	"crypto/sha3"

	"github.com/emmansun/gmsm/internal/deps/cpu"
	"github.com/emmansun/gmsm/internal/keccakx4"
)

var useAVX2 = cpu.X86.HasAVX2

// gammaMulTable stores [r, gamma[0], r, gamma[1], ..., r, gamma[127]] as int16 lanes.
// It is consumed directly by AVX2 assembly in internalNTTMul*.
var gammaMulTable [256]fieldElement

// nttTwiddleL8Precomp stores 8 YMM vectors, each as [z0 x8 | z1 x8], from zetasMontgomery[16..31].
var nttTwiddleL8Precomp [128]fieldElement

// nttTwiddleL4Precomp stores 8 YMM vectors, each as [z0 x4, z1 x4, z2 x4, z3 x4], from zetasMontgomery[32..63].
var nttTwiddleL4Precomp [128]fieldElement

// nttTwiddleL2Precomp stores 8 YMM vectors, each as
// [z0,z0,z1,z1,z4,z4,z5,z5,z2,z2,z3,z3,z6,z6,z7,z7], from zetasMontgomery[64..127].
var nttTwiddleL2Precomp [128]fieldElement

// inttTwiddleL8Precomp stores 8 YMM vectors, each as [z0 x8 | z1 x8], from zetasMontgomery[31..16].
var inttTwiddleL8Precomp [128]fieldElement

// inttTwiddleL4Precomp stores 8 YMM vectors, each as [z0 x4, z1 x4, z2 x4, z3 x4], from zetasMontgomery[63..32].
var inttTwiddleL4Precomp [128]fieldElement

// inttTwiddleL2Precomp stores 8 YMM vectors, each as
// [z0,z0,z1,z1,z4,z4,z5,z5,z2,z2,z3,z3,z6,z6,z7,z7], from zetasMontgomery[127..64].
var inttTwiddleL2Precomp [128]fieldElement

func init() {
	const montOne fieldElement = 2285

	for i, g := range gammasMontgomery {
		gammaMulTable[2*i] = montOne
		gammaMulTable[2*i+1] = g
	}

	for block := 0; block < 8; block++ {
		base8 := block * 16
		z8 := 16 + block*2
		for i := 0; i < 8; i++ {
			nttTwiddleL8Precomp[base8+i] = zetasMontgomery[z8]
			nttTwiddleL8Precomp[base8+8+i] = zetasMontgomery[z8+1]
		}

		base4 := block * 16
		z4 := 32 + block*4
		for i := 0; i < 4; i++ {
			nttTwiddleL4Precomp[base4+i] = zetasMontgomery[z4]
			nttTwiddleL4Precomp[base4+4+i] = zetasMontgomery[z4+1]
			nttTwiddleL4Precomp[base4+8+i] = zetasMontgomery[z4+2]
			nttTwiddleL4Precomp[base4+12+i] = zetasMontgomery[z4+3]
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
		nttTwiddleL2Precomp[base2+0] = z0
		nttTwiddleL2Precomp[base2+1] = z0
		nttTwiddleL2Precomp[base2+2] = z1
		nttTwiddleL2Precomp[base2+3] = z1
		nttTwiddleL2Precomp[base2+4] = z4v
		nttTwiddleL2Precomp[base2+5] = z4v
		nttTwiddleL2Precomp[base2+6] = z5
		nttTwiddleL2Precomp[base2+7] = z5
		nttTwiddleL2Precomp[base2+8] = z2v
		nttTwiddleL2Precomp[base2+9] = z2v
		nttTwiddleL2Precomp[base2+10] = z3
		nttTwiddleL2Precomp[base2+11] = z3
		nttTwiddleL2Precomp[base2+12] = z6
		nttTwiddleL2Precomp[base2+13] = z6
		nttTwiddleL2Precomp[base2+14] = z7
		nttTwiddleL2Precomp[base2+15] = z7

		iz8 := 31 - block*2
		for i := 0; i < 8; i++ {
			inttTwiddleL8Precomp[base8+i] = zetasMontgomery[iz8]
			inttTwiddleL8Precomp[base8+8+i] = zetasMontgomery[iz8-1]
		}

		iz4 := 63 - block*4
		for i := 0; i < 4; i++ {
			inttTwiddleL4Precomp[base4+i] = zetasMontgomery[iz4]
			inttTwiddleL4Precomp[base4+4+i] = zetasMontgomery[iz4-1]
			inttTwiddleL4Precomp[base4+8+i] = zetasMontgomery[iz4-2]
			inttTwiddleL4Precomp[base4+12+i] = zetasMontgomery[iz4-3]
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
		inttTwiddleL2Precomp[base2+0] = iz0
		inttTwiddleL2Precomp[base2+1] = iz0
		inttTwiddleL2Precomp[base2+2] = iz1
		inttTwiddleL2Precomp[base2+3] = iz1
		inttTwiddleL2Precomp[base2+4] = iz4v
		inttTwiddleL2Precomp[base2+5] = iz4v
		inttTwiddleL2Precomp[base2+6] = iz5
		inttTwiddleL2Precomp[base2+7] = iz5
		inttTwiddleL2Precomp[base2+8] = iz2v
		inttTwiddleL2Precomp[base2+9] = iz2v
		inttTwiddleL2Precomp[base2+10] = iz3
		inttTwiddleL2Precomp[base2+11] = iz3
		inttTwiddleL2Precomp[base2+12] = iz6
		inttTwiddleL2Precomp[base2+13] = iz6
		inttTwiddleL2Precomp[base2+14] = iz7
		inttTwiddleL2Precomp[base2+15] = iz7
	}
}

//go:noescape
func internalNTTAVX2(f *ringElement)

//go:noescape
func internalInverseNTTAVX2(f *nttElement)

//go:noescape
func internalNTTMulAVX2(acc, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccAVX2(acc, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccKeyGenAVX2(acc, lhs, rhs *nttElement)

//go:noescape
func rejUniformAMD64(buf []byte, a *nttElement, j int) int

//go:noescape
func samplePolyCBD2AVX2(f *ringElement, buf *[128]byte)

//go:noescape
func samplePolyCBD3AVX2(f *ringElement, buf *[192]byte)

//go:noescape
func polyAddAssignAVX2(dst, src *ringElement)

//go:noescape
func polySubAssignAVX2(dst, src *ringElement)

//go:noescape
func ringCompressAndEncode4AVX2(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress4AVX2(b *[encodingSize4]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode5AVX2(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress5AVX2(b *[encodingSize5]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode10AVX2(out []byte, f *ringElement)

//go:noescape
func decodeAndDecompressU10AVX2(dst []ringElement, c []byte)

//go:noescape
func ringCompressAndEncode11AVX2(out []byte, f *ringElement)

//go:noescape
func decodeAndDecompressU11AVX2(dst []ringElement, c []byte)

//go:noescape
func ringCompressAndEncode1AVX2(out []byte, f *ringElement)

func nttMul(acc, lhs, rhs *nttElement) {
	if useAVX2 {
		internalNTTMulAVX2(acc, lhs, rhs)
		return
	}
	nttMulGeneric(acc, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	if useAVX2 {
		internalNTTMulAccAVX2(acc, lhs, rhs)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}

func internalNTT(f *ringElement) {
	if useAVX2 {
		internalNTTAVX2(f)
		return
	}
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	if useAVX2 {
		internalInverseNTTAVX2(f)
		return
	}
	internalInverseNTTGeneric(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	if useAVX2 {
		internalNTTMulAccKeyGenAVX2(acc, lhs, rhs)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}

func decodeAndDecompressU10(dst []ringElement, c []byte) {
	if useAVX2 {
		decodeAndDecompressU10AVX2(dst, c)
		return
	}
	decodeAndDecompressU10Generic(dst, c)
}

func decodeAndDecompressU11(dst []ringElement, c []byte) {
	if useAVX2 {
		decodeAndDecompressU11AVX2(dst, c)
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
	switch {
	case useAVX2 && η == 2:
		prf.Read(B[:128])
		var f ringElement
		samplePolyCBD2AVX2(&f, (*[128]byte)(B[:128]))
		return f
	case useAVX2 && η == 3:
		prf.Read(B[:192])
		var f ringElement
		samplePolyCBD3AVX2(&f, (*[192]byte)(B[:192]))
		return f
	default:
		prf.Read(B[:64*η])
		return samplePolyCBDGeneric(B[:], η)
	}
}

func polyAddAssign(dst *ringElement, src *ringElement) {
	if useAVX2 {
		polyAddAssignAVX2(dst, src)
		return
	}
	polyAddAssignGeneric(dst, src)
}

func polySubAssign(dst *ringElement, src *ringElement) {
	if useAVX2 {
		polySubAssignAVX2(dst, src)
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
	if useAVX2 {
		ringCompressAndEncode4AVX2(b, f)
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
	if useAVX2 {
		ringDecodeAndDecompress4AVX2(b, f)
		return
	}
	ringDecodeAndDecompress4Generic(b, f)
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s,
// compressing eight coefficients per five bytes.
//
// It implements Compress₅, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₅, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode5(s []byte, f *ringElement) []byte {
	if useAVX2 {
		s, b := sliceForAppend(s, encodingSize5)
		ringCompressAndEncode5AVX2(b, f)
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
	if useAVX2 {
		var f ringElement
		ringDecodeAndDecompress5AVX2(bb, &f)
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
	if useAVX2 {
		ringCompressAndEncode10AVX2(b, f)
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
	if useAVX2 {
		s, b := sliceForAppend(s, encodingSize11)
		ringCompressAndEncode11AVX2(b, f)
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
	ringCompressAndEncode1AVX2(b, f)
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

	// Keep rejUniformAMD64 on its len==24 fast path, but amortize SHAKE.Read
	// overhead by filling seven 24-byte chunks per squeeze.
	var batch [168]byte

	for j < n {
		B.Read(batch[:])
		for off := 0; off < len(batch) && j < n; off += 24 {
			j += rejUniformAMD64(batch[off:off+24], &a, j)
		}
	}
	return a
}

func sampleNTTx4(rho []byte, indices [4][2]byte) [4]nttElement {
	var xof keccakx4.SHAKE128x4
	xof.AbsorbSeed(rho, indices)

	var results [4]nttElement
	var j [4]int
	var batch [4][168]byte

	for {
		xof.Squeeze(batch[0][:], batch[1][:], batch[2][:], batch[3][:])
		allDone := true
		for lane := range 4 {
			if j[lane] >= n {
				continue
			}
			for off := 0; off < 168 && j[lane] < n; off += 24 {
				j[lane] += rejUniformAMD64(batch[lane][off:off+24], &results[lane], j[lane])
			}
			if j[lane] < n {
				allDone = false
			}
		}
		if allDone {
			break
		}
	}
	return results
}
