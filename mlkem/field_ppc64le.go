// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build ppc64le && !purego

package mlkem

import (
	"crypto/sha3"
)

// No runtime VMX detection needed:
// ppc64le Linux requires minimum POWER8, which mandates VMX+VSX unconditionally.

// nttTwiddleL5PrecompPPC64LE stores 8 VMX vectors (128-bit each), each as [z0×4, z1×4] (8×int16),
// from zetas[16..31] in plain (Barrett) form.
var nttTwiddleL5PrecompPPC64LE [64]fieldElement

// nttTwiddleL4PrecompPPC64LE stores 16 VMX vectors, each as [z0×2, z1×2, z2×2, z3×2],
// from zetas[32..63] in plain (Barrett) form.
var nttTwiddleL4PrecompPPC64LE [128]fieldElement

// nttTwiddleL2PrecompPPC64LE stores 32 VMX vectors with interleaved 2-element layout,
// from zetas[64..127] in plain (Barrett) form.
var nttTwiddleL2PrecompPPC64LE [256]fieldElement

// inttTwiddleL5PrecompPPC64LE: inverse NTT zetas for layer 5 (reverse order of forward).
var inttTwiddleL5PrecompPPC64LE [64]fieldElement

// inttTwiddleL4PrecompPPC64LE: inverse NTT zetas for layer 4.
var inttTwiddleL4PrecompPPC64LE [128]fieldElement

// inttTwiddleL2PrecompPPC64LE: inverse NTT zetas for layer 2.
var inttTwiddleL2PrecompPPC64LE [256]fieldElement

// inverseDegreeVecPPC64LE broadcasts kInverseDegree=3303 (= 128⁻¹ mod q) for INTT final scaling.
var inverseDegreeVecPPC64LE [8]fieldElement

// nttGammaU32PPC64LE stores gammas[0..127] as uint32 for Barrett nttMulAcc.
// Each group of 4 gammas (processed per VMX iteration) is stored as [g1,g0,g3,g2]
// in LE uint32 format. LXVD2X (reverses within each 8-byte group) then loads
// them as [g0,g1,g2,g3] as 4 uint32 for direct VMULUWM multiplication.
// Extra 16 bytes of padding prevent out-of-bounds reads at the last iteration.
// (128 gammas × 4 bytes each = 512 bytes + 16 = 128 + 4 elements = 132 uint32)
var nttGammaU32PPC64LE [132]uint32

func init() {
	// Forward NTT twiddle tables (Barrett form: plain zeta values, not Montgomery)

	// Layer 5 (len=8): 8 blocks of 2 zetas, each broadcast to 4 lanes
	// zetas[16..31]: block i uses zetas[16+2*i] and zetas[16+2*i+1]
	for block := 0; block < 8; block++ {
		base := block * 8
		z := 16 + block*2
		for i := 0; i < 4; i++ {
			nttTwiddleL5PrecompPPC64LE[base+i] = zetas[z]
			nttTwiddleL5PrecompPPC64LE[base+4+i] = zetas[z+1]
		}
	}

	// Layer 4 (len=16): 8 blocks of 4 zetas, each broadcast to 2 lanes
	// zetas[32..63]: block i uses zetas[32+4*i..32+4*i+3]
	for block := 0; block < 8; block++ {
		base := block * 16
		z := 32 + block*4
		for i := 0; i < 2; i++ {
			nttTwiddleL4PrecompPPC64LE[base+i] = zetas[z]
			nttTwiddleL4PrecompPPC64LE[base+2+i] = zetas[z+1]
			nttTwiddleL4PrecompPPC64LE[base+4+i] = zetas[z+2]
			nttTwiddleL4PrecompPPC64LE[base+6+i] = zetas[z+3]
		}
		// second vector for this block (same 4 zetas, same layout)
		base2 := base + 8
		for i := 0; i < 2; i++ {
			nttTwiddleL4PrecompPPC64LE[base2+i] = zetas[z]
			nttTwiddleL4PrecompPPC64LE[base2+2+i] = zetas[z+1]
			nttTwiddleL4PrecompPPC64LE[base2+4+i] = zetas[z+2]
			nttTwiddleL4PrecompPPC64LE[base2+6+i] = zetas[z+3]
		}
	}

	// Layer 2 (len=2): 8 blocks of 8 zetas, interleaved pairs
	// zetas[64..127]: block i uses zetas[64+8*i..64+8*i+7]
	for block := 0; block < 8; block++ {
		base := block * 32
		z := 64 + block*8
		// Each pair of zetas fills one VMX vector (8 × int16)
		// Layout: [z0,z0,z1,z1,z2,z2,z3,z3] then [z4,z4,z5,z5,z6,z6,z7,z7]
		for i := 0; i < 4; i++ {
			nttTwiddleL2PrecompPPC64LE[base+i*2] = zetas[z+i]
			nttTwiddleL2PrecompPPC64LE[base+i*2+1] = zetas[z+i]
		}
		base2 := base + 8
		for i := 0; i < 4; i++ {
			nttTwiddleL2PrecompPPC64LE[base2+i*2] = zetas[z+4+i]
			nttTwiddleL2PrecompPPC64LE[base2+i*2+1] = zetas[z+4+i]
		}
		// Repeat for the remaining 16 entries (4 more vectors, covering layer 1 len=2 within block)
		base3 := base + 16
		for i := 0; i < 4; i++ {
			nttTwiddleL2PrecompPPC64LE[base3+i*2] = zetas[z+i]
			nttTwiddleL2PrecompPPC64LE[base3+i*2+1] = zetas[z+i]
		}
		base4 := base + 24
		for i := 0; i < 4; i++ {
			nttTwiddleL2PrecompPPC64LE[base4+i*2] = zetas[z+4+i]
			nttTwiddleL2PrecompPPC64LE[base4+i*2+1] = zetas[z+4+i]
		}
	}

	// Inverse NTT twiddle tables (reverse order of forward, plain zeta values)
	for block := 0; block < 8; block++ {
		base := block * 8
		iz := 31 - block*2
		for i := 0; i < 4; i++ {
			inttTwiddleL5PrecompPPC64LE[base+i] = zetas[iz]
			inttTwiddleL5PrecompPPC64LE[base+4+i] = zetas[iz-1]
		}

		base4 := block * 16
		iz4 := 63 - block*4
		for i := 0; i < 2; i++ {
			inttTwiddleL4PrecompPPC64LE[base4+i] = zetas[iz4]
			inttTwiddleL4PrecompPPC64LE[base4+2+i] = zetas[iz4-1]
			inttTwiddleL4PrecompPPC64LE[base4+4+i] = zetas[iz4-2]
			inttTwiddleL4PrecompPPC64LE[base4+6+i] = zetas[iz4-3]
		}
		base42 := base4 + 8
		for i := 0; i < 2; i++ {
			inttTwiddleL4PrecompPPC64LE[base42+i] = zetas[iz4]
			inttTwiddleL4PrecompPPC64LE[base42+2+i] = zetas[iz4-1]
			inttTwiddleL4PrecompPPC64LE[base42+4+i] = zetas[iz4-2]
			inttTwiddleL4PrecompPPC64LE[base42+6+i] = zetas[iz4-3]
		}

		base2 := block * 32
		iz2 := 127 - block*8
		for i := 0; i < 4; i++ {
			inttTwiddleL2PrecompPPC64LE[base2+i*2] = zetas[iz2-i]
			inttTwiddleL2PrecompPPC64LE[base2+i*2+1] = zetas[iz2-i]
		}
		base22 := base2 + 8
		for i := 0; i < 4; i++ {
			inttTwiddleL2PrecompPPC64LE[base22+i*2] = zetas[iz2-4-i]
			inttTwiddleL2PrecompPPC64LE[base22+i*2+1] = zetas[iz2-4-i]
		}
		base23 := base2 + 16
		for i := 0; i < 4; i++ {
			inttTwiddleL2PrecompPPC64LE[base23+i*2] = zetas[iz2-i]
			inttTwiddleL2PrecompPPC64LE[base23+i*2+1] = zetas[iz2-i]
		}
		base24 := base2 + 24
		for i := 0; i < 4; i++ {
			inttTwiddleL2PrecompPPC64LE[base24+i*2] = zetas[iz2-4-i]
			inttTwiddleL2PrecompPPC64LE[base24+i*2+1] = zetas[iz2-4-i]
		}
	}

	// INTT final scaling: 3303 = 128⁻¹ mod q
	for i := range inverseDegreeVecPPC64LE {
		inverseDegreeVecPPC64LE[i] = 3303
	}

	// nttGammaU32PPC64LE: gammas for Barrett nttMulAcc as uint32, stored for LXVD2X.
	// Each 8-byte group (2 uint32) is stored in reversed pair order:
	// [g1,g0, g3,g2] as LE uint32 → LXVD2X byte-reversal gives [g0,g1,g2,g3] as uint32. ✓
	for i := 0; i < 32; i++ {
		base := i * 4
		nttGammaU32PPC64LE[4*i+0] = uint32(gammas[base+1]) // g1 in first position of pair
		nttGammaU32PPC64LE[4*i+1] = uint32(gammas[base+0]) // g0 in second position
		nttGammaU32PPC64LE[4*i+2] = uint32(gammas[base+3]) // g3 in first position of pair
		nttGammaU32PPC64LE[4*i+3] = uint32(gammas[base+2]) // g2 in second position
	}
}

//go:noescape
func polyAddAssignPPC64LE(dst, src *ringElement)

//go:noescape
func polySubAssignPPC64LE(dst, src *ringElement)

//go:noescape
func internalNTTPPC64LE(f *ringElement)

//go:noescape
func internalInverseNTTPPC64LE(f *nttElement)

//go:noescape
func internalNTTMulPPC64LE(out, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccPPC64LE(acc, lhs, rhs *nttElement)

//go:noescape
func ringCompressAndEncode1PPC64LE(out []byte, f *ringElement)

//go:noescape
func ringCompressAndEncode4PPC64LE(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress4PPC64LE(b *[encodingSize4]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode5PPC64LE(out []byte, f *ringElement)

//go:noescape
func ringDecodeAndDecompress5PPC64LE(b *[encodingSize5]byte, f *ringElement)

//go:noescape
func ringCompressAndEncode10PPC64LE(out []byte, f *ringElement)

//go:noescape
func ringCompressAndEncode11PPC64LE(out []byte, f *ringElement)

//go:noescape
func decodeAndDecompressU10PPC64LE(dst []ringElement, c []byte)

//go:noescape
func decodeAndDecompressU11PPC64LE(dst []ringElement, c []byte)

//go:noescape
func samplePolyCBD2PPC64LE(f *ringElement, buf *[128]byte)

//go:noescape
func samplePolyCBD3PPC64LE(f *ringElement, buf *[192]byte)

//go:noescape
func rejUniformPPC64LE(buf []byte, a *nttElement, j int) int

func nttMul(acc, lhs, rhs *nttElement) {
	internalNTTMulPPC64LE(acc, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	internalNTTMulAccPPC64LE(acc, lhs, rhs)
}

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTGeneric(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	internalNTTMulAccPPC64LE(acc, lhs, rhs)
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
	polyAddAssignPPC64LE(dst, src)
}

func polySubAssign(dst *ringElement, src *ringElement) {
	polySubAssignPPC64LE(dst, src)
}

// ringCompressAndEncode4 appends a 128-byte encoding of a ring element to s,
// compressing two coefficients per byte.
func ringCompressAndEncode4(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	ringCompressAndEncode4Generic(b, f)
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
func ringDecodeAndDecompress4(b *[encodingSize4]byte, f *ringElement) {
	ringDecodeAndDecompress4Generic(b, f)
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s.
func ringCompressAndEncode5(s []byte, f *ringElement) []byte {
	return ringCompressAndEncode(s, f, 5)
}

// ringDecodeAndDecompress5 decodes a 160-byte encoding of a ring element.
func ringDecodeAndDecompress5(bb *[encodingSize5]byte) ringElement {
	return ringDecodeAndDecompress(bb[:], 5)
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s.
func ringCompressAndEncode10(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	ringCompressAndEncode10Generic(b, f)
	return s
}

// ringCompressAndEncode11 appends a 352-byte encoding of a ring element to s.
func ringCompressAndEncode11(s []byte, f *ringElement) []byte {
	return ringCompressAndEncode(s, f, 11)
}

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s.
func ringCompressAndEncode1(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	clear(b)
	ringCompressAndEncode1Generic(b, f)
	return s
}

// sampleNTT draws a uniformly random nttElement from a stream of uniformly
// random bytes generated by the XOF function, according to FIPS 203, Algorithm 7.
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewSHAKE128()
	B.Write(rho)
	var domain [2]byte
	domain[0] = ii
	domain[1] = jj
	B.Write(domain[:])

	var a nttElement
	var j int

	var batch [168]byte
	for j < n {
		B.Read(batch[:])
		for off := 0; off < len(batch) && j < n; off += 24 {
			j += rejUniformGeneric(batch[off:off+24], &a, j)
		}
	}
	return a
}

func sampleNTTx4(rho []byte, indices [4][2]byte) [4]nttElement {
	return [4]nttElement{
		sampleNTT(rho, indices[0][0], indices[0][1]),
		sampleNTT(rho, indices[1][0], indices[1][1]),
		sampleNTT(rho, indices[2][0], indices[2][1]),
		sampleNTT(rho, indices[3][0], indices[3][1]),
	}
}
