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

// nttTwiddleL1PrecompPPC64LE: 1 VMX vector, zeta[1] broadcast to 8 lanes.
var nttTwiddleL1PrecompPPC64LE [8]fieldElement

// nttTwiddleL2bPrecompPPC64LE: 2 VMX vectors, zeta[2] and zeta[3] each broadcast to 8 lanes.
var nttTwiddleL2bPrecompPPC64LE [16]fieldElement

// nttTwiddleL3PrecompPPC64LE: 4 VMX vectors, zeta[4..7] each broadcast to 8 lanes.
var nttTwiddleL3PrecompPPC64LE [32]fieldElement

// nttTwiddleL4bPrecompPPC64LE: 8 VMX vectors, zeta[8..15] each broadcast to 8 lanes.
var nttTwiddleL4bPrecompPPC64LE [64]fieldElement

// nttTwiddleL5PrecompPPC64LE: 16 VMX vectors, each as broadcast of one zeta,
// from zetas[16..31]. Each vector = z broadcast to 8 lanes.
var nttTwiddleL5PrecompPPC64LE [128]fieldElement

// nttTwiddleL4PrecompPPC64LE stores 16 VMX vectors, each as [z0×2, z1×2, z2×2, z3×2],
// from zetas[32..63] in plain (Barrett) form.
var nttTwiddleL4PrecompPPC64LE [128]fieldElement

// nttTwiddleL2PrecompPPC64LE stores 8 VMX vectors of 8 distinct zetas each,
// from zetas[64..127]. Each vector = [z_{8k}..z_{8k+7}] for iter k.
var nttTwiddleL2PrecompPPC64LE [128]fieldElement

// inttTwiddleL5PrecompPPC64LE: inverse NTT zetas for L5 (16 broadcast vectors, reverse order).
var inttTwiddleL5PrecompPPC64LE [128]fieldElement

// inttTwiddleL4PrecompPPC64LE: inverse NTT zetas for layer 4.
var inttTwiddleL4PrecompPPC64LE [128]fieldElement

// inttTwiddleL2PrecompPPC64LE: inverse NTT zetas for layer 2 (16 vecs of 8 = 128 entries).
var inttTwiddleL2PrecompPPC64LE [128]fieldElement

// inttTwiddleL1PrecompPPC64LE: INTT broadcast zeta tables for layers L1-L4b (reverse).
var inttTwiddleL1PrecompPPC64LE [8]fieldElement
var inttTwiddleL2bPrecompPPC64LE [16]fieldElement
var inttTwiddleL3PrecompPPC64LE [32]fieldElement
var inttTwiddleL4bPrecompPPC64LE [64]fieldElement

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

	// L1 (len=128): 1 zeta broadcast
	for i := range nttTwiddleL1PrecompPPC64LE {
		nttTwiddleL1PrecompPPC64LE[i] = zetas[1]
	}
	// L2 (len=64): 2 zetas, each broadcast
	for i := 0; i < 8; i++ {
		nttTwiddleL2bPrecompPPC64LE[i] = zetas[2]
		nttTwiddleL2bPrecompPPC64LE[8+i] = zetas[3]
	}
	// L3 (len=32): 4 zetas, each broadcast
	for g := 0; g < 4; g++ {
		for i := 0; i < 8; i++ {
			nttTwiddleL3PrecompPPC64LE[g*8+i] = zetas[4+g]
		}
	}
	// L4 (len=16): 8 zetas, each broadcast
	for g := 0; g < 8; g++ {
		for i := 0; i < 8; i++ {
			nttTwiddleL4bPrecompPPC64LE[g*8+i] = zetas[8+g]
		}
	}

	// Layer 5 (len=8): 16 iters, 1 group per iter, 1 zeta broadcast per iter.
	// zetas[16..31]: iter k uses zetas[16+k] broadcast to 8 lanes.
	for k := 0; k < 16; k++ {
		base := k * 8
		for i := 0; i < 8; i++ {
			nttTwiddleL5PrecompPPC64LE[base+i] = zetas[16+k]
		}
	}

	// Layer 6 (len=4): 16 iters, each covering 2 groups via XXPERMDI split.
	// Twiddle for iter k = [z_a×4, z_b×4], zetas[32+2k] and zetas[32+2k+1].
	for iter := 0; iter < 16; iter++ {
		base := iter * 8
		za := zetas[32+2*iter]
		zb := zetas[32+2*iter+1]
		for i := 0; i < 4; i++ {
			nttTwiddleL4PrecompPPC64LE[base+i] = za
		}
		for i := 0; i < 4; i++ {
			nttTwiddleL4PrecompPPC64LE[base+4+i] = zb
		}
	}

	// Layer 2 (len=2): 16 iters, each processes 4 groups (32 elements / 2 vectors).
	// Each group has 2 lo+2 hi elements sharing one zeta. 4 distinct zetas per iter, each ×2.
	// zetas[64..127]: iter k uses zetas[64+4k..64+4k+3], each stored twice.
	for block := 0; block < 16; block++ {
		base := block * 8
		z := 64 + block*4
		for i := 0; i < 4; i++ {
			nttTwiddleL2PrecompPPC64LE[base+i*2] = zetas[z+i]
			nttTwiddleL2PrecompPPC64LE[base+i*2+1] = zetas[z+i]
		}
	}

	// Inverse NTT twiddle tables (reverse order of forward, plain zeta values)

	// INTT L5 (forward len=8, INTT reverse): 16 iters, zetas[31..16] reversed broadcast.
	for k := 0; k < 16; k++ {
		base := k * 8
		for i := 0; i < 8; i++ {
			inttTwiddleL5PrecompPPC64LE[base+i] = zetas[31-k]
		}
	}

	// INTT L6 (forward len=4, INTT reverse): 16 iters, [za×4, zb×4], zetas[63..32] reversed.
	for iter := 0; iter < 16; iter++ {
		base := iter * 8
		za := zetas[63-2*iter]
		zb := zetas[63-2*iter-1]
		for i := 0; i < 4; i++ {
			inttTwiddleL4PrecompPPC64LE[base+i] = za
		}
		for i := 0; i < 4; i++ {
			inttTwiddleL4PrecompPPC64LE[base+4+i] = zb
		}
	}

	// INTT L7 (forward len=2, INTT reverse): 16 iters, 4 distinct zetas per iter, each ×2.
	// INTT at len=2 reverses the forward L7 groups in reverse order: zetas[127..64] reversed,
	// each broadcast twice (to match the lo/lo, hi/hi pair structure).
	for block := 0; block < 16; block++ {
		base := block * 8
		iz2 := 127 - block*4
		for i := 0; i < 4; i++ {
			inttTwiddleL2PrecompPPC64LE[base+i*2] = zetas[iz2-i]
			inttTwiddleL2PrecompPPC64LE[base+i*2+1] = zetas[iz2-i]
		}
	}

	// INTT final scaling: 3303 = 128⁻¹ mod q
	for i := range inverseDegreeVecPPC64LE {
		inverseDegreeVecPPC64LE[i] = 3303
	}

	// INTT broadcast tables for L1b-L4b (reverse order)
	for i := range inttTwiddleL1PrecompPPC64LE {
		inttTwiddleL1PrecompPPC64LE[i] = zetas[1]
	}
	for i := 0; i < 8; i++ {
		inttTwiddleL2bPrecompPPC64LE[i] = zetas[3]
		inttTwiddleL2bPrecompPPC64LE[8+i] = zetas[2]
	}
	for g := 0; g < 4; g++ {
		for i := 0; i < 8; i++ {
			inttTwiddleL3PrecompPPC64LE[g*8+i] = zetas[7-g]
		}
	}
	for g := 0; g < 8; g++ {
		for i := 0; i < 8; i++ {
			inttTwiddleL4bPrecompPPC64LE[g*8+i] = zetas[15-g]
		}
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
	internalNTTPPC64LE(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTPPC64LE(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	internalNTTMulAccPPC64LE(acc, lhs, rhs)
}

func decodeAndDecompressU10(dst []ringElement, c []byte) {
	decodeAndDecompressU10PPC64LE(dst, c)
}

func decodeAndDecompressU11(dst []ringElement, c []byte) {
	decodeAndDecompressU11PPC64LE(dst, c)
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
	ringCompressAndEncode4PPC64LE(b, f)
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
func ringDecodeAndDecompress4(b *[encodingSize4]byte, f *ringElement) {
	ringDecodeAndDecompress4PPC64LE(b, f)
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s.
func ringCompressAndEncode5(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize5)
	ringCompressAndEncode5PPC64LE(b, f)
	return s
}

// ringDecodeAndDecompress5 decodes a 160-byte encoding of a ring element.
func ringDecodeAndDecompress5(bb *[encodingSize5]byte) ringElement {
	var f ringElement
	ringDecodeAndDecompress5PPC64LE(bb, &f)
	return f
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s.
func ringCompressAndEncode10(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	ringCompressAndEncode10PPC64LE(b, f)
	return s
}

// ringCompressAndEncode11 appends a 352-byte encoding of a ring element to s.
func ringCompressAndEncode11(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize11)
	ringCompressAndEncode11PPC64LE(b, f)
	return s
}

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s.
func ringCompressAndEncode1(s []byte, f *ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	clear(b)
	ringCompressAndEncode1PPC64LE(b, f)
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
