// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

var qMinusZetasMontgomeryARM64 [n]fieldElement
var qMinusZetasMontgomeryL0ReorderedARM64 [128]fieldElement
var zetasMontgomeryL6ReorderedARM64 [128]fieldElement
var zetasQNegInvLo32ARM64 [n]uint32
var zetasQNegInvLo32L6ReorderedARM64 [128]uint32
var qMinusZetasMontgomeryL1ReorderedARM64 [128]fieldElement

func init() {
	for i := 0; i < n; i++ {
		qMinusZetasMontgomeryARM64[i] = q - zetasMontgomery[i]
		zetasQNegInvLo32ARM64[i] = uint32(uint64(zetasMontgomery[i]) * uint64(qNegInv))
	}
	for i := 0; i < 128; i++ {
		qMinusZetasMontgomeryL0ReorderedARM64[i] = qMinusZetasMontgomeryARM64[255-i]
	}
	for i := 0; i < 32; i++ {
		z0 := zetasMontgomery[64+2*i]
		z1 := zetasMontgomery[64+2*i+1]
		z0MulQNegInvLow32 := zetasQNegInvLo32ARM64[64+2*i]
		z1MulQNegInvLow32 := zetasQNegInvLo32ARM64[64+2*i+1]
		j := 4 * i
		zetasMontgomeryL6ReorderedARM64[j+0] = z0
		zetasMontgomeryL6ReorderedARM64[j+1] = z0
		zetasMontgomeryL6ReorderedARM64[j+2] = z1
		zetasMontgomeryL6ReorderedARM64[j+3] = z1
		zetasQNegInvLo32L6ReorderedARM64[j+0] = z0MulQNegInvLow32
		zetasQNegInvLo32L6ReorderedARM64[j+1] = z0MulQNegInvLow32
		zetasQNegInvLo32L6ReorderedARM64[j+2] = z1MulQNegInvLow32
		zetasQNegInvLo32L6ReorderedARM64[j+3] = z1MulQNegInvLow32

		qz0 := qMinusZetasMontgomeryARM64[127-2*i]
		qz1 := qMinusZetasMontgomeryARM64[127-(2*i+1)]
		qMinusZetasMontgomeryL1ReorderedARM64[j+0] = qz0
		qMinusZetasMontgomeryL1ReorderedARM64[j+1] = qz0
		qMinusZetasMontgomeryL1ReorderedARM64[j+2] = qz1
		qMinusZetasMontgomeryL1ReorderedARM64[j+3] = qz1
	}
}

//go:noescape
func nttMulNEON(lhs, rhs, out *nttElement)

//go:noescape
func nttMulAccNEON(lhs, rhs, out *nttElement)

//go:noescape
func internalNTTNEON(f *ringElement)

//go:noescape
func internalInverseNTTNEON(f *nttElement)

//go:noescape
func polyAddAssignNEON(dst, src *fieldElement)

//go:noescape
func polySubAssignNEON(dst, src *fieldElement)

//go:noescape
func polyInfinityNormNEON(a *fieldElement) uint32

//go:noescape
func polyInfinityNormSignedNEON(a *int32) uint32

//go:noescape
func decomposeSubToR0Gamma32ARM64(w, cs2 *fieldElement, out *int32)

//go:noescape
func decomposeSubToR0Gamma88ARM64(w, cs2 *fieldElement, out *int32)

//go:noescape
func useHintPolyGamma32ARM64(h, r, out *fieldElement)

//go:noescape
func useHintPolyGamma88ARM64(h, r, out *fieldElement)

//go:noescape
func makeHintPolyGamma32NEON(ct0, cs2, w, hint *fieldElement)

//go:noescape
func makeHintPolyGamma88NEON(ct0, cs2, w, hint *fieldElement)

func nttMul(out, lhs, rhs *nttElement) {
	nttMulNEON(lhs, rhs, out)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	nttMulAccNEON(lhs, rhs, acc)
}

func polyAddAssign[T ~[n]fieldElement](dst, src *T) {
	polyAddAssignNEON(&(*dst)[0], &(*src)[0])
}

func polySubAssign[T ~[n]fieldElement](dst, src *T) {
	polySubAssignNEON(&(*dst)[0], &(*src)[0])
}

func polyInfinityNorm[T ~[n]fieldElement](a *T, norm int) int {
	current := uint32(norm)
	return int(maxUint32(current, polyInfinityNormNEON(&(*a)[0])))
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	current := uint32(norm)
	return int(maxUint32(current, polyInfinityNormSignedNEON(&(*a)[0])))
}

func decomposeSubToR0(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32) {
	switch gamma2 {
	case gamma2QMinus1Div32:
		decomposeSubToR0Gamma32ARM64(&(*w)[0], &(*cs2)[0], &(*dst)[0])
	case gamma2QMinus1Div88:
		decomposeSubToR0Gamma88ARM64(&(*w)[0], &(*cs2)[0], &(*dst)[0])
	default:
		decomposeSubToR0Generic(dst, w, cs2, gamma2)
	}
}

func useHintPoly(dst, h, r *ringElement, gamma2 uint32) {
	switch gamma2 {
	case gamma2QMinus1Div32:
		useHintPolyGamma32ARM64(&(*h)[0], &(*r)[0], &(*dst)[0])
	case gamma2QMinus1Div88:
		useHintPolyGamma88ARM64(&(*h)[0], &(*r)[0], &(*dst)[0])
	default:
		useHintPolyGeneric(dst, h, r, gamma2)
	}
}

func vectorMakeHint(ct0, cs2, w, hint []ringElement, gamma2 uint32) {
	switch gamma2 {
	case gamma2QMinus1Div32:
		for i := range ct0 {
			makeHintPolyGamma32NEON(&ct0[i][0], &cs2[i][0], &w[i][0], &hint[i][0])
		}
	case gamma2QMinus1Div88:
		for i := range ct0 {
			makeHintPolyGamma88NEON(&ct0[i][0], &cs2[i][0], &w[i][0], &hint[i][0])
		}
	default:
		vectorMakeHintGeneric(ct0, cs2, w, hint, gamma2)
	}
}

func internalNTT(f *ringElement) {
	internalNTTNEON(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTNEON(f)
}
