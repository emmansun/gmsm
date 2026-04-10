// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

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
	return polyInfinityNormGeneric(a, norm)
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	return polyInfinityNormSignedGeneric(a, norm)
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

func internalNTT(f *ringElement) {
	internalNTTNEON(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTNEON(f)
}
