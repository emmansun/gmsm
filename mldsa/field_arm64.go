// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package mldsa

// Phase 1 bring-up: route only nttMul to arm64 assembly.
// Other operations stay on generic implementations until verified.

//go:noescape
func nttMulNEON(lhs, rhs, out *nttElement)

//go:noescape
func nttMulAccNEON(lhs, rhs, out *nttElement)

func nttMul(out, lhs, rhs *nttElement) {
	nttMulNEON(lhs, rhs, out)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	nttMulAccNEON(acc, lhs, rhs)
}

func polyAddAssign[T ~[n]fieldElement](dst, src *T) {
	polyAddGeneric(dst, src)
}

func polySubAssign[T ~[n]fieldElement](dst, src *T) {
	polySubGeneric(dst, src)
}

func polyInfinityNorm[T ~[n]fieldElement](a *T, norm int) int {
	return polyInfinityNormGeneric(a, norm)
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	return polyInfinityNormSignedGeneric(a, norm)
}

func decomposeSubToR0(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32) {
	decomposeSubToR0Generic(dst, w, cs2, gamma2)
}

func useHintPoly(dst, h, r *ringElement, gamma2 uint32) {
	useHintPolyGeneric(dst, h, r, gamma2)
}

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTGeneric(f)
}
