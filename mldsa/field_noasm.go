// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package mldsa

func polyInfinityNorm[T ~[n]fieldElement](a *T, norm int) int {
	return polyInfinityNormGeneric(a, norm)
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	return polyInfinityNormSignedGeneric(a, norm)
}

func nttMul(out, lhs, rhs *nttElement) {
	nttMulGeneric(out, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	nttMulAccGeneric(acc, lhs, rhs)
}

// polyAddAssign updates dst as dst += src (fallback to generic).
func polyAddAssign[T ~[n]fieldElement](dst, src *T) {
	polyAddGeneric(dst, src)
}

// polySubAssign updates dst as dst -= src (fallback to generic).
func polySubAssign[T ~[n]fieldElement](dst, src *T) {
	polySubGeneric(dst, src)
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
