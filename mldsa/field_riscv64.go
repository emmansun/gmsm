// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.26 && !purego

package mldsa

import "github.com/emmansun/gmsm/internal/deps/cpu"

var hasRVV = cpu.RISCV64.HasV

//go:noescape
func polyAddAssignRVV(dst, src *fieldElement)

//go:noescape
func polySubAssignRVV(dst, src *fieldElement)

//go:noescape
func nttMulRVV(lhs, rhs, out *nttElement)

func nttMul(out, lhs, rhs *nttElement) {
	if !hasRVV {
		nttMulGeneric(out, lhs, rhs)
		return
	}

	nttMulRVV(lhs, rhs, out)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	nttMulAccGeneric(acc, lhs, rhs)
}

func nttMatRowVecMul(dst, vec, matRow *nttElement, len int) {
	nttMatRowVecMulGeneric(dst, vec, matRow, len)
}

// polyAddAssign updates dst as dst += src (fallback to generic).
func polyAddAssign[T ~[n]fieldElement](dst, src *T) {
	if !hasRVV {
		polyAddGeneric(dst, src)
		return
	}
	polyAddAssignRVV(&(*dst)[0], &(*src)[0])
}

// polySubAssign updates dst as dst -= src (fallback to generic).
func polySubAssign[T ~[n]fieldElement](dst, src *T) {
	if !hasRVV {
		polySubGeneric(dst, src)
		return
	}
	polySubAssignRVV(&(*dst)[0], &(*src)[0])
}

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTGeneric(f)
}

func decomposeSubToR0(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32) {
	decomposeSubToR0Generic(dst, w, cs2, gamma2)
}

func useHintPoly(dst, h, r *ringElement, gamma2 uint32) {
	useHintPolyGeneric(dst, h, r, gamma2)
}

func vectorMakeHint(ct0, cs2, w, hint []ringElement, gamma2 uint32) {
	vectorMakeHintGeneric(ct0, cs2, w, hint, gamma2)
}

func polyInfinityNorm[T ~[n]fieldElement](a *T, norm int) int {
	return polyInfinityNormGeneric(a, norm)
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	return polyInfinityNormSignedGeneric(a, norm)
}
