// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.26 && !purego

package mldsa

import "github.com/emmansun/gmsm/internal/deps/cpu"

var hasRVV = cpu.RISCV64.HasV

var zetasMontgomeryInverse [256]fieldElement

func init() {
	for i := 0; i < 256; i++ {
		zetasMontgomeryInverse[i] = zetasMontgomery[255-i]
	}
}

//go:noescape
func polyAddAssignRVV(dst, src *fieldElement)

//go:noescape
func polySubAssignRVV(dst, src *fieldElement)

//go:noescape
func nttMulRVV(lhs, rhs, out *nttElement)

//go:noescape
func nttMulAccRVV(acc, lhs, rhs *nttElement)

//go:noescape
func nttMatRowVecMulRVV(dst, vec, matRow *nttElement, len int)

//go:noescape
func internalNTTRVV(f *ringElement)

//go:noescape
func internalInverseNTTRVV(f *nttElement)

//go:noescape
func decomposeSubToR0Gamma32RVV(w, cs2 *fieldElement, out *int32)

//go:noescape
func decomposeSubToR0Gamma88RVV(w, cs2 *fieldElement, out *int32)

func nttMul(out, lhs, rhs *nttElement) {
	if !hasRVV {
		nttMulGeneric(out, lhs, rhs)
		return
	}

	nttMulRVV(lhs, rhs, out)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	if !hasRVV {
		nttMulAccGeneric(acc, lhs, rhs)
		return
	}

	nttMulAccRVV(acc, lhs, rhs)
}

func nttMatRowVecMul(dst, vec, matRow *nttElement, len int) {
	if !hasRVV {
		nttMatRowVecMulGeneric(dst, vec, matRow, len)
		return
	}

	nttMatRowVecMulRVV(dst, vec, matRow, len)
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
	if !hasRVV {
		internalNTTGeneric(f)
		return
	}

	internalNTTRVV(f)
}

func internalInverseNTT(f *nttElement) {
	if !hasRVV {
		internalInverseNTTGeneric(f)
		return
	}

	internalInverseNTTRVV(f)
}

func decomposeSubToR0(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32) {
	if !hasRVV {
		decomposeSubToR0Generic(dst, w, cs2, gamma2)
		return
	}

	switch gamma2 {
	case gamma2QMinus1Div32:
		decomposeSubToR0Gamma32RVV(&w[0], &cs2[0], &dst[0])
	case gamma2QMinus1Div88:
		decomposeSubToR0Gamma88RVV(&w[0], &cs2[0], &dst[0])
	default:
		decomposeSubToR0Generic(dst, w, cs2, gamma2)
	}
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
