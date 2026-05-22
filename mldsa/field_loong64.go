// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import "github.com/emmansun/gmsm/internal/deps/cpu"

var useLASX = cpu.Loong64.HasLASX

//go:noescape
func polyAddAssignLASX(dst, src *fieldElement)

//go:noescape
func polySubAssignLASX(dst, src *fieldElement)

//go:noescape
func nttMulLASX(lhs, rhs, out *nttElement)

//go:noescape
func nttMulAccLASX(lhs, rhs, out *nttElement)

//go:noescape
func nttMatRowVecMulLASX(dst, vec, matRow *nttElement, length int)

//go:noescape
func internalNTTLASX(f *ringElement)

//go:noescape
func internalInverseNTTLASX(f *nttElement)

//go:noescape
func polyInfinityNormLASX(a *fieldElement) uint32

//go:noescape
func polyInfinityNormSignedLASX(a *int32) uint32

//go:noescape
func decomposeSubToR0Gamma32LASX(w, cs2 *fieldElement, out *int32)

//go:noescape
func decomposeSubToR0Gamma88LASX(w, cs2 *fieldElement, out *int32)

//go:noescape
func useHintPolyGamma32LASX(h, r, out *fieldElement)

//go:noescape
func useHintPolyGamma88LASX(h, r, out *fieldElement)

//go:noescape
func makeHintPolyGamma32LASX(ct0, cs2, w, hint *fieldElement)

//go:noescape
func makeHintPolyGamma88LASX(ct0, cs2, w, hint *fieldElement)

func nttMul(out, lhs, rhs *nttElement) {
	if useLASX {
		nttMulLASX(lhs, rhs, out)
		return
	}
	nttMulGeneric(out, lhs, rhs)
}

func nttMulAcc(acc, lhs, rhs *nttElement) {
	if useLASX {
		nttMulAccLASX(lhs, rhs, acc)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}

func nttMatRowVecMul(dst, vec, matRow *nttElement, len int) {
	if useLASX {
		nttMatRowVecMulLASX(dst, vec, matRow, len)
		return
	}
	nttMatRowVecMulGeneric(dst, vec, matRow, len)
}

func polyAddAssign[T ~[n]fieldElement](dst, src *T) {
	if useLASX {
		polyAddAssignLASX(&(*dst)[0], &(*src)[0])
		return
	}
	polyAddGeneric(dst, src)
}

func polySubAssign[T ~[n]fieldElement](dst, src *T) {
	if useLASX {
		polySubAssignLASX(&(*dst)[0], &(*src)[0])
		return
	}
	polySubGeneric(dst, src)
}

func polyInfinityNorm[T ~[n]fieldElement](a *T, norm int) int {
	if useLASX {
		current := uint32(norm)
		return int(maxUint32(current, polyInfinityNormLASX(&(*a)[0])))
	}
	return polyInfinityNormGeneric(a, norm)
}

func polyInfinityNormSigned(a *[n]int32, norm int) int {
	if useLASX {
		current := uint32(norm)
		return int(maxUint32(current, polyInfinityNormSignedLASX(&(*a)[0])))
	}
	return polyInfinityNormSignedGeneric(a, norm)
}

func decomposeSubToR0(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32) {
	if useLASX {
		switch gamma2 {
		case gamma2QMinus1Div32:
			decomposeSubToR0Gamma32LASX(&(*w)[0], &(*cs2)[0], &(*dst)[0])
			return
		case gamma2QMinus1Div88:
			decomposeSubToR0Gamma88LASX(&(*w)[0], &(*cs2)[0], &(*dst)[0])
			return
		}
	}
	decomposeSubToR0Generic(dst, w, cs2, gamma2)
}

func useHintPoly(dst, h, r *ringElement, gamma2 uint32) {
	if useLASX {
		switch gamma2 {
		case gamma2QMinus1Div32:
			useHintPolyGamma32LASX(&(*h)[0], &(*r)[0], &(*dst)[0])
			return
		case gamma2QMinus1Div88:
			useHintPolyGamma88LASX(&(*h)[0], &(*r)[0], &(*dst)[0])
			return
		}
	}
	useHintPolyGeneric(dst, h, r, gamma2)
}

func vectorMakeHint(ct0, cs2, w, hint []ringElement, gamma2 uint32) {
	if useLASX {
		switch gamma2 {
		case gamma2QMinus1Div32:
			for i := range ct0 {
				makeHintPolyGamma32LASX(&ct0[i][0], &cs2[i][0], &w[i][0], &hint[i][0])
			}
			return
		case gamma2QMinus1Div88:
			for i := range ct0 {
				makeHintPolyGamma88LASX(&ct0[i][0], &cs2[i][0], &w[i][0], &hint[i][0])
			}
			return
		}
	}
	vectorMakeHintGeneric(ct0, cs2, w, hint, gamma2)
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
