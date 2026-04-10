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
	decomposeSubToR0Generic(dst, w, cs2, gamma2)
}

func useHintPoly(dst, h, r *ringElement, gamma2 uint32) {
	useHintPolyGeneric(dst, h, r, gamma2)
}

func internalNTT(f *ringElement) {
	internalNTTNEON(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTNEON(f)
}
