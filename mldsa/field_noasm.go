// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package mldsa

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

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTGeneric(f)
}
