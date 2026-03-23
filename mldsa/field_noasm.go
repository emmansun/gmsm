// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package mldsa

func nttMul(out, lhs, rhs *nttElement) {
	nttMulGeneric(out, lhs, rhs)
}

func internalNTT(f *ringElement) {
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	internalInverseNTTGeneric(f)
}
