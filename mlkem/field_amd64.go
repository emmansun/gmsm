// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package mlkem

import "github.com/emmansun/gmsm/internal/deps/cpu"

var useAVX2 = cpu.X86.HasAVX2

//go:noescape
func internalNTTAVX2(f *ringElement)

//go:noescape
func internalInverseNTTAVX2(f *nttElement)

//go:noescape
func internalNTTMulAccAVX2(acc, lhs, rhs *nttElement)

//go:noescape
func internalNTTMulAccKeyGenAVX2(acc, lhs, rhs *nttElement)

func nttMulAcc(acc, lhs, rhs *nttElement) {
	if useAVX2 {
		internalNTTMulAccAVX2(acc, lhs, rhs)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}

func internalNTT(f *ringElement) {
	if useAVX2 {
		internalNTTAVX2(f)
		return
	}
	internalNTTGeneric(f)
}

func internalInverseNTT(f *nttElement) {
	if useAVX2 {
		internalInverseNTTAVX2(f)
		return
	}
	internalInverseNTTGeneric(f)
}

func nttMulAccKeyGen(acc, lhs, rhs *nttElement) {
	if useAVX2 {
		internalNTTMulAccKeyGenAVX2(acc, lhs, rhs)
		return
	}
	nttMulAccGeneric(acc, lhs, rhs)
}
