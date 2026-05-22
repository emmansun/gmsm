// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import "github.com/emmansun/gmsm/internal/deps/cpu"

var useLASX = cpu.Loong64.HasLASX

// nttZetasL2PrecompLASX stores twiddle factors for NTT layer 6 (len=2, 64 groups).
// Each vector entry (8 int32) holds 4 consecutive group zetas in scrambled order:
// [z_g2, z_g2, z_g0, z_g0 | z_g3, z_g3, z_g1, z_g1]
// Total: 16 entries × 8 int32 = 128 int32 values.
var nttZetasL2PrecompLASX [128]fieldElement

// nttZetasL1PrecompLASX stores twiddle factors for NTT layer 7 (len=1, 128 groups).
// Each vector entry (8 int32) holds 8 consecutive group zetas in scrambled order:
// [z_g4, z_g5, z_g0, z_g1 | z_g6, z_g7, z_g2, z_g3]
// Total: 16 entries × 8 int32 = 128 int32 values.
var nttZetasL1PrecompLASX [128]fieldElement

// inttQMinusZetasL2PrecompLASX stores twiddle factors for INTT layer 1 (len=2, 64 groups).
// Same layout as nttZetasL2PrecompLASX but with q - zetasMontgomery[k] values
// and processed in reverse k order.
var inttQMinusZetasL2PrecompLASX [128]fieldElement

// inttQMinusZetasL1PrecompLASX stores twiddle factors for INTT layer 0 (len=1, 128 groups).
// Same layout as nttZetasL1PrecompLASX but with q - zetasMontgomery[k] values.
var inttQMinusZetasL1PrecompLASX [128]fieldElement

func init() {
	// NTT L6 (len=2, 64 groups): zetas k=64..127, 4 groups per vector.
	// Block b (b=0..15): groups 4b..4b+3, zetas z64+4b..z64+4b+3.
	// Scrambled layout: [z2,z2,z0,z0 | z3,z3,z1,z1] where z0=zetasMontgomery[64+4b].
	for b := 0; b < 16; b++ {
		base := b * 8
		z0 := zetasMontgomery[64+4*b]
		z1 := zetasMontgomery[65+4*b]
		z2 := zetasMontgomery[66+4*b]
		z3 := zetasMontgomery[67+4*b]
		nttZetasL2PrecompLASX[base+0] = z2
		nttZetasL2PrecompLASX[base+1] = z2
		nttZetasL2PrecompLASX[base+2] = z0
		nttZetasL2PrecompLASX[base+3] = z0
		nttZetasL2PrecompLASX[base+4] = z3
		nttZetasL2PrecompLASX[base+5] = z3
		nttZetasL2PrecompLASX[base+6] = z1
		nttZetasL2PrecompLASX[base+7] = z1
	}

	// NTT L7 (len=1, 128 groups): zetas k=128..255, 8 groups per vector.
	// Block b (b=0..15): groups 8b..8b+7, zetas z128+8b..z128+8b+7.
	// Scrambled layout: [z4,z5,z0,z1 | z6,z7,z2,z3].
	for b := 0; b < 16; b++ {
		base := b * 8
		z0 := zetasMontgomery[128+8*b]
		z1 := zetasMontgomery[129+8*b]
		z2 := zetasMontgomery[130+8*b]
		z3 := zetasMontgomery[131+8*b]
		z4 := zetasMontgomery[132+8*b]
		z5 := zetasMontgomery[133+8*b]
		z6 := zetasMontgomery[134+8*b]
		z7 := zetasMontgomery[135+8*b]
		nttZetasL1PrecompLASX[base+0] = z4
		nttZetasL1PrecompLASX[base+1] = z5
		nttZetasL1PrecompLASX[base+2] = z0
		nttZetasL1PrecompLASX[base+3] = z1
		nttZetasL1PrecompLASX[base+4] = z6
		nttZetasL1PrecompLASX[base+5] = z7
		nttZetasL1PrecompLASX[base+6] = z2
		nttZetasL1PrecompLASX[base+7] = z3
	}

	// INTT L1 (len=2, 64 groups): q-zeta k=127..64, 4 groups per vector.
	// Block b (b=0..15): groups 4b..4b+3, k=127-4b..124-4b.
	// qmz[i] = q - zetasMontgomery[127-4b-i].
	// Scrambled layout: [qmz2,qmz2,qmz0,qmz0 | qmz3,qmz3,qmz1,qmz1].
	for b := 0; b < 16; b++ {
		base := b * 8
		qmz0 := q - zetasMontgomery[127-4*b]
		qmz1 := q - zetasMontgomery[126-4*b]
		qmz2 := q - zetasMontgomery[125-4*b]
		qmz3 := q - zetasMontgomery[124-4*b]
		inttQMinusZetasL2PrecompLASX[base+0] = qmz2
		inttQMinusZetasL2PrecompLASX[base+1] = qmz2
		inttQMinusZetasL2PrecompLASX[base+2] = qmz0
		inttQMinusZetasL2PrecompLASX[base+3] = qmz0
		inttQMinusZetasL2PrecompLASX[base+4] = qmz3
		inttQMinusZetasL2PrecompLASX[base+5] = qmz3
		inttQMinusZetasL2PrecompLASX[base+6] = qmz1
		inttQMinusZetasL2PrecompLASX[base+7] = qmz1
	}

	// INTT L0 (len=1, 128 groups): q-zeta k=255..128, 8 groups per vector.
	// Block b (b=0..15): groups 8b..8b+7, k=255-8b..248-8b.
	// qmz[i] = q - zetasMontgomery[255-8b-i].
	// Scrambled layout: [qmz4,qmz5,qmz0,qmz1 | qmz6,qmz7,qmz2,qmz3].
	for b := 0; b < 16; b++ {
		base := b * 8
		qmz0 := q - zetasMontgomery[255-8*b]
		qmz1 := q - zetasMontgomery[254-8*b]
		qmz2 := q - zetasMontgomery[253-8*b]
		qmz3 := q - zetasMontgomery[252-8*b]
		qmz4 := q - zetasMontgomery[251-8*b]
		qmz5 := q - zetasMontgomery[250-8*b]
		qmz6 := q - zetasMontgomery[249-8*b]
		qmz7 := q - zetasMontgomery[248-8*b]
		inttQMinusZetasL1PrecompLASX[base+0] = qmz4
		inttQMinusZetasL1PrecompLASX[base+1] = qmz5
		inttQMinusZetasL1PrecompLASX[base+2] = qmz0
		inttQMinusZetasL1PrecompLASX[base+3] = qmz1
		inttQMinusZetasL1PrecompLASX[base+4] = qmz6
		inttQMinusZetasL1PrecompLASX[base+5] = qmz7
		inttQMinusZetasL1PrecompLASX[base+6] = qmz2
		inttQMinusZetasL1PrecompLASX[base+7] = qmz3
	}
}

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
