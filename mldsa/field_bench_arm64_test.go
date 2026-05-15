// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulArm64Sink nttElement
var benchmarkInternalNTTArm64Sink ringElement
var benchmarkInverseNTTArm64Sink nttElement
var benchmarkPolyRingArm64Sink ringElement
var benchmarkPolyNTTArm64Sink nttElement
var benchmarkNormArm64Sink uint32
var benchmarkR0Arm64Sink [n]int32
var benchmarkHintArm64Sink ringElement

func BenchmarkNTTMulArm64(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMulGeneric(&out, &left, &right)
		}
		benchmarkNTTMulArm64Sink = out
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMul(&out, &left, &right)
		}
		benchmarkNTTMulArm64Sink = out
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMulNEON(&out, &left, &right)
		}
		benchmarkNTTMulArm64Sink = out
	})
}

func BenchmarkNTTMulAccArm64(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	base := ntt(randomRingElement())
	var acc nttElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAccGeneric(&acc, &left, &right)
		}
		benchmarkNTTMulArm64Sink = acc
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAcc(&acc, &left, &right)
		}
		benchmarkNTTMulArm64Sink = acc
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAccNEON(&left, &right, &acc)
		}
		benchmarkNTTMulArm64Sink = acc
	})
}

func BenchmarkInternalNTTArm64(b *testing.B) {
	base := randomRingElement()
	var value ringElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = base
			internalNTTGeneric(&value)
		}
		benchmarkInternalNTTArm64Sink = value
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = base
			internalNTT(&value)
		}
		benchmarkInternalNTTArm64Sink = value
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = base
			internalNTTNEON(&value)
		}
		benchmarkInternalNTTArm64Sink = value
	})
}

func BenchmarkInverseNTTArm64(b *testing.B) {
	base := randomRingElement()
	input := nttElement(base)
	internalNTTGeneric((*ringElement)(&input))
	var value nttElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = input
			internalInverseNTTGeneric(&value)
		}
		benchmarkInverseNTTArm64Sink = value
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = input
			internalInverseNTT(&value)
		}
		benchmarkInverseNTTArm64Sink = value
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			value = input
			internalInverseNTTNEON(&value)
		}
		benchmarkInverseNTTArm64Sink = value
	})
}

func BenchmarkPolyAddArm64(b *testing.B) {
	left := randomRingElement()
	right := randomRingElement()
	var out ringElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddGeneric(&out, &right)
		}
		benchmarkPolyRingArm64Sink = out
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssign(&out, &right)
		}
		benchmarkPolyRingArm64Sink = out
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssignNEON(&out[0], &right[0])
		}
		benchmarkPolyRingArm64Sink = out
	})
}

func BenchmarkPolySubArm64(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubGeneric(&out, &right)
		}
		benchmarkPolyNTTArm64Sink = out
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssign(&out, &right)
		}
		benchmarkPolyNTTArm64Sink = out
	})

	b.Run("into/neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssignNEON(&out[0], &right[0])
		}
		benchmarkPolyNTTArm64Sink = out
	})
}

func BenchmarkPolyInfinityNormArm64(b *testing.B) {
	r := randomRingElement()

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormGeneric(&r, 0)
		}
		benchmarkNormArm64Sink = uint32(out)
	})

	b.Run("into/dispatch", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNorm(&r, 0)
		}
		benchmarkNormArm64Sink = uint32(out)
	})

	b.Run("into/neon", func(b *testing.B) {
		var out uint32
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormNEON(&r[0])
		}
		benchmarkNormArm64Sink = out
	})
}

func BenchmarkPolyInfinityNormSignedArm64(b *testing.B) {
	var a [n]int32
	r := randomRingElement()
	for i := range a {
		a[i] = int32(r[i]) - int32(qMinus1Div2)
	}

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSignedGeneric(&a, 0)
		}
		benchmarkNormArm64Sink = uint32(out)
	})

	b.Run("into/dispatch", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSigned(&a, 0)
		}
		benchmarkNormArm64Sink = uint32(out)
	})

	b.Run("into/neon", func(b *testing.B) {
		var out uint32
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSignedNEON(&a[0])
		}
		benchmarkNormArm64Sink = out
	})
}

func BenchmarkDecomposeSubToR0Arm64(b *testing.B) {
	w := randomRingElement()
	cs2 := randomRingElement()
	var out [n]int32

	b.ReportAllocs()

	b.Run("gamma32/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Generic(&out, &w, &cs2, gamma2QMinus1Div32)
		}
		benchmarkR0Arm64Sink = out
	})

	b.Run("gamma32/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0(&out, &w, &cs2, gamma2QMinus1Div32)
		}
		benchmarkR0Arm64Sink = out
	})

	b.Run("gamma32/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Gamma32ARM64(&w[0], &cs2[0], &out[0])
		}
		benchmarkR0Arm64Sink = out
	})

	b.Run("gamma88/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Generic(&out, &w, &cs2, gamma2QMinus1Div88)
		}
		benchmarkR0Arm64Sink = out
	})

	b.Run("gamma88/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0(&out, &w, &cs2, gamma2QMinus1Div88)
		}
		benchmarkR0Arm64Sink = out
	})

	b.Run("gamma88/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Gamma88ARM64(&w[0], &cs2[0], &out[0])
		}
		benchmarkR0Arm64Sink = out
	})
}

func BenchmarkUseHintPolyArm64(b *testing.B) {
	h := randomRingElement()
	r := randomRingElement()
	for i := range h {
		h[i] &= 1
	}
	hSparse := ringElement{}
	for i := 0; i < 9; i++ {
		hSparse[(i*29)%n] = 1
	}
	var out ringElement

	b.ReportAllocs()

	b.Run("gamma32/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &h, &r, gamma2QMinus1Div32)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &h, &r, gamma2QMinus1Div32)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGamma32ARM64(&h[0], &r[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32-sparse/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &hSparse, &r, gamma2QMinus1Div32)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32-sparse/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &hSparse, &r, gamma2QMinus1Div32)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32-sparse/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGamma32ARM64(&hSparse[0], &r[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &h, &r, gamma2QMinus1Div88)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &h, &r, gamma2QMinus1Div88)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGamma88ARM64(&h[0], &r[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88-sparse/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &hSparse, &r, gamma2QMinus1Div88)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88-sparse/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &hSparse, &r, gamma2QMinus1Div88)
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88-sparse/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGamma88ARM64(&hSparse[0], &r[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})
}

func BenchmarkMakeHintPolyArm64(b *testing.B) {
	ct0 := randomRingElement()
	cs2 := randomRingElement()
	w := randomRingElement()
	var out ringElement

	b.ReportAllocs()

	b.Run("gamma32/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range n {
				out[j] = makeHint(ct0[j], cs2[j], w[j], gamma2QMinus1Div32)
			}
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma32/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			makeHintPolyGamma32NEON(&ct0[0], &cs2[0], &w[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range n {
				out[j] = makeHint(ct0[j], cs2[j], w[j], gamma2QMinus1Div88)
			}
		}
		benchmarkHintArm64Sink = out
	})

	b.Run("gamma88/arm64-asm", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			makeHintPolyGamma88NEON(&ct0[0], &cs2[0], &w[0], &out[0])
		}
		benchmarkHintArm64Sink = out
	})
}
