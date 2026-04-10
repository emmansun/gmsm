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
