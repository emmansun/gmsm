// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulSink nttElement
var benchmarkNTTSink ringElement
var benchmarkInverseNTTSink nttElement
var benchmarkPolyRingSink ringElement
var benchmarkPolyNTTSink nttElement
var benchmarkR0Sink [n]int32
var benchmarkHintSink ringElement

func BenchmarkNTT(b *testing.B) {
	r := randomRingElement()

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			got := r
			internalNTTGeneric(&got)
			benchmarkNTTSink = got
		}
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}

		for i := 0; i < b.N; i++ {
			got := r
			internalNTTAVX2(&got)
			benchmarkNTTSink = got
		}
	})
}

func BenchmarkNTTMul(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("into/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMulGeneric(&out, &left, &right)
		}
		benchmarkNTTMulSink = out
	})

	b.Run("into/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMul(&out, &left, &right)
		}
		benchmarkNTTMulSink = out
	})

	b.Run("into/avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}

		for i := 0; i < b.N; i++ {
			nttMulAVX2(&left, &right, &out)
		}
		benchmarkNTTMulSink = out
	})
}

func BenchmarkInverseNTT(b *testing.B) {
	r := randomRingElement()
	input := nttElement(r)
	internalNTTGeneric((*ringElement)(&input))

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			got := input
			internalInverseNTTGeneric(&got)
			benchmarkInverseNTTSink = got
		}
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			got := input
			internalInverseNTT(&got)
			benchmarkInverseNTTSink = got
		}
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}

		for i := 0; i < b.N; i++ {
			got := input
			internalInverseNTTAVX2(&got)
			benchmarkInverseNTTSink = got
		}
	})
}

func BenchmarkPolyAdd(b *testing.B) {
	left := randomRingElement()
	right := randomRingElement()
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddGeneric(&out, &right)
		}
		benchmarkPolyRingSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssign(&out, &right)
		}
		benchmarkPolyRingSink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}

		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssignAVX2(&out[0], &right[0])
		}
		benchmarkPolyRingSink = out
	})
}

func BenchmarkPolySub(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubGeneric(&out, &right)
		}
		benchmarkPolyNTTSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssign(&out, &right)
		}
		benchmarkPolyNTTSink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}

		for i := 0; i < b.N; i++ {
			out = left
			polySubAssignAVX2(&out[0], &right[0])
		}
		benchmarkPolyNTTSink = out
	})
}

func BenchmarkDecomposeSubToR0(b *testing.B) {
	w := randomRingElement()
	cs2 := randomRingElement()
	var out [n]int32

	b.ReportAllocs()

	b.Run("gamma32/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Generic(&out, &w, &cs2, gamma2QMinus1Div32)
		}
		benchmarkR0Sink = out
	})

	b.Run("gamma32/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0(&out, &w, &cs2, gamma2QMinus1Div32)
		}
		benchmarkR0Sink = out
	})

	b.Run("gamma32/avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Gamma32AVX2(&w[0], &cs2[0], &out[0])
		}
		benchmarkR0Sink = out
	})

	b.Run("gamma88/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Generic(&out, &w, &cs2, gamma2QMinus1Div88)
		}
		benchmarkR0Sink = out
	})

	b.Run("gamma88/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decomposeSubToR0(&out, &w, &cs2, gamma2QMinus1Div88)
		}
		benchmarkR0Sink = out
	})

	b.Run("gamma88/avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			decomposeSubToR0Gamma88AVX2(&w[0], &cs2[0], &out[0])
		}
		benchmarkR0Sink = out
	})
}

func BenchmarkUseHintPoly(b *testing.B) {
	h := randomRingElement()
	r := randomRingElement()
	for i := range h {
		h[i] &= 1
	}
	var out ringElement

	b.ReportAllocs()

	b.Run("gamma32/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &h, &r, gamma2QMinus1Div32)
		}
		benchmarkHintSink = out
	})

	b.Run("gamma32/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &h, &r, gamma2QMinus1Div32)
		}
		benchmarkHintSink = out
	})

	b.Run("gamma32/avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			useHintPolyGamma32AVX2(&h[0], &r[0], &out[0])
		}
		benchmarkHintSink = out
	})

	b.Run("gamma88/generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPolyGeneric(&out, &h, &r, gamma2QMinus1Div88)
		}
		benchmarkHintSink = out
	})

	b.Run("gamma88/dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			useHintPoly(&out, &h, &r, gamma2QMinus1Div88)
		}
		benchmarkHintSink = out
	})

	b.Run("gamma88/avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			useHintPolyGamma88AVX2(&h[0], &r[0], &out[0])
		}
		benchmarkHintSink = out
	})
}
