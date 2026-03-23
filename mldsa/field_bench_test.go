// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulSink nttElement
var benchmarkNTTSink ringElement
var benchmarkInverseNTTSink nttElement

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
