//go:build amd64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulSink nttElement
var benchmarkNTTSink ringElement

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
