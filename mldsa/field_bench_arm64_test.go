// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulArm64Sink nttElement

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
