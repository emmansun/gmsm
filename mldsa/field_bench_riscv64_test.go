// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && !purego

package mldsa

import "testing"

var benchmarkNTTMulRVVSink nttElement
var benchmarkRingRVVSink ringElement
var benchmarkR0RVVSink [n]int32
var benchmarkNormRVVSink uint32

func requireRVVBenchmark(b *testing.B) {
	b.Helper()
	if !hasRVV {
		b.Skip("RVV is not available")
	}
}

func BenchmarkPolyAddRVV(b *testing.B) {
	left := randomRingElement()
	right := randomRingElement()
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddGeneric(&out, &right)
		}
		benchmarkRingRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssign(&out, &right)
		}
		benchmarkRingRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssignRVV(&out[0], &right[0])
		}
		benchmarkRingRVVSink = out
	})
}

func BenchmarkPolySubRVV(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubGeneric(&out, &right)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssign(&out, &right)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssignRVV(&out[0], &right[0])
		}
		benchmarkNTTMulRVVSink = out
	})
}

func BenchmarkNTTMulRVV(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMulGeneric(&out, &left, &right)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMul(&out, &left, &right)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			nttMulRVV(&left, &right, &out)
		}
		benchmarkNTTMulRVVSink = out
	})
}

func BenchmarkNTTMulAccRVV(b *testing.B) {
	left := ntt(randomRingElement())
	right := ntt(randomRingElement())
	base := ntt(randomRingElement())
	var acc nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAccGeneric(&acc, &left, &right)
		}
		benchmarkNTTMulRVVSink = acc
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAcc(&acc, &left, &right)
		}
		benchmarkNTTMulRVVSink = acc
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			acc = base
			nttMulAccRVV(&acc, &left, &right)
		}
		benchmarkNTTMulRVVSink = acc
	})
}

func BenchmarkNTTMatRowVecMulRVV(b *testing.B) {
	const length = 8
	var vec, matRow [length]nttElement
	for i := range vec {
		vec[i] = ntt(randomRingElement())
		matRow[i] = ntt(randomRingElement())
	}
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMatRowVecMulGeneric(&out, &vec[0], &matRow[0], length)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMatRowVecMul(&out, &vec[0], &matRow[0], length)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			nttMatRowVecMulRVV(&out, &vec[0], &matRow[0], length)
		}
		benchmarkNTTMulRVVSink = out
	})
}

func BenchmarkInternalNTTRVV(b *testing.B) {
	base := randomRingElement()
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = base
			internalNTTGeneric(&out)
		}
		benchmarkRingRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = base
			internalNTT(&out)
		}
		benchmarkRingRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			out = base
			internalNTTRVV(&out)
		}
		benchmarkRingRVVSink = out
	})
}

func BenchmarkInternalInverseNTTRVV(b *testing.B) {
	input := nttElement(randomRingElement())
	internalNTTGeneric((*ringElement)(&input))
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = input
			internalInverseNTTGeneric(&out)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = input
			internalInverseNTT(&out)
		}
		benchmarkNTTMulRVVSink = out
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		for i := 0; i < b.N; i++ {
			out = input
			internalInverseNTTRVV(&out)
		}
		benchmarkNTTMulRVVSink = out
	})
}

func BenchmarkDecomposeSubToR0RVV(b *testing.B) {
	w := randomRingElement()
	cs2 := randomRingElement()
	var out [n]int32

	b.ReportAllocs()
	for _, tc := range []struct {
		name   string
		gamma2 uint32
		rvv    func(*fieldElement, *fieldElement, *int32)
	}{
		{"gamma32", gamma2QMinus1Div32, decomposeSubToR0Gamma32RVV},
		{"gamma88", gamma2QMinus1Div88, decomposeSubToR0Gamma88RVV},
	} {
		b.Run(tc.name+"/generic", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				decomposeSubToR0Generic(&out, &w, &cs2, tc.gamma2)
			}
			benchmarkR0RVVSink = out
		})
		b.Run(tc.name+"/dispatch", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				decomposeSubToR0(&out, &w, &cs2, tc.gamma2)
			}
			benchmarkR0RVVSink = out
		})
		b.Run(tc.name+"/rvv", func(b *testing.B) {
			requireRVVBenchmark(b)
			for i := 0; i < b.N; i++ {
				tc.rvv(&w[0], &cs2[0], &out[0])
			}
			benchmarkR0RVVSink = out
		})
	}
}

func BenchmarkUseHintPolyRVV(b *testing.B) {
	h := randomRingElement()
	r := randomRingElement()
	for i := range h {
		h[i] &= 1
	}
	var out ringElement

	b.ReportAllocs()
	for _, tc := range []struct {
		name   string
		gamma2 uint32
		rvv    func(*fieldElement, *fieldElement, *fieldElement)
	}{
		{"gamma32", gamma2QMinus1Div32, useHintPolyGamma32RVV},
		{"gamma88", gamma2QMinus1Div88, useHintPolyGamma88RVV},
	} {
		b.Run(tc.name+"/generic", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				useHintPolyGeneric(&out, &h, &r, tc.gamma2)
			}
			benchmarkRingRVVSink = out
		})
		b.Run(tc.name+"/dispatch", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				useHintPoly(&out, &h, &r, tc.gamma2)
			}
			benchmarkRingRVVSink = out
		})
		b.Run(tc.name+"/rvv", func(b *testing.B) {
			requireRVVBenchmark(b)
			for i := 0; i < b.N; i++ {
				tc.rvv(&h[0], &r[0], &out[0])
			}
			benchmarkRingRVVSink = out
		})
	}
}

func BenchmarkMakeHintPolyRVV(b *testing.B) {
	ct0 := randomRingElement()
	cs2 := randomRingElement()
	w := randomRingElement()
	var out ringElement

	b.ReportAllocs()
	for _, tc := range []struct {
		name   string
		gamma2 uint32
		rvv    func(*fieldElement, *fieldElement, *fieldElement, *fieldElement)
	}{
		{"gamma32", gamma2QMinus1Div32, makeHintPolyGamma32RVV},
		{"gamma88", gamma2QMinus1Div88, makeHintPolyGamma88RVV},
	} {
		b.Run(tc.name+"/generic", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := range n {
					out[j] = makeHint(ct0[j], cs2[j], w[j], tc.gamma2)
				}
			}
			benchmarkRingRVVSink = out
		})
		b.Run(tc.name+"/dispatch", func(b *testing.B) {
			ct0Slice := []ringElement{ct0}
			cs2Slice := []ringElement{cs2}
			wSlice := []ringElement{w}
			outSlice := []ringElement{out}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				vectorMakeHint(ct0Slice, cs2Slice, wSlice, outSlice, tc.gamma2)
			}
			benchmarkRingRVVSink = outSlice[0]
		})
		b.Run(tc.name+"/rvv", func(b *testing.B) {
			requireRVVBenchmark(b)
			for i := 0; i < b.N; i++ {
				tc.rvv(&ct0[0], &cs2[0], &w[0], &out[0])
			}
			benchmarkRingRVVSink = out
		})
	}
}

func BenchmarkPolyInfinityNormRVV(b *testing.B) {
	r := randomRingElement()

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormGeneric(&r, 0)
		}
		benchmarkNormRVVSink = uint32(out)
	})

	b.Run("dispatch", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNorm(&r, 0)
		}
		benchmarkNormRVVSink = uint32(out)
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		var out uint32
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormRVV(&r[0])
		}
		benchmarkNormRVVSink = out
	})
}

func BenchmarkPolyInfinityNormSignedRVV(b *testing.B) {
	var input [n]int32
	r := randomRingElement()
	for i := range input {
		input[i] = int32(r[i]) - int32(qMinus1Div2)
	}

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSignedGeneric(&input, 0)
		}
		benchmarkNormRVVSink = uint32(out)
	})

	b.Run("dispatch", func(b *testing.B) {
		var out int
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSigned(&input, 0)
		}
		benchmarkNormRVVSink = uint32(out)
	})

	b.Run("rvv", func(b *testing.B) {
		requireRVVBenchmark(b)
		var out uint32
		for i := 0; i < b.N; i++ {
			out = polyInfinityNormSignedRVV(&input[0])
		}
		benchmarkNormRVVSink = out
	})
}
