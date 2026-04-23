// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mlkem

import (
	"crypto/sha3"
	"testing"
)

var benchDecodeSink fieldElement
var benchEncode4Sink byte

func ringCompressAndEncode5Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 5)
}

func ringCompressAndEncode11Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 11)
}

func benchCiphertextBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 17)
	}
	return b
}

func TestNEONForwardNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTNEON(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONOptForwardNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTNEON(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: NEONOpt forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONInverseNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTNEON(&got)
		internalMontInverseNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONDispatchNTTRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		in := randomRingElement()

		got := in
		internalNTT(&got)
		internalInverseNTT((*nttElement)(&got))

		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: dispatch round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestRejUniformARM64MatchesGeneric(t *testing.T) {
	for _, start := range []int{0, 1, n - 2, n - 1, n} {
		for iter := 0; iter < 200; iter++ {
			var buf [24]byte
			for i := range buf {
				buf[i] = byte(iter*37 + i*19 + start)
			}

			var got nttElement
			var want nttElement
			for i := 0; i < start && i < n; i++ {
				seed := fieldElement((i*17 + iter + start) % int(q))
				got[i] = seed
				want[i] = seed
			}

			gotCount := rejUniformARM64(buf[:], &got, start)
			wantCount := rejUniformGeneric(buf[:], &want, start)

			if gotCount != wantCount {
				t.Fatalf("start=%d iter=%d: count mismatch: got=%d want=%d", start, iter, gotCount, wantCount)
			}
			if got != want {
				t.Fatalf("start=%d iter=%d: output mismatch", start, iter)
			}
		}
	}
}

func TestNEONNTTMulAccMatchesMontgomery(t *testing.T) {
	for i := 0; i < 100; i++ {
		lhs := randomRingElement()
		rhs := randomRingElement()
		accNEON := randomRingElement()
		accRef := accNEON

		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&accNEON)
		internalMontNTT(&accRef)

		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		naccNEON := nttElement(accNEON)
		naccRef := nttElement(accRef)

		internalNTTMulAccNEON(&naccNEON, &nlhs, &nrhs)
		nttMontMulAcc(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				t.Fatalf("iter=%d idx=%d: NTTMulAcc mismatch: got=%d want=%d", i, j, naccNEON[j], naccRef[j])
			}
		}
	}
}

// TestInternalNTTMulAccNEONOnly isolates the mul-acc NEON path so it can be
// debugged independently from forward/inverse NTT assembly behavior.
func TestInternalNTTMulAccNEONOnly(t *testing.T) {
	for i := 0; i < 200; i++ {
		// Construct direct NTT-domain operands so this test depends only on
		// internalNTTMulAccNEON and the reference nttMontMulAcc implementation.
		nlhs := nttElement(randomRingElement())
		nrhs := nttElement(randomRingElement())
		naccNEON := nttElement(randomRingElement())
		naccInit := naccNEON
		naccRef := naccNEON

		internalNTTMulAccNEON(&naccNEON, &nlhs, &nrhs)
		nttMontMulAcc(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				pair := j &^ 1
				a0, a1 := nlhs[pair], nlhs[pair+1]
				b0, b1 := nrhs[pair], nrhs[pair+1]
				accInit0, accInit1 := naccInit[pair], naccInit[pair+1]
				acc0, acc1 := naccRef[pair], naccRef[pair+1]

				ab00 := fieldMontMul(a0, b0)
				ab11 := fieldMontMul(a1, b1)
				ab01 := fieldMontMul(a0, b1)
				ab10 := fieldMontMul(a1, b0)
				evenDelta := fieldAdd(ab00, fieldMontMul(ab11, gammasMontgomery[pair/2]))
				oddDelta := fieldAdd(ab01, ab10)

				neonDeltaEvenRaw := uint16(naccNEON[pair] - accInit0)
				neonDeltaOddRaw := uint16(naccNEON[pair+1] - accInit1)
				neonDeltaEven := fieldReduceOnce(neonDeltaEvenRaw)
				neonDeltaOdd := fieldReduceOnce(neonDeltaOddRaw)

				t.Fatalf("iter=%d idx=%d: internalNTTMulAccNEON mismatch: got=%d want=%d pair=%d a0=%d a1=%d b0=%d b1=%d initAccEven=%d initAccOdd=%d refEvenDelta=%d refOddDelta=%d refAB00=%d refAB11=%d refAB01=%d refAB10=%d refAccEven=%d refAccOdd=%d neonDeltaEvenRaw=%d neonDeltaOddRaw=%d neonDeltaEven=%d neonDeltaOdd=%d",
					i, j, naccNEON[j], naccRef[j], pair/2, a0, a1, b0, b1, accInit0, accInit1, evenDelta, oddDelta, ab00, ab11, ab01, ab10, acc0, acc1, neonDeltaEvenRaw, neonDeltaOddRaw, neonDeltaEven, neonDeltaOdd)
			}
		}
	}
}

func TestNEONNTTMulAccKeyGenMatchesMontgomery(t *testing.T) {
	for i := 0; i < 100; i++ {
		lhs := randomRingElement()
		rhs := randomRingElement()
		accNEON := randomRingElement()
		accRef := accNEON

		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&accNEON)
		internalMontNTT(&accRef)

		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		naccNEON := nttElement(accNEON)
		naccRef := nttElement(accRef)

		internalNTTMulAccKeyGenNEON(&naccNEON, &nlhs, &nrhs)
		nttMulAccGeneric(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				t.Fatalf("iter=%d idx=%d: NTTMulAccKeyGen mismatch: got=%d want=%d", i, j, naccNEON[j], naccRef[j])
			}
		}
	}
}

func TestRingCompressAndEncode4NEONMatchesGenericExhaustiveSingleValue(t *testing.T) {
	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4NEON(got[:], &f)
		ringCompressAndEncode4Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("x=%d byte=%d: mismatch got=%02x want=%02x", x, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode4NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4NEON(got[:], &f)
		ringCompressAndEncode4Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("iter=%d byte=%d: mismatch got=%02x want=%02x", iter, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode5NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize5]byte
		var want [encodingSize5]byte
		ringCompressAndEncode5NEON(got[:], &f)
		ringCompressAndEncode5Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("iter=%d byte=%d: mismatch got=%02x want=%02x", iter, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode5NEONMatchesGenericEdgePatterns(t *testing.T) {
	patterns := []struct {
		name string
		fill func(i int) fieldElement
	}{
		{
			name: "all-zero",
			fill: func(i int) fieldElement { return 0 },
		},
		{
			name: "all-max",
			fill: func(i int) fieldElement { return q - 1 },
		},
		{
			name: "alternating-zero-max",
			fill: func(i int) fieldElement {
				if i%2 == 0 {
					return 0
				}
				return q - 1
			},
		},
		{
			name: "ascending-mod-q",
			fill: func(i int) fieldElement { return fieldElement(i % int(q)) },
		},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			var f ringElement
			for i := range f {
				f[i] = tc.fill(i)
			}

			var got [encodingSize5]byte
			var want [encodingSize5]byte
			ringCompressAndEncode5NEON(got[:], &f)
			ringCompressAndEncode5Generic(want[:], &f)

			if got != want {
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("pattern=%s byte=%d: mismatch got=%02x want=%02x", tc.name, i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestRingCompressAndEncode5NEONMatchesGenericExhaustiveSingleValue(t *testing.T) {
	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize5]byte
		var want [encodingSize5]byte
		ringCompressAndEncode5NEON(got[:], &f)
		ringCompressAndEncode5Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("x=%d byte=%d: mismatch got=%02x want=%02x", x, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode10NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10NEON(got[:], &f)
		ringCompressAndEncode10Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("iter=%d byte=%d: mismatch got=%02x want=%02x", iter, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode10NEONMatchesGenericEdgePatterns(t *testing.T) {
	patterns := []struct {
		name string
		fill func(i int) fieldElement
	}{
		{name: "all-zero", fill: func(i int) fieldElement { return 0 }},
		{name: "all-max", fill: func(i int) fieldElement { return q - 1 }},
		{
			name: "alternating-zero-max",
			fill: func(i int) fieldElement {
				if i%2 == 0 {
					return 0
				}
				return q - 1
			},
		},
		{name: "ascending-mod-q", fill: func(i int) fieldElement { return fieldElement(i % int(q)) }},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			var f ringElement
			for i := range f {
				f[i] = tc.fill(i)
			}

			var got [encodingSize10]byte
			var want [encodingSize10]byte
			ringCompressAndEncode10NEON(got[:], &f)
			ringCompressAndEncode10Generic(want[:], &f)

			if got != want {
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("pattern=%s byte=%d: mismatch got=%02x want=%02x", tc.name, i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestRingCompressAndEncode10NEONMatchesGenericExhaustiveSingleValue(t *testing.T) {
	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10NEON(got[:], &f)
		ringCompressAndEncode10Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("x=%d byte=%d: mismatch got=%02x want=%02x", x, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode11NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11NEON(got[:], &f)
		ringCompressAndEncode11Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("iter=%d byte=%d: mismatch got=%02x want=%02x", iter, i, got[i], want[i])
				}
			}
		}
	}
}

func TestRingCompressAndEncode11NEONMatchesGenericEdgePatterns(t *testing.T) {
	patterns := []struct {
		name string
		fill func(i int) fieldElement
	}{
		{name: "all-zero", fill: func(i int) fieldElement { return 0 }},
		{name: "all-max", fill: func(i int) fieldElement { return q - 1 }},
		{
			name: "alternating-zero-max",
			fill: func(i int) fieldElement {
				if i%2 == 0 {
					return 0
				}
				return q - 1
			},
		},
		{name: "ascending-mod-q", fill: func(i int) fieldElement { return fieldElement(i % int(q)) }},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			var f ringElement
			for i := range f {
				f[i] = tc.fill(i)
			}

			var got [encodingSize11]byte
			var want [encodingSize11]byte
			ringCompressAndEncode11NEON(got[:], &f)
			ringCompressAndEncode11Generic(want[:], &f)

			if got != want {
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("pattern=%s byte=%d: mismatch got=%02x want=%02x", tc.name, i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestRingCompressAndEncode11NEONMatchesGenericExhaustiveSingleValue(t *testing.T) {
	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11NEON(got[:], &f)
		ringCompressAndEncode11Generic(want[:], &f)

		if got != want {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("x=%d byte=%d: mismatch got=%02x want=%02x", x, i, got[i], want[i])
				}
			}
		}
	}
}

func BenchmarkRingCompressAndEncode4(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize4]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode4Generic(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("NEON", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize4]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode4NEON(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize4]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode4(out[:0], &f)
		}
		benchEncode4Sink = out[0]
	})
}

func BenchmarkRingCompressAndEncode5(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize5]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode5Generic(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("NEON", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize5]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode5NEON(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize5]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode5(out[:0], &f)
		}
		benchEncode4Sink = out[0]
	})
}

func BenchmarkRingCompressAndEncode10(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize10]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize10)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode10Generic(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("NEON", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize10]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize10)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode10NEON(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize10]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize10)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode10(out[:0], &f)
		}
		benchEncode4Sink = out[0]
	})
}

func BenchmarkRingCompressAndEncode11(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize11]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize11)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode11Generic(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("NEON", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize11]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize11)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode11NEON(out[:], &f)
		}
		benchEncode4Sink = out[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		f := randomRingElement()
		var out [encodingSize11]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize11)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode11(out[:0], &f)
		}
		benchEncode4Sink = out[0]
	})
}

func BenchmarkNTTForward(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTGeneric(&elem2)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTNEON(&elem2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTT(&elem2)
		}
	})
}

func BenchmarkNTTInverse(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		elem := randomRingElement()
		internalNTTGeneric(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalInverseNTTGeneric(&elem2)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		elem := randomRingElement()
		internalNTTNEON(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalInverseNTTNEON(&elem2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		elem := randomRingElement()
		internalNTT(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalInverseNTT(&elem2)
		}
	})
}

func BenchmarkNTTRoundTrip(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTGeneric(&elem2)
			internalInverseNTTGeneric((*nttElement)(&elem2))
		}
	})

	b.Run("NEON", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTNEON(&elem2)
			internalInverseNTTNEON((*nttElement)(&elem2))
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTT(&elem2)
			internalInverseNTT((*nttElement)(&elem2))
		}
	})
}

func BenchmarkNTTMulAcc(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTGeneric(&lhs)
		internalNTTGeneric(&rhs)
		internalNTTGeneric(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			nttMulAccGeneric(&acc2, &nlhs, &nrhs)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTNEON(&lhs)
		internalNTTNEON(&rhs)
		internalNTTNEON(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			internalNTTMulAccNEON(&acc2, &nlhs, &nrhs)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTT(&lhs)
		internalNTT(&rhs)
		internalNTT(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			nttMulAcc(&acc2, &nlhs, &nrhs)
		}
	})
}

func BenchmarkNTTMulAccKeyGen(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTGeneric(&lhs)
		internalNTTGeneric(&rhs)
		internalNTTGeneric(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			nttMulAccGeneric(&acc2, &nlhs, &nrhs)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTNEON(&lhs)
		internalNTTNEON(&rhs)
		internalNTTNEON(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			internalNTTMulAccKeyGenNEON(&acc2, &nlhs, &nrhs)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTT(&lhs)
		internalNTT(&rhs)
		internalNTT(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			nttMulAccKeyGen(&acc2, &nlhs, &nrhs)
		}
	})
}

func TestSamplePolyCBD2NEONMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Build 128-byte input for eta=2
		var B [128]byte
		for i := 0; i < 128; i++ {
			B[i] = byte((seed[i%32] + byte(i)) ^ 0xAA)
		}

		// Compute via NEON path
		gotNEON := ringElement{}
		samplePolyCBD2NEON(&gotNEON, &B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 2)

		// Compare all coefficients
		for i := range gotNEON {
			if gotNEON[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD2NEON mismatch: got=%d want=%d", iter, i, gotNEON[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBD3NEONMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Build 192-byte input for eta=3
		var B [192]byte
		for i := 0; i < 192; i++ {
			B[i] = byte((seed[i%32] + byte(i)) ^ 0x55)
		}

		// Compute via NEON path
		gotNEON := ringElement{}
		samplePolyCBD3NEON(&gotNEON, &B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 3)

		// Compare all coefficients
		for i := range gotNEON {
			if gotNEON[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD3NEON mismatch: got=%d want=%d", iter, i, gotNEON[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBDDispatchEta2(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Compute via dispatch (should route to NEON for eta=2 on arm64)
		gotDispatch := samplePolyCBD(seed[:], byte(iter), 2)

		// Compute via generic
		var B [128]byte
		prf := sha3.NewSHAKE256()
		prf.Write(seed[:])
		prf.Write([]byte{byte(iter)})
		prf.Read(B[:])
		wantGeneric := samplePolyCBDGeneric(B[:], 2)

		for i := range gotDispatch {
			if gotDispatch[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: dispatch eta=2 mismatch: got=%d want=%d", iter, i, gotDispatch[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBDDispatchEta3(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Compute via dispatch (should route to NEON for eta=3 on arm64)
		gotDispatch := samplePolyCBD(seed[:], byte(iter), 3)

		// Compute via generic
		var B [192]byte
		prf := sha3.NewSHAKE256()
		prf.Write(seed[:])
		prf.Write([]byte{byte(iter)})
		prf.Read(B[:])
		wantGeneric := samplePolyCBDGeneric(B[:], 3)

		for i := range gotDispatch {
			if gotDispatch[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: dispatch eta=3 mismatch: got=%d want=%d", iter, i, gotDispatch[i], wantGeneric[i])
			}
		}
	}
}

func TestDecodeAndDecompressU11NEONMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k1024)
		want := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(got))
		for i := range c {
			c[i] ^= byte(iter*29 + i)
		}

		decodeAndDecompressU11NEON(got, c)
		decodeAndDecompressU11Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU11NEON mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestDecodeAndDecompressU10NEONMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k)
		want := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(got))
		for i := range c {
			c[i] ^= byte(iter*23 + i)
		}

		decodeAndDecompressU10NEON(got, c)
		decodeAndDecompressU10Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU10NEON mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestDecodeAndDecompressU10DispatchMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k)
		want := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(got))
		for i := range c {
			c[i] ^= byte(iter*31 + i*5)
		}

		decodeAndDecompressU10(got, c)
		decodeAndDecompressU10Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU10 dispatch mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestDecodeAndDecompressU11DispatchMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k1024)
		want := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(got))
		for i := range c {
			c[i] ^= byte(iter*17 + i*3)
		}

		decodeAndDecompressU11(got, c)
		decodeAndDecompressU11Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU11 dispatch mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestRingDecodeAndDecompress4NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		var b [encodingSize4]byte
		for i := range b {
			b[i] = byte(iter*131+i*17+7) & 0xFF
		}

		var got, want ringElement
		ringDecodeAndDecompress4NEON(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d coeff=%d: mismatch got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func TestRingDecodeAndDecompress4NEONMatchesGenericEdgePatterns(t *testing.T) {
	patterns := []struct {
		name string
		fill func(i int) byte
	}{
		{
			name: "all-zero",
			fill: func(i int) byte { return 0x00 },
		},
		{
			name: "all-ones",
			fill: func(i int) byte { return 0xFF },
		},
		{
			name: "alternating-0x00-0xFF",
			fill: func(i int) byte {
				if i%2 == 0 {
					return 0x00
				}
				return 0xFF
			},
		},
		{
			name: "low-nibble-only",
			fill: func(i int) byte { return 0x0F },
		},
		{
			name: "high-nibble-only",
			fill: func(i int) byte { return 0xF0 },
		},
		{
			name: "ascending",
			fill: func(i int) byte { return byte(i) },
		},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			var b [encodingSize4]byte
			for i := range b {
				b[i] = tc.fill(i)
			}

			var got, want ringElement
			ringDecodeAndDecompress4NEON(&b, &got)
			ringDecodeAndDecompress4Generic(&b, &want)

			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("pattern=%s coeff=%d: mismatch got=%d want=%d", tc.name, i, got[i], want[i])
				}
			}
		})
	}
}

func TestRingDecodeAndDecompress4NEONMatchesGenericExhaustiveSingleByte(t *testing.T) {
	for v := 0; v < 256; v++ {
		var b [encodingSize4]byte
		for i := range b {
			b[i] = byte(v)
		}

		var got, want ringElement
		ringDecodeAndDecompress4NEON(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte=0x%02x coeff=%d: mismatch got=%d want=%d", v, i, got[i], want[i])
			}
		}
	}
}

func TestRingDecodeAndDecompress5NEONMatchesGenericRandom(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		var b [encodingSize5]byte
		for i := range b {
			b[i] = byte(iter*131+i*17+7) & 0xFF
		}

		var got ringElement
		ringDecodeAndDecompress5NEON(&b, &got)
		want := ringDecodeAndDecompress(b[:], 5)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d coeff=%d: mismatch got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func TestRingDecodeAndDecompress5NEONMatchesGenericEdgePatterns(t *testing.T) {
	patterns := []struct {
		name string
		fill func(i int) byte
	}{
		{
			name: "all-zero",
			fill: func(i int) byte { return 0x00 },
		},
		{
			name: "all-ones",
			fill: func(i int) byte { return 0xFF },
		},
		{
			name: "alternating-0x00-0xFF",
			fill: func(i int) byte {
				if i%2 == 0 {
					return 0x00
				}
				return 0xFF
			},
		},
		{
			name: "low-nibble-only",
			fill: func(i int) byte { return 0x0F },
		},
		{
			name: "high-nibble-only",
			fill: func(i int) byte { return 0xF0 },
		},
		{
			name: "ascending",
			fill: func(i int) byte { return byte(i) },
		},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			var b [encodingSize5]byte
			for i := range b {
				b[i] = tc.fill(i)
			}

			var got ringElement
			ringDecodeAndDecompress5NEON(&b, &got)
			want := ringDecodeAndDecompress(b[:], 5)

			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("pattern=%s coeff=%d: mismatch got=%d want=%d", tc.name, i, got[i], want[i])
				}
			}
		})
	}
}

func TestRingDecodeAndDecompress5NEONMatchesGenericExhaustiveSingleByte(t *testing.T) {
	for v := 0; v < 256; v++ {
		var b [encodingSize5]byte
		for i := range b {
			b[i] = byte(v)
		}

		var got ringElement
		ringDecodeAndDecompress5NEON(&b, &got)
		want := ringDecodeAndDecompress(b[:], 5)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte=0x%02x coeff=%d: mismatch got=%d want=%d", v, i, got[i], want[i])
			}
		}
	}
}

func BenchmarkSamplePolyCBD2(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		B := make([]byte, 128)
		for i := range B {
			B[i] = byte(i)
		}
		b.ReportAllocs()
		b.SetBytes(128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBDGeneric(B, 2)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		var B [128]byte
		for i := range B {
			B[i] = byte(i)
		}
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD2NEON(&f, &B)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		seed := []byte("mlkem-cbd-bench-seed-eta2")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD(seed, byte(i), 2)
		}
	})
}

func BenchmarkSamplePolyCBD3(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		B := make([]byte, 192)
		for i := range B {
			B[i] = byte(i)
		}
		b.ReportAllocs()
		b.SetBytes(192)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBDGeneric(B, 3)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		var B [192]byte
		for i := range B {
			B[i] = byte(i)
		}
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(192)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD3NEON(&f, &B)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		seed := []byte("mlkem-cbd-bench-seed-eta3")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD(seed, byte(i), 3)
		}
	})
}

// TestPolyAddAssignNEONCorrectness verifies polyAddAssignNEON matches the generic implementation.
func TestPolyAddAssignNEONCorrectness(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignNEON(&got, &src)
		polyAddAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polyAddAssignNEON mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

// TestPolyAddAssignNEONZero tests adding zero polynomial.
func TestPolyAddAssignNEONZero(t *testing.T) {
	dst := randomRingElement()
	var src ringElement // zero polynomial

	got := dst
	want := dst

	polyAddAssignNEON(&got, &src)
	polyAddAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero add NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

// TestPolyAddAssignNEONMaxBoundary tests adding all max values (q-1).
func TestPolyAddAssignNEONMaxBoundary(t *testing.T) {
	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polyAddAssignNEON(&got, &src)
	polyAddAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max boundary NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		// Result should be (q-1)+(q-1) mod q = q-2
		expected := 2 * (q - 1) % q
		if got[i] != fieldElement(expected) {
			t.Fatalf("max boundary NEON: idx=%d: got=%d expected=%d", i, got[i], expected)
		}
	}
}

// TestPolyAddAssignNEONIdempotence tests adding to itself.
func TestPolyAddAssignNEONIdempotence(t *testing.T) {
	src := randomRingElement()

	got := src
	want := src

	polyAddAssignNEON(&got, &got)      // dst[i] += dst[i]
	polyAddAssignGeneric(&want, &want) // want[i] = fieldAdd(want[i], want[i])

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("idempotence NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

// TestPolySubAssignNEONCorrectness verifies polySubAssignNEON matches the generic implementation.
func TestPolySubAssignNEONCorrectness(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignNEON(&got, &src)
		polySubAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polySubAssignNEON mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

// TestPolySubAssignNEONZeroMinusZero tests zero - zero.
func TestPolySubAssignNEONZeroMinusZero(t *testing.T) {
	var dst, src ringElement // both zero

	got := dst
	want := dst

	polySubAssignNEON(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero-zero NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("zero-zero NEON: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolySubAssignNEONSameMinusSame tests x - x = 0.
func TestPolySubAssignNEONSameMinusSame(t *testing.T) {
	src := randomRingElement()

	got := src
	want := src

	polySubAssignNEON(&got, &got) // dst[i] -= dst[i]
	polySubAssignGeneric(&want, &want)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("same-same NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("same-same NEON: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolySubAssignNEONMaxMinusZero tests max - zero.
func TestPolySubAssignNEONMaxMinusZero(t *testing.T) {
	var dst ringElement
	var src ringElement // zero
	for i := range dst {
		dst[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignNEON(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max-zero NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != q-1 {
			t.Fatalf("max-zero NEON: idx=%d: expected %d, got=%d", i, q-1, got[i])
		}
	}
}

// TestPolySubAssignNEONZeroMinusMax tests zero - max.
func TestPolySubAssignNEONZeroMinusMax(t *testing.T) {
	var dst ringElement // zero
	var src ringElement
	for i := range src {
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignNEON(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero-max NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		// 0 - (q-1) should be (0 - (q-1) + q) mod q = 1
		expected := fieldElement((0 - (q - 1) + q) % q)
		if got[i] != expected {
			t.Fatalf("zero-max NEON: idx=%d: expected %d, got=%d", i, expected, got[i])
		}
	}
}

// TestPolySubAssignNEONMaxMinusMax tests max - max.
func TestPolySubAssignNEONMaxMinusMax(t *testing.T) {
	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignNEON(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max-max NEON: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("max-max NEON: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolyAddSubNEONConsistency tests that Add and Sub are consistent: (a+b)-b = a.
func TestPolyAddSubNEONConsistency(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		a := randomRingElement()
		b := randomRingElement()

		// Compute a + b
		aPlusB := a
		polyAddAssignNEON(&aPlusB, &b)

		// Compute (a + b) - b
		result := aPlusB
		polySubAssignNEON(&result, &b)

		// result should equal a
		for i := range result {
			if result[i] != a[i] {
				t.Fatalf("consistency NEON iter=%d idx=%d: (a+b)-b = %d, expected a = %d",
					iter, i, result[i], a[i])
			}
		}
	}
}

func BenchmarkPolyAddAssign(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polyAddAssignGeneric(&dst2, &src)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polyAddAssignNEON(&dst2, &src)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polyAddAssign(&dst2, &src)
		}
	})
}

func BenchmarkPolySubAssign(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polySubAssignGeneric(&dst2, &src)
		}
	})

	b.Run("NEON", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polySubAssignNEON(&dst2, &src)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polySubAssign(&dst2, &src)
		}
	})
}

func BenchmarkDecodeAndDecompressU10(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		dst := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU10Generic(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("NEON", func(b *testing.B) {
		dst := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU10NEON(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		dst := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU10(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})
}

func BenchmarkDecodeAndDecompressU11(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		dst := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU11Generic(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("NEON", func(b *testing.B) {
		dst := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU11NEON(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		dst := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU11(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})
}
