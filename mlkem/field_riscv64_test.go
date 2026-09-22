// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.26 && !purego

package mlkem

import (
	mathrand "math/rand/v2"
	"testing"
)

var benchDecodeSink fieldElement
var benchCBDSink ringElement
var benchEncodeSink byte

func benchCiphertextBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 17)
	}
	return b
}

func benchCBDBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*73 + 29)
	}
	return b
}

func requireRVV(t *testing.T) {
	t.Helper()
	if !hasRVV {
		t.Skip("RVV not available on this machine")
	}
}

func TestNTTMulRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("skipping test: RVV not available")
	}
	for range 64 {
		var lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
		}

		internalNTTMulRVV(&got, &lhs, &rhs)
		nttMontMul(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestNTTMulAccRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("skipping test: RVV not available")
	}
	for range 64 {
		var acc, lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
			acc[i] = fieldElement(mathrand.IntN(q))
		}

		copy(got[:], acc[:])
		copy(want[:], acc[:])
		internalNTTMulAccRVV(&got, &lhs, &rhs)
		nttMontMulAcc(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestRVVForwardNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTRVV(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestRVVInverseNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTRVV(&got)
		internalMontInverseNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestDecodeAndDecompressU10RVVMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k)
		want := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(got))
		for i := range c {
			c[i] ^= byte(iter*23 + i)
		}

		decodeAndDecompressU10RVV(got, c)
		decodeAndDecompressU10Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU10RVV mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestDecodeAndDecompressU11RVVMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		got := make([]ringElement, k1024)
		want := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(got))
		for i := range c {
			c[i] ^= byte(iter*29 + i)
		}

		decodeAndDecompressU11RVV(got, c)
		decodeAndDecompressU11Generic(want, c)

		for i := range got {
			for j := range got[i] {
				if got[i][j] != want[i][j] {
					t.Fatalf("iter=%d poly=%d coeff=%d: decodeAndDecompressU11RVV mismatch: got=%d want=%d", iter, i, j, got[i][j], want[i][j])
				}
			}
		}
	}
}

func TestRingCompressAndEncode10RVVMatchesGenericRandom(t *testing.T) {
	requireRVV(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10RVV(got[:], &f)
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

func TestRingCompressAndEncode10RVVMatchesGenericEdgePatterns(t *testing.T) {
	requireRVV(t)

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

			var got [encodingSize10]byte
			var want [encodingSize10]byte
			ringCompressAndEncode10RVV(got[:], &f)
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

func TestRingCompressAndEncode10RVVMatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireRVV(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10RVV(got[:], &f)
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

func ringCompressAndEncode11Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 11)
}

func TestRingCompressAndEncode11RVVMatchesGenericRandom(t *testing.T) {
	requireRVV(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11RVV(got[:], &f)
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

func TestRingCompressAndEncode11RVVMatchesGenericEdgePatterns(t *testing.T) {
	requireRVV(t)

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

			var got [encodingSize11]byte
			var want [encodingSize11]byte
			ringCompressAndEncode11RVV(got[:], &f)
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

func TestRingCompressAndEncode11RVVMatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireRVV(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11RVV(got[:], &f)
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

func TestPolyAddAssignRVVCorrectness(t *testing.T) {
	requireRVV(t)

	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignRVV(&got, &src)
		polyAddAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polyAddAssign mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func TestPolyAddAssignRVVZero(t *testing.T) {
	requireRVV(t)

	dst := randomRingElement()
	var src ringElement // zero polynomial

	got := dst
	want := dst

	polyAddAssignRVV(&got, &src)
	polyAddAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero add: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

// TestPolyAddAssignRVVMaxBoundary tests adding all max values (q-1).
func TestPolyAddAssignRVVMaxBoundary(t *testing.T) {
	requireRVV(t)

	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polyAddAssignRVV(&got, &src)
	polyAddAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max boundary: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		// Result should be (q-1)+(q-1) mod q = q-2
		expected := 2 * (q - 1) % q
		if got[i] != fieldElement(expected) {
			t.Fatalf("max boundary: idx=%d: got=%d expected=%d", i, got[i], expected)
		}
	}
}

// TestPolyAddAssignRVVIdempotence tests adding to itself.
func TestPolyAddAssignRVVIdempotence(t *testing.T) {
	requireRVV(t)

	src := randomRingElement()

	got := src
	want := src

	polyAddAssignRVV(&got, &got)      // dst[i] += dst[i]
	polyAddAssignGeneric(&want, &want) // want[i] = fieldAdd(want[i], want[i])

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("idempotence: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

func TestPolySubAssignRVVCorrectness(t *testing.T) {
	requireRVV(t)

	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignRVV(&got, &src)
		polySubAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polySubAssign mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

// TestPolySubAssignRVVZeroMinusZero tests zero - zero.
func TestPolySubAssignRVVZeroMinusZero(t *testing.T) {
	requireRVV(t)

	var dst, src ringElement // both zero

	got := dst
	want := dst

	polySubAssignRVV(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero-zero: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("zero-zero: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolySubAssignRVVSameMinusSame tests x - x = 0.
func TestPolySubAssignRVVSameMinusSame(t *testing.T) {
	requireRVV(t)

	src := randomRingElement()

	got := src
	want := src

	polySubAssignRVV(&got, &got) // dst[i] -= dst[i]
	polySubAssignGeneric(&want, &want)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("same-same: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("same-same: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolySubAssignRVVMaxMinusZero tests max - zero.
func TestPolySubAssignRVVMaxMinusZero(t *testing.T) {
	requireRVV(t)

	var dst ringElement
	var src ringElement // zero
	for i := range dst {
		dst[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignRVV(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max-zero: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != q-1 {
			t.Fatalf("max-zero: idx=%d: expected %d, got=%d", i, q-1, got[i])
		}
	}
}

// TestPolySubAssignRVVZeroMinusMax tests zero - max.
func TestPolySubAssignRVVZeroMinusMax(t *testing.T) {
	requireRVV(t)

	var dst ringElement // zero
	var src ringElement
	for i := range src {
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignRVV(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero-max: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		// 0 - (q-1) should be (0 - (q-1) + q) mod q = 1
		expected := fieldElement((0 - (q - 1) + q) % q)
		if got[i] != expected {
			t.Fatalf("zero-max: idx=%d: expected %d, got=%d", i, expected, got[i])
		}
	}
}

// TestPolySubAssignRVVMaxMinusMax tests max - max.
func TestPolySubAssignRVVMaxMinusMax(t *testing.T) {
	requireRVV(t)

	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignRVV(&got, &src)
	polySubAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("max-max: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
		if got[i] != 0 {
			t.Fatalf("max-max: idx=%d: expected 0, got=%d", i, got[i])
		}
	}
}

// TestPolyAddSubRVVConsistency tests that Add and Sub are consistent: (a+b)-b = a.
func TestPolyAddSubRVVConsistency(t *testing.T) {
	requireRVV(t)

	for iter := 0; iter < 50; iter++ {
		a := randomRingElement()
		b := randomRingElement()

		// Compute a + b
		aPlusB := a
		polyAddAssignRVV(&aPlusB, &b)

		// Compute (a + b) - b
		result := aPlusB
		polySubAssignRVV(&result, &b)

		// result should equal a
		for i := range result {
			if result[i] != a[i] {
				t.Fatalf("consistency iter=%d idx=%d: (a+b)-b = %d, expected a = %d",
					iter, i, result[i], a[i])
			}
		}
	}
}

func TestSamplePolyCBD2RVVMatchesGeneric(t *testing.T) {
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
		samplePolyCBD2RVV(&gotNEON, &B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 2)

		// Compare all coefficients
		for i := range gotNEON {
			if gotNEON[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD2RVV mismatch: got=%d want=%d", iter, i, gotNEON[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBD3RVVMatchesGeneric(t *testing.T) {
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
		samplePolyCBD3RVV(&gotNEON, &B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 3)

		// Compare all coefficients
		for i := range gotNEON {
			if gotNEON[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD3RVV mismatch: got=%d want=%d", iter, i, gotNEON[i], wantGeneric[i])
			}
		}
	}
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

	b.Run("RVV", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTRVV(&elem2)
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

	b.Run("RVV", func(b *testing.B) {
		elem := randomRingElement()
		internalNTTRVV(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalInverseNTTRVV(&elem2)
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

	b.Run("RVV", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTRVV(&elem2)
			internalInverseNTTRVV((*nttElement)(&elem2))
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

	b.Run("RVV", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTRVV(&lhs)
		internalNTTRVV(&rhs)
		internalNTTRVV(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			internalNTTMulAccRVV(&acc2, &nlhs, &nrhs)
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

	b.Run("RVV", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTRVV(&lhs)
		internalNTTRVV(&rhs)
		internalNTTRVV(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			internalNTTMulAccKeyGenRVV(&acc2, &nlhs, &nrhs)
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

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		dst := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU10RVV(dst, c)
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

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		dst := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU11RVV(dst, c)
		}
		benchDecodeSink = dst[0][0]
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
		benchEncodeSink = out[0]
	})

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize10]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize10)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode10RVV(out[:], &f)
		}
		benchEncodeSink = out[0]
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
		benchEncodeSink = out[0]
	})

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize11]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize11)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode11RVV(out[:], &f)
		}
		benchEncodeSink = out[0]
	})
}

func BenchmarkSamplePolyCBD2(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		B := benchCBDBytes(128)
		b.ReportAllocs()
		b.SetBytes(128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchCBDSink = samplePolyCBDGeneric(B, 2)
		}
	})

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		var B [128]byte
		copy(B[:], benchCBDBytes(len(B)))
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD2RVV(&f, &B)
		}
		benchCBDSink = f
	})
}

func BenchmarkSamplePolyCBD3(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		B := benchCBDBytes(192)
		b.ReportAllocs()
		b.SetBytes(192)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchCBDSink = samplePolyCBDGeneric(B, 3)
		}
	})

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		var B [192]byte
		copy(B[:], benchCBDBytes(len(B)))
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(192)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD3RVV(&f, &B)
		}
		benchCBDSink = f
	})
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

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polyAddAssignRVV(&dst2, &src)
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

	b.Run("RVV", func(b *testing.B) {
		if !hasRVV {
			b.Skip("RVV not available on this machine")
		}

		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polySubAssignRVV(&dst2, &src)
		}
	})
}
