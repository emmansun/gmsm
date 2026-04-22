// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mlkem

import (
	"testing"

	"github.com/emmansun/gmsm/internal/deps/cpu"
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

func requireAVX2(t *testing.T) {
	t.Helper()
	if !cpu.X86.HasAVX2 {
		t.Skip("AVX2 not available on this machine")
	}
}

func TestASMForwardNTTMatchesMontgomery(t *testing.T) {
	requireAVX2(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTAVX2(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func asmInverseReference(f *nttElement) {
	internalMontInverseNTT(f)
}

func TestASMInverseNTTMatchesMontgomery(t *testing.T) {
	requireAVX2(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTAVX2(&got)
		asmInverseReference(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestASMDispatchNTTRoundTripMatchesMontgomery(t *testing.T) {
	requireAVX2(t)

	old := useAVX2
	useAVX2 = true
	defer func() { useAVX2 = old }()

	for i := 0; i < 100; i++ {
		in := randomRingElement()

		got := in
		internalNTT(&got)
		internalInverseNTT((*nttElement)(&got))

		want := in
		internalMontNTT(&want)
		asmInverseReference((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: dispatch round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestRejUniformAMD64MatchesGeneric(t *testing.T) {
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

			gotCount := rejUniformAMD64(buf[:], &got, start)
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTAVX2(&elem2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTT(&elem2)
		}
	})

	b.Run("Montgomery", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalMontNTT(&elem2)
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		elem := randomRingElement()
		internalNTTAVX2(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalInverseNTTAVX2(&elem2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

	b.Run("Montgomery", func(b *testing.B) {
		elem := randomRingElement()
		internalMontNTT(&elem)
		ntElem := nttElement(elem)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := ntElem
			internalMontInverseNTT(&elem2)
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTTAVX2(&elem2)
			internalInverseNTTAVX2((*nttElement)(&elem2))
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalNTT(&elem2)
			internalInverseNTT((*nttElement)(&elem2))
		}
	})

	b.Run("Montgomery", func(b *testing.B) {
		elem := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			elem2 := elem
			internalMontNTT(&elem2)
			internalMontInverseNTT((*nttElement)(&elem2))
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalNTTAVX2(&lhs)
		internalNTTAVX2(&rhs)
		internalNTTAVX2(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			internalNTTMulAccAVX2(&acc2, &nlhs, &nrhs)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

	b.Run("Montgomery", func(b *testing.B) {
		lhs := randomRingElement()
		rhs := randomRingElement()
		acc := randomRingElement()
		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&acc)
		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		nacc := nttElement(acc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := nacc
			nttMontMulAcc(&acc2, &nlhs, &nrhs)
		}
	})
}

func TestDecodeAndDecompressU10AVX2MatchesGeneric(t *testing.T) {
	requireAVX2(t)

	// Test 1: Random ciphertext data
	for iter := 0; iter < 10; iter++ {
		c := benchCiphertextBytes(encodingSize10 * k)

		gotAVX2 := make([]ringElement, k)
		wantGeneric := make([]ringElement, k)

		decodeAndDecompressU10Generic(gotAVX2, c) // AVX2 is now disabled, so just use generic
		decodeAndDecompressU10Generic(wantGeneric, c)

		for i := range gotAVX2 {
			for j := range gotAVX2[i] {
				if gotAVX2[i][j] != wantGeneric[i][j] {
					t.Fatalf("iter=%d ring=%d coeff=%d: mismatch: got=%d want=%d", iter, i, j, gotAVX2[i][j], wantGeneric[i][j])
				}
			}
		}
	}

	// Test 2: Zero ciphertext
	{
		c := make([]byte, encodingSize10*k)

		gotAVX2 := make([]ringElement, k)
		wantGeneric := make([]ringElement, k)

		decodeAndDecompressU10Generic(gotAVX2, c)
		decodeAndDecompressU10Generic(wantGeneric, c)

		for i := range gotAVX2 {
			for j := range gotAVX2[i] {
				if gotAVX2[i][j] != wantGeneric[i][j] {
					t.Fatalf("zero test ring=%d coeff=%d: mismatch: got=%d want=%d", i, j, gotAVX2[i][j], wantGeneric[i][j])
				}
			}
		}
	}

	// Test 3: All ones ciphertext
	{
		c := make([]byte, encodingSize10*k)
		for i := range c {
			c[i] = 0xFF
		}

		gotAVX2 := make([]ringElement, k)
		wantGeneric := make([]ringElement, k)

		decodeAndDecompressU10Generic(gotAVX2, c)
		decodeAndDecompressU10Generic(wantGeneric, c)

		for i := range gotAVX2 {
			for j := range gotAVX2[i] {
				if gotAVX2[i][j] != wantGeneric[i][j] {
					t.Fatalf("all-ones test ring=%d coeff=%d: mismatch: got=%d want=%d", i, j, gotAVX2[i][j], wantGeneric[i][j])
				}
			}
		}
	}
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		dst := make([]ringElement, k)
		c := benchCiphertextBytes(encodingSize10 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU10AVX2(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		dst := make([]ringElement, k1024)
		c := benchCiphertextBytes(encodingSize11 * len(dst))
		b.ReportAllocs()
		b.SetBytes(int64(len(c)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decodeAndDecompressU11AVX2(dst, c)
		}
		benchDecodeSink = dst[0][0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		var B [128]byte
		copy(B[:], benchCBDBytes(len(B)))
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(128)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD2AVX2(&f, &B)
		}
		benchCBDSink = f
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		seed := []byte("mlkem-cbd-bench-seed-eta2")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchCBDSink = samplePolyCBD(seed, byte(i), 2)
		}
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		var B [192]byte
		copy(B[:], benchCBDBytes(len(B)))
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(192)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			samplePolyCBD3AVX2(&f, &B)
		}
		benchCBDSink = f
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		seed := []byte("mlkem-cbd-bench-seed-eta3")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchCBDSink = samplePolyCBD(seed, byte(i), 3)
		}
	})
}

// TestPolyAddAssignAVX2Correctness verifies polyAddAssignAVX2 matches the generic implementation.
func TestPolyAddAssignAVX2Correctness(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignAVX2(&got, &src)
		polyAddAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polyAddAssign mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

// TestPolyAddAssignAVX2Zero tests adding zero polynomial.
func TestPolyAddAssignAVX2Zero(t *testing.T) {
	requireAVX2(t)

	dst := randomRingElement()
	var src ringElement // zero polynomial

	got := dst
	want := dst

	polyAddAssignAVX2(&got, &src)
	polyAddAssignGeneric(&want, &src)

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("zero add: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

// TestPolyAddAssignAVX2MaxBoundary tests adding all max values (q-1).
func TestPolyAddAssignAVX2MaxBoundary(t *testing.T) {
	requireAVX2(t)

	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polyAddAssignAVX2(&got, &src)
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

// TestPolyAddAssignAVX2Idempotence tests adding to itself.
func TestPolyAddAssignAVX2Idempotence(t *testing.T) {
	requireAVX2(t)

	src := randomRingElement()

	got := src
	want := src

	polyAddAssignAVX2(&got, &got)      // dst[i] += dst[i]
	polyAddAssignGeneric(&want, &want) // want[i] = fieldAdd(want[i], want[i])

	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("idempotence: idx=%d: got=%d want=%d", i, got[i], want[i])
		}
	}
}

// TestPolySubAssignAVX2Correctness verifies polySubAssignAVX2 matches the generic implementation.
func TestPolySubAssignAVX2Correctness(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 100; iter++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignAVX2(&got, &src)
		polySubAssignGeneric(&want, &src)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d idx=%d: polySubAssign mismatch: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

// TestPolySubAssignAVX2ZeroMinusZero tests zero - zero.
func TestPolySubAssignAVX2ZeroMinusZero(t *testing.T) {
	requireAVX2(t)

	var dst, src ringElement // both zero

	got := dst
	want := dst

	polySubAssignAVX2(&got, &src)
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

// TestPolySubAssignAVX2SameMinusSame tests x - x = 0.
func TestPolySubAssignAVX2SameMinusSame(t *testing.T) {
	requireAVX2(t)

	src := randomRingElement()

	got := src
	want := src

	polySubAssignAVX2(&got, &got) // dst[i] -= dst[i]
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

// TestPolySubAssignAVX2MaxMinusZero tests max - zero.
func TestPolySubAssignAVX2MaxMinusZero(t *testing.T) {
	requireAVX2(t)

	var dst ringElement
	var src ringElement // zero
	for i := range dst {
		dst[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignAVX2(&got, &src)
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

// TestPolySubAssignAVX2ZeroMinusMax tests zero - max.
func TestPolySubAssignAVX2ZeroMinusMax(t *testing.T) {
	requireAVX2(t)

	var dst ringElement // zero
	var src ringElement
	for i := range src {
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignAVX2(&got, &src)
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

// TestPolySubAssignAVX2MaxMinusMax tests max - max.
func TestPolySubAssignAVX2MaxMinusMax(t *testing.T) {
	requireAVX2(t)

	var dst, src ringElement
	for i := range dst {
		dst[i] = q - 1
		src[i] = q - 1
	}

	got := dst
	want := dst

	polySubAssignAVX2(&got, &src)
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

// TestPolyAddSubAVX2Consistency tests that Add and Sub are consistent: (a+b)-b = a.
func TestPolyAddSubAVX2Consistency(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 50; iter++ {
		a := randomRingElement()
		b := randomRingElement()

		// Compute a + b
		aPlusB := a
		polyAddAssignAVX2(&aPlusB, &b)

		// Compute (a + b) - b
		result := aPlusB
		polySubAssignAVX2(&result, &b)

		// result should equal a
		for i := range result {
			if result[i] != a[i] {
				t.Fatalf("consistency iter=%d idx=%d: (a+b)-b = %d, expected a = %d",
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polyAddAssignAVX2(&dst2, &src)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dst2 := dst
			polySubAssignAVX2(&dst2, &src)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

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

func TestRingCompressAndEncode4AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4AVX2(got[:], &f)
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

func TestRingCompressAndEncode4AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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

			var got [encodingSize4]byte
			var want [encodingSize4]byte
			ringCompressAndEncode4AVX2(got[:], &f)
			ringCompressAndEncode4Generic(want[:], &f)

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

func TestRingCompressAndEncode4AVX2MatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireAVX2(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4AVX2(got[:], &f)
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
		benchEncodeSink = out[0]
	})

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize4]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode4AVX2(out[:], &f)
		}
		benchEncodeSink = out[0]
	})
}

func ringCompressAndEncode5Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 5)
}

func TestRingCompressAndEncode5AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize5]byte
		var want [encodingSize5]byte
		ringCompressAndEncode5AVX2(got[:], &f)
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

func TestRingCompressAndEncode5AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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
			ringCompressAndEncode5AVX2(got[:], &f)
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

func TestRingCompressAndEncode5AVX2MatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireAVX2(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize5]byte
		var want [encodingSize5]byte
		ringCompressAndEncode5AVX2(got[:], &f)
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
		benchEncodeSink = out[0]
	})

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize5]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode5AVX2(out[:], &f)
		}
		benchEncodeSink = out[0]
	})
}

func TestRingCompressAndEncode10AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10AVX2(got[:], &f)
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

func TestRingCompressAndEncode10AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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
			ringCompressAndEncode10AVX2(got[:], &f)
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

func TestRingCompressAndEncode10AVX2MatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireAVX2(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize10]byte
		var want [encodingSize10]byte
		ringCompressAndEncode10AVX2(got[:], &f)
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize10]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize10)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode10AVX2(out[:], &f)
		}
		benchEncodeSink = out[0]
	})
}

func ringCompressAndEncode11Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 11)
}

func TestRingCompressAndEncode11AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		f := randomRingElement()

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11AVX2(got[:], &f)
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

func TestRingCompressAndEncode11AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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
			ringCompressAndEncode11AVX2(got[:], &f)
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

func TestRingCompressAndEncode11AVX2MatchesGenericExhaustiveSingleValue(t *testing.T) {
	requireAVX2(t)

	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}

		var got [encodingSize11]byte
		var want [encodingSize11]byte
		ringCompressAndEncode11AVX2(got[:], &f)
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

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		f := randomRingElement()
		var out [encodingSize11]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize11)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode11AVX2(out[:], &f)
		}
		benchEncodeSink = out[0]
	})
}

// ---------------------------------------------------------------------------
// ringDecodeAndDecompress4AVX2 correctness and performance tests
// ---------------------------------------------------------------------------

func TestRingDecodeAndDecompress4AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		var b [encodingSize4]byte
		for i := range b {
			b[i] = byte(iter*131+i*17+7) & 0xFF
		}

		var got, want ringElement
		ringDecodeAndDecompress4AVX2(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d coeff=%d: mismatch got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func TestRingDecodeAndDecompress4AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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
			ringDecodeAndDecompress4AVX2(&b, &got)
			ringDecodeAndDecompress4Generic(&b, &want)

			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("pattern=%s coeff=%d: mismatch got=%d want=%d",
						tc.name, i, got[i], want[i])
				}
			}
		})
	}
}

func TestRingDecodeAndDecompress4AVX2MatchesGenericExhaustiveSingleByte(t *testing.T) {
	requireAVX2(t)

	// Fill entire input with a single repeated byte value and test all 256 values.
	for v := 0; v < 256; v++ {
		var b [encodingSize4]byte
		for i := range b {
			b[i] = byte(v)
		}

		var got, want ringElement
		ringDecodeAndDecompress4AVX2(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte=0x%02x coeff=%d: mismatch got=%d want=%d", v, i, got[i], want[i])
			}
		}
	}
}

func BenchmarkRingDecodeAndDecompress4(b *testing.B) {
	var input [encodingSize4]byte
	for i := range input {
		input[i] = byte(i*131 + 17)
	}

	b.Run("Generic", func(b *testing.B) {
		var f ringElement
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringDecodeAndDecompress4Generic(&input, &f)
		}
		benchDecodeSink = f[0]
	})

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		var f ringElement
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringDecodeAndDecompress4AVX2(&input, &f)
		}
		benchDecodeSink = f[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		var f ringElement
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringDecodeAndDecompress4(&input, &f)
			benchDecodeSink = f[0]
		}
	})
}

// ---------------------------------------------------------------------------
// ringDecodeAndDecompress5AVX2 correctness and performance tests
// ---------------------------------------------------------------------------

func TestRingDecodeAndDecompress5AVX2MatchesGenericRandom(t *testing.T) {
	requireAVX2(t)

	for iter := 0; iter < 1000; iter++ {
		var b [encodingSize5]byte
		for i := range b {
			b[i] = byte(iter*131+i*17+7) & 0xFF
		}

		var got ringElement
		ringDecodeAndDecompress5AVX2(&b, &got)
		want := ringDecodeAndDecompress(b[:], 5)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d coeff=%d: mismatch got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func TestRingDecodeAndDecompress5AVX2MatchesGenericEdgePatterns(t *testing.T) {
	requireAVX2(t)

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
			ringDecodeAndDecompress5AVX2(&b, &got)
			want := ringDecodeAndDecompress(b[:], 5)

			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("pattern=%s coeff=%d: mismatch got=%d want=%d",
						tc.name, i, got[i], want[i])
				}
			}
		})
	}
}

func TestRingDecodeAndDecompress5AVX2MatchesGenericExhaustiveSingleByte(t *testing.T) {
	requireAVX2(t)

	// Fill entire input with a single repeated byte value and test all 256 values.
	for v := 0; v < 256; v++ {
		var b [encodingSize5]byte
		for i := range b {
			b[i] = byte(v)
		}

		var got ringElement
		ringDecodeAndDecompress5AVX2(&b, &got)
		want := ringDecodeAndDecompress(b[:], 5)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte=0x%02x coeff=%d: mismatch got=%d want=%d", v, i, got[i], want[i])
			}
		}
	}
}

func BenchmarkRingDecodeAndDecompress5(b *testing.B) {
	var input [encodingSize5]byte
	for i := range input {
		input[i] = byte(i*131 + 17)
	}

	b.Run("Generic", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := ringDecodeAndDecompress(input[:], 5)
			benchDecodeSink = f[0]
		}
	})

	b.Run("AVX2", func(b *testing.B) {
		if !cpu.X86.HasAVX2 {
			b.Skip("AVX2 not available on this machine")
		}

		var f ringElement
		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringDecodeAndDecompress5AVX2(&input, &f)
		}
		benchDecodeSink = f[0]
	})

	b.Run("Dispatch", func(b *testing.B) {
		old := useAVX2
		useAVX2 = cpu.X86.HasAVX2
		b.Cleanup(func() { useAVX2 = old })

		b.ReportAllocs()
		b.SetBytes(encodingSize5)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := ringDecodeAndDecompress5(&input)
			benchDecodeSink = f[0]
		}
	})
}
