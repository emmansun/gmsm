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

func BenchmarkNTTForwardAVX2(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalNTTAVX2(&elem2)
	}
}

// BenchmarkNTTForwardMontgomery measures Montgomery forward NTT performance.
func BenchmarkNTTForwardMontgomery(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalMontNTT(&elem2)
	}
}

// BenchmarkNTTInverseAVX2 measures AVX2 inverse NTT performance.
func BenchmarkNTTInverseAVX2(b *testing.B) {
	elem := randomRingElement()
	internalNTTAVX2(&elem)
	ntElem := nttElement(elem)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := ntElem
		internalInverseNTTAVX2(&elem2)
	}
}

// BenchmarkNTTInverseMontgomery measures Montgomery inverse NTT performance.
func BenchmarkNTTInverseMontgomery(b *testing.B) {
	elem := randomRingElement()
	internalMontNTT(&elem)
	ntElem := nttElement(elem)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := ntElem
		internalMontInverseNTT(&elem2)
	}
}

// BenchmarkNTTRoundTripAVX2 measures full forward→inverse cycle with AVX2 dispatcher.
func BenchmarkNTTRoundTripAVX2(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalNTT(&elem2)
		internalInverseNTT((*nttElement)(&elem2))
	}
}

// BenchmarkNTTRoundTripMontgomery measures full forward→inverse cycle with Montgomery.
func BenchmarkNTTRoundTripMontgomery(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalMontNTT(&elem2)
		internalMontInverseNTT((*nttElement)(&elem2))
	}
}

// BenchmarkNTTMulAccAVX2 measures AVX2 Montgomery multiply-accumulate.
func BenchmarkNTTMulAccAVX2(b *testing.B) {
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
}

// BenchmarkNTTMulAccMontgomery measures Montgomery multiply-accumulate (Go reference).
func BenchmarkNTTMulAccMontgomery(b *testing.B) {
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
}

// BenchmarkNTTForwardGeneric measures pure-Go generic forward NTT performance.
func BenchmarkNTTForwardGeneric(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalNTTGeneric(&elem2)
	}
}

// BenchmarkNTTInverseGeneric measures pure-Go generic inverse NTT performance.
func BenchmarkNTTInverseGeneric(b *testing.B) {
	elem := randomRingElement()
	internalNTTGeneric(&elem)
	ntElem := nttElement(elem)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := ntElem
		internalInverseNTTGeneric(&elem2)
	}
}

// BenchmarkNTTMulAccGeneric measures pure-Go generic multiply-accumulate.
func BenchmarkNTTMulAccGeneric(b *testing.B) {
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
}

// BenchmarkNTTMulAccDispatch measures the dispatched nttMulAcc (AVX2 on supported hardware).
func BenchmarkNTTMulAccDispatch(b *testing.B) {
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
}

func BenchmarkDecodeAndDecompressU10Generic(b *testing.B) {
	dst := make([]ringElement, k)
	c := benchCiphertextBytes(encodingSize10 * len(dst))
	b.ReportAllocs()
	b.SetBytes(int64(len(c)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeAndDecompressU10Generic(dst, c)
	}
	benchDecodeSink = dst[0][0]
}

func BenchmarkDecodeAndDecompressU10Dispatch(b *testing.B) {
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
}

func BenchmarkDecodeAndDecompressU10AVX2(b *testing.B) {
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
}

func BenchmarkDecodeAndDecompressU11Generic(b *testing.B) {
	dst := make([]ringElement, k1024)
	c := benchCiphertextBytes(encodingSize11 * len(dst))
	b.ReportAllocs()
	b.SetBytes(int64(len(c)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeAndDecompressU11Generic(dst, c)
	}
	benchDecodeSink = dst[0][0]
}

func BenchmarkDecodeAndDecompressU11Dispatch(b *testing.B) {
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
}

func BenchmarkDecodeAndDecompressU11AVX2(b *testing.B) {
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
}

func BenchmarkSamplePolyCBD2Generic(b *testing.B) {
	B := benchCBDBytes(128)
	b.ReportAllocs()
	b.SetBytes(128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCBDSink = samplePolyCBDGeneric(B, 2)
	}
}

func BenchmarkSamplePolyCBD3Generic(b *testing.B) {
	B := benchCBDBytes(192)
	b.ReportAllocs()
	b.SetBytes(192)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCBDSink = samplePolyCBDGeneric(B, 3)
	}
}

func BenchmarkSamplePolyCBD2AVX2(b *testing.B) {
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
}

func BenchmarkSamplePolyCBD3AVX2(b *testing.B) {
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
}

func BenchmarkSamplePolyCBD2Dispatch(b *testing.B) {
	old := useAVX2
	useAVX2 = cpu.X86.HasAVX2
	b.Cleanup(func() { useAVX2 = old })

	seed := []byte("mlkem-cbd-bench-seed-eta2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCBDSink = samplePolyCBD(seed, byte(i), 2)
	}
}

func BenchmarkSamplePolyCBD3Dispatch(b *testing.B) {
	old := useAVX2
	useAVX2 = cpu.X86.HasAVX2
	b.Cleanup(func() { useAVX2 = old })

	seed := []byte("mlkem-cbd-bench-seed-eta3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCBDSink = samplePolyCBD(seed, byte(i), 3)
	}
}
