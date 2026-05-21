// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
	"crypto/rand"
	"testing"
)

func requireLASX(t *testing.T) {
	t.Helper()
	if !useLASX {
		t.Skip("LASX not available on this machine")
	}
}

func TestLASXPolyAddAssignMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignLASX(&got, &src)
		polyAddAssignGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polyAdd mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXPolySubAssignMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignLASX(&got, &src)
		polySubAssignGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polySub mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXForwardNTTMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTLASX(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXInverseNTTMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTLASX(&got)
		internalMontInverseNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXNTTRoundTrip(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		internalNTTLASX(&got)
		internalInverseNTTLASX((*nttElement)(&got))

		// internalMontNTT + internalMontInverseNTT gives r*in mod q (not identity),
		// so compare against the scalar Montgomery roundtrip result.
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: NTT round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// TestLASXScalarNTTThenLASXINTT applies scalar NTT then LASX inverse NTT.
// If this passes, the INTT is correct; if it fails, INTT is the problem.
func TestLASXScalarNTTThenLASXINTT(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		// Apply scalar forward NTT then LASX inverse NTT
		internalMontNTT(&got)
		internalInverseNTTLASX((*nttElement)(&got))

		// Compare against scalar Montgomery roundtrip (which gives r*in, not in)
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: scalar-NTT+LASX-INTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// TestLASXNTTThenScalarINTT applies LASX NTT then scalar inverse NTT.
// If this passes, the forward NTT is correct; if it fails, NTT is the problem.
func TestLASXNTTThenScalarINTT(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		// Apply LASX forward NTT then scalar inverse NTT
		internalNTTLASX(&got)
		internalMontInverseNTT((*nttElement)(&got))

		// Compare against scalar Montgomery roundtrip (which gives r*in, not in)
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: LASX-NTT+scalar-INTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func randomNTTElement() nttElement {
	return nttElement(randomRingElement())
}

func TestLASXNTTMulMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		lhs := randomNTTElement()
		rhs := randomNTTElement()

		var got, want nttElement
		internalNTTMulLASX(&got, &lhs, &rhs)
		nttMontMul(&want, &lhs, &rhs)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: nttMul mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXNTTMulAccMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc0 := randomNTTElement()

		got := acc0
		want := acc0
		internalNTTMulAccLASX(&got, &lhs, &rhs)
		nttMontMulAcc(&want, &lhs, &rhs)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: nttMulAcc mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXNTTMulAccKeyGenMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		lhs := randomRingElement()
		rhs := randomRingElement()
		accLASX := randomRingElement()
		accRef := accLASX

		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&accLASX)
		internalMontNTT(&accRef)

		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		naccLASX := nttElement(accLASX)
		naccRef := nttElement(accRef)

		internalNTTMulAccKeyGenLASX(&naccLASX, &nlhs, &nrhs)
		nttMulAccGeneric(&naccRef, &nlhs, &nrhs)

		for j := range naccLASX {
			if naccLASX[j] != naccRef[j] {
				t.Fatalf("iter=%d idx=%d: NTTMulAccKeyGen mismatch: got=%d want=%d", i, j, naccLASX[j], naccRef[j])
			}
		}
	}
}

func TestLASXDispatchNTTRoundTripMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	old := useLASX
	useLASX = true
	defer func() { useLASX = old }()

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

// montMulLASXSigned computes Montgomery multiplication using the signed approach
// that LASX assembly uses. This is a Go reference for debugging.
func montMulLASXSigned(a, b int16) int16 {
	const qInv = int16(-3327) // 62209 as uint16, -3327 as int16
	const q = int16(3329)
	prodLo := int16(int32(a) * int32(b) & 0xFFFF)
	prodHi := int16(int32(a) * int32(b) >> 16)
	t := int16(int32(prodLo) * int32(qInv) & 0xFFFF)
	tqHi := int16(int32(t) * int32(q) >> 16)
	result := prodHi - tqHi
	// REDUCE_MONT: if result < 0, add q
	if result < 0 {
		result += q
	}
	return result
}

// TestMontMulSignedMatchesScalar verifies the signed LASX Montgomery formula
// matches fieldMontMul.
func TestMontMulSignedMatchesScalar(t *testing.T) {
	for a := 0; a < q; a++ {
		for b := 0; b < q; b++ {
			got := montMulLASXSigned(int16(a), int16(b))
			want := fieldMontMul(fieldElement(a), fieldElement(b))
			if fieldElement(got) != want {
				t.Fatalf("montMulLASXSigned(%d, %d) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestLASXRingCompressAndEncode4MatchesGeneric(t *testing.T) {
	requireLASX(t)

	// Exhaustive single-value test
	for x := 0; x < int(q); x++ {
		var f ringElement
		for i := range f {
			f[i] = fieldElement(x)
		}
		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4LASX(got[:], &f)
		ringCompressAndEncode4Generic(want[:], &f)
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("x=%d byte=%d: got=0x%02x want=0x%02x", x, i, got[i], want[i])
			}
		}
	}

	// Random test
	for iter := 0; iter < 200; iter++ {
		f := randomRingElement()
		var got [encodingSize4]byte
		var want [encodingSize4]byte
		ringCompressAndEncode4LASX(got[:], &f)
		ringCompressAndEncode4Generic(want[:], &f)
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d byte=%d: got=0x%02x want=0x%02x", iter, i, got[i], want[i])
			}
		}
	}
}

func TestLASXRingDecodeAndDecompress4MatchesGeneric(t *testing.T) {
	requireLASX(t)

	// Exhaustive single-nibble test: all 128 bytes set to the same packed pair (v, v)
	for x := 0; x < 16; x++ {
		packed := byte(x | (x << 4))
		var b [encodingSize4]byte
		for i := range b {
			b[i] = packed
		}
		var got ringElement
		var want ringElement
		ringDecodeAndDecompress4LASX(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("x=%d coeff=%d: got=%d want=%d", x, i, got[i], want[i])
			}
		}
	}

	// Random test
	for iter := 0; iter < 200; iter++ {
		var b [encodingSize4]byte
		rand.Read(b[:])
		var got ringElement
		var want ringElement
		ringDecodeAndDecompress4LASX(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter=%d coeff=%d: got=%d want=%d", iter, i, got[i], want[i])
			}
		}
	}
}

func BenchmarkNTTForward(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f2 := f
			internalNTTGeneric(&f2)
		}
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		f := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f2 := f
			internalNTTLASX(&f2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		f := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f2 := f
			internalNTT(&f2)
		}
	})
}

func BenchmarkNTTInverse(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		internalNTTGeneric(&f)
		nf := nttElement(f)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nf2 := nf
			internalInverseNTTGeneric(&nf2)
		}
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		f := randomRingElement()
		internalNTTLASX(&f)
		nf := nttElement(f)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nf2 := nf
			internalInverseNTTLASX(&nf2)
		}
	})

	b.Run("Dispatch", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		f := randomRingElement()
		internalNTT(&f)
		nf := nttElement(f)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nf2 := nf
			internalInverseNTT(&nf2)
		}
	})
}

func BenchmarkNTTMul(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		var out nttElement
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nttMontMul(&out, &lhs, &rhs)
		}
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		var out nttElement
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			internalNTTMulLASX(&out, &lhs, &rhs)
		}
	})
}

func BenchmarkNTTMulAcc(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := acc
			nttMontMulAcc(&acc2, &lhs, &rhs)
		}
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := acc
			internalNTTMulAccLASX(&acc2, &lhs, &rhs)
		}
	})
}

func BenchmarkNTTMulAccKeyGen(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := acc
			nttMulAccGeneric(&acc2, &lhs, &rhs)
		}
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			acc2 := acc
			internalNTTMulAccKeyGenLASX(&acc2, &lhs, &rhs)
		}
	})
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
	})

	b.Run("LASX", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available on this machine")
		}
		f := randomRingElement()
		var out [encodingSize4]byte
		b.ReportAllocs()
		b.SetBytes(encodingSize4)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ringCompressAndEncode4LASX(out[:], &f)
		}
	})
}
