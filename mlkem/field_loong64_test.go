// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
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

func BenchmarkNTTLASX(b *testing.B) {
	requireLASX(&testing.T{})
	f := randomRingElement()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		internalNTTLASX(&f)
	}
}

func BenchmarkInverseNTTLASX(b *testing.B) {
	requireLASX(&testing.T{})
	f := randomRingElement()
	internalNTTLASX(&f)
	nf := nttElement(f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		internalInverseNTTLASX(&nf)
	}
}
