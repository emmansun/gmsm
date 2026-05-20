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

		for j := range got {
			if got[j] != in[j] {
				t.Fatalf("iter=%d idx=%d: NTT round-trip mismatch: got=%d want=%d", i, j, got[j], in[j])
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
