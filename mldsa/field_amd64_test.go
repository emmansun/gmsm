// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mldsa

import "testing"

func TestInternalNTTAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		got := r
		internalNTTAVX2(&got)

		want := r
		internalNTTGeneric(&want)

		if got != want {
			t.Logf("want: %v", want)
			t.Logf("got:  %v", got)
			t.Fatalf("internalNTTAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestInternalInverseNTTAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		// Convert to NTT representation
		nttForm := r
		internalNTTGeneric(&nttForm)

		// Test AVX2 version
		got := nttElement(nttForm)
		internalInverseNTTAVX2(&got)

		// Test generic version
		want := nttElement(nttForm)
		internalInverseNTTGeneric(&want)

		if got != want {
			t.Logf("want: %v", want)
			t.Logf("got:  %v", got)
			t.Fatalf("internalInverseNTTAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestNTTMulAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		var got nttElement
		nttMulAVX2(&left, &right, &got)

		var want nttElement
		nttMulGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestNTTMul(t *testing.T) {
	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		var got nttElement
		nttMul(&got, &left, &right)

		var want nttElement
		nttMulGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulInto mismatch on iteration %d", i)
		}
	}
}

func TestPolyAddAssignAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		left := randomRingElement()
		right := randomRingElement()

		got := left
		polyAddAssignAVX2(&got[0], &right[0])

		want := left
		polyAddGeneric(&want, &right)
		if got != want {
			t.Fatalf("polyAddAssignAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestPolySubAssignAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		got := left
		polySubAssignAVX2(&got[0], &right[0])

		want := left
		polySubGeneric(&want, &right)
		if got != want {
			t.Fatalf("polySubAssignAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestPolyAddAssign(t *testing.T) {
	for i := 0; i < 16; i++ {
		left := randomRingElement()
		right := randomRingElement()

		got := left
		polyAddAssign(&got, &right)

		want := left
		polyAddGeneric(&want, &right)
		if got != want {
			t.Fatalf("polyAddAssign mismatch on iteration %d", i)
		}
	}
}

func TestPolySubAssign(t *testing.T) {
	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		got := left
		polySubAssign(&got, &right)

		want := left
		polySubGeneric(&want, &right)
		if got != want {
			t.Fatalf("polySubAssign mismatch on iteration %d", i)
		}
	}
}
