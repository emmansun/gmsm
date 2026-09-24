// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.26 && !purego

package mldsa

import (
	"crypto/rand"
	"testing"
)

func requireRVV(t *testing.T) {
	t.Helper()
	if !hasRVV {
		t.Skip("RVV not available on this machine")
	}
}

func randomNttElement() nttElement {
	return ntt(randomRingElementMldsa())
}

func randomRingElementMldsa() ringElement {
	var f ringElement
	for i := range f {
		// Random value in [0, q)
		var b [4]byte
		rand.Read(b[:])
		v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		f[i] = fieldElement(v % q)
	}
	return f
}

func TestPolyAddAssignRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		left := randomRingElement()
		right := randomRingElement()

		got := left
		polyAddAssignRVV(&got[0], &right[0])

		want := left
		polyAddGeneric(&want, &right)
		if got != want {
			t.Fatalf("polyAddAssignRVV mismatch on iteration %d", i)
		}
	}
}

func TestPolySubAssignRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		got := left
		polySubAssignRVV(&got[0], &right[0])

		want := left
		polySubGeneric(&want, &right)
		if got != want {
			t.Fatalf("polySubAssignRVV mismatch on iteration %d", i)
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

func TestNTTMulRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		var got nttElement
		nttMulRVV(&left, &right, &got)

		var want nttElement
		nttMulGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulRVV mismatch on iteration %d", i)
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

func TestNTTMulAccRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())
		acc := ntt(randomRingElement())

		got := acc
		nttMulAccRVV(&got, &left, &right)

		want := acc
		nttMulAccGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulAccRVV mismatch on iteration %d", i)
		}
	}
}

func TestNttMatRowVecMulRVVMatchesGeneric(t *testing.T) {
	requireRVV(t)

	for length := 1; length <= 5; length++ {
		vec := make([]nttElement, length)
		mat := make([]nttElement, length)
		for i := range vec {
			vec[i] = randomNttElement()
			mat[i] = randomNttElement()
		}
		var got, want nttElement

		nttMatRowVecMulRVV(&got, &vec[0], &mat[0], length)
		nttMatRowVecMulGeneric(&want, &vec[0], &mat[0], length)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("length=%d idx=%d: nttMatRowVecMul mismatch: got=%d want=%d", length, j, got[j], want[j])
			}
		}
	}
}

func TestInternalNTTRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		got := r
		internalNTTRVV(&got)

		want := r
		internalNTTGeneric(&want)

		if got != want {
			t.Logf("want: %v", want)
			t.Logf("got:  %v", got)
			t.Fatalf("internalNTTRVV mismatch on iteration %d", i)
		}
	}
}
