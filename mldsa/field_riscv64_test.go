// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.26 && !purego

package mldsa

import "testing"

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

