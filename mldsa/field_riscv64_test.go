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

func TestInternalInverseNTTRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		// Convert to NTT representation
		nttForm := r
		internalNTTGeneric(&nttForm)

		// Test RVV version
		got := nttElement(nttForm)
		internalInverseNTTRVV(&got)

		// Test generic version
		want := nttElement(nttForm)
		internalInverseNTTGeneric(&want)

		if got != want {
			t.Logf("want: %v", want)
			t.Logf("got:  %v", got)
			t.Fatalf("internalInverseNTTRVV mismatch on iteration %d", i)
		}
	}
}

func TestDecomposeSubToR0Gamma32RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		w := randomRingElement()
		cs2 := randomRingElement()

		var got [n]int32
		decomposeSubToR0Gamma32RVV(&w[0], &cs2[0], &got[0])

		var want [n]int32
		decomposeSubToR0Generic(&want, &w, &cs2, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("decomposeSubToR0Gamma32RVV mismatch on iteration %d", i)
		}
	}
}

func TestDecomposeSubToR0Gamma88RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		w := randomRingElement()
		cs2 := randomRingElement()

		var got [n]int32
		decomposeSubToR0Gamma88RVV(&w[0], &cs2[0], &got[0])

		var want [n]int32
		decomposeSubToR0Generic(&want, &w, &cs2, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("decomposeSubToR0Gamma88RVV mismatch on iteration %d", i)
		}
	}
}

func TestDecomposeSubToR0(t *testing.T) {
	for i := 0; i < 16; i++ {
		w := randomRingElement()
		cs2 := randomRingElement()

		for _, gamma2 := range []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88} {
			var got [n]int32
			decomposeSubToR0(&got, &w, &cs2, gamma2)

			var want [n]int32
			decomposeSubToR0Generic(&want, &w, &cs2, gamma2)

			if got != want {
				t.Fatalf("decomposeSubToR0 mismatch on iteration %d gamma2=%d", i, gamma2)
			}
		}
	}
}

func TestUseHintPolyGamma32RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		h := randomRingElement()
		r := randomRingElement()
		for j := range h {
			h[j] &= 1
		}

		var got ringElement
		useHintPolyGamma32RVV(&h[0], &r[0], &got[0])

		var want ringElement
		useHintPolyGeneric(&want, &h, &r, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("useHintPolyGamma32RVV mismatch on iteration %d", i)
		}
	}
}

func TestUseHintPolyGamma88RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		h := randomRingElement()
		r := randomRingElement()
		for j := range h {
			h[j] &= 1
		}

		var got ringElement
		useHintPolyGamma88RVV(&h[0], &r[0], &got[0])

		var want ringElement
		useHintPolyGeneric(&want, &h, &r, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("useHintPolyGamma88RVV mismatch on iteration %d", i)
		}
	}
}

func TestUseHintPoly(t *testing.T) {
	for i := 0; i < 16; i++ {
		h := randomRingElement()
		r := randomRingElement()
		for j := range h {
			h[j] &= 1
		}

		for _, gamma2 := range []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88} {
			var got ringElement
			useHintPoly(&got, &h, &r, gamma2)

			var want ringElement
			useHintPolyGeneric(&want, &h, &r, gamma2)

			if got != want {
				t.Fatalf("useHintPoly mismatch on iteration %d gamma2=%d", i, gamma2)
			}
		}
	}
}

func TestMakeHintPolyGamma32RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 64; i++ {
		ct0 := randomRingElement()
		cs2 := randomRingElement()
		w := randomRingElement()

		var got ringElement
		makeHintPolyGamma32RVV(&ct0[0], &cs2[0], &w[0], &got[0])

		var want ringElement
		for j := range n {
			want[j] = makeHint(ct0[j], cs2[j], w[j], gamma2QMinus1Div32)
		}

		if got != want {
			t.Fatalf("makeHintPolyGamma32RVV mismatch on iteration %d", i)
		}
	}
}

func TestMakeHintPolyGamma88RVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 64; i++ {
		ct0 := randomRingElement()
		cs2 := randomRingElement()
		w := randomRingElement()

		var got ringElement
		makeHintPolyGamma88RVV(&ct0[0], &cs2[0], &w[0], &got[0])

		var want ringElement
		for j := range n {
			want[j] = makeHint(ct0[j], cs2[j], w[j], gamma2QMinus1Div88)
		}

		if got != want {
			t.Fatalf("makeHintPolyGamma88RVV mismatch on iteration %d", i)
		}
	}
}

func TestVectorMakeHintRVV(t *testing.T) {
	for _, gamma2 := range []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88} {
		for i := 0; i < 16; i++ {
			k := 4
			ct0 := make([]ringElement, k)
			cs2 := make([]ringElement, k)
			w := make([]ringElement, k)
			for j := range k {
				ct0[j] = randomRingElement()
				cs2[j] = randomRingElement()
				w[j] = randomRingElement()
			}

			got := make([]ringElement, k)
			vectorMakeHint(ct0, cs2, w, got, gamma2)

			want := make([]ringElement, k)
			vectorMakeHintGeneric(ct0, cs2, w, want, gamma2)

			for j := range k {
				if got[j] != want[j] {
					t.Fatalf("vectorMakeHint mismatch on i=%d j=%d gamma2=%d", i, j, gamma2)
				}
			}
		}
	}
}

func TestPolyInfinityNormRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		got := int(polyInfinityNormRVV(&r[0]))
		want := polyInfinityNormGeneric(&r, 0)
		if got != want {
			t.Fatalf("polyInfinityNormRVV mismatch on iteration %d: got %d want %d", i, got, want)
		}
	}
}

func TestPolyInfinityNormSignedRVV(t *testing.T) {
	if !hasRVV {
		t.Skip("RVV is not available")
	}

	for i := 0; i < 16; i++ {
		var a [n]int32
		r := randomRingElement()
		for j := range a {
			a[j] = int32(r[j]) - int32(qMinus1Div2)
		}
		got := int(polyInfinityNormSignedRVV(&a[0]))
		want := polyInfinityNormSignedGeneric(&a, 0)
		if got != want {
			t.Fatalf("polyInfinityNormSignedRVV mismatch on iteration %d: got %d want %d", i, got, want)
		}
	}
}
