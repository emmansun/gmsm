// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import (
	mathrand "math/rand/v2"
	"testing"
)

func TestNTTMulNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
		}

		nttMulNEON(&lhs, &rhs, &got)
		nttMulGeneric(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestNTTMulAccNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
			// pre-populate accumulator with random values
			got[i] = fieldElement(mathrand.IntN(q))
			want[i] = got[i]
		}

		nttMulAccNEON(&lhs, &rhs, &got)
		nttMulAccGeneric(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestInternalNTTNEONMatchesGeneric(t *testing.T) {
	for range 32 {
		var got, want ringElement
		for i := range got {
			v := fieldElement(mathrand.IntN(q))
			got[i] = v
			want[i] = v
		}

		internalNTTNEON(&got)
		internalNTTGeneric(&want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestInternalInverseNTTNEONMatchesGeneric(t *testing.T) {
	for range 32 {
		var got, want nttElement
		for i := range got {
			v := fieldElement(mathrand.IntN(q))
			got[i] = v
			want[i] = v
		}

		internalInverseNTTNEON(&got)
		internalInverseNTTGeneric(&want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestPolyAddAssignNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var dstNEON, dstGeneric, src [n]fieldElement
		for i := range dstNEON {
			dstNEON[i] = fieldElement(mathrand.IntN(q))
			dstGeneric[i] = dstNEON[i]
			src[i] = fieldElement(mathrand.IntN(q))
		}

		polyAddAssignNEON(&dstNEON[0], &src[0])
		polyAddGeneric(&dstGeneric, &src)

		for i := range dstNEON {
			if dstNEON[i] != dstGeneric[i] {
				t.Fatalf("index %d: got %d, want %d", i, dstNEON[i], dstGeneric[i])
			}
		}
	}
}

func TestPolySubAssignNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var dstNEON, dstGeneric, src [n]fieldElement
		for i := range dstNEON {
			dstNEON[i] = fieldElement(mathrand.IntN(q))
			dstGeneric[i] = dstNEON[i]
			src[i] = fieldElement(mathrand.IntN(q))
		}

		polySubAssignNEON(&dstNEON[0], &src[0])
		polySubGeneric(&dstGeneric, &src)

		for i := range dstNEON {
			if dstNEON[i] != dstGeneric[i] {
				t.Fatalf("index %d: got %d, want %d", i, dstNEON[i], dstGeneric[i])
			}
		}
	}
}

func TestPolyInfinityNormNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var a [n]fieldElement
		for i := range a {
			a[i] = fieldElement(mathrand.IntN(q))
		}
		base := mathrand.IntN(int(qMinus1Div2))

		got := int(maxUint32(uint32(base), polyInfinityNormNEON(&a[0])))
		want := polyInfinityNormGeneric(&a, base)
		if got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	}
}

func TestPolyInfinityNormSignedNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var a [n]int32
		for i := range a {
			left := int32(mathrand.IntN(1 << 30))
			right := int32(mathrand.IntN(1 << 30))
			a[i] = left - right
		}
		base := mathrand.IntN(1 << 29)

		got := int(maxUint32(uint32(base), polyInfinityNormSignedNEON(&a[0])))
		want := polyInfinityNormSignedGeneric(&a, base)
		if got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	}
}

func TestDecomposeSubToR0Gamma32ARM64(t *testing.T) {
	for i := 0; i < 16; i++ {
		w := randomRingElement()
		cs2 := randomRingElement()

		var got [n]int32
		decomposeSubToR0Gamma32ARM64(&w[0], &cs2[0], &got[0])

		var want [n]int32
		decomposeSubToR0Generic(&want, &w, &cs2, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("decomposeSubToR0Gamma32ARM64 mismatch on iteration %d", i)
		}
	}
}

func TestDecomposeSubToR0Gamma88ARM64(t *testing.T) {
	for i := 0; i < 16; i++ {
		w := randomRingElement()
		cs2 := randomRingElement()

		var got [n]int32
		decomposeSubToR0Gamma88ARM64(&w[0], &cs2[0], &got[0])

		var want [n]int32
		decomposeSubToR0Generic(&want, &w, &cs2, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("decomposeSubToR0Gamma88ARM64 mismatch on iteration %d", i)
		}
	}
}

func TestDecomposeSubToR0ARM64Dispatch(t *testing.T) {
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

func TestUseHintPolyGamma32ARM64(t *testing.T) {
	for i := 0; i < 16; i++ {
		h := randomRingElement()
		r := randomRingElement()
		for j := range h {
			h[j] &= 1
		}

		var got ringElement
		useHintPolyGamma32ARM64(&h[0], &r[0], &got[0])

		var want ringElement
		useHintPolyGeneric(&want, &h, &r, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("useHintPolyGamma32ARM64 mismatch on iteration %d", i)
		}
	}
}

func TestUseHintPolyGamma88ARM64(t *testing.T) {
	for i := 0; i < 16; i++ {
		h := randomRingElement()
		r := randomRingElement()
		for j := range h {
			h[j] &= 1
		}

		var got ringElement
		useHintPolyGamma88ARM64(&h[0], &r[0], &got[0])

		var want ringElement
		useHintPolyGeneric(&want, &h, &r, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("useHintPolyGamma88ARM64 mismatch on iteration %d", i)
		}
	}
}

func TestUseHintPolyARM64Dispatch(t *testing.T) {
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
