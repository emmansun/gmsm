// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import (
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"
)

func requireLASX(t *testing.T) {
	t.Helper()
	if !useLASX {
		t.Skip("LASX not available on this machine")
	}
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

func TestLASXPolyAddAssignMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		dst := randomRingElementMldsa()
		src := randomRingElementMldsa()

		got := dst
		want := dst

		polyAddAssignLASX(&got[0], &src[0])
		polyAddGeneric(&want, &src)

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
		dst := randomRingElementMldsa()
		src := randomRingElementMldsa()

		got := dst
		want := dst

		polySubAssignLASX(&got[0], &src[0])
		polySubGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polySub mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func BenchmarkPolyAdd(b *testing.B) {
	left := randomRingElementMldsa()
	right := randomRingElementMldsa()
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddGeneric(&out, &right)
		}
		_ = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssign(&out, &right)
		}
		_ = out
	})

	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available")
		}
		for i := 0; i < b.N; i++ {
			out = left
			polyAddAssignLASX(&out[0], &right[0])
		}
		_ = out
	})
}

func BenchmarkPolySub(b *testing.B) {
	left := randomRingElementMldsa()
	right := randomRingElementMldsa()
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubGeneric(&out, &right)
		}
		_ = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssign(&out, &right)
		}
		_ = out
	})

	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available")
		}
		for i := 0; i < b.N; i++ {
			out = left
			polySubAssignLASX(&out[0], &right[0])
		}
		_ = out
	})
}

func randomNttElement() nttElement {
	return ntt(randomRingElementMldsa())
}

func TestLASXNttMulMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		lhs := randomNttElement()
		rhs := randomNttElement()
		var got, want nttElement

		nttMulLASX(&lhs, &rhs, &got)
		nttMulGeneric(&want, &lhs, &rhs)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: nttMul mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXNttMulAccMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		lhs := randomNttElement()
		rhs := randomNttElement()
		accGot := randomNttElement()
		accWant := accGot

		nttMulAccLASX(&lhs, &rhs, &accGot)
		nttMulAccGeneric(&accWant, &lhs, &rhs)

		for j := range accGot {
			if accGot[j] != accWant[j] {
				t.Fatalf("iter=%d idx=%d: nttMulAcc mismatch: got=%d want=%d", i, j, accGot[j], accWant[j])
			}
		}
	}
}

func TestLASXNttMatRowVecMulMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for length := 1; length <= 5; length++ {
		vec := make([]nttElement, length)
		mat := make([]nttElement, length)
		for i := range vec {
			vec[i] = randomNttElement()
			mat[i] = randomNttElement()
		}
		var got, want nttElement

		nttMatRowVecMulLASX(&got, &vec[0], &mat[0], length)
		nttMatRowVecMulGeneric(&want, &vec[0], &mat[0], length)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("length=%d idx=%d: nttMatRowVecMul mismatch: got=%d want=%d", length, j, got[j], want[j])
			}
		}
	}
}

func BenchmarkNTTMul(b *testing.B) {
	lhs := randomNttElement()
	rhs := randomNttElement()
	var out nttElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMulGeneric(&out, &lhs, &rhs)
		}
		_ = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			nttMul(&out, &lhs, &rhs)
		}
		_ = out
	})

	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available")
		}
		for i := 0; i < b.N; i++ {
			nttMulLASX(&lhs, &rhs, &out)
		}
		_ = out
	})
}

func TestLASXNTTMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		f := randomRingElementMldsa()
		got := f
		want := f

		internalNTTLASX(&got)
		internalNTTGeneric(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: internalNTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXInverseNTTMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		f := nttElement(randomRingElementMldsa())
		got := f
		want := f

		internalInverseNTTLASX(&got)
		internalInverseNTTGeneric(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: internalInverseNTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func BenchmarkNTT(b *testing.B) {
	f := randomRingElementMldsa()

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := f
			internalNTTGeneric(&x)
		}
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := f
			internalNTT(&x)
		}
	})

	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available")
		}
		for i := 0; i < b.N; i++ {
			x := f
			internalNTTLASX(&x)
		}
	})
}

func BenchmarkInverseNTT(b *testing.B) {
	f := nttElement(randomRingElementMldsa())

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := f
			internalInverseNTTGeneric(&x)
		}
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := f
			internalInverseNTT(&x)
		}
	})

	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX not available")
		}
		for i := 0; i < b.N; i++ {
			x := f
			internalInverseNTTLASX(&x)
		}
	})
}

func TestLASXPolyInfinityNormMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		a := randomRingElementMldsa()

		got := polyInfinityNormLASX(&a[0])
		want := uint32(polyInfinityNormGeneric(&a, 0))

		if got != want {
			t.Fatalf("iter=%d: polyInfinityNorm mismatch: got=%d want=%d", i, got, want)
		}
	}
}

func TestLASXPolyInfinityNormSignedMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		// Random signed int32 values in (-q/2, q/2)
		var a [n]int32
		for j := range a {
			var b [4]byte
			rand.Read(b[:])
			v := int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
			a[j] = v % int32(qMinus1Div2)
		}

		got := polyInfinityNormSignedLASX(&a[0])
		want := uint32(polyInfinityNormSignedGeneric(&a, 0))

		if got != want {
			t.Fatalf("iter=%d: polyInfinityNormSigned mismatch: got=%d want=%d", i, got, want)
		}
	}
}

func TestLASXDecomposeSubToR0Gamma32MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var w, cs2 ringElement
		var gotDst, wantDst [n]int32
		for i := range w {
			w[i] = fieldElement(mathrand.IntN(int(q)))
			cs2[i] = fieldElement(mathrand.IntN(int(q)))
		}
		decomposeSubToR0Gamma32LASX(&w[0], &cs2[0], &gotDst[0])
		decomposeSubToR0Generic(&wantDst, &w, &cs2, gamma2QMinus1Div32)
		for i := range gotDst {
			if gotDst[i] != wantDst[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotDst[i], wantDst[i])
			}
		}
	}
}

func TestLASXDecomposeSubToR0Gamma88MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var w, cs2 ringElement
		var gotDst, wantDst [n]int32
		for i := range w {
			w[i] = fieldElement(mathrand.IntN(int(q)))
			cs2[i] = fieldElement(mathrand.IntN(int(q)))
		}
		decomposeSubToR0Gamma88LASX(&w[0], &cs2[0], &gotDst[0])
		decomposeSubToR0Generic(&wantDst, &w, &cs2, gamma2QMinus1Div88)
		for i := range gotDst {
			if gotDst[i] != wantDst[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotDst[i], wantDst[i])
			}
		}
	}
}

func TestLASXUseHintGamma32MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var h, r, gotDst, wantDst ringElement
		for i := range h {
			h[i] = fieldElement(mathrand.IntN(2))
			r[i] = fieldElement(mathrand.IntN(int(q)))
		}
		useHintPolyGamma32LASX(&h[0], &r[0], &gotDst[0])
		useHintPolyGeneric(&wantDst, &h, &r, gamma2QMinus1Div32)
		for i := range gotDst {
			if gotDst[i] != wantDst[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotDst[i], wantDst[i])
			}
		}
	}
}

func TestLASXUseHintGamma88MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var h, r, gotDst, wantDst ringElement
		for i := range h {
			h[i] = fieldElement(mathrand.IntN(2))
			r[i] = fieldElement(mathrand.IntN(int(q)))
		}
		useHintPolyGamma88LASX(&h[0], &r[0], &gotDst[0])
		useHintPolyGeneric(&wantDst, &h, &r, gamma2QMinus1Div88)
		for i := range gotDst {
			if gotDst[i] != wantDst[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotDst[i], wantDst[i])
			}
		}
	}
}

func TestLASXMakeHintGamma32MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var ct0, cs2, w, gotHint, wantHint ringElement
		for i := range ct0 {
			ct0[i] = fieldElement(mathrand.IntN(int(q)))
			cs2[i] = fieldElement(mathrand.IntN(int(q)))
			w[i] = fieldElement(mathrand.IntN(int(q)))
		}
		makeHintPolyGamma32LASX(&ct0[0], &cs2[0], &w[0], &gotHint[0])
		for i := range wantHint {
			wantHint[i] = makeHint(ct0[i], cs2[i], w[i], gamma2QMinus1Div32)
		}
		for i := range gotHint {
			if gotHint[i] != wantHint[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotHint[i], wantHint[i])
			}
		}
	}
}

func TestLASXMakeHintGamma88MatchesGeneric(t *testing.T) {
	requireLASX(t)

	for range 200 {
		var ct0, cs2, w, gotHint, wantHint ringElement
		for i := range ct0 {
			ct0[i] = fieldElement(mathrand.IntN(int(q)))
			cs2[i] = fieldElement(mathrand.IntN(int(q)))
			w[i] = fieldElement(mathrand.IntN(int(q)))
		}
		makeHintPolyGamma88LASX(&ct0[0], &cs2[0], &w[0], &gotHint[0])
		for i := range wantHint {
			wantHint[i] = makeHint(ct0[i], cs2[i], w[i], gamma2QMinus1Div88)
		}
		for i := range gotHint {
			if gotHint[i] != wantHint[i] {
				t.Fatalf("index %d: got=%d want=%d", i, gotHint[i], wantHint[i])
			}
		}
	}
}
