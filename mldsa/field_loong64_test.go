// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

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
