// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build ppc64le && !purego

package mlkem

import (
	"testing"
)

// randomNTTElement returns an nttElement with coefficients in [0, q).
func randomNTTElement() nttElement {
	f := randomRingElement()
	internalNTTGeneric(&f)
	return nttElement(f)
}

func TestPPC64LEPolyAddAssignMatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignPPC64LE(&got, &src)
		polyAddAssignGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polyAdd mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestPPC64LEPolySubAssignMatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignPPC64LE(&got, &src)
		polySubAssignGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polySub mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestPPC64LENTTMulAccMatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		acc := randomNTTElement()
		lhs := randomNTTElement()
		rhs := randomNTTElement()

		got := acc
		want := acc

		internalNTTMulAccPPC64LE(&got, &lhs, &rhs)
		nttMulAccGeneric(&want, &lhs, &rhs)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: nttMulAcc mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func BenchmarkPPC64LEPolyAdd(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d := dst
			polyAddAssignGeneric(&d, &src)
		}
	})
	b.Run("PPC64LE", func(b *testing.B) {
		dst := randomRingElement()
		src := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d := dst
			polyAddAssignPPC64LE(&d, &src)
		}
	})
}

func BenchmarkPPC64LENTTMulAcc(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a := acc
			nttMulAccGeneric(&a, &lhs, &rhs)
		}
	})
	b.Run("PPC64LE", func(b *testing.B) {
		lhs := randomNTTElement()
		rhs := randomNTTElement()
		acc := randomNTTElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			a := acc
			internalNTTMulAccPPC64LE(&a, &lhs, &rhs)
		}
	})
}

func TestPPC64LENTTMulMatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		lhs := randomNTTElement()
		rhs := randomNTTElement()

		var got, want nttElement

		internalNTTMulPPC64LE(&got, &lhs, &rhs)
		nttMulGeneric(&want, &lhs, &rhs)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: nttMul mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestPPC64LENTTMatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		got := f
		want := f

		internalNTTPPC64LE(&got)
		internalNTTGeneric(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}
