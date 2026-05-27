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
				t.Logf("input[0..15]=%v", f[:16])
				t.Logf("want[0..15]=%v", want[:16])
				t.Logf("got [0..15]=%v", got[:16])
				t.Fatalf("iter=%d idx=%d: NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// applyNTTL1 applies only Layer 1 of the NTT to f in-place (pure Go reference).
func applyNTTL1(f *ringElement) {
	// len=128, zeta=zetas[1], lo=f[0..127], hi=f[128..255]
	zeta := zetas[1]
	for i := 0; i < 128; i++ {
		lo := f[i]
		hi := f[i+128]
		t := fieldMulGeneric(zeta, hi)
		f[i] = barrettReduceGeneric(uint32(lo) + uint32(t))
		f[i+128] = barrettReduceGeneric(uint32(q) + uint32(lo) - uint32(t))
	}
}

func fieldMulGeneric(a, b fieldElement) fieldElement {
	return fieldElement(uint32(a) * uint32(b) % q)
}

func barrettReduceGeneric(x uint32) fieldElement {
	return fieldElement(x % q)
}

// TestPPC64LENTTUnitInput verifies specific cases to narrow the bug.
func TestPPC64LENTTUnitInput(t *testing.T) {
	// Test 1: f[0]=1, all others zero. Only L1 butterfly involves element 0.
	// After full NTT, f[0] should equal genwant[0].
	for testIdx := 0; testIdx < 4; testIdx++ {
		var f ringElement
		f[testIdx] = 1

		got := f
		want := f
		internalNTTPPC64LE(&got)
		internalNTTGeneric(&want)

		if got[testIdx] != want[testIdx] {
			t.Logf("f[%d]=1: NTT[%d]: got=%d want=%d", testIdx, testIdx, got[testIdx], want[testIdx])
		}
		// Check all elements
		for j := range got {
			if got[j] != want[j] {
				t.Errorf("f[%d]=1: idx=%d: got=%d want=%d", testIdx, j, got[j], want[j])
				break
			}
		}
	}

	// Test 2: linear input f[i]=i
	var f ringElement
	for i := range f {
		f[i] = fieldElement(i)
	}
	got := f
	want := f
	internalNTTPPC64LE(&got)
	internalNTTGeneric(&want)
	t.Logf("Linear input: got[0:4]=%v, want[0:4]=%v", got[:4], want[:4])
	for j := range got {
		if got[j] != want[j] {
			t.Errorf("linear idx=%d: got=%d want=%d", j, got[j], want[j])
			break
		}
	}
}
