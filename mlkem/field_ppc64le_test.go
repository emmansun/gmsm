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
	// Test with single nonzero element, various values
	for testIdx := 0; testIdx < 256; testIdx++ {
		for val := fieldElement(1); val < 3329; val += 100 {
			var f ringElement
			f[testIdx] = val

			got := f
			want := f
			internalNTTPPC64LE(&got)
			internalNTTGeneric(&want)

			for j := range got {
				if got[j] != want[j] {
					t.Errorf("f[%d]=%d: idx=%d: got=%d want=%d", testIdx, val, j, got[j], want[j])
					goto nextTest
				}
			}
		nextTest:
		}
	}

	// Test with two nonzero elements to detect interference
	for a := 0; a < 256; a += 16 {
		for b := a + 1; b < 256; b += 16 {
			var f ringElement
			f[a] = 100
			f[b] = 200

			got := f
			want := f
			internalNTTPPC64LE(&got)
			internalNTTGeneric(&want)

			for j := range got {
				if got[j] != want[j] {
					t.Errorf("f[%d]=100,f[%d]=200: idx=%d: got=%d want=%d", a, b, j, got[j], want[j])
					goto nextPair
				}
			}
		nextPair:
		}
	}
}
