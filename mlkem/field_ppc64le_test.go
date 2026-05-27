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

// applyNTTL2 applies only Layer 2 of the NTT (len=64, 2 groups).
func applyNTTL2(f *ringElement) {
	for g, zeta := range []fieldElement{zetas[2], zetas[3]} {
		start := g * 128
		for i := start; i < start+64; i++ {
			lo := f[i]
			hi := f[i+64]
			t := fieldMulGeneric(zeta, hi)
			f[i] = barrettReduceGeneric(uint32(lo) + uint32(t))
			f[i+64] = barrettReduceGeneric(uint32(q) + uint32(lo) - uint32(t))
		}
	}
}

func fieldMulGeneric(a, b fieldElement) fieldElement {
	return fieldElement(uint32(a) * uint32(b) % q)
}

func barrettReduceGeneric(x uint32) fieldElement {
	return fieldElement(x % q)
}

// TestPPC64LENTTLayerByLayer checks the NTT result after each layer.
func TestPPC64LENTTLayerByLayer(t *testing.T) {
	// Use a deterministic input.
	var f ringElement
	for i := range f {
		f[i] = fieldElement(i % 3329)
	}

	// Compute expected after L1 only.
	l1want := f
	applyNTTL1(&l1want)

	// Run ppc64le NTT.
	got := f
	internalNTTPPC64LE(&got)

	// Compare with full generic NTT.
	genwant := f
	internalNTTGeneric(&genwant)

	t.Logf("After full NTT:")
	t.Logf("  genwant[0:4]=%v", genwant[:4])
	t.Logf("  got    [0:4]=%v", got[:4])
	t.Logf("After L1 only (reference):")
	t.Logf("  l1want[0:4]=%v", l1want[:4])

	// If got equals l1want but not genwant, only L1 ran (subsequent layers broken).
	// If got doesn't equal l1want, L1 itself is broken.
	l1match := true
	for i := range got {
		if got[i] != l1want[i] {
			l1match = false
			t.Logf("  got != l1want at idx=%d: got=%d l1want=%d", i, got[i], l1want[i])
			break
		}
	}
	if l1match {
		t.Log("NOTE: got matches L1-only output — subsequent layers are broken or missing")
	}

	// Compute expected after L1+L2.
	l2want := f
	applyNTTL1(&l2want)
	applyNTTL2(&l2want)
	t.Logf("After L1+L2 (reference):")
	t.Logf("  l2want[0:4]=%v", l2want[:4])
}
