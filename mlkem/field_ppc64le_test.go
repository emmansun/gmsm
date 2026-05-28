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

// applyINTTLayer applies one layer of the inverse NTT (Gentleman-Sande) to f in place.
// len: the current length (2, 4, 8, ..., 128).
// k: starting zeta index (127 for len=2, decreasing).
// Returns the next k value.
func applyINTTLayer(f *nttElement, length, k int) int {
	for start := 0; start < 256; start += 2 * length {
		zeta := zetas[k]
		k--
		for j := 0; j < length; j++ {
			lo := f[start+j]
			hi := f[start+length+j]
			f[start+j] = fieldAdd(lo, hi)
			f[start+length+j] = fieldMulSub(zeta, hi, lo)
		}
	}
	return k
}

func TestPPC64LEInverseNTTLayerByLayer(t *testing.T) {
	for iter := 0; iter < 10; iter++ {
		in := randomNTTElement()

		// Apply INTT layer by layer in Go, check after EACH layer
		ref := in
		k := 127
		layerLens := []int{2, 4, 8, 16, 32, 64, 128}
		for li, length := range layerLens {
			k = applyINTTLayer(&ref, length, k)
			_ = li
		}
		// Apply final scale
		for i := range ref {
			ref[i] = fieldMul(ref[i], 3303)
		}

		got := in
		internalInverseNTTPPC64LE(&got)

		mismatch := false
		for j := range got {
			if got[j] != ref[j] {
				t.Errorf("iter=%d idx=%d: got=%d want=%d", iter, j, got[j], ref[j])
				mismatch = true
			}
		}
		if mismatch {
			t.Logf("in[64..71]=%v", in[64:72])
			t.Logf("got[64..71]=%v", got[64:72])
			t.Logf("ref[64..71]=%v", ref[64:72])
			return
		}
	}
}

func TestPPC64LEInverseNTTMatchesGeneric(t *testing.T) {
	for i := 0; i < 5; i++ {
		in := randomNTTElement()
		got := in
		want := in

		internalInverseNTTPPC64LE(&got)
		internalInverseNTTGeneric(&want)

		var mismatches []int
		for j := range got {
			if got[j] != want[j] {
				mismatches = append(mismatches, j)
			}
		}
		if len(mismatches) > 0 {
			t.Errorf("iter=%d: %d mismatches, first few indices: %v", i, len(mismatches), mismatches[:min(20, len(mismatches))])
			for _, j := range mismatches[:min(8, len(mismatches))] {
				t.Errorf("  idx=%d: got=%d want=%d diff=%d", j, got[j], want[j], int(got[j])-int(want[j]))
			}
			t.Logf("in[60..75]=%v", in[60:76])
			t.Logf("got[60..75]=%v", got[60:76])
			t.Logf("want[60..75]=%v", want[60:76])
			return
		}
	}
}

func TestPPC64LENTTRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		orig := randomRingElement()
		f := orig

		internalNTTPPC64LE(&f)
		nf := nttElement(f)
		internalInverseNTTPPC64LE(&nf)
		result := ringElement(nf)

		for j := range orig {
			if orig[j] != result[j] {
				t.Fatalf("iter=%d idx=%d: round-trip mismatch: got=%d want=%d", i, j, result[j], orig[j])
			}
		}
	}
}

func BenchmarkPPC64LENTTInverse(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		internalNTTGeneric(&f)
		nf := nttElement(f)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nf2 := nf
			internalInverseNTTGeneric(&nf2)
		}
	})
	b.Run("PPC64LE", func(b *testing.B) {
		f := randomRingElement()
		internalNTTPPC64LE(&f)
		nf := nttElement(f)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nf2 := nf
			internalInverseNTTPPC64LE(&nf2)
		}
	})
}

func BenchmarkPPC64LENTTNTT(b *testing.B) {
	b.Run("Generic", func(b *testing.B) {
		f := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f2 := f
			internalNTTGeneric(&f2)
		}
	})
	b.Run("PPC64LE", func(b *testing.B) {
		f := randomRingElement()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f2 := f
			internalNTTPPC64LE(&f2)
		}
	})
}

func ringCompressAndEncode5Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 5)
}

func ringCompressAndEncode11Generic(out []byte, f *ringElement) {
	ringCompressAndEncode(out[:0], f, 11)
}

func TestPPC64LECompressAndEncode1MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		var got, want [encodingSize1]byte
		ringCompressAndEncode1PPC64LE(got[:], &f)
		ringCompressAndEncode1Generic(want[:], &f)
		if got != want {
			t.Fatalf("iter=%d: encode1 mismatch\ngot=%x\nwant=%x", i, got, want)
		}
	}
}

func TestPPC64LECompressAndEncode4MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		var got, want [encodingSize4]byte
		ringCompressAndEncode4PPC64LE(got[:], &f)
		ringCompressAndEncode4Generic(want[:], &f)
		if got != want {
			t.Fatalf("iter=%d: encode4 mismatch\ngot=%x\nwant=%x", i, got, want)
		}
	}
}

func TestPPC64LEDecodeAndDecompress4MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		var b [encodingSize4]byte
		for j := range b {
			b[j] = byte(i*7 + j*13)
		}
		var got, want ringElement
		ringDecodeAndDecompress4PPC64LE(&b, &got)
		ringDecodeAndDecompress4Generic(&b, &want)
		if got != want {
			t.Fatalf("iter=%d: decode4 mismatch idx=0: got=%d want=%d", i, got[0], want[0])
		}
	}
}

func TestPPC64LECompressAndEncode5MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		var got, want [encodingSize5]byte
		ringCompressAndEncode5PPC64LE(got[:], &f)
		ringCompressAndEncode5Generic(want[:], &f)
		if got != want {
			t.Fatalf("iter=%d: encode5 mismatch", i)
		}
	}
}

func TestPPC64LEDecodeAndDecompress5MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		var b [encodingSize5]byte
		for j := range b {
			b[j] = byte(i*11 + j*7)
		}
		var got ringElement
		ringDecodeAndDecompress5PPC64LE(&b, &got)
		want := ringDecodeAndDecompress(b[:], 5)
		if got != want {
			t.Fatalf("iter=%d: decode5 mismatch idx=0: got=%d want=%d", i, got[0], want[0])
		}
	}
}

func TestPPC64LECompressAndEncode10MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		var got, want [encodingSize10]byte
		ringCompressAndEncode10PPC64LE(got[:], &f)
		ringCompressAndEncode10Generic(want[:], &f)
		if got != want {
			t.Fatalf("iter=%d: encode10 mismatch", i)
		}
	}
}

func TestPPC64LECompressAndEncode11MatchesGeneric(t *testing.T) {
	for i := 0; i < 200; i++ {
		f := randomRingElement()
		var got, want [encodingSize11]byte
		ringCompressAndEncode11PPC64LE(got[:], &f)
		ringCompressAndEncode11Generic(want[:], &f)
		if got != want {
			t.Fatalf("iter=%d: encode11 mismatch", i)
		}
	}
}

func TestPPC64LEDecodeAndDecompressU10MatchesGeneric(t *testing.T) {
	for i := 0; i < 50; i++ {
		// Build random input for k=2 ring elements
		const k = 2
		c := make([]byte, k*encodingSize10)
		for j := range c {
			c[j] = byte(i*3 + j*7)
		}
		got := make([]ringElement, k)
		want := make([]ringElement, k)
		decodeAndDecompressU10PPC64LE(got, c)
		decodeAndDecompressU10Generic(want, c)
		for ki := range got {
			if got[ki] != want[ki] {
				t.Fatalf("iter=%d ki=%d: decodeU10 mismatch", i, ki)
			}
		}
	}
}

func TestPPC64LEDecodeAndDecompressU11MatchesGeneric(t *testing.T) {
	for i := 0; i < 50; i++ {
		const k = 2
		c := make([]byte, k*encodingSize11)
		for j := range c {
			c[j] = byte(i*5 + j*11)
		}
		got := make([]ringElement, k)
		want := make([]ringElement, k)
		decodeAndDecompressU11PPC64LE(got, c)
		decodeAndDecompressU11Generic(want, c)
		for ki := range got {
			if got[ki] != want[ki] {
				t.Fatalf("iter=%d ki=%d: decodeU11 mismatch", i, ki)
			}
		}
	}
}
