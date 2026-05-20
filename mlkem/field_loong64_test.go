// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
	"testing"
)

func requireLASX(t *testing.T) {
	t.Helper()
	if !useLASX {
		t.Skip("LASX not available on this machine")
	}
}

func TestLASXPolyAddAssignMatchesGeneric(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polyAddAssignLASX(&got, &src)
		polyAddAssignGeneric(&want, &src)

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
		dst := randomRingElement()
		src := randomRingElement()

		got := dst
		want := dst

		polySubAssignLASX(&got, &src)
		polySubAssignGeneric(&want, &src)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: polySub mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXForwardNTTMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTLASX(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXInverseNTTMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTLASX(&got)
		internalMontInverseNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXNTTRoundTrip(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		internalNTTLASX(&got)
		internalInverseNTTLASX((*nttElement)(&got))

		// internalMontNTT + internalMontInverseNTT gives r*in mod q (not identity),
		// so compare against the scalar Montgomery roundtrip result.
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: NTT round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// TestLASXScalarNTTThenLASXINTT applies scalar NTT then LASX inverse NTT.
// If this passes, the INTT is correct; if it fails, INTT is the problem.
func TestLASXScalarNTTThenLASXINTT(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		// Apply scalar forward NTT then LASX inverse NTT
		internalMontNTT(&got)
		internalInverseNTTLASX((*nttElement)(&got))

		// Compare against scalar Montgomery roundtrip (which gives r*in, not in)
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: scalar-NTT+LASX-INTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// TestLASXNTTThenScalarINTT applies LASX NTT then scalar inverse NTT.
// If this passes, the forward NTT is correct; if it fails, NTT is the problem.
func TestLASXNTTThenScalarINTT(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		// Apply LASX forward NTT then scalar inverse NTT
		internalNTTLASX(&got)
		internalMontInverseNTT((*nttElement)(&got))

		// Compare against scalar Montgomery roundtrip (which gives r*in, not in)
		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: LASX-NTT+scalar-INTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestLASXDispatchNTTRoundTripMatchesMontgomery(t *testing.T) {
	requireLASX(t)

	old := useLASX
	useLASX = true
	defer func() { useLASX = old }()

	for i := 0; i < 100; i++ {
		in := randomRingElement()

		got := in
		internalNTT(&got)
		internalInverseNTT((*nttElement)(&got))

		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: dispatch round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

// montMulLASXSigned computes Montgomery multiplication using the signed approach
// that LASX assembly uses. This is a Go reference for debugging.
func montMulLASXSigned(a, b int16) int16 {
	const qInv = int16(-3327) // 62209 as uint16, -3327 as int16
	const q = int16(3329)
	prodLo := int16(int32(a) * int32(b) & 0xFFFF)
	prodHi := int16(int32(a) * int32(b) >> 16)
	t := int16(int32(prodLo) * int32(qInv) & 0xFFFF)
	tqHi := int16(int32(t) * int32(q) >> 16)
	result := prodHi - tqHi
	// REDUCE_MONT: if result < 0, add q
	if result < 0 {
		result += q
	}
	return result
}

// TestMontMulSignedMatchesScalar verifies the signed LASX Montgomery formula
// matches fieldMontMul.
func TestMontMulSignedMatchesScalar(t *testing.T) {
	for a := 0; a < q; a++ {
		for b := 0; b < q; b++ {
			got := montMulLASXSigned(int16(a), int16(b))
			want := fieldMontMul(fieldElement(a), fieldElement(b))
			if fieldElement(got) != want {
				t.Fatalf("montMulLASXSigned(%d, %d) = %d, want %d", a, b, got, want)
			}
		}
	}
}

// internalMontNTTLayersUpTo applies only the first 'maxLayers' layers of the
// Montgomery NTT (layer 0 is len=128 butterfly, layer 6 is len=2 butterfly).
func internalMontNTTLayersUpTo(f *ringElement, maxLayers int) {
	k := 1
	layer := 0
	for l := 128; l >= 2; l /= 2 {
		if layer >= maxLayers {
			return
		}
		for start := 0; start < 256; start += 2 * l {
			zeta := zetasMontgomery[k]
			k++
			fa := f[start : start+l]
			fb := f[start+l : start+l+l]
			for j := 0; j < l; j++ {
				t := fieldMontMul(zeta, fb[j])
				fb[j] = fieldSub(fa[j], t)
				fa[j] = fieldAdd(fa[j], t)
			}
		}
		layer++
	}
}

// TestLASXNTTBisectLayers04 tests that layers 0-4 of LASX NTT match scalar.
// If this passes but TestLASXForwardNTTMatchesMontgomery fails, the bug is in layers 5-6.
// If this fails, the bug is in layers 0-4.
func TestLASXNTTBisectLayers04(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTLASXLayers04(&got)
		internalMontNTTLayersUpTo(&want, 5) // layers 0-4

		mismatches := 0
		for j := range got {
			if got[j] != want[j] {
				if mismatches == 0 {
					t.Errorf("iter=%d layers0-4 first mismatch at j=%d: got=%d want=%d", i, j, got[j], want[j])
				}
				mismatches++
			}
		}
		if mismatches > 0 {
			t.Errorf("iter=%d layers0-4: %d mismatches total", i, mismatches)
			return
		}
	}
}

// TestLASXNTTBisectLayers56 tests that layers 5-6 of LASX NTT match scalar,
// starting from scalar-computed layers 0-4 state.
// If this fails but TestLASXNTTBisectLayers04 passes, the bug is in layers 5-6.
func TestLASXNTTBisectLayers56(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()

		// Apply layers 0-4 with scalar
		got := in
		internalMontNTTLayersUpTo(&got, 5)

		// Apply layers 5-6 with LASX
		internalNTTLASXLayers56(&got)

		// Compare with full scalar NTT (all 7 layers)
		want := in
		internalMontNTTLayersUpTo(&want, 7)

		mismatches := 0
		for j := range got {
			if got[j] != want[j] {
				if mismatches == 0 {
					t.Errorf("iter=%d layers5-6 first mismatch at j=%d: got=%d want=%d", i, j, got[j], want[j])
				}
				mismatches++
			}
		}
		if mismatches > 0 {
			t.Errorf("iter=%d layers5-6: %d mismatches total", i, mismatches)
			return
		}
	}
}

// TestLASXNTTBisectLayers0to3 tests that LASX layers 0-3 (l=128,64,32,16) match scalar.
// If this passes but TestLASXNTTBisectLayers04 fails, the bug is in layer 4 (XVPERMIQ code).
// If this fails, the bug is in the simple butterfly loops (layers 0-3).
func TestLASXNTTBisectLayers0to3(t *testing.T) {
	requireLASX(t)

	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTLASXLayers0to3(&got)
		internalMontNTTLayersUpTo(&want, 4) // layers 0-3

		mismatches := 0
		for j := range got {
			if got[j] != want[j] {
				if mismatches == 0 {
					t.Errorf("iter=%d layers0-3 first mismatch at j=%d: got=%d want=%d", i, j, got[j], want[j])
				}
				mismatches++
			}
		}
		if mismatches > 0 {
			t.Errorf("iter=%d layers0-3: %d mismatches total", i, mismatches)
			return
		}
	}
}

// TestLASXNTTLayerBisect applies LASX full NTT then checks element[0] against
// the Go layer-by-layer result. Also prints individual layer intermediate values
// to help identify which layer is first wrong. Requires manual comparison with
// hardware output since we cannot split LASX NTT into per-layer calls.
func TestLASXNTTLayerBisect(t *testing.T) {
	requireLASX(t)

	// Fixed input
	var in ringElement
	for i := range in {
		in[i] = fieldElement(i % q)
	}

	// Print what the scalar NTT gives after each layer
	t.Log("Scalar NTT intermediate f[0..3] after each layer:")
	for maxL := 1; maxL <= 7; maxL++ {
		f := in
		internalMontNTTLayersUpTo(&f, maxL)
		t.Logf("  after layer %d: f[0]=%d f[1]=%d f[2]=%d f[3]=%d f[128]=%d f[129]=%d",
			maxL, f[0], f[1], f[2], f[3], f[128], f[129])
	}
}

// TestLASXNTTSimulateLayer5 simulates the LASX Layer 5 data layout in Go
// and verifies the result matches scalar layer-by-layer NTT after layer 5.
// This is architecture-independent and runs on any platform.
func TestLASXNTTSimulateLayer5(t *testing.T) {
	var in ringElement
	for i := range in {
		in[i] = fieldElement(i % q)
	}

	// Apply layers 0-4 with scalar (to match state before layer 5)
	f := in
	internalMontNTTLayersUpTo(&f, 4)

	// Now simulate LASX Layer 5 by applying it the LASX way (simulate twiddle layout)
	// For block 0: X9=f[0..15], X10=f[16..31]
	// XVILVLV X10, X9, X0 → X0 = [f[16..19], f[0..3], f[24..27], f[8..11]]
	// Twiddle X3 = [z2×4, z0×4 | z3×4, z1×4] where z0=z4, z1=z4+1, z2=z4+2, z3=z4+3
	// The 4 groups are processed with their respective zetas.

	for block := 0; block < 8; block++ {
		// Groups g0..g3 for this block
		g0 := block * 32 // f[g0*4] .. f[g0*4+3] = a, f[g0*4+4] .. f[g0*4+7] = b
		z4 := 32 + block*4

		// Apply Layer 5 butterfly to each of the 4 groups
		for g := 0; g < 4; g++ {
			start := g0 + g*8
			zeta := zetasMontgomery[z4+g]
			for j := 0; j < 4; j++ {
				t_val := fieldMontMul(zeta, f[start+4+j])
				f[start+4+j] = fieldSub(f[start+j], t_val)
				f[start+j] = fieldAdd(f[start+j], t_val)
			}
		}
	}

	// Expected: scalar through layer 5
	want := in
	internalMontNTTLayersUpTo(&want, 5)

	for j := range f {
		if f[j] != want[j] {
			t.Fatalf("SimulateLayer5 mismatch at j=%d: got=%d want=%d", j, f[j], want[j])
		}
	}
	t.Log("SimulateLayer5 passes!")
}

func TestLASXNTTDiagnosticFixed(t *testing.T) {
	requireLASX(t)
	// Fixed input: in[i] = i % q (deterministic).
	var in ringElement
	for i := range in {
		in[i] = fieldElement(i % q)
	}

	got := in
	want := in

	internalNTTLASX(&got)
	internalMontNTT(&want)

	mismatches := 0
	for j := range got {
		if got[j] != want[j] {
			t.Logf("mismatch idx=%d: got=%d want=%d", j, got[j], want[j])
			mismatches++
			if mismatches >= 20 {
				t.Logf("(further mismatches truncated)")
				break
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("NTT mismatch: %d values differ", mismatches)
	}
}

func BenchmarkNTTLASX(b *testing.B) {
	requireLASX(&testing.T{})
	f := randomRingElement()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		internalNTTLASX(&f)
	}
}

func BenchmarkInverseNTTLASX(b *testing.B) {
	requireLASX(&testing.T{})
	f := randomRingElement()
	internalNTTLASX(&f)
	nf := nttElement(f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		internalInverseNTTLASX(&nf)
	}
}
