// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"math/big"
	mathrand "math/rand/v2"
	"testing"
)

const qInv = 58728449 // q⁻¹ satisfies: q⁻¹ * q = 1 mod 2³²

func bitreverse(x byte) byte {
	var y byte
	for i := range 8 {
		y |= (x & 1) << (7 - i)
		x >>= 1
	}
	return y
}

func TestConstants(t *testing.T) {
	q1 := big.NewInt(q)
	a := big.NewInt(1 << 32)

	q1Inv := new(big.Int)
	q1Inv.ModInverse(q1, a)
	if q1Inv.Cmp(big.NewInt(int64(qInv))) != 0 {
		t.Fatalf("q^-1 mod 2^32 = %d, expected %d", q1, qInv)
	}

	q1Neg := new(big.Int)
	q1Neg.Sub(a, q1)
	q1NegInv := new(big.Int)
	q1NegInv.ModInverse(q1Neg, a)
	if q1NegInv.Cmp(big.NewInt(int64(qNegInv))) != 0 {
		t.Fatalf("-q^-1 mod 2^32 = %d, expected %d", q1Neg, int64(qNegInv))
	}

	r1 := new(big.Int)
	r1.Mod(a, q1)
	if r1.Cmp(big.NewInt(int64(r))) != 0 {
		t.Fatalf("r = 2^32 mod q = %d, expected %d", r1, r)
	}

	dgreeInv := new(big.Int)
	dgreeInv.ModInverse(big.NewInt(int64(256)), q1)
	dgreeInv.Mul(dgreeInv, r1)
	dgreeInv.Mul(dgreeInv, r1)
	dgreeInv.Mod(dgreeInv, q1)
	if dgreeInv.Int64() != 41978 {
		t.Fatalf("dgreeInv = ((256^(-1) mod q) * r^2) mod q  = %d, expected 41978", dgreeInv)
	}

	// test zetas
	zeta := big.NewInt(1753)
	for i := 1; i < 256; i++ {
		bitRev := bitreverse(byte(i))
		zetaV := new(big.Int).Exp(zeta, big.NewInt(int64(bitRev)), q1)
		if uint32(zetaV.Int64()) != uint32(zetas[i]) {
			t.Fatalf("zetas[%d] = %d, expected %d", i, uint32(zetaV.Int64()), zetas[i])
		}
	}

	// test zetasMontgomery
	for i, z := range zetas {
		zMont := big.NewInt(int64(z))
		zMont.Mul(zMont, r1)
		zMont.Mod(zMont, q1)
		if zMont.Cmp(big.NewInt(int64(zetasMontgomery[i]))) != 0 {
			t.Fatalf("zetasMontgomery[%d] = %d, expected %d", i, zMont, zetasMontgomery[i])
		}
	}
}

func TestFieldAdd(t *testing.T) {
	for a := fieldElement(q - 1000); a < q; a++ {
		for b := fieldElement(q - 1000); b < q; b++ {
			got := fieldAdd(a, b)
			exp := (a + b) % q
			if got != exp {
				t.Fatalf("%d + %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldSub(t *testing.T) {
	for a := fieldElement(0); a < 2000; a++ {
		for b := fieldElement(q - 1000); b < q; b++ {
			got := fieldSub(a, b)
			exp := (a - b + q) % q
			if got != exp {
				t.Fatalf("%d - %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldMul(t *testing.T) {
	for a := fieldElement(q - 1000); a < q; a++ {
		for b := fieldElement(q - 1000); b < q; b++ {
			got := fieldMul(fieldElement((uint64(a)*uint64(r))%q), b)
			exp := fieldElement((uint64(a) * uint64(b)) % q)
			if got != exp {
				t.Fatalf("%d * %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldBarrettMul(t *testing.T) {
	for a := fieldElement(q - 1000); a < q; a++ {
		for b := fieldElement(q - 1000); b < q; b++ {
			got := fieldBarrettMul(a, b)
			exp := fieldElement((uint64(a) * uint64(b)) % q)
			if got != exp {
				t.Fatalf("%d * %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func randomRingElement() ringElement {
	var r ringElement
	for i := range r {
		r[i] = fieldElement(mathrand.IntN(q))
	}
	return r
}

func TestNTT(t *testing.T) {
	r := randomRingElement()
	rNTT := ntt(r)
	rBarretNTT := barrettNTT(r)
	for i, v := range rNTT {
		if v != rBarretNTT[i] {
			t.Errorf("expected %v, got %v", v, rBarretNTT[i])
		}
	}
}

func TestInverseNTT(t *testing.T) {
	r := randomRingElement()
	ret := inverseNTT(ntt(r))
	for i, v := range r {
		if v != fieldReduce(uint64(ret[i])) {
			t.Errorf("expected %v, got %v", v, fieldReduce(uint64(ret[i])))
		}
	}
}

func TestInverseBarrettNTT(t *testing.T) {
	r := randomRingElement()
	ret := inverseBarrettNTT(barrettNTT(r))
	for i, v := range r {
		if v != ret[i] {
			t.Errorf("expected %v, got %v", v, ret[i])
		}
	}
}

// this is the real use case for NTT:
//
//   - convert to NTT
//   - multiply in NTT
//   - inverse NTT
func TestInverseNTTWithMultiply(t *testing.T) {
	r1 := randomRingElement()
	r2 := randomRingElement()

	// Montgomery Method
	r1NTT := ntt(r1)
	r2NTT := ntt(r2)
	var product nttElement
	nttMul(&product, &r1NTT, &r2NTT)
	ret1 := inverseNTT(product)

	// Barrett Method
	ret2 := inverseBarrettNTT(nttBarrettMul(barrettNTT(r1), barrettNTT(r2)))

	// Check if the results are equal
	for i := range ret1 {
		if ret1[i] != ret2[i] {
			t.Errorf("expected %v, got %v", ret2[i], ret1[i])
		}
	}
}

func TestInfinityNorm(t *testing.T) {
	cases := []struct {
		input    fieldElement
		expected uint32
	}{
		{0, 0},
		{1, 1},
		{(q - 1) / 2, (q - 1) / 2},
		{(q-1)/2 + 1, q - 1 - (q-1)/2},
		{q - 1, 1},
	}
	for _, c := range cases {
		got := infinityNorm(c.input)
		if got != c.expected {
			t.Fatalf("infinityNorm(%d) = %d, expected %d", c.input, got, c.expected)
		}
	}
}

func TestPolyInfinityNorm(t *testing.T) {
	r := randomRingElement()
	got := polyInfinityNorm(&r, 0)
	var expected int

	for _, v := range r {
		if v > qMinus1Div2 {
			v = q - v
		}
		if int(v) > expected {
			expected = int(v)
		}
	}
	if got != expected {
		t.Fatalf("polyInfinityNorm(%v) = %d, expected %d", r, got, expected)
	}
}

func TestPolyInfinityNormGeneric(t *testing.T) {
	// Fixed cases: all zeros, single max positive, single max negative, mixed.
	t.Run("zero", func(t *testing.T) {
		var a ringElement
		if got := polyInfinityNormGeneric(&a, 0); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("norm_is_1_at_q_minus_1", func(t *testing.T) {
		// q-1 maps to infinityNorm = 1 (since q-(q-1) = 1)
		var a ringElement
		a[0] = q - 1
		if got := polyInfinityNormGeneric(&a, 0); got != 1 {
			t.Fatalf("got %d, want 1", got)
		}
	})

	t.Run("norm_is_qMinus1Div2_at_boundary", func(t *testing.T) {
		var a ringElement
		a[0] = qMinus1Div2
		if got := polyInfinityNormGeneric(&a, 0); got != qMinus1Div2 {
			t.Fatalf("got %d, want %d", got, qMinus1Div2)
		}
	})

	t.Run("initial_norm_dominates", func(t *testing.T) {
		var a ringElement // all zero coefficients
		const initNorm = 12345
		if got := polyInfinityNormGeneric(&a, initNorm); got != initNorm {
			t.Fatalf("got %d, want %d", got, initNorm)
		}
	})

	// Randomised: result must equal naive reference.
	t.Run("random_matches_reference", func(t *testing.T) {
		for range 64 {
			r := randomRingElement()
			got := polyInfinityNormGeneric(&r, 0)

			var want int
			for _, v := range r {
				norm := int(infinityNorm(v))
				if norm > want {
					want = norm
				}
			}
			if got != want {
				t.Fatalf("polyInfinityNormGeneric mismatch: got %d, want %d", got, want)
			}
		}
	})

	// Generic and dispatch must agree.
	t.Run("generic_matches_dispatch", func(t *testing.T) {
		for range 64 {
			r := randomRingElement()
			if polyInfinityNormGeneric(&r, 0) != polyInfinityNorm(&r, 0) {
				t.Fatal("polyInfinityNormGeneric and polyInfinityNorm disagree")
			}
		}
	})
}

func TestPolyInfinityNormSignedGeneric(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		var a [n]int32
		if got := polyInfinityNormSignedGeneric(&a, 0); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("positive_values", func(t *testing.T) {
		var a [n]int32
		a[0] = 100
		a[100] = 200
		if got := polyInfinityNormSignedGeneric(&a, 0); got != 200 {
			t.Fatalf("got %d, want 200", got)
		}
	})

	t.Run("negative_values", func(t *testing.T) {
		var a [n]int32
		a[0] = -300
		a[1] = 50
		if got := polyInfinityNormSignedGeneric(&a, 0); got != 300 {
			t.Fatalf("got %d, want 300", got)
		}
	})

	t.Run("min_int32_boundary", func(t *testing.T) {
		// absInt32(-1) == 1
		var a [n]int32
		a[0] = -1
		if got := polyInfinityNormSignedGeneric(&a, 0); got != 1 {
			t.Fatalf("got %d, want 1", got)
		}
	})

	t.Run("initial_norm_dominates", func(t *testing.T) {
		var a [n]int32 // all zeros
		const initNorm = 9999
		if got := polyInfinityNormSignedGeneric(&a, initNorm); got != initNorm {
			t.Fatalf("got %d, want %d", got, initNorm)
		}
	})

	// Randomised: result must equal naive |max|.
	t.Run("random_matches_reference", func(t *testing.T) {
		for range 64 {
			var a [n]int32
			r := randomRingElement()
			for i := range a {
				a[i] = int32(r[i]) - int32(qMinus1Div2)
			}
			got := polyInfinityNormSignedGeneric(&a, 0)

			var want int
			for _, v := range a {
				if abs := int(absInt32(v)); abs > want {
					want = abs
				}
			}
			if got != want {
				t.Fatalf("polyInfinityNormSignedGeneric mismatch: got %d, want %d", got, want)
			}
		}
	})

	// Generic and dispatch must agree.
	t.Run("generic_matches_dispatch", func(t *testing.T) {
		for range 64 {
			var a [n]int32
			r := randomRingElement()
			for i := range a {
				a[i] = int32(r[i]) - int32(qMinus1Div2)
			}
			if polyInfinityNormSignedGeneric(&a, 0) != polyInfinityNormSigned(&a, 0) {
				t.Fatal("polyInfinityNormSignedGeneric and polyInfinityNormSigned disagree")
			}
		}
	})
}
