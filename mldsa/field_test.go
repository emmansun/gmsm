// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"fmt"
	"math/big"
	mathrand "math/rand/v2"
	"testing"
)

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
		t.Fatalf("-q^-1 mod 2^32 = %d, expected %d", q1Neg, qNegInv)
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
	for _, z := range zetasMontgomery {
		fmt.Printf("%v, ", fieldReduce(uint64(z)))
	}
	fmt.Println()
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
	r1 := r
	r2 := ntt(r)
	r3 := barrettNTT(r1)
	for i, v := range r3 {
		if v != r2[i] {
			t.Errorf("expected %v, got %v", v, r2[i])
		}
	}
}

func TestInverseNTT(t *testing.T) {
	r := randomRingElement()
	r1 := r
	r2 := ntt(r1)
	r3 := inverseNTT(r2)
	for i, v := range r {
		if v != fieldReduce(uint64(r3[i])) {
			t.Errorf("expected %v, got %v", v, fieldReduce(uint64(r3[i])))
		}
	}
}

func TestInverseBarrettNTT(t *testing.T) {
	r := randomRingElement()
	r1 := r
	r2 := barrettNTT(r1)
	r3 := inverseBarrettNTT(r2)
	for i, v := range r {
		if v != r3[i] {
			t.Errorf("expected %v, got %v", v, r3[i])
		}
	}
}

// this is the real use case for NTT:
//
//  - convert to NTT
//  - multiply in NTT
//  - inverse NTT
func TestInverseNTTWithMultiply(t *testing.T) {
	r1 := randomRingElement()
	r2 := randomRingElement()

	// Montgomery Method
	r11 := r1
	r111 := ntt(r11)
	r22 := r2
	r222 := ntt(r22)
	r31 := nttMul(r111, r222)
	r32 := inverseNTT(r31)

	// Barrett Method
	b11 := barrettNTT(r1)
	b22 := barrettNTT(r2)
	r33 := nttBarrettMul(b11, b22)
	r34 := inverseBarrettNTT(r33)

	// Check if the results are equal
	for i := range r32 {
		if r32[i] != r34[i] {
			t.Errorf("expected %v, got %v", r34[i], r32[i])
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
	got := polyInfinityNorm(r, 0)
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

func TestInfinityNormSigned(t *testing.T) {
	cases := []struct {
		input    int32
		expected int
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{-2, 2},
	}
	for _, c := range cases {
		got := infinityNormSigned(c.input)
		if got != c.expected {
			t.Fatalf("infinityNormSigned(%d) = %d, expected %d", c.input, got, c.expected)
		}
	}
}

func TestPolyInfinityNormSigned(t *testing.T) {
	cases := []struct {
		input    []int32
		expected int
	}{
		{[]int32{0, 0, 0}, 0},
		{[]int32{1, 2, 3}, 3},
		{[]int32{0, -1, -2, -3, 2}, 3},
	}
	for _, c := range cases {
		got := polyInfinityNormSigned(c.input, 0)
		if got != c.expected {
			t.Fatalf("polyInfinityNormSigned(%v) = %d, expected %d", c.input, got, c.expected)
		}
	}
}
