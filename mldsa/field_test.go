// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"fmt"
	mathrand "math/rand/v2"
	"testing"
)

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
