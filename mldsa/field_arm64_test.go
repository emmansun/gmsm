// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import (
	mathrand "math/rand/v2"
	"testing"
)

func TestNTTMulNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
		}

		nttMulNEON(&lhs, &rhs, &got)
		nttMulGeneric(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestNTTMulAccNEONMatchesGeneric(t *testing.T) {
	for range 64 {
		var lhs, rhs, got, want nttElement
		for i := range lhs {
			lhs[i] = fieldElement(mathrand.IntN(q))
			rhs[i] = fieldElement(mathrand.IntN(q))
			// pre-populate accumulator with random values
			got[i] = fieldElement(mathrand.IntN(q))
			want[i] = got[i]
		}

		nttMulAccNEON(&lhs, &rhs, &got)
		nttMulAccGeneric(&want, &lhs, &rhs)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestInternalNTTNEONMatchesGeneric(t *testing.T) {
	for range 32 {
		var got, want ringElement
		for i := range got {
			v := fieldElement(mathrand.IntN(q))
			got[i] = v
			want[i] = v
		}

		internalNTTNEON(&got)
		internalNTTGeneric(&want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}

func TestInternalInverseNTTNEONMatchesGeneric(t *testing.T) {
	for range 32 {
		var got, want nttElement
		for i := range got {
			v := fieldElement(mathrand.IntN(q))
			got[i] = v
			want[i] = v
		}

		internalInverseNTTNEON(&got)
		internalInverseNTTGeneric(&want)

		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	}
}
