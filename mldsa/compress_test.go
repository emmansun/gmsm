// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"testing"
)

func _power2Round(r uint32) (r1 uint32, r0 int32) {
	const rd = 1 << d
	r = r % q
	r0 = int32(r % rd)
	if r0 > int32(rd/2) {
		r0 -= int32(rd)
	}
	r1 = uint32((int32(r) - r0) / int32(rd))
	if r0 < 0 {
		r0 += int32(q)
	}
	return
}

func _decompse(r uint32, gamma2 uint32) (r1 uint32, r0 int32) {
	r = r % q
	r0 = int32(r % (2 * gamma2))
	if r0 > int32(gamma2) {
		r0 -= 2 * int32(gamma2)
	}
	if int32(r)-r0 == q-1 {
		r1 = 0
		r0--
	} else {
		r1 = uint32(int32(r)-r0) / (2 * gamma2)
	}
	return
}

func TestPower2Round(t *testing.T) {
	for i := 0; i <= 1000; i++ {
		r1, r0 := power2Round(fieldElement(i))
		expectedR1, expectedR0 := _power2Round(uint32(i))
		if r1 != fieldElement(expectedR1) {
			t.Errorf("power2Round(%d) = %d, want %d", i, r1, expectedR1)
		}
		if r0 != fieldElement(expectedR0) {
			t.Errorf("power2Round(%d) = %d, want %d", i, r0, expectedR0)
		}
	}
	for i := q - 1001; i < q; i++ {
		r1, r0 := power2Round(fieldElement(i))
		expectedR1, expectedR0 := _power2Round(uint32(i))
		if r1 != fieldElement(expectedR1) {
			t.Errorf("power2Round(%d) = %d, want %d", i, r1, expectedR1)
		}
		if r0 != fieldElement(expectedR0) {
			t.Errorf("power2Round(%d) = %d, want %d", i, r0, expectedR0)
		}
	}
}

func TestDecompose(t *testing.T) {
	gammas := []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88}
	for _, gamma := range gammas {
		for i := 0; i <= 1000; i++ {
			r1, r0 := decompose(fieldElement(i), gamma)
			expectedR1, expectedR0 := _decompse(uint32(i), gamma)
			if r1 != expectedR1 {
				t.Errorf("decompose(%d/%d) r1 = %d, want %d", i, gamma, r1, expectedR1)
			}
			if r0 != expectedR0 {
				t.Errorf("decompose(%d/%d) r0 = %d, want %d", i, gamma, r0, expectedR0)
			}
		}
		for i := q - 1001; i < q; i++ {
			r1, r0 := decompose(fieldElement(i), gamma)
			expectedR1, expectedR0 := _decompse(uint32(i), gamma)
			if r1 != expectedR1 {
				t.Errorf("decompose(%d/%d) r1 = %d, want %d", i, gamma, r1, expectedR1)
			}
			if r0 != expectedR0 {
				t.Errorf("decompose(%d/%d) r0 = %d, want %d", i, gamma, r0, expectedR0)
			}
		}
	}
}
