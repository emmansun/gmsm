// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"crypto/rand"
	"testing"
)

func TestSampleInBall(t *testing.T) {
	var seed [32]byte
	rand.Reader.Read(seed[:])
	var count int
	taus := []int{tau39, tau49, tau60}
	for _, tau := range taus {
		for range 1000 {
			count = 0
			f := sampleInBall(seed[:], tau)
			for _, v := range f {
				if v != 0 {
					count++
				}
			}
			if count != tau {
				t.Errorf("sampleInBall(%x) = %d, expected %d", seed[:], count, tau)
			}
		}
	}
}
