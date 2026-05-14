// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import (
	"testing"
)

func TestSeed(t *testing.T) {
	seed := Seed()

	// Check seed is not all zeros.
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Seed returned all zeros")
	}
}

func TestSeed_DifferentResults(t *testing.T) {
	seed1 := Seed()
	seed2 := Seed()

	if seed1 == seed2 {
		t.Error("two consecutive Seed calls returned identical results")
	}
}

func TestSeed_Concurrent(t *testing.T) {
	const goroutines = 10
	results := make(chan [SeedSize]byte, goroutines)

	for range goroutines {
		go func() {
			results <- Seed()
		}()
	}

	seeds := make([][SeedSize]byte, 0, goroutines)
	for range goroutines {
		seeds = append(seeds, <-results)
	}

	// All seeds should be distinct.
	for i := 0; i < len(seeds); i++ {
		for j := i + 1; j < len(seeds); j++ {
			if seeds[i] == seeds[j] {
				t.Errorf("goroutines %d and %d produced identical seeds", i, j)
			}
		}
	}
}

func TestHashDf(t *testing.T) {
	input := []byte("test input for Hash_df")

	// Test different output sizes.
	for _, size := range []int{16, 32, 55, 64, 111} {
		result := hashDf(input, size)
		if len(result) != size {
			t.Errorf("hashDf returned %d bytes, want %d", len(result), size)
		}
	}
}

func BenchmarkSeed(b *testing.B) {
	for b.Loop() {
		Seed()
	}
}
