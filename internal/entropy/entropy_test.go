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
