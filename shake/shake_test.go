package shake

import (
	"bytes"
	"crypto/sha3"
	"hash"
	"testing"
)

func TestSHAKE128HashAdapter(t *testing.T) {
	h := NewSHAKE128(32)

	// Write some data
	h.Write([]byte("hello"))

	// Sum should be idempotent
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("Sum() is not idempotent")
	}

	// Should be able to continue writing after Sum
	h.Write([]byte(" world"))
	sum3 := h.Sum(nil)

	if bytes.Equal(sum1, sum3) {
		t.Error("Sum should change after more writes")
	}

	// Check size
	if len(sum1) != 32 {
		t.Errorf("Expected size 32, got %d", len(sum1))
	}

	if h.Size() != 32 {
		t.Errorf("Size() returned %d, expected 32", h.Size())
	}
}

func TestSHAKE256HashAdapter(t *testing.T) {
	h := NewSHAKE256(64)
	h.Write([]byte("test"))
	sum := h.Sum(nil)

	if len(sum) != 64 {
		t.Errorf("Expected size 64, got %d", len(sum))
	}

	if h.Size() != 64 {
		t.Errorf("Size() returned %d, expected 64", h.Size())
	}
}

func TestHashAdapterReset(t *testing.T) {
	h := NewSHAKE128(32)
	h.Write([]byte("hello"))
	sum1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte("hello"))
	sum2 := h.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("Reset didn't work correctly")
	}
}

func TestHashAdapterWithAppend(t *testing.T) {
	h := NewSHAKE128(32)
	h.Write([]byte("test"))

	prefix := []byte("prefix:")
	result := h.Sum(prefix)

	if !bytes.HasPrefix(result, prefix) {
		t.Error("Sum didn't preserve prefix")
	}

	if len(result) != len(prefix)+32 {
		t.Errorf("Expected length %d, got %d", len(prefix)+32, len(result))
	}
}

func TestHashAdapterBlockSize(t *testing.T) {
	h128 := NewSHAKE128(32)
	h256 := NewSHAKE256(64)

	// SHAKE128 has block size of 168 bytes
	if h128.BlockSize() != 168 {
		t.Errorf("SHAKE128 BlockSize() = %d, expected 168", h128.BlockSize())
	}

	// SHAKE256 has block size of 136 bytes
	if h256.BlockSize() != 136 {
		t.Errorf("SHAKE256 BlockSize() = %d, expected 136", h256.BlockSize())
	}
}

func TestHashAdapterInterface(t *testing.T) {
	var _ hash.Hash = (*HashAdapter)(nil)
	var _ hash.Hash = NewSHAKE128(32)
	var _ hash.Hash = NewSHAKE256(64)
}

func TestDifferentOutputSizes(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"128 bytes", 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewSHAKE128(tt.size)
			h.Write([]byte("test data"))
			sum := h.Sum(nil)

			if len(sum) != tt.size {
				t.Errorf("Expected size %d, got %d", tt.size, len(sum))
			}
		})
	}
}

func TestConsistentWithDirectSHAKE(t *testing.T) {
	// Test that our adapter produces same output as direct SHAKE usage
	data := []byte("test data for consistency check")

	// Using our adapter
	h1 := NewSHAKE128(32)
	h1.Write(data)
	output1 := h1.Sum(nil)

	// Using sha3 directly
	h2 := sha3.NewSHAKE128()
	h2.Write(data)
	output2 := make([]byte, 32)
	h2.Read(output2)

	if !bytes.Equal(output1, output2) {
		t.Error("Output doesn't match direct SHAKE usage")
	}
}

func TestMultipleSumCalls(t *testing.T) {
	h := NewSHAKE128(32)
	h.Write([]byte("test"))

	// Call Sum multiple times
	results := make([][]byte, 5)
	for i := range results {
		results[i] = h.Sum(nil)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if !bytes.Equal(results[0], results[i]) {
			t.Errorf("Sum call %d produced different result", i)
		}
	}
}

func TestWriteAfterSum(t *testing.T) {
	h := NewSHAKE128(32)

	// First write
	h.Write([]byte("hello"))
	sum1 := h.Sum(nil)

	// Write more after Sum
	h.Write([]byte(" world"))
	sum2 := h.Sum(nil)

	// Results should be different
	if bytes.Equal(sum1, sum2) {
		t.Error("Sum should be different after additional Write")
	}

	// Reset and write same data as before
	h.Reset()
	h.Write([]byte("hello"))
	sum3 := h.Sum(nil)

	// Should match first sum
	if !bytes.Equal(sum1, sum3) {
		t.Error("Sum after reset should match original")
	}
}

// Benchmarks

func BenchmarkSHAKE128_32(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h := NewSHAKE128(32)
		h.Write(data)
		_ = h.Sum(nil)
	}
}

func BenchmarkSHAKE256_64(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h := NewSHAKE256(64)
		h.Write(data)
		_ = h.Sum(nil)
	}
}

func BenchmarkSumIdempotency(b *testing.B) {
	h := NewSHAKE128(32)
	h.Write([]byte("test data"))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = h.Sum(nil)
	}
}

func BenchmarkIncrementalWrite(b *testing.B) {
	data := []byte("chunk")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h := NewSHAKE128(32)
		for j := 0; j < 100; j++ {
			h.Write(data)
		}
		_ = h.Sum(nil)
	}
}

// Examples

func ExampleNewSHAKE128() {
	// Create a SHAKE128 hash with 32-byte output
	h := NewSHAKE128(32)
	h.Write([]byte("Hello, World!"))
	_ = h.Sum(nil)

	// Can call Sum multiple times
	_ = h.Sum(nil)

	// Continue writing
	h.Write([]byte(" More data"))
	_ = h.Sum(nil)
	// Output:
}

func ExampleNewSHAKE256() {
	// Create a SHAKE256 hash with 64-byte output
	h := NewSHAKE256(64)
	h.Write([]byte("Secure message"))
	_ = h.Sum(nil)
	// Output:
}

func ExampleHashAdapter_Sum() {
	h := NewSHAKE128(32)
	h.Write([]byte("data"))

	// Sum can be called multiple times
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil)

	// Results are identical
	_ = bytes.Equal(sum1, sum2) // true

	// Can append to existing slice
	prefix := []byte("hash:")
	result := h.Sum(prefix)
	_ = result // []byte("hash:" + sum1...)
	// Output:
}
