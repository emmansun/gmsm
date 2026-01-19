package padding

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestZeroPaddingBasic(t *testing.T) {
	pad := NewZeroPadding(16)

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "3 bytes data",
			input:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "15 bytes data",
			input:    bytes.Repeat([]byte{0xFF}, 15),
			expected: append(bytes.Repeat([]byte{0xFF}, 15), 0x00),
		},
		{
			name:     "16 bytes data (full block, no padding)",
			input:    bytes.Repeat([]byte{0xAA}, 16),
			expected: bytes.Repeat([]byte{0xAA}, 16),
		},
		{
			name:     "17 bytes data",
			input:    bytes.Repeat([]byte{0xBB}, 17),
			expected: append(bytes.Repeat([]byte{0xBB}, 17), bytes.Repeat([]byte{0x00}, 15)...),
		},
		{
			name:     "empty data",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "1 byte data",
			input:    []byte{0xFF},
			expected: append([]byte{0xFF}, bytes.Repeat([]byte{0x00}, 15)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pad.Pad(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Pad failed\nExpected: %v\nGot:      %v", tt.expected, result)
			}
		})
	}
}

func TestZeroPaddingUnpad(t *testing.T) {
	pad := NewZeroPadding(16)

	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		shouldErr bool
	}{
		{
			name:      "valid padding - 3 bytes data",
			input:     []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected:  []byte{0x01, 0x02, 0x03},
			shouldErr: false,
		},
		{
			name:      "valid padding - 15 bytes data",
			input:     append(bytes.Repeat([]byte{0xFF}, 15), 0x00),
			expected:  bytes.Repeat([]byte{0xFF}, 15),
			shouldErr: false,
		},
		{
			name:      "no padding - full block",
			input:     bytes.Repeat([]byte{0xAA}, 16),
			expected:  bytes.Repeat([]byte{0xAA}, 16),
			shouldErr: false,
		},
		{
			name:      "all zeros (ambiguous case)",
			input:     bytes.Repeat([]byte{0x00}, 16),
			expected:  []byte{}, // All treated as padding
			shouldErr: false,
		},
		{
			name:      "data ending with zeros (ambiguous)",
			input:     []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected:  []byte{0x01, 0x02}, // Cannot distinguish original 0x00 from padding
			shouldErr: false,
		},
		{
			name:      "invalid - not multiple of block size",
			input:     []byte{0x01, 0x02, 0x03},
			shouldErr: true,
		},
		{
			name:      "invalid - empty input",
			input:     []byte{},
			shouldErr: true,
		},
		{
			name:      "single non-zero byte followed by zeros",
			input:     append([]byte{0xFF}, bytes.Repeat([]byte{0x00}, 15)...),
			expected:  []byte{0xFF},
			shouldErr: false,
		},
		{
			name:      "multiple blocks with trailing zeros",
			input:     append(bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x00}, 16)...),
			expected:  bytes.Repeat([]byte{0x01}, 16),
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pad.Unpad(tt.input)
			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("Unpad failed\nExpected: %v\nGot:      %v", tt.expected, result)
				}
			}
		})
	}
}

func TestZeroPaddingConstantTimeUnpad(t *testing.T) {
	pad := NewZeroPadding(16)

	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		shouldErr bool
	}{
		{
			name:      "valid - zeros at end",
			input:     []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected:  []byte{0x01, 0x02, 0x03},
			shouldErr: false,
		},
		{
			name:      "valid - no trailing zeros",
			input:     bytes.Repeat([]byte{0xFF}, 16),
			expected:  bytes.Repeat([]byte{0xFF}, 16),
			shouldErr: false,
		},
		{
			name:      "valid - single zero at end",
			input:     append(bytes.Repeat([]byte{0x01}, 15), 0x00),
			expected:  bytes.Repeat([]byte{0x01}, 15),
			shouldErr: false,
		},
		{
			name:      "all zeros",
			input:     bytes.Repeat([]byte{0x00}, 16),
			expected:  []byte{},
			shouldErr: false,
		},
		{
			name:      "invalid - not aligned",
			input:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			shouldErr: true,
		},
		{
			name:      "invalid - empty",
			input:     []byte{},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pad.ConstantTimeUnpad(tt.input)
			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("ConstantTimeUnpad failed\nExpected: %v\nGot:      %v", tt.expected, result)
				}
			}
		})
	}
}

func TestZeroPaddingRoundTrip(t *testing.T) {
	pad := NewZeroPadding(16)

	// Test data that does NOT end with 0x00 (to avoid ambiguity)
	testData := [][]byte{
		{0x01},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xFF}, 15),
		bytes.Repeat([]byte{0xAA}, 16),
		bytes.Repeat([]byte{0x55}, 31),
		bytes.Repeat([]byte{0x33}, 32),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	}

	for i, data := range testData {
		t.Run(fmt.Sprintf("data_len_%d", len(data)), func(t *testing.T) {
			// Pad
			padded := pad.Pad(data)

			// Verify padding structure
			if len(padded)%16 != 0 {
				t.Errorf("Padded length %d is not multiple of block size", len(padded))
			}

			// Unpad
			result, err := pad.Unpad(padded)
			if err != nil {
				t.Fatalf("Unpad failed: %v", err)
			}

			// Verify round-trip
			if !bytes.Equal(result, data) {
				t.Errorf("Round-trip failed for test %d\nExpected: %v\nGot:      %v", i, data, result)
			}
		})
	}
}

func TestZeroPaddingAmbiguity(t *testing.T) {
	pad := NewZeroPadding(16)

	t.Run("ambiguous case - data ends with zeros", func(t *testing.T) {
		// Original data ending with 0x00
		original := []byte{0x01, 0x02, 0x03, 0x00, 0x00}

		// Pad it
		padded := pad.Pad(original)
		// Expected: [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, ...]

		// Unpad it
		result, err := pad.Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad failed: %v", err)
		}

		// Result will be [0x01, 0x02, 0x03] - original trailing zeros are lost!
		expected := []byte{0x01, 0x02, 0x03}
		if !bytes.Equal(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}

		// This demonstrates the ambiguity problem
		if bytes.Equal(result, original) {
			t.Error("Round-trip succeeded unexpectedly - this should demonstrate data loss")
		}
	})
}

func TestZeroPaddingBlockSizes(t *testing.T) {
	blockSizes := []uint{8, 16, 32, 64, 128}

	for _, bs := range blockSizes {
		t.Run(fmt.Sprintf("blocksize_%d", bs), func(t *testing.T) {
			pad := NewZeroPadding(bs)

			// Test various data lengths
			for dataLen := 1; dataLen < int(bs)*2; dataLen++ {
				data := bytes.Repeat([]byte{0xFF}, dataLen)

				padded := pad.Pad(data)
				if len(padded)%int(bs) != 0 {
					t.Errorf("Padded length %d not aligned to block size %d", len(padded), bs)
				}

				unpadded, err := pad.Unpad(padded)
				if err != nil {
					t.Fatalf("Unpad failed for data length %d: %v", dataLen, err)
				}

				if !bytes.Equal(unpadded, data) {
					t.Errorf("Round-trip failed for data length %d", dataLen)
				}
			}
		})
	}
}

func TestZeroPaddingInvalidBlockSize(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for block size 0")
		}
	}()
	NewZeroPadding(0)
}

func TestZeroPaddingInvalidBlockSizeTooLarge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for block size > 255")
		}
	}()
	NewZeroPadding(256)
}

// BenchmarkZeroPaddingUnpadConstantTime verifies constant-time behavior
func BenchmarkZeroPaddingUnpadConstantTime(b *testing.B) {
	pad := NewZeroPadding(16)

	// Different amounts of trailing zeros
	inputs := [][]byte{
		// 0 trailing zeros (no padding)
		bytes.Repeat([]byte{0xFF}, 16),
		// 5 trailing zeros
		append(bytes.Repeat([]byte{0xFF}, 11), bytes.Repeat([]byte{0x00}, 5)...),
		// 10 trailing zeros
		append(bytes.Repeat([]byte{0xFF}, 6), bytes.Repeat([]byte{0x00}, 10)...),
		// 15 trailing zeros
		append([]byte{0xFF}, bytes.Repeat([]byte{0x00}, 15)...),
	}

	for i, input := range inputs {
		b.Run(fmt.Sprintf("zeros_%d", []int{0, 5, 10, 15}[i]), func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, _ = pad.ConstantTimeUnpad(input)
			}
		})
	}
}

func BenchmarkZeroPaddingPad(b *testing.B) {
	pad := NewZeroPadding(16)
	data := bytes.Repeat([]byte{0x01}, 100)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = pad.Pad(data)
	}
}

func BenchmarkZeroPaddingUnpad(b *testing.B) {
	pad := NewZeroPadding(16)
	data := bytes.Repeat([]byte{0x01}, 100)
	padded := pad.Pad(data)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _ = pad.Unpad(padded)
	}
}

func TestZeroPaddingLargeData(t *testing.T) {
	pad := NewZeroPadding(16)

	// Test with large random data (that doesn't end with 0x00)
	for size := 1024; size <= 1024*1024; size *= 2 {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			data := make([]byte, size)
			_, err := rand.Read(data)
			if err != nil {
				t.Fatalf("Failed to generate random data: %v", err)
			}

			// Ensure data doesn't end with 0x00 to avoid ambiguity
			for data[len(data)-1] == 0x00 {
				data[len(data)-1] = 0xFF
			}

			// Pad
			padded := pad.Pad(data)
			if len(padded)%16 != 0 {
				t.Errorf("Padded length not aligned: %d", len(padded))
			}

			// Unpad
			result, err := pad.Unpad(padded)
			if err != nil {
				t.Fatalf("Unpad failed: %v", err)
			}

			// Verify
			if !bytes.Equal(result, data) {
				t.Error("Large data round-trip failed")
			}
		})
	}
}

func TestZeroPaddingEdgeCases(t *testing.T) {
	pad := NewZeroPadding(16)

	t.Run("data exactly one block", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x01}, 16)
		padded := pad.Pad(data)
		// Should not add padding
		if !bytes.Equal(padded, data) {
			t.Error("Should not add padding to aligned data")
		}

		result, err := pad.Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad failed: %v", err)
		}
		if !bytes.Equal(result, data) {
			t.Error("Failed to unpad aligned data")
		}
	})

	t.Run("data one byte less than block", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x01}, 15)
		padded := pad.Pad(data)
		if len(padded) != 16 {
			t.Errorf("Expected 16 bytes, got %d", len(padded))
		}
		if padded[15] != 0x00 {
			t.Error("Last byte should be 0x00")
		}

		result, err := pad.Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad failed: %v", err)
		}
		if !bytes.Equal(result, data) {
			t.Error("Round-trip failed")
		}
	})

	t.Run("data one byte more than block", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x01}, 17)
		padded := pad.Pad(data)
		if len(padded) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(padded))
		}

		result, err := pad.Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad failed: %v", err)
		}
		if !bytes.Equal(result, data) {
			t.Error("Round-trip failed")
		}
	})
}

func TestZeroPaddingInterfaceCompliance(t *testing.T) {
	var _ Padding = NewZeroPadding(16)
}
