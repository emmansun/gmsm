package padding

import (
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
)

// Zero Padding appends zero bytes (0x00) to the end of the data until it reaches
// a multiple of the block size.
//
// WARNING: Zero Padding is NOT a standard padding scheme and has significant limitations:
//   - It cannot distinguish between original trailing 0x00 bytes and padding bytes
//   - Unpadding is ambiguous if the original data ends with 0x00
//   - It is NOT suitable for arbitrary binary data
//
// Suitable Use Cases:
//   - Legacy system compatibility that explicitly requires Zero Padding
//   - Text data where trailing 0x00 bytes are guaranteed not to occur
//   - Fixed-length protocol fields where the original length is known separately
//   - Scenarios where unpadding is not required (encrypt-only operations)
//
// NOT Suitable For:
//   - General-purpose encryption of arbitrary binary data
//   - Security-critical applications (use PKCS#7 or ISO/IEC 9797-1 Method 2 instead)
//   - Any scenario requiring precise recovery of original data length
//
// Example:
//
//	data := []byte{0x01, 0x02, 0x03}
//	padded := pad.Pad(data) // [0x01, 0x02, 0x03, 0x00, 0x00, ...]
//	// Note: If data was [0x01, 0x02, 0x03, 0x00], unpadding cannot distinguish it
type zeroPadding uint

func (pad zeroPadding) BlockSize() int {
	return int(pad)
}

// Pad appends zero bytes (0x00) to reach a multiple of the block size.
// If the data is already aligned to the block size, no padding is added.
func (pad zeroPadding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	if overhead == pad.BlockSize() {
		overhead = 0 // Already aligned, no padding needed
	}

	ret, out := alias.SliceForAppend(src, overhead)
	// Go's slice allocation already initializes bytes to 0x00
	clear(out[:overhead])
	return ret
}

// Unpad removes trailing zero bytes.
//
// This is a variable-time implementation that may be faster than ConstantTimeUnpad
// but is vulnerable to timing attacks. Use this only when:
//   - Timing attacks are not a concern for your use case
//   - Performance is critical and the data is not security-sensitive
//   - You are working with public data or in a trusted environment
//
// For security-critical applications, use ConstantTimeUnpad instead.
//
// WARNING: This method CANNOT distinguish between original trailing 0x00 bytes
// and padding bytes.
//
// Returns an error if:
//   - The input length is not a multiple of the block size
//   - The input is empty
func (pad zeroPadding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)

	// Basic length validation
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: invalid padding size")
	}

	// Fast path: traverse from end until we find a non-zero byte
	// This is variable-time and may leak information through timing
	count := 0
	for i := srcLen - 1; i >= 0; i-- {
		if src[i] != 0x00 {
			break // Early exit - not constant time!
		}
		count++
	}

	// Handle edge case: all bytes are 0x00
	if count == srcLen {
		return []byte{}, nil
	}

	// WARNING: This cannot distinguish original trailing 0x00 from padding
	return src[:srcLen-count], nil
}

// ConstantTimeUnpad removes Zero Padding in constant time to prevent timing attacks.
//
// This implementation is inspired by BouncyCastle's constant-time approach:
// it always examines all bytes in the input, regardless of where the padding ends.
//
// Algorithm:
//  1. Traverse the entire input from end to beginning
//  2. Count consecutive trailing 0x00 bytes using constant-time operations
//  3. Stop counting when a non-zero byte is encountered (but continue traversing)
//  4. Return the data without the trailing zeros
//
// IMPORTANT LIMITATION:
// This method cannot distinguish between:
//   - Original data: [0x01, 0x02, 0x03, 0x00] with no padding
//   - Padded data: [0x01, 0x02, 0x03] with one 0x00 padding byte
//
// Both will result in [0x01, 0x02, 0x03] after unpadding.
//
// Returns an error if:
//   - The input length is not a multiple of the block size
//   - The input is empty
func (pad zeroPadding) ConstantTimeUnpad(src []byte) ([]byte, error) {
	srcLen := len(src)

	// Basic length validation (structural check, can be non-constant-time)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: invalid padding size")
	}

	// Constant-time counting of trailing 0x00 bytes (inspired by BouncyCastle)
	// This ensures the execution time does not depend on the padding length.
	count := 0
	still00Mask := -1 // All bits set to 1 (0xFFFFFFFF in 32-bit)

	// Traverse the entire input (constant time requirement)
	// We examine every byte to prevent timing attacks
	for i := srcLen - 1; i >= 0; i-- {
		next := int(src[i])

		// Check if current byte is 0x00 using constant-time comparison
		// Mathematical trick:
		//   If next == 0x00: 0 - 1 = -1, then -1 >> 31 = -1 (0xFFFFFFFF)
		//   If next != 0x00: next - 1 >= 0, then result >> 31 = 0
		match00Mask := (next - 1) >> 31

		// Update still00Mask: becomes 0 once we encounter a non-0x00 byte
		// This effectively "locks" the count when we find the first non-zero byte
		still00Mask &= match00Mask

		// Increment count only while still00Mask is -1 (all 1s)
		// When still00Mask becomes 0, count stops incrementing
		// Equivalent to: if (still00Mask) count++ but in constant time
		count -= still00Mask
	}

	// Handle edge case: all bytes are 0x00 (entire input is padding)
	if count > srcLen {
		return nil, errors.New("padding: invalid padding")
	}

	// WARNING: This cannot distinguish original trailing 0x00 from padding
	return src[:srcLen-count], nil
}
