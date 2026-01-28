// Package padding implements some padding schemes for padding octets at the trailing end.
package padding

// Padding interface represents a padding scheme for block cipher operations.
//
// All padding schemes must handle data alignment to a fixed block size.
// Different schemes use different methods to pad the data and indicate
// the padding length during unpadding.
//
// Implementations should ensure that:
//   - Pad() always produces output aligned to BlockSize()
//   - Unpad() can correctly remove padding added by Pad()
//   - ConstantTimeUnpad() provides timing-attack resistance
type Padding interface {
	// BlockSize returns the block size in bytes that this padding scheme operates on.
	// The block size must be a positive integer, typically 8, 16, or 32 bytes
	// for common block ciphers (DES, AES, SM4, etc.).
	//
	// This value is used to determine:
	//   - How many padding bytes to add in Pad()
	//   - The alignment requirement for Unpad() operations
	//   - The expected structure of padded data
	BlockSize() int

	// Pad adds padding bytes to src to make its length a multiple of BlockSize().
	//
	// The padding is appended to the end of the data. If the input is already
	// aligned to the block size, the behavior depends on the padding scheme:
	//   - PKCS#7: Always adds a full block of padding
	//   - Zero Padding: May not add padding (implementation-dependent)
	//   - ISO 9797-1 M2: Always adds at least one byte (0x80)
	//   - ISO 9797-1 M3: Always adds a full block header
	//
	// This operation is typically not constant-time, as it operates on plaintext
	// before encryption. Timing variations do not leak sensitive information.
	//
	// Parameters:
	//   - src: The input data to be padded (can be any length, including empty)
	//
	// Returns:
	//   - A new byte slice containing the original data followed by padding bytes
	//   - The returned slice length is always a multiple of BlockSize()
	//
	// Note: The implementation may reuse the underlying array of src if it has
	// sufficient capacity, or allocate a new array if needed.
	Pad(src []byte) []byte

	// Unpad removes padding bytes from src and returns the original data.
	//
	// This is a variable-time implementation that may be faster than ConstantTimeUnpad()
	// but is vulnerable to timing attacks. It may perform early exits or conditional
	// branches based on the padding content, which can leak information about the
	// padding length through timing side channels.
	//
	// Use this method only when:
	//   - Timing attacks are not a concern (e.g., processing public data)
	//   - Performance is critical and the data is not security-sensitive
	//   - You are working in a trusted environment without potential attackers
	//
	// For security-critical applications (especially after decryption), use
	// ConstantTimeUnpad() instead to prevent padding oracle attacks.
	//
	// Parameters:
	//   - src: The padded data (must be a multiple of BlockSize())
	//
	// Returns:
	//   - The original data with padding removed
	//   - An error if the input is invalid:
	//     * Length is not a multiple of BlockSize()
	//     * Padding bytes are malformed or inconsistent
	//     * Input is empty (for most schemes)
	//
	// WARNING: This method may be vulnerable to padding oracle attacks when used
	// with encrypted data. Attackers can potentially recover plaintext by observing
	// timing differences in padding validation.
	Unpad(src []byte) ([]byte, error)

	// ConstantTimeUnpad removes padding bytes in constant time to prevent timing attacks.
	//
	// This method always examines the same amount of data regardless of the padding
	// content, ensuring that the execution time does not depend on:
	//   - The padding length
	//   - The position of invalid padding bytes
	//   - Whether the padding is valid or invalid
	//
	// This constant-time behavior is critical for security when processing decrypted
	// data, as it prevents padding oracle attacks where an attacker could:
	//   1. Submit crafted ciphertexts
	//   2. Observe decryption/unpadding timing
	//   3. Deduce information about the plaintext
	//   4. Potentially recover the entire plaintext byte-by-byte
	//
	// Use this method for:
	//   - All security-critical applications
	//   - Processing data after decryption
	//   - Any scenario where timing attacks are a concern
	//   - Compliance with cryptographic best practices
	//
	// Performance Note: This method is typically slightly slower than Unpad() because
	// it cannot take shortcuts, but the security benefit is essential for encrypted data.
	//
	// Parameters:
	//   - src: The padded data (must be a multiple of BlockSize())
	//
	// Returns:
	//   - The original data with padding removed
	//   - An error if the input is invalid:
	//     * Length is not a multiple of BlockSize()
	//     * Padding bytes are malformed or inconsistent
	//     * Input is empty (for most schemes)
	//
	// The error handling is also designed to be constant-time - the same error
	// is returned regardless of which validation check fails.
	ConstantTimeUnpad(src []byte) ([]byte, error)
}

type NewPaddingFunc func(blockSize uint) Padding

// NewPKCS7Padding creates a new PKCS7 padding scheme with the specified block size.
// The block size must be between 1 and 255, inclusive. If the block size is 0 or greater than 255,
// the function will panic with an "invalid block size" error.
func NewPKCS7Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return pkcs7Padding(blockSize)
}

// NewANSIX923Padding creates a new instance of ANSI X.923 padding with the specified block size.
// The block size must be between 1 and 255, inclusive. If the block size is 0 or greater than 255,
// the function will panic with an "invalid block size" message.
func NewANSIX923Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return ansiX923Padding(blockSize)
}

// NewISO9797M2Padding creates a new ISO/IEC 9797-1 Padding Method 2 (also known as ISO 10126) instance
// with the specified block size. The block size must be between 1 and 255 inclusive.
func NewISO9797M2Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return iso9797M2Padding(blockSize)
}

// NewISO9797M3Padding creates a new ISO/IEC 9797-1 Padding Method 3 (also known as ISO 10126) padding scheme
// with the specified block size. The block size must be between 1 and 255 inclusive.
func NewISO9797M3Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return iso9797M3Padding(blockSize)
}

// NewZeroPadding creates a Zero Padding scheme with the specified block size.
//
// WARNING: Zero Padding is NOT a standard padding scheme and has limitations.
// See the documentation of zeroPadding for details on suitable use cases.
//
// The block size must be between 1 and 255, inclusive. If the block size is 0
// or greater than 255, the function will panic with an "invalid block size" error.
//
// For general-purpose encryption, prefer NewPKCS7Padding or NewISO9797M2Padding.
func NewZeroPadding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return zeroPadding(blockSize)
}
