// Package padding implements some padding schemes for padding octets at the trailing end.
package padding

// Padding interface represents a padding scheme
type Padding interface {
	BlockSize() int
	Pad(src []byte) []byte
	Unpad(src []byte) ([]byte, error)
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
