// Package padding implements some padding schemes for padding octets at the trailing end.
package padding

// Padding interface represents a padding scheme
type Padding interface {
	BlockSize() int
	Pad(src []byte) []byte
	Unpad(src []byte) ([]byte, error)
}

func NewPKCS7Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return pkcs7Padding(blockSize)
}

func NewANSIX923Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return ansiX923Padding(blockSize)
}

func NewISO9797M2Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return iso9797M2Padding(blockSize)
}

func NewISO9797M3Padding(blockSize uint) Padding {
	if blockSize == 0 || blockSize > 255 {
		panic("padding: invalid block size")
	}
	return iso9797M3Padding(blockSize)
}
