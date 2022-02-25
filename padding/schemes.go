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
