package padding

import (
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
)

// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
type pkcs7Padding uint

func (pad pkcs7Padding) BlockSize() int {
	return int(pad)
}

func (pad pkcs7Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := alias.SliceForAppend(src, overhead)
	for i := 0; i < overhead; i++ {
		out[i] = byte(overhead)
	}
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad pkcs7Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	paddedLen := src[srcLen-1]
	if paddedLen == 0 || int(paddedLen) > pad.BlockSize() {
		return nil, errors.New("padding: invalid padding byte/length")
	}
	for _, b := range src[srcLen-int(paddedLen) : srcLen-1] {
		if b != paddedLen {
			return nil, errors.New("padding: inconsistent padding bytes")
		}
	}
	return src[:srcLen-int(paddedLen)], nil
}
