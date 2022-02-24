// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
package padding

import (
	goSubtle "crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/subtle"
)

type pkcs7Padding uint

func (pad pkcs7Padding) BlockSize() int {
	return int(pad)
}

func (pad pkcs7Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := subtle.SliceForAppend(src, overhead)
	for i := 0; i < overhead; i++ {
		out[i] = byte(overhead)
	}
	return ret
}

func (pad pkcs7Padding) Unpad(src []byte) ([]byte, error) {
	if len(src)%pad.BlockSize() != 0 {
		return nil, errors.New("pkcs7: invalid src size")
	}
	overhead := src[len(src)-1]
	if overhead == 0 || int(overhead) > pad.BlockSize() {
		return nil, errors.New("pkcs7: invalid padding byte/length")
	}
	tag := make([]byte, pad.BlockSize())
	copy(tag, src[len(src)-pad.BlockSize():])
	for i := pad.BlockSize() - int(overhead); i < pad.BlockSize(); i++ {
		tag[i] = byte(overhead)
	}
	if goSubtle.ConstantTimeCompare(tag, src[len(src)-pad.BlockSize():]) != 1 {
		return nil, errors.New("pkcs7: inconsistent padding bytes")
	}

	return src[:len(src)-int(overhead)], nil
}
