package padding

import (
	"crypto/subtle"
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

// ConstantTimeUnpad removes PKCS#7 padding in constant time to prevent padding oracle attacks.
func (pad pkcs7Padding) ConstantTimeUnpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}

	// Read padding length from last byte
	paddedLen := int(src[srcLen-1])

	// Constant-time validation: 1 <= paddedLen <= blockSize
	validLen := subtle.ConstantTimeLessOrEq(1, paddedLen) &
		subtle.ConstantTimeLessOrEq(paddedLen, pad.BlockSize())

	// Constant-time check: verify all padding bytes are correct
	// We must check all blockSize positions to maintain constant time
	paddingOk := 1
	for i := 0; i < pad.BlockSize(); i++ {
		// Calculate position from end
		pos := srcLen - pad.BlockSize() + i

		// Check if this position should contain padding
		// (i.e., pos >= srcLen - paddedLen)
		inPadding := subtle.ConstantTimeLessOrEq(srcLen-paddedLen, pos)

		// Verify the byte value matches paddedLen
		correctValue := subtle.ConstantTimeByteEq(src[pos], byte(paddedLen))

		// Update paddingOk only if this byte is in the padding range
		paddingOk &= subtle.ConstantTimeSelect(inPadding, correctValue, 1)
	}

	// Combine all checks
	if (validLen & paddingOk) == 0 {
		return nil, errors.New("padding: invalid padding")
	}

	return src[:srcLen-paddedLen], nil
}
