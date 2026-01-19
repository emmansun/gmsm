package padding

import (
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
)

// https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining
type ansiX923Padding uint

func (pad ansiX923Padding) BlockSize() int {
	return int(pad)
}

func (pad ansiX923Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := alias.SliceForAppend(src, overhead)
	out[overhead-1] = byte(overhead)
	clear(out[:overhead-1])
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad ansiX923Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	paddedLen := src[srcLen-1]
	if paddedLen == 0 || int(paddedLen) > pad.BlockSize() {
		return nil, errors.New("padding: invalid padding length")
	}
	for _, b := range src[srcLen-int(paddedLen) : srcLen-1] {
		if b != 0 {
			return nil, errors.New("padding: invalid padding bytes")
		}
	}
	return src[:srcLen-int(paddedLen)], nil
}

// ConstantTimeUnpad removes ANSI X.923 padding in constant time.
//
// ANSI X.923 padding format:
// - All padding bytes are 0x00 except the last byte
// - The last byte contains the padding length
//
// This implementation prevents timing attacks by always examining all bytes
// in the last block, regardless of the padding length or validity.
func (pad ansiX923Padding) ConstantTimeUnpad(src []byte) ([]byte, error) {
	srcLen := len(src)

	// Basic length validation (structural check, can be non-constant-time)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}

	// Read padding length from last byte
	paddedLen := int(src[srcLen-1])

	// Constant-time validation: 1 <= paddedLen <= blockSize
	validLen := subtle.ConstantTimeLessOrEq(1, paddedLen) &
		subtle.ConstantTimeLessOrEq(paddedLen, pad.BlockSize())

	// Constant-time check: verify all padding bytes (except last) are 0x00
	// We must check all possible positions in the last block to maintain constant time
	paddingOk := 1
	blockSize := pad.BlockSize()
	lastBlockStart := srcLen - blockSize

	for i := 0; i < blockSize-1; i++ { // -1 because last byte is the length
		pos := lastBlockStart + i

		// Check if this position is in the padding range
		// (i.e., pos >= srcLen - paddedLen)
		inPadding := subtle.ConstantTimeLessOrEq(srcLen-paddedLen, pos)

		// Verify the byte is 0x00
		isZero := subtle.ConstantTimeByteEq(src[pos], 0x00)

		// Update paddingOk only if this byte should be padding
		paddingOk &= subtle.ConstantTimeSelect(inPadding, isZero, 1)
	}

	// Combine all validation checks
	if (validLen & paddingOk) == 0 {
		return nil, errors.New("padding: invalid padding")
	}

	return src[:srcLen-paddedLen], nil
}
