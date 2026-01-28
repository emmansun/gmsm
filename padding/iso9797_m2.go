package padding

import (
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
)

// Add a single bit with value 1 to the end of the data.
// Then if necessary add bits with value 0 to the end of the data until the padded data is a multiple of n.
//
// https://en.wikipedia.org/wiki/ISO/IEC_9797-1
// also GB/T 17964-2021 C.2 Padding method 2
type iso9797M2Padding uint

func (pad iso9797M2Padding) BlockSize() int {
	return int(pad)
}

func (pad iso9797M2Padding) Pad(src []byte) []byte {
	overhead := pad.BlockSize() - len(src)%pad.BlockSize()
	ret, out := alias.SliceForAppend(src, overhead)
	out[0] = 0x80
	clear(out[1:overhead])
	return ret
}

// Unpad decrypted plaintext, non-constant-time
func (pad iso9797M2Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}
	tail := src[srcLen-pad.BlockSize():]
	allZero := true
	padStart := 0
	for i := pad.BlockSize() - 1; i >= 0; i-- {
		if tail[i] == 0x80 {
			padStart = i
			break
		}
		if tail[i] != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		return nil, errors.New("padding: inconsistent padding bytes")
	}
	return src[:srcLen-pad.BlockSize()+padStart], nil
}

// ConstantTimeUnpad removes ISO/IEC 9797-1 Method 2 padding in constant time.
//
// This method prevents timing attacks by always examining all bytes in the last block,
// regardless of where the 0x80 marker is found or if padding is invalid.
func (pad iso9797M2Padding) ConstantTimeUnpad(src []byte) ([]byte, error) {
	srcLen := len(src)

	// Basic length validation (structural check, can be non-constant-time)
	if srcLen == 0 || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: src length is not multiple of block size")
	}

	// We need to find the position of 0x80 from the end, and verify all bytes after it are 0x00
	// To maintain constant time, we must examine all bytes in the last block

	blockSize := pad.BlockSize()
	lastBlockStart := srcLen - blockSize

	// Track the position of 0x80 (initialized to an invalid position)
	padStartPos := -1
	found0x80 := 0 // Will be 1 if we find exactly one 0x80

	// Constant-time search for 0x80 from end to beginning of last block
	for i := blockSize - 1; i >= 0; i-- {
		pos := lastBlockStart + i
		b := src[pos]

		// Check if this byte is 0x80
		is0x80 := subtle.ConstantTimeByteEq(b, 0x80)

		// Check if we haven't found 0x80 yet (found0x80 == 0)
		notFoundYet := subtle.ConstantTimeByteEq(byte(found0x80), 0)

		// If this is 0x80 AND we haven't found one yet, record the position
		shouldRecord := is0x80 & notFoundYet
		padStartPos = subtle.ConstantTimeSelect(shouldRecord, i, padStartPos)
		found0x80 |= is0x80
	}

	// Constant-time validation: all bytes after 0x80 must be 0x00
	paddingOk := 1
	for i := 0; i < blockSize; i++ {
		pos := lastBlockStart + i
		b := src[pos]

		// Check if this position is after the 0x80 marker
		afterMarker := subtle.ConstantTimeLessOrEq(padStartPos+1, i)

		// Verify the byte is 0x00
		isZero := subtle.ConstantTimeByteEq(b, 0x00)

		// Update paddingOk only if this position should be 0x00
		paddingOk &= subtle.ConstantTimeSelect(afterMarker, isZero, 1)
	}

	// Constant-time check: padStartPos must be valid (>= 0)
	validPos := subtle.ConstantTimeLessOrEq(0, padStartPos)

	// Constant-time check: must have found exactly one 0x80
	found0x80Valid := subtle.ConstantTimeByteEq(byte(found0x80), 1)

	// Combine all validation checks
	if (validPos & found0x80Valid & paddingOk) == 0 {
		return nil, errors.New("padding: invalid padding")
	}

	return src[:lastBlockStart+padStartPos], nil
}
