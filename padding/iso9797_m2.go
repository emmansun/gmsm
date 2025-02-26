package padding

import (
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
	padStart := -1

	for i, b := range src[srcLen-pad.BlockSize() : srcLen] {
		if b == 0x80 {
			padStart = i
		} else if b != 0 && padStart >=0 {
			padStart = -1
		}
	}
	if padStart >= 0 {
		return src[:srcLen-pad.BlockSize()+padStart], nil	
	}
	return src, nil
}
