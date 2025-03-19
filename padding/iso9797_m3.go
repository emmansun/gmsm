package padding

import (
	"errors"

	"github.com/emmansun/gmsm/internal/byteorder"
)

// The padded data comprises (in this order):
//
// - The length of the unpadded data (in bits) expressed in big-endian binary in n bits (i.e. one cipher block)
// - The unpadded data
// - As many (possibly none) bits with value 0 as are required to bring the total length to a multiple of n bits
// It is not necessary to transmit or store the padding bits, because the recipient can regenerate them, knowing the length of the unpadded data and the padding method used.
//
// https://en.wikipedia.org/wiki/ISO/IEC_9797-1#Padding_method_3
// also GB/T 17964-2021 C.4 Padding method 3
type iso9797M3Padding uint

func (pad iso9797M3Padding) BlockSize() int {
	return int(pad)
}

func (pad iso9797M3Padding) Pad(src []byte) []byte {
	srcLen := len(src)
	overhead := pad.BlockSize() - srcLen%pad.BlockSize()
	if overhead == pad.BlockSize() && srcLen > 0 {
		overhead = 0
	}

	var head, tail []byte
	total := srcLen + overhead + pad.BlockSize()

	if total <= 0 {
		panic("padding: total length overflow")
	}

	if cap(src) >= total {
		head = src[:total]
	} else {
		head = make([]byte, total)
	}

	tail = head[srcLen+pad.BlockSize():]
	clear(head[:pad.BlockSize()])
	copy(head[pad.BlockSize():], src)
	if overhead > 0 {
		clear(tail)
	}
	byteorder.BEPutUint64(head[8:], uint64(srcLen*8))
	return head
}

// Unpad decrypted plaintext, non-constant-time
func (pad iso9797M3Padding) Unpad(src []byte) ([]byte, error) {
	srcLen := len(src)
	if srcLen < 2*pad.BlockSize() || srcLen%pad.BlockSize() != 0 {
		return nil, errors.New("padding: invalid src length")
	}
	for _, b := range src[:8] {
		if b != 0 {
			return nil, errors.New("padding: invalid padding header")
		}
	}
	dstLen := int(byteorder.BEUint64(src[8:pad.BlockSize()])/8)
	if dstLen < 0 || dstLen > srcLen-pad.BlockSize() {
		return nil, errors.New("padding: invalid padding header")
	}
	padded := src[pad.BlockSize()+dstLen:]
	for _, b := range padded {
		if b != 0 {
			return nil, errors.New("padding: invalid padding bytes")
		}
	}
	return src[pad.BlockSize() : pad.BlockSize()+dstLen], nil
}
