package zuc

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/internal/xor"
)

// NewCipher create a stream cipher based on key and iv aguments.
func NewCipher(key, iv []byte) (cipher.Stream, error) {
	return newZUCState(key, iv)
}

// NewEEACipher create a stream cipher based on key, count, bearer and direction arguments according specification.
func NewEEACipher(key []byte, count, bearer, direction uint32) (cipher.Stream, error) {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv, count)
	copy(iv[8:12], iv[:4])
	iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
	iv[12] = iv[4]
	return newZUCState(key, iv)
}

func (c *zucState32) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}
	words := (len(src) + 3) / 4
	var out [4]byte
	for i := 0; i < words; i++ {
		binary.BigEndian.PutUint32(out[:], c.genKeyword())
		xor.XorBytes(dst, src, out[:])
		if i < words-1 {
			dst = dst[4:]
			src = src[4:]
		}
	}
}
