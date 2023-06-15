package zuc

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
)

const RoundWords = 32

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

func xorKeyStreamGeneric(c *zucState32, dst, src []byte) {
	words := (len(src) + 3) / 4
	rounds := words / RoundWords
	var keyBytes [RoundWords * 4]byte
	for i := 0; i < rounds; i++ {
		genKeyStreamRev32(keyBytes[:], c)
		subtle.XORBytes(dst, src, keyBytes[:])
		dst = dst[RoundWords*4:]
		src = src[RoundWords*4:]
	}
	if rounds*RoundWords < words {
		genKeyStreamRev32(keyBytes[:4*(words-rounds*RoundWords)], c)
		subtle.XORBytes(dst, src, keyBytes[:])
	}
}

func (c *zucState32) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}
	xorKeyStream(c, dst, src)
}
