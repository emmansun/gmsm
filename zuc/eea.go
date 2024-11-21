package zuc

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/subtle"
)

const RoundWords = 32

type eea struct {
	zucState32
	x    [4]byte // remaining bytes buffer
	xLen int     // number of remaining bytes
}

// NewCipher create a stream cipher based on key and iv aguments.
func NewCipher(key, iv []byte) (cipher.Stream, error) {
	s, err := newZUCState(key, iv)
	if err != nil {
		return nil, err
	}
	c := new(eea)
	c.zucState32 = *s
	return c, nil
}

// NewEEACipher create a stream cipher based on key, count, bearer and direction arguments according specification.
func NewEEACipher(key []byte, count, bearer, direction uint32) (cipher.Stream, error) {
	iv := make([]byte, 16)
	byteorder.BEPutUint32(iv, count)
	copy(iv[8:12], iv[:4])
	iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
	iv[12] = iv[4]
	s, err := newZUCState(key, iv)
	if err != nil {
		return nil, err
	}
	c := new(eea)
	c.zucState32 = *s
	return c, nil
}

func genKeyStreamRev32Generic(keyStream []byte, pState *zucState32) {
	for len(keyStream) >= 4 {
		z := genKeyword(pState)
		byteorder.BEPutUint32(keyStream, z)
		keyStream = keyStream[4:]
	}
}

func (c *eea) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}
	if c.xLen > 0 {
		// handle remaining key bytes
		n := subtle.XORBytes(dst, src, c.x[:c.xLen])
		c.xLen -= n
		dst = dst[n:]
		src = src[n:]
		if c.xLen > 0 {
			copy(c.x[:], c.x[n:c.xLen+n])
			return
		}
	}
	words := (len(src) + 3) / 4
	rounds := words / RoundWords
	var keyBytes [RoundWords * 4]byte
	for i := 0; i < rounds; i++ {
		genKeyStreamRev32(keyBytes[:], &c.zucState32)
		subtle.XORBytes(dst, src, keyBytes[:])
		dst = dst[RoundWords*4:]
		src = src[RoundWords*4:]
	}
	if rounds*RoundWords < words {
		byteLen := 4 * (words - rounds*RoundWords)
		genKeyStreamRev32(keyBytes[:byteLen], &c.zucState32)
		n := subtle.XORBytes(dst, src, keyBytes[:])
		// save remaining key bytes
		c.xLen = byteLen - n
		if c.xLen > 0 {
			copy(c.x[:], keyBytes[n:byteLen])
		}
	}
}
