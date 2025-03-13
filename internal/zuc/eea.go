package zuc

import (
	"crypto/subtle"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
)

const (
	// number of words in a round
	RoundWords = 32
	// number of bytes in a word
	WordSize = 4
	WordMask = WordSize - 1
	// number of bytes in a round
	RoundBytes = RoundWords * WordSize
)

type eea struct {
	zucState32
	x         [WordSize]byte // remaining bytes buffer
	xLen      int            // number of remaining bytes
	initState zucState32     // initial state for reset
	used      uint64         // number of key bytes processed, current offset
}

// NewCipher create a stream cipher based on key and iv aguments.
// The key must be 16 bytes long and iv must be 16 bytes long for zuc 128;
// or the key must be 32 bytes long and iv must be 23 bytes long for zuc 256;
// otherwise, an error will be returned.
func NewCipher(key, iv []byte) (*eea, error) {
	s, err := newZUCState(key, iv)
	if err != nil {
		return nil, err
	}
	c := new(eea)
	c.zucState32 = *s
	c.initState = *s
	c.used = 0
	return c, nil
}

// NewEEACipher create a stream cipher based on key, count, bearer and direction arguments according specification.
// The key must be 16 bytes long and iv must be 16 bytes long, otherwise, an error will be returned.
// The count is the 32-bit counter value, the bearer is the 5-bit bearer identity and the direction is the 1-bit
// transmission direction flag.
func NewEEACipher(key []byte, count, bearer, direction uint32) (*eea, error) {
	iv := make([]byte, 16)
	byteorder.BEPutUint32(iv, count)
	copy(iv[8:12], iv[:4])
	iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
	iv[12] = iv[4]
	return NewCipher(key, iv)
}

func genKeyStreamRev32Generic(keyStream []byte, pState *zucState32) {
	for len(keyStream) >= WordSize {
		z := genKeyword(pState)
		byteorder.BEPutUint32(keyStream, z)
		keyStream = keyStream[WordSize:]
	}
}

func (c *eea) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}
	used := len(src)
	if c.xLen > 0 {
		// handle remaining key bytes
		n := subtle.XORBytes(dst, src, c.x[:c.xLen])
		c.xLen -= n
		dst = dst[n:]
		src = src[n:]
		if c.xLen > 0 {
			copy(c.x[:], c.x[n:c.xLen+n])
			c.used += uint64(used)
			return
		}
	}
	var keyBytes [RoundBytes]byte
	for len(src) >= RoundBytes {
		genKeyStreamRev32(keyBytes[:], &c.zucState32)
		subtle.XORBytes(dst, src, keyBytes[:])
		dst = dst[RoundBytes:]
		src = src[RoundBytes:]
	}
	if len(src) > 0 {
		byteLen := (len(src) + WordMask) &^ WordMask
		genKeyStreamRev32(keyBytes[:byteLen], &c.zucState32)
		n := subtle.XORBytes(dst, src, keyBytes[:])
		// save remaining key bytes
		c.xLen = byteLen - n
		if c.xLen > 0 {
			copy(c.x[:], keyBytes[n:byteLen])
		}
	}
	c.used += uint64(used)
}

func (c *eea) reset() {
	c.zucState32 = c.initState
	c.xLen = 0
	c.used = 0
}

// seek sets the offset for the next XORKeyStream operation.
//
// If the offset is less than the current offset, the state will be reset to the initial state.
// If the offset is equal to the current offset, the function behaves the same as XORKeyStream.
// If the offset is greater than the current offset, the function will forward the state to the offset.
// Note: This method is not thread-safe.
func (c *eea) seek(offset uint64) {
	if offset < c.used {
		c.reset()
	}
	if offset == c.used {
		return
	}
	gap := offset - c.used
	if gap <= uint64(c.xLen) {
		// offset is within the remaining key bytes
		c.xLen -= int(gap)
		c.used += gap
		if c.xLen > 0 {
			// adjust remaining key bytes
			copy(c.x[:], c.x[gap:])
		}
		return
	}
	// consumed all remaining key bytes first
	if c.xLen > 0 {
		c.used += uint64(c.xLen)
		gap -= uint64(c.xLen)
		c.xLen = 0
	}

	// forward the state to the offset
	c.used += gap
	stepLen := uint64(RoundBytes)
	var keyStream [RoundWords]uint32
	for gap >= stepLen {
		genKeyStream(keyStream[:], &c.zucState32)
		gap -= stepLen
	}

	if gap > 0 {
		numWords := (gap + WordMask) / WordSize
		genKeyStream(keyStream[:numWords], &c.zucState32)
		partiallyUsed := int(gap & WordMask)
		if partiallyUsed > 0 {
			// save remaining key bytes (less than 4 bytes)
			c.xLen = WordSize - partiallyUsed
			byteorder.BEPutUint32(c.x[:], keyStream[numWords-1])
			copy(c.x[:], c.x[partiallyUsed:])
		}
	}
}

func (c *eea) XORKeyStreamAt(dst, src []byte, offset uint64) {
	c.seek(offset)
	c.XORKeyStream(dst, src)
}
