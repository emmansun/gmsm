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
	// number of bytes in a round
	RoundBytes = RoundWords * WordSize
)

type eea struct {
	zucState32
	x          [RoundBytes]byte // remaining bytes buffer
	xLen       int              // number of remaining bytes
	used       uint64           // number of key bytes processed, current offset
	states     []*zucState32    // internal states for seek
	stateIndex int              // current state index, for test usage
	bucketSize int
}

// NewCipher creates a stream cipher based on key and iv aguments.
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
	c.states = append(c.states, s)
	c.used = 0
	c.bucketSize = 0
	c.stateIndex = 0
	return c, nil
}

// NewCipherWithBucketSize creates a new instance of the eea cipher with the specified
// bucket size. The bucket size is rounded up to the nearest multiple of RoundBytes.
func NewCipherWithBucketSize(key, iv []byte, bucketSize int) (*eea, error) {
	c, err := NewCipher(key, iv)
	if err != nil {
		return nil, err
	}
	if bucketSize > 0 {
		c.bucketSize = ((bucketSize + RoundBytes - 1) / RoundBytes) * RoundBytes
	}
	return c, nil
}

func construcIV4EEA(count, bearer, direction uint32) []byte {
	iv := make([]byte, 16)
	byteorder.BEPutUint32(iv, count)
	copy(iv[8:12], iv[:4])
	iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
	iv[12] = iv[4]
	return iv
}

// NewEEACipher creates a stream cipher based on key, count, bearer and direction arguments according specification.
// The key must be 16 bytes long and iv must be 16 bytes long, otherwise, an error will be returned.
// The count is the 32-bit counter value, the bearer is the 5-bit bearer identity and the direction is the 1-bit
// transmission direction flag.
func NewEEACipher(key []byte, count, bearer, direction uint32) (*eea, error) {
	return NewCipher(key, construcIV4EEA(count, bearer, direction))
}

// NewEEACipherWithBucketSize creates a new instance of the EEA cipher with a specified bucket size.
// It initializes the cipher using the provided key, count, bearer, and direction parameters,
// and adjusts the bucket size to be a multiple of RoundBytes.
func NewEEACipherWithBucketSize(key []byte, count, bearer, direction uint32, bucketSize int) (*eea, error) {
	return NewCipherWithBucketSize(key, construcIV4EEA(count, bearer, direction), bucketSize)
}

func genKeyStreamRev32Generic(keyStream []byte, pState *zucState32) {
	for len(keyStream) >= WordSize {
		z := genKeyword(pState)
		byteorder.BEPutUint32(keyStream, z)
		keyStream = keyStream[WordSize:]
	}
}

func (c *eea) appendState() {
	state := c.zucState32
	c.states = append(c.states, &state)
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
		c.used += uint64(n)
		dst = dst[n:]
		src = src[n:]
		if c.xLen > 0 {
			copy(c.x[:], c.x[n:c.xLen+n])
			return
		}
	}
	var keyBytes [RoundBytes]byte
	stepLen := uint64(RoundBytes)
	nextBucketOffset := c.bucketSize * len(c.states)
	for len(src) >= RoundBytes {
		genKeyStreamRev32(keyBytes[:], &c.zucState32)
		subtle.XORBytes(dst, src, keyBytes[:])
		dst = dst[RoundBytes:]
		src = src[RoundBytes:]
		c.used += stepLen
		if c.bucketSize > 0 && int(c.used) >= nextBucketOffset {
			c.appendState()
			nextBucketOffset += c.bucketSize
		}
	}
	remaining := len(src)
	if remaining > 0 {
		genKeyStreamRev32(keyBytes[:], &c.zucState32)
		subtle.XORBytes(dst, src, keyBytes[:])
		c.xLen = RoundBytes - remaining
		copy(c.x[:], keyBytes[remaining:])
		if c.bucketSize > 0 && int(c.used)+RoundBytes >= nextBucketOffset {
			c.appendState()
		}
		c.used += uint64(remaining)
	}
}

func (c *eea) reset(offset uint64) {
	var n uint64
	if c.bucketSize > 0 {
		n = offset / uint64(c.bucketSize)
	}
	// due to offset < c.used, n must be less than len(c.states)
	c.stateIndex = int(n)
	c.zucState32 = *c.states[n]
	c.xLen = 0
	c.used = n * uint64(c.bucketSize)
}

// seek sets the offset for the next XORKeyStream operation.
//
// If the offset is less than the current offset, the state will be reset to the initial state.
// If the offset is equal to the current offset, the function behaves the same as XORKeyStream.
// If the offset is greater than the current offset, the function will forward the state to the offset.
// Note: This method is not thread-safe.
func (c *eea) seek(offset uint64) {
	if offset < c.used {
		c.reset(offset)
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
	nextBucketOffset := c.bucketSize * len(c.states)
	stepLen := uint64(RoundBytes)
	var keyStream [RoundWords]uint32
	for gap >= stepLen {
		genKeyStream(keyStream[:], &c.zucState32)
		gap -= stepLen
		c.used += stepLen
		if c.bucketSize > 0 && int(c.used) >= nextBucketOffset {
			c.appendState()
			nextBucketOffset += c.bucketSize
		}
	}

	if gap > 0 {
		var keyBytes [RoundBytes]byte
		genKeyStreamRev32(keyBytes[:], &c.zucState32)
		c.xLen = RoundBytes - int(gap)
		copy(c.x[:], keyBytes[gap:])
		if c.bucketSize > 0 && int(c.used)+RoundBytes >= nextBucketOffset {
			c.appendState()
		}
		c.used += uint64(gap)
	}
}

func (c *eea) XORKeyStreamAt(dst, src []byte, offset uint64) {
	c.seek(offset)
	c.XORKeyStream(dst, src)
}
