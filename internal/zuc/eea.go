package zuc

import (
	"crypto/subtle"
	"errors"

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
	bucketSize int              // size of the state bucket, 0 means no bucket
}

const (
	magic            = "zuceea"
	stateSize        = (16 + 6) * 4 // zucState32 size in bytes
	minMarshaledSize = len(magic) + stateSize + 8 + 4*3
)

// NewEmptyCipher creates and returns a new empty ZUC-EEA cipher instance.
// This function initializes an empty eea struct that can be used for
// unmarshaling a previously saved state using the UnmarshalBinary method.
// The returned cipher instance is not ready for encryption or decryption.
func NewEmptyCipher() *eea {
	return new(eea)
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

func appendState(b []byte, e *zucState32) []byte {
	for i := range 16 {
		b = byteorder.BEAppendUint32(b, e.lfsr[i])
	}
	b = byteorder.BEAppendUint32(b, e.r1)
	b = byteorder.BEAppendUint32(b, e.r2)
	b = byteorder.BEAppendUint32(b, e.x0)
	b = byteorder.BEAppendUint32(b, e.x1)
	b = byteorder.BEAppendUint32(b, e.x2)
	b = byteorder.BEAppendUint32(b, e.x3)

	return b
}

func (e *eea) MarshalBinary() ([]byte, error) {
	return e.AppendBinary(make([]byte, 0, minMarshaledSize))
}

func (e *eea) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, magic...)
	b = appendState(b, &e.zucState32)
	b = byteorder.BEAppendUint32(b, uint32(e.xLen))
	b = byteorder.BEAppendUint64(b, e.used)
	b = byteorder.BEAppendUint32(b, uint32(e.stateIndex))
	b = byteorder.BEAppendUint32(b, uint32(e.bucketSize))
	if e.xLen > 0 {
		b = append(b, e.x[:e.xLen]...)
	}
	for _, state := range e.states {
		b = appendState(b, state)
	}
	return b, nil
}

func unmarshalState(b []byte, e *zucState32) []byte {
	for i := range 16 {
		b, e.lfsr[i] = consumeUint32(b)
	}
	b, e.r1 = consumeUint32(b)
	b, e.r2 = consumeUint32(b)
	b, e.x0 = consumeUint32(b)
	b, e.x1 = consumeUint32(b)
	b, e.x2 = consumeUint32(b)
	b, e.x3 = consumeUint32(b)
	return b
}

func UnmarshalCipher(b []byte) (*eea, error) {
	var e eea
	if err := e.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *eea) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
		return errors.New("zuc: invalid eea state identifier")
	}
	if len(b) < minMarshaledSize {
		return errors.New("zuc: invalid eea state size")
	}
	b = b[len(magic):]
	b = unmarshalState(b, &e.zucState32)
	var tmpUint32 uint32
	b, tmpUint32 = consumeUint32(b)
	e.xLen = int(tmpUint32)
	b, e.used = consumeUint64(b)
	b, tmpUint32 = consumeUint32(b)
	e.stateIndex = int(tmpUint32)
	b, tmpUint32 = consumeUint32(b)
	e.bucketSize = int(tmpUint32)
	if e.xLen < 0 || e.xLen > RoundBytes {
		return errors.New("zuc: invalid eea remaining bytes length")
	}
	if e.xLen > 0 {
		if len(b) < e.xLen {
			return errors.New("zuc: invalid eea remaining bytes")
		}
		copy(e.x[:e.xLen], b[:e.xLen])
		b = b[e.xLen:]
	}
	statesCount := len(b) / stateSize
	if len(b)%stateSize != 0 {
		return errors.New("zuc: invalid eea states size")
	}

	for range statesCount {
		var state zucState32
		b = unmarshalState(b, &state)
		e.states = append(e.states, &state)
	}

	if e.stateIndex >= len(e.states) {
		return errors.New("zuc: invalid eea state index")
	}

	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], byteorder.BEUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], byteorder.BEUint32(b)
}

// reference GB/T 33133.2-2021 A.2
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

// fastForward advances the ZUC cipher state to handle a given offset
// without having to process each intermediate byte. This optimization
// leverages precomputed states stored in buckets to move the cipher
// state forward efficiently.
func (c *eea) fastForward(offset uint64) {
	// fast forward, check and adjust state if needed
	var n uint64
	if c.bucketSize > 0 {
		n = offset / uint64(c.bucketSize)
		expectedStateIndex := int(n)
		if expectedStateIndex > c.stateIndex && expectedStateIndex < len(c.states) {
			c.stateIndex = int(n)
			c.zucState32 = *c.states[n]
			c.xLen = 0
			c.used = n * uint64(c.bucketSize)
		}
	}
}

// seek advances the internal state of the ZUC stream cipher to a given offset in the
// key stream. It efficiently positions the cipher state to allow encryption or decryption
// starting from the specified byte offset.
func (c *eea) seek(offset uint64) {
	// 1. fast forward to the nearest precomputed state
	c.fastForward(offset)

	// 2. check if need to reset and backward, regardless of bucketSize
	if offset < c.used {
		c.reset(offset)
	}

	// 3. if offset equals to c.used, nothing to do
	if offset == c.used {
		return
	}

	// 4. offset > used, need to forward
	gap := offset - c.used

	// 5. gap <= c.xLen, consume remaining key bytes, adjust buffer and return
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

	// 6. gap > c.xLen, consume remaining key bytes first
	if c.xLen > 0 {
		c.used += uint64(c.xLen)
		gap -= uint64(c.xLen)
		c.xLen = 0
	}

	// 7. for the remaining gap, generate and discard key bytes in chunks
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

	// 8. finally consume remaining gap < RoundBytes
	//    and save remaining key bytes if any
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
