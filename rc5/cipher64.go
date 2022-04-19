package rc5

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"

	"github.com/emmansun/gmsm/internal/subtle"
)

const (
	// BlockSize the RC5/64 block size in bytes.
	BlockSize64 = 16
	P64         = 0xB7E151628AED2A6B
	Q64         = 0x9E3779B97F4A7C15
)

type rc5Cipher64 struct {
	rounds uint
	rk     []uint64
}

func newCipher64(key []byte, rounds uint) (cipher.Block, error) {
	c := &rc5Cipher64{}
	c.rounds = rounds
	c.rk = make([]uint64, (rounds+1)<<1)
	expandKey64(key, c.rk)
	return c, nil
}

func expandKey64(key []byte, rk []uint64) {
	roundKeys := len(rk)
	// L is initially a c-length list of 0-valued w-length words
	L := make([]uint64, len(key)/8)
	lenL := len(L)
	for i := 0; i < lenL; i++ {
		L[i] = binary.LittleEndian.Uint64(key[:8])
		key = key[8:]
	}
	// Initialize key-independent pseudorandom S array
	// S is initially a t=2(r+1) length list of undefined w-length words
	rk[0] = P64
	for i := 1; i < roundKeys; i++ {
		rk[i] = rk[i-1] + Q64
	}
	// The main key scheduling loop
	var A uint64
	var B uint64
	var i, j int
	for k := 0; k < 3*roundKeys; k++ {
		rk[i] = bits.RotateLeft64(rk[i]+(A+B), 3)
		A = rk[i]
		L[j] = bits.RotateLeft64(L[j]+(A+B), int(A+B))
		B = L[j]
		i = (i + 1) % roundKeys
		j = (j + 1) % lenL
	}
}

func (c *rc5Cipher64) BlockSize() int { return BlockSize64 }

func (c *rc5Cipher64) Encrypt(dst, src []byte) {
	if len(src) < BlockSize64 {
		panic("rc5-64: input not full block")
	}
	if len(dst) < BlockSize64 {
		panic("rc5-64: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize64], src[:BlockSize64]) {
		panic("rc5-64: invalid buffer overlap")
	}
	A := binary.LittleEndian.Uint64(src[:8]) + c.rk[0]
	B := binary.LittleEndian.Uint64(src[8:BlockSize64]) + c.rk[1]

	for r := 1; r <= int(c.rounds); r++ {
		A = bits.RotateLeft64(A^B, int(B)) + c.rk[r<<1]
		B = bits.RotateLeft64(B^A, int(A)) + c.rk[r<<1+1]
	}
	binary.LittleEndian.PutUint64(dst[:8], A)
	binary.LittleEndian.PutUint64(dst[8:16], B)
}

func (c *rc5Cipher64) Decrypt(dst, src []byte) {
	if len(src) < BlockSize64 {
		panic("rc5-64: input not full block")
	}
	if len(dst) < BlockSize64 {
		panic("rc5-64: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize64], src[:BlockSize64]) {
		panic("rc5-64: invalid buffer overlap")
	}
	A := binary.LittleEndian.Uint64(src[:8])
	B := binary.LittleEndian.Uint64(src[8:16])
	for r := c.rounds; r >= 1; r-- {
		B = A ^ bits.RotateLeft64(B-c.rk[r<<1+1], -int(A))
		A = B ^ bits.RotateLeft64(A-c.rk[r<<1], -int(B))
	}
	binary.LittleEndian.PutUint64(dst[:8], A-c.rk[0])
	binary.LittleEndian.PutUint64(dst[8:16], B-c.rk[1])
}
