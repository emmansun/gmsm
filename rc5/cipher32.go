package rc5

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"

	"github.com/emmansun/gmsm/internal/subtle"
)

const (
	// BlockSize the RC5/32 block size in bytes.
	BlockSize32 = 8
	P32         = 0xB7E15163
	Q32         = 0x9E3779B9
)

type rc5Cipher32 struct {
	rounds uint
	rk     []uint32
}

func newCipher32(key []byte, rounds uint) (cipher.Block, error) {
	c := &rc5Cipher32{}
	c.rounds = rounds
	c.rk = make([]uint32, (rounds+1)<<1)
	expandKey32(key, c.rk)
	return c, nil
}

func expandKey32(key []byte, rk []uint32) {
	roundKeys := len(rk)
	// L is initially a c-length list of 0-valued w-length words
	L := make([]uint32, len(key)/4)
	lenL := len(L)
	for i := 0; i < lenL; i++ {
		L[i] = binary.LittleEndian.Uint32(key[:4])
		key = key[4:]
	}
	// Initialize key-independent pseudorandom S array
	// S is initially a t=2(r+1) length list of undefined w-length words
	rk[0] = P32
	for i := 1; i < roundKeys; i++ {
		rk[i] = rk[i-1] + Q32
	}
	// The main key scheduling loop
	var A uint32
	var B uint32
	var i, j int
	for k := 0; k < 3*roundKeys; k++ {
		rk[i] = bits.RotateLeft32(rk[i]+(A+B), 3)
		A = rk[i]
		L[j] = bits.RotateLeft32(L[j]+(A+B), int(A+B))
		B = L[j]
		i = (i + 1) % roundKeys
		j = (j + 1) % lenL
	}
}

func (c *rc5Cipher32) BlockSize() int { return BlockSize32 }

func (c *rc5Cipher32) Encrypt(dst, src []byte) {
	if len(src) < BlockSize32 {
		panic("rc5-32: input not full block")
	}
	if len(dst) < BlockSize32 {
		panic("rc5-32: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize32], src[:BlockSize32]) {
		panic("rc5-32: invalid buffer overlap")
	}
	A := binary.LittleEndian.Uint32(src[:4]) + c.rk[0]
	B := binary.LittleEndian.Uint32(src[4:BlockSize32]) + c.rk[1]

	for r := 1; r <= int(c.rounds); r++ {
		A = bits.RotateLeft32(A^B, int(B)) + c.rk[r<<1]
		B = bits.RotateLeft32(B^A, int(A)) + c.rk[r<<1+1]
	}
	binary.LittleEndian.PutUint32(dst[:4], A)
	binary.LittleEndian.PutUint32(dst[4:8], B)
}

func (c *rc5Cipher32) Decrypt(dst, src []byte) {
	if len(src) < BlockSize32 {
		panic("rc5-32: input not full block")
	}
	if len(dst) < BlockSize32 {
		panic("rc5-32: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize32], src[:BlockSize32]) {
		panic("rc5-32: invalid buffer overlap")
	}
	A := binary.LittleEndian.Uint32(src[:4])
	B := binary.LittleEndian.Uint32(src[4:8])
	for r := c.rounds; r >= 1; r-- {
		B = A ^ bits.RotateLeft32(B-c.rk[r<<1+1], -int(A))
		A = B ^ bits.RotateLeft32(A-c.rk[r<<1], -int(B))
	}
	binary.LittleEndian.PutUint32(dst[:4], A-c.rk[0])
	binary.LittleEndian.PutUint32(dst[4:8], B-c.rk[1])
}
