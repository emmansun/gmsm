//go:build amd64 || arm64
// +build amd64 arm64

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/internal/xor"
)

// Assert that sm4CipherAsm implements the cbcDecAble interfaces.
var _ cbcDecAble = (*sm4CipherAsm)(nil)

type cbc struct {
	b   *sm4CipherAsm
	iv  []byte
	tmp []byte
}

func (b *sm4CipherAsm) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.iv = make([]byte, BlockSize)
	c.tmp = make([]byte, BlockSize)
	copy(c.iv, iv)
	return &c
}

func (x *cbc) BlockSize() int { return BlockSize }

func (x *cbc) CryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}
	end := len(src)
	copy(x.tmp, src[end-BlockSize:end])
	start := end - FourBlocksSize
	var temp []byte = make([]byte, FourBlocksSize)
	var src64 []byte = make([]byte, FourBlocksSize)
	for start > 0 {
		encryptBlocksAsm(&x.b.dec[0], &temp[0], &src[start:end][0])
		xor.XorBytes(dst[end-BlockSize:end], temp[FourBlocksSize-BlockSize:FourBlocksSize], src[end-2*BlockSize:end-BlockSize])
		xor.XorBytes(dst[end-2*BlockSize:end-BlockSize], temp[FourBlocksSize-2*BlockSize:FourBlocksSize-BlockSize], src[end-3*BlockSize:end-2*BlockSize])
		xor.XorBytes(dst[end-3*BlockSize:end-2*BlockSize], temp[FourBlocksSize-3*BlockSize:FourBlocksSize-2*BlockSize], src[end-4*BlockSize:end-3*BlockSize])
		xor.XorBytes(dst[end-4*BlockSize:end-3*BlockSize], temp[:BlockSize], src[end-5*BlockSize:end-4*BlockSize])

		end = start
		start -= FourBlocksSize
	}

	copy(src64, src[:end])
	encryptBlocksAsm(&x.b.dec[0], &temp[0], &src[:end][0])
	count := end / BlockSize
	for i := count; i > 1; i-- {
		xor.XorBytes(dst[end-BlockSize:end], temp[end-BlockSize:end], src[end-2*BlockSize:end-BlockSize])
		end -= BlockSize
	}
	xor.XorBytes(dst[0:end], temp[0:end], x.iv[:])
	// Set the new iv to the first block we copied earlier.
	x.iv, x.tmp = x.tmp, x.iv
}

func (x *cbc) SetIV(iv []byte) {
	if len(iv) != BlockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}
