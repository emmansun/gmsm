//go:build (amd64 && !generic) || (arm64 && !generic)
// +build amd64,!generic arm64,!generic

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
	start := end - x.b.blocksSize
	var temp []byte = make([]byte, x.b.blocksSize)
	var batchSrc []byte = make([]byte, x.b.blocksSize)
	for start > 0 {
		x.b.DecryptBlocks(temp, src[start:end])
		for i := 0; i < x.b.batchBlocks; i++ {
			xor.XorBytes(dst[end-(i+1)*BlockSize:end-i*BlockSize], temp[x.b.blocksSize-(i+1)*BlockSize:x.b.blocksSize-i*BlockSize], src[end-(i+2)*BlockSize:end-(i+1)*BlockSize])
		}
		end = start
		start -= x.b.blocksSize
	}

	copy(batchSrc, src[:end])
	x.b.DecryptBlocks(temp, batchSrc)
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
