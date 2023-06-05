//go:build (amd64 && !purego) || (arm64 && !purego)
// +build amd64,!purego arm64,!purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
)

// Assert that sm4CipherAsm implements the cbcEncAble and cbcDecAble interfaces.
var _ cbcEncAble = (*sm4CipherAsm)(nil)
var _ cbcDecAble = (*sm4CipherAsm)(nil)

const cbcEncrypt = 1
const cbcDecrypt = 0

type cbc struct {
	b   *sm4CipherAsm
	iv  []byte
	tmp []byte
	enc int
}

func (b *sm4CipherAsm) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.enc = cbcEncrypt
	c.iv = make([]byte, BlockSize)
	c.tmp = make([]byte, BlockSize)
	copy(c.iv, iv)
	return &c
}

func (b *sm4CipherAsm) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.enc = cbcDecrypt
	c.iv = make([]byte, BlockSize)
	c.tmp = make([]byte, BlockSize)
	copy(c.iv, iv)
	return &c
}

func (x *cbc) BlockSize() int { return BlockSize }

//go:noescape
func encryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)

func (x *cbc) CryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}
	if x.enc == cbcEncrypt {
		encryptBlocksChain(&x.b.enc[0], dst, src, &x.iv[0])
		return
	}
	// For each block, we need to xor the decrypted data with the previous block's ciphertext (the iv).
	// To avoid making a copy each time, we loop over the blocks BACKWARDS.
	end := len(src)
	// Copy the last block of ciphertext in preparation as the new iv.
	copy(x.tmp, src[end-BlockSize:end])

	start := end - x.b.blocksSize
	var temp []byte = make([]byte, x.b.blocksSize)
	var batchSrc []byte = make([]byte, x.b.blocksSize+BlockSize)

	for start > 0 {
		x.b.DecryptBlocks(temp, src[start:end])
		subtle.XORBytes(temp, temp, src[start-BlockSize:end-BlockSize])
		copy(dst[start:], temp)
		end = start
		start -= x.b.blocksSize
	}

	// Handle remain first blocks
	copy(batchSrc[BlockSize:], src[:end])
	x.b.DecryptBlocks(temp, batchSrc[BlockSize:])
	copy(batchSrc, x.iv)
	subtle.XORBytes(dst, temp[:end], batchSrc)

	// Set the new iv to the first block we copied earlier.
	x.iv, x.tmp = x.tmp, x.iv
}

func (x *cbc) SetIV(iv []byte) {
	if len(iv) != BlockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}
