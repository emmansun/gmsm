//go:build (amd64 && !purego) || (arm64 && !purego)

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

// Assert that sm4CipherAsm implements the cbcEncAble and cbcDecAble interfaces.
var _ cbcEncAble = (*sm4CipherAsm)(nil)
var _ cbcDecAble = (*sm4CipherAsm)(nil)

const cbcEncrypt = 1
const cbcDecrypt = 0

type cbc struct {
	b   *sm4CipherAsm
	iv  []byte
	enc int
}

func (b *sm4CipherAsm) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.enc = cbcEncrypt
	c.iv = make([]byte, BlockSize)
	copy(c.iv, iv)
	return &c
}

func (b *sm4CipherAsm) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.enc = cbcDecrypt
	c.iv = make([]byte, BlockSize)
	copy(c.iv, iv)
	return &c
}

func (x *cbc) BlockSize() int { return BlockSize }

//go:noescape
func encryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)

//go:noescape
func decryptBlocksChain(xk *uint32, dst, src []byte, iv *byte)

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

	decryptBlocksChain(&x.b.dec[0], dst, src, &x.iv[0])
}

func (x *cbc) SetIV(iv []byte) {
	if len(iv) != BlockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}
