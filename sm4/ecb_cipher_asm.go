//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

// Assert that sm4CipherAsm implements the ecbEncAble and ecbDecAble interfaces.
var _ ecbEncAble = (*sm4CipherAsm)(nil)
var _ ecbDecAble = (*sm4CipherAsm)(nil)

const ecbEncrypt = 1
const ecbDecrypt = 0

type ecb struct {
	b   *sm4CipherAsm
	enc int
}

func (x *ecb) validate(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
}

func (b *sm4CipherAsm) NewECBEncrypter() cipher.BlockMode {
	var c ecb
	c.b = b
	c.enc = ecbEncrypt
	return &c
}

func (b *sm4CipherAsm) NewECBDecrypter() cipher.BlockMode {
	var c ecb
	c.b = b
	c.enc = ecbDecrypt
	return &c
}

func (x *ecb) BlockSize() int { return BlockSize }

//go:noescape
func encryptSm4Ecb(xk *uint32, dst, src []byte)

func (x *ecb) CryptBlocks(dst, src []byte) {
	x.validate(dst, src)
	if len(src) == 0 {
		return
	}
	xk := &x.b.enc[0]
	if x.enc == ecbDecrypt {
		xk = &x.b.dec[0]
	}
	encryptSm4Ecb(xk, dst, src)
}
