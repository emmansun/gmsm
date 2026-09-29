//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"
)

// Assert that sm4CipherAsm implements the xtsEncAble and xtsDecAble interfaces.
var _ xtsEncAble = (*sm4CipherAsm)(nil)
var _ xtsDecAble = (*sm4CipherAsm)(nil)

type xts struct {
	b     *sm4CipherAsm
	tweak [BlockSize]byte
	isGB  bool // if true, follows GB/T 17964-2021
	enc   int
}

func (b *sm4CipherAsm) NewXTSEncrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode {
	var c xts
	c.b = b
	c.enc = xtsEncrypt
	c.isGB = isGB
	copy(c.tweak[:], encryptedTweak[:])
	return &c
}

func (b *sm4CipherAsm) NewXTSDecrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode {
	var c xts
	c.b = b
	c.enc = xtsDecrypt
	c.isGB = isGB
	copy(c.tweak[:], encryptedTweak[:])
	return &c
}

func (x *xts) BlockSize() int { return BlockSize }

//go:noescape
func encryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)

//go:noescape
func decryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)

func (x *xts) CryptBlocks(dst, src []byte) {
	validateXtsInput(dst, src)
	if x.enc == xtsEncrypt {
		encryptSm4Xts(&x.b.enc[0], &x.tweak, dst, src, x.isGB)
	} else {
		decryptSm4Xts(&x.b.dec[0], &x.tweak, dst, src, x.isGB)
	}
}
