//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"
)

// Assert that sm4CipherAsm implements the xtsEncAble and xtsDecAble interfaces.
var _ xtsEncAble = (*sm4CipherNI)(nil)
var _ xtsDecAble = (*sm4CipherNI)(nil)

type xtsNI struct {
	b     *sm4CipherNI
	tweak [BlockSize]byte
	isGB  bool // if true, follows GB/T 17964-2021
	enc   int
}

func (b *sm4CipherNI) NewXTSEncrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode {
	var c xtsNI
	c.b = b
	c.enc = xtsEncrypt
	c.isGB = isGB
	copy(c.tweak[:], encryptedTweak[:])
	return &c
}

func (b *sm4CipherNI) NewXTSDecrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode {
	var c xtsNI
	c.b = b
	c.enc = xtsDecrypt
	c.isGB = isGB
	copy(c.tweak[:], encryptedTweak[:])
	return &c
}

func (x *xtsNI) BlockSize() int { return BlockSize }

//go:noescape
func encryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)

//go:noescape
func decryptSm4NiXts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte, isGB bool)

func (x *xtsNI) CryptBlocks(dst, src []byte) {
	validateXtsInput(dst, src)
	if x.enc == xtsEncrypt {
		encryptSm4NiXts(&x.b.enc[0], &x.tweak, dst, src, x.isGB)
	} else {
		decryptSm4NiXts(&x.b.dec[0], &x.tweak, dst, src, x.isGB)
	}
}
