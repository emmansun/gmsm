//go:build amd64 && !purego
// +build amd64,!purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

// Assert that sm4CipherAsm implements the xtsEncAble and xtsDecAble interfaces.
var _ xtsEncAble = (*sm4CipherAsm)(nil)
var _ xtsDecAble = (*sm4CipherAsm)(nil)

const xtsEncrypt = 1
const xtsDecrypt = 0

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
func encryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)

//go:noescape
func encryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)

//go:noescape
func decryptSm4Xts(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)

//go:noescape
func decryptSm4XtsGB(xk *uint32, tweak *[BlockSize]byte, dst, src []byte)

func (x *xts) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("xts: dst is smaller than src")
	}
	if len(src) < BlockSize {
		panic("xts: src length is smaller than the block size")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("xts: invalid buffer overlap")
	}
	if x.enc == xtsEncrypt {
		if x.isGB {
			encryptSm4XtsGB(&x.b.enc[0], &x.tweak, dst, src)
		} else {
			encryptSm4Xts(&x.b.enc[0], &x.tweak, dst, src)
		}
	} else {
		if x.isGB {
			decryptSm4XtsGB(&x.b.dec[0], &x.tweak, dst, src)
		} else {
			decryptSm4Xts(&x.b.dec[0], &x.tweak, dst, src)
		}	
	}
}
