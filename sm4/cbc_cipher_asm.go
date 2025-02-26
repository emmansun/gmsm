//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package sm4

import (
	"bytes"
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
	enc int
}

func (b *sm4CipherAsm) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return &cbc{
		b:   b,
		iv:  bytes.Clone(iv),
		enc: cbcEncrypt,
	}
}

func (b *sm4CipherAsm) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return &cbc{
		b:   b,
		iv:  bytes.Clone(iv),
		enc: cbcDecrypt,
	}
}

func (x *cbc) BlockSize() int { return BlockSize }

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
		iv := x.iv

		for len(src) >= BlockSize {
			// Write the xor to dst, then encrypt in place.
			subtle.XORBytes(dst[:BlockSize], src[:BlockSize], iv)
			x.b.encrypt(dst[:BlockSize], dst[:BlockSize])

			// Move to the next block with this block as the next iv.
			iv = dst[:BlockSize]
			src = src[BlockSize:]
			dst = dst[BlockSize:]
		}

		// Save the iv for the next CryptBlocks call.
		copy(x.iv, iv)
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
