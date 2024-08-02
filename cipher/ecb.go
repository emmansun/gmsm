// Electronic Code Book (ECB) mode.

// Please do NOT use this mode alone.
package cipher

import (
	goCipher "crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

type ecb struct {
	b         goCipher.Block
	blockSize int
}

func newECB(b goCipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func validate(size int, dst, src []byte) {
	if len(src)%size != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
}

type ecbEncrypter ecb

// ecbEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of ECB encryption, like sm4.
// NewECBEncrypter will check for this interface and return the specific
// BlockMode if found.
type ecbEncAble interface {
	NewECBEncrypter() goCipher.BlockMode
}

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b goCipher.Block) goCipher.BlockMode {
	if ecb, ok := b.(ecbEncAble); ok {
		return ecb.NewECBEncrypter()
	}
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// ecbDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of ECB decryption, like sm4.
// NewECBDecrypter will check for this interface and return the specific
// BlockMode if found.
type ecbDecAble interface {
	NewECBDecrypter() goCipher.BlockMode
}

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b goCipher.Block) goCipher.BlockMode {
	if ecb, ok := b.(ecbDecAble); ok {
		return ecb.NewECBDecrypter()
	}
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
