// Block Chaining operation mode (BC mode) in Chinese national standard GB/T 17964-2021.
// See GB/T 17964-2021 Chapter 12.
package cipher

import (
	"bytes"
	_cipher "crypto/cipher"

	"github.com/emmansun/gmsm/internal/subtle"
)

type bc struct {
	b         _cipher.Block
	blockSize int
	iv        []byte
}

func newBC(b _cipher.Block, iv []byte) *bc {
	return &bc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
	}
}

type bcEncrypter bc

// bcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of BC encryption.
// NewBCEncrypter will check for this interface and return the specific
// BlockMode if found.
type bcEncAble interface {
	NewBCEncrypter(iv []byte) _cipher.BlockMode
}

// NewBCEncrypter returns a BlockMode which encrypts in block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size.
func NewBCEncrypter(b _cipher.Block, iv []byte) _cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewBCEncrypter: IV length must equal block size")
	}
	if bc, ok := b.(bcEncAble); ok {
		return bc.NewBCEncrypter(iv)
	}
	return (*bcEncrypter)(newBC(b, iv))
}

func (x *bcEncrypter) BlockSize() int { return x.blockSize }

func (x *bcEncrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	iv := x.iv

	for len(src) > 0 {
		// Write the xor to dst, then encrypt in place.
		subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		subtle.XORBytes(iv, iv, dst[:x.blockSize])

		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *bcEncrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

type bcDecrypter bc

// bcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of BC decryption.
// NewBCDecrypter will check for this interface and return the specific
// BlockMode if found.
type bcDecAble interface {
	NewBCDecrypter(iv []byte) _cipher.BlockMode
}

// NewBCDecrypter returns a BlockMode which decrypts in block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size and must match the iv used to encrypt the data.
func NewBCDecrypter(b _cipher.Block, iv []byte) _cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewBCDecrypter: IV length must equal block size")
	}
	if bc, ok := b.(bcDecAble); ok {
		return bc.NewBCDecrypter(iv)
	}
	return (*bcDecrypter)(newBC(b, iv))
}

func (x *bcDecrypter) BlockSize() int { return x.blockSize }

func (x *bcDecrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	if len(src) == 0 {
		return
	}

	iv := x.iv
	nextIV := make([]byte, x.blockSize)

	for len(src) > 0 {
		// Get F(i+1)
		subtle.XORBytes(nextIV, iv, src[:x.blockSize])
		// Get plaintext P(i)
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], iv)

		copy(iv, nextIV)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *bcDecrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}
