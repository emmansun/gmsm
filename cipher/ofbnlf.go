// Output feedback with a nonlinear function operation mode (OFBNLF mode) in Chinese national standard GB/T 17964-2021.
// See GB/T 17964-2021 Chapter 13.

package cipher

import (
	"bytes"
	_cipher "crypto/cipher"
	"errors"
)

type ofbnlf struct {
	cipherFunc CipherCreator
	b          _cipher.Block
	blockSize  int
	iv         []byte
}

func newOFBNLF(cipherFunc CipherCreator, key, iv []byte) (*ofbnlf, error) {
	c := &ofbnlf{
		cipherFunc: cipherFunc,
	}
	var err error
	c.b, err = cipherFunc(key)
	if err != nil {
		return nil, err
	}
	c.blockSize = c.b.BlockSize()
	if len(iv) != c.blockSize {
		return nil, errors.New("cipher: IV length must equal block size")
	}
	c.iv = bytes.Clone(iv)

	return c, nil
}

type ofbnlfEncrypter ofbnlf

// NewOFBNLFEncrypter returns a BlockMode which encrypts in Output feedback
// with a nonlinear function operation mode, using the given Block.
// The length of iv must be the same as the Block's block size.
func NewOFBNLFEncrypter(cipherFunc CipherCreator, key, iv []byte) (_cipher.BlockMode, error) {
	c, err := newOFBNLF(cipherFunc, key, iv)
	if err != nil {
		return nil, err
	}
	return (*ofbnlfEncrypter)(c), nil
}

func (x *ofbnlfEncrypter) BlockSize() int { return x.blockSize }

func (x *ofbnlfEncrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	iv := x.iv
	k := make([]byte, x.blockSize)

	for len(src) > 0 {
		x.b.Encrypt(k, iv)
		c, err := x.cipherFunc(k)
		if err != nil {
			panic(err)
		}
		c.Encrypt(dst, src)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
		copy(iv, k)
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *ofbnlfEncrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

type ofbnlfDecrypter ofbnlf

// NewOFBNLFDecrypter returns a BlockMode which decrypts in Output feedback
// with a nonlinear function operation mode, using the given Block.
// The length of iv must be the same as the Block's block size and must match
// the iv used to encrypt the data.
func NewOFBNLFDecrypter(cipherFunc CipherCreator, key, iv []byte) (_cipher.BlockMode, error) {
	c, err := newOFBNLF(cipherFunc, key, iv)
	if err != nil {
		return nil, err
	}
	return (*ofbnlfDecrypter)(c), nil
}

func (x *ofbnlfDecrypter) BlockSize() int { return x.blockSize }

func (x *ofbnlfDecrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	if len(src) == 0 {
		return
	}

	iv := x.iv
	k := make([]byte, x.blockSize)

	for len(src) > 0 {
		x.b.Encrypt(k, iv)
		c, err := x.cipherFunc(k)
		if err != nil {
			panic(err)
		}
		c.Decrypt(dst, src)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
		copy(iv, k)
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *ofbnlfDecrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}
