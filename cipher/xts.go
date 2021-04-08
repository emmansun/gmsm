package cipher

import (
	_cipher "crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
)

const GF128_FDBK byte = 0x87

type CipherCreator func([]byte) (_cipher.Block, error)

type concurrentBlocks interface {
	Concurrency() int
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

// A XTSBlockMode represents a block cipher running in a XTS mode
type XTSBlockMode interface {
	// BlockSize returns the mode's block size.
	BlockSize() int

	// Encrypt encrypts or decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	Encrypt(dst, src []byte, sectorNum uint64)

	// Decrypt decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	Decrypt(dst, src []byte, sectorNum uint64)
}

// Cipher contains an expanded key structure. It is safe for concurrent use if
// the underlying block cipher is safe for concurrent use.
type xts struct {
	k1, k2 _cipher.Block
}

// blockSize is the block size that the underlying cipher must have. XTS is
// only defined for 16-byte ciphers.
const blockSize = 16

var tweakPool = sync.Pool{
	New: func() interface{} {
		return new([blockSize]byte)
	},
}

// NewXTS creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes). The key must be
// twice the length of the underlying cipher's key.
func NewXTS(cipherFunc CipherCreator, key []byte) (XTSBlockMode, error) {
	k1, err := cipherFunc(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	k2, err := cipherFunc(key[len(key)/2:])
	c := &xts{
		k1,
		k2,
	}

	if c.k1.BlockSize() != blockSize {
		err = errors.New("xts: cipher does not have a block size of 16")
		return nil, err
	}
	return c, nil
}

func (c *xts) BlockSize() int {
	return blockSize
}

// Encrypt encrypts a sector of plaintext and puts the result into ciphertext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) Encrypt(ciphertext, plaintext []byte, sectorNum uint64) {
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("xts: plaintext length is smaller than the block size")
	}
	if InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("xts: invalid buffer overlap")
	}

	tweak := tweakPool.Get().(*[blockSize]byte)

	for i := range tweak {
		tweak[i] = 0
	}
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	c.k2.Encrypt(tweak[:], tweak[:])

	lastCiphertext := ciphertext

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(plaintext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak)
			}
			XorBytes(ciphertext, plaintext, tweaks)
			concCipher.EncryptBlocks(ciphertext, ciphertext)
			XorBytes(ciphertext, ciphertext, tweaks)
			plaintext = plaintext[batchSize:]
			lastCiphertext = ciphertext[batchSize-blockSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}
	for len(plaintext) >= blockSize {
		XorBytes(ciphertext, plaintext, tweak[:])
		c.k1.Encrypt(ciphertext, ciphertext)
		XorBytes(ciphertext, ciphertext, tweak[:])
		plaintext = plaintext[blockSize:]
		lastCiphertext = ciphertext
		ciphertext = ciphertext[blockSize:]
		mul2(tweak)
	}
	// is there a final partial block to handle?
	if remain := len(plaintext); remain > 0 {
		var x [blockSize]byte
		//Copy the final ciphertext bytes
		copy(ciphertext, lastCiphertext[:remain])
		//Copy the final plaintext bytes
		copy(x[:], plaintext)
		//Steal ciphertext to complete the block
		copy(x[remain:], lastCiphertext[remain:blockSize])
		//Merge the tweak into the input block
		XorBytes(x[:], x[:], tweak[:])
		//Encrypt the final block using K1
		c.k1.Encrypt(x[:], x[:])
		//Merge the tweak into the output block
		XorBytes(lastCiphertext, x[:], tweak[:])
	}
	tweakPool.Put(tweak)
}

// Decrypt decrypts a sector of ciphertext and puts the result into plaintext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) Decrypt(plaintext, ciphertext []byte, sectorNum uint64) {
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext) < blockSize {
		panic("xts: ciphertext length is smaller than the block size")
	}
	if InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("xts: invalid buffer overlap")
	}

	tweak := tweakPool.Get().(*[blockSize]byte)
	for i := range tweak {
		tweak[i] = 0
	}
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)

	c.k2.Encrypt(tweak[:], tweak[:])

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(ciphertext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak)
			}
			XorBytes(plaintext, ciphertext, tweaks)
			concCipher.DecryptBlocks(plaintext, plaintext)
			XorBytes(plaintext, plaintext, tweaks)
			plaintext = plaintext[batchSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}

	for len(ciphertext) >= 2*blockSize {
		XorBytes(plaintext, ciphertext, tweak[:])
		c.k1.Decrypt(plaintext, plaintext)
		XorBytes(plaintext, plaintext, tweak[:])
		plaintext = plaintext[blockSize:]
		ciphertext = ciphertext[blockSize:]

		mul2(tweak)
	}

	if remain := len(ciphertext); remain >= blockSize {
		var x [blockSize]byte
		if remain > blockSize {
			var tt [blockSize]byte
			copy(tt[:], tweak[:])
			mul2(&tt)
			XorBytes(x[:], ciphertext, tt[:])
			c.k1.Decrypt(x[:], x[:])
			XorBytes(plaintext, x[:], tt[:])

			//Retrieve the length of the final block
			remain -= blockSize

			//Copy the final plaintext bytes
			copy(plaintext[blockSize:], plaintext)
			//Copy the final ciphertext bytes
			copy(x[:], ciphertext[blockSize:])
			//Steal ciphertext to complete the block
			copy(x[remain:], plaintext[remain:blockSize])
		} else {
			//The last block contains exactly 128 bits
			copy(x[:], ciphertext)
		}
		XorBytes(x[:], x[:], tweak[:])
		c.k1.Decrypt(x[:], x[:])
		XorBytes(plaintext, x[:], tweak[:])
	}

	tweakPool.Put(tweak)
}

// mul2 multiplies tweak by 2 in GF(2¹²⁸) with an irreducible polynomial of
// x¹²⁸ + x⁷ + x² + x + 1.
func mul2(tweak *[blockSize]byte) {
	var carryIn byte
	for j := range tweak {
		carryOut := tweak[j] >> 7
		tweak[j] = (tweak[j] << 1) + carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		// If we have a carry bit then we need to subtract a multiple
		// of the irreducible polynomial (x¹²⁸ + x⁷ + x² + x + 1).
		// By dropping the carry bit, we're subtracting the x^128 term
		// so all that remains is to subtract x⁷ + x² + x + 1.
		// Subtraction (and addition) in this representation is just
		// XOR.
		tweak[0] ^= GF128_FDBK // 1<<7 | 1<<2 | 1<<1 | 1
	}
}
