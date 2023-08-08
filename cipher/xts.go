package cipher

import (
	_cipher "crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
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
	Encrypt(dst, src []byte, tweak *[blockSize]byte)

	// Decrypt decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	Decrypt(dst, src []byte, tweak *[blockSize]byte)

	// Encrypt encrypts or decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	EncryptSector(dst, src []byte, sectorNum uint64)

	// Decrypt decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	DecryptSector(dst, src []byte, sectorNum uint64)
}

// Cipher contains an expanded key structure. It is safe for concurrent use if
// the underlying block cipher is safe for concurrent use.
type xts struct {
	k1, k2 _cipher.Block
	isGB   bool // if true, follows GB/T 17964-2021
}

// blockSize is the block size that the underlying cipher must have. XTS is
// only defined for 16-byte ciphers.
const blockSize = 16

// NewGBXTS creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes). The key must be
// twice the length of the underlying cipher's key.
// It follows GB/T 17964-2021.
func NewGBXTS(cipherFunc CipherCreator, key []byte) (XTSBlockMode, error) {
	return newXTS(cipherFunc, key, true)
}

// NewXTS creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes). The key must be
// twice the length of the underlying cipher's key.
func NewXTS(cipherFunc CipherCreator, key []byte) (XTSBlockMode, error) {
	return newXTS(cipherFunc, key, false)
}

func newXTS(cipherFunc CipherCreator, key []byte, isGB bool) (*xts, error) {
	k1, err := cipherFunc(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	k2, err := cipherFunc(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	c := &xts{
		k1,
		k2,
		isGB,
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

func (c *xts) fillTweak(tweak *[blockSize]byte, sectorNum uint64) {
	for i := range tweak {
		tweak[i] = 0
	}
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
}

// Encrypt encrypts a sector of plaintext and puts the result into ciphertext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) Encrypt(ciphertext, plaintext []byte, tweak *[blockSize]byte) {
	if tweak == nil {
		panic("xts: invalid tweak")
	}
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("xts: plaintext length is smaller than the block size")
	}
	if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("xts: invalid buffer overlap")
	}

	c.k2.Encrypt(tweak[:], tweak[:])

	lastCiphertext := ciphertext

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(plaintext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak, c.isGB)
			}
			subtle.XORBytes(ciphertext, plaintext, tweaks)
			concCipher.EncryptBlocks(ciphertext, ciphertext)
			subtle.XORBytes(ciphertext, ciphertext, tweaks)
			plaintext = plaintext[batchSize:]
			lastCiphertext = ciphertext[batchSize-blockSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}
	for len(plaintext) >= blockSize {
		subtle.XORBytes(ciphertext, plaintext, tweak[:])
		c.k1.Encrypt(ciphertext, ciphertext)
		subtle.XORBytes(ciphertext, ciphertext, tweak[:])
		plaintext = plaintext[blockSize:]
		lastCiphertext = ciphertext
		ciphertext = ciphertext[blockSize:]
		mul2(tweak, c.isGB)
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
		subtle.XORBytes(x[:], x[:], tweak[:])
		//Encrypt the final block using K1
		c.k1.Encrypt(x[:], x[:])
		//Merge the tweak into the output block
		subtle.XORBytes(lastCiphertext, x[:], tweak[:])
	}
}

// Encrypt encrypts a sector of plaintext and puts the result into ciphertext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) EncryptSector(ciphertext, plaintext []byte, sectorNum uint64) {
	var tweak [blockSize]byte
	c.fillTweak(&tweak, sectorNum)
	c.Encrypt(ciphertext, plaintext, &tweak)
}

// Decrypt decrypts a sector of ciphertext and puts the result into plaintext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) Decrypt(plaintext, ciphertext []byte, tweak *[blockSize]byte) {
	if tweak == nil {
		panic("xts: invalid tweak")
	}
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext) < blockSize {
		panic("xts: ciphertext length is smaller than the block size")
	}
	if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("xts: invalid buffer overlap")
	}

	c.k2.Encrypt(tweak[:], tweak[:])

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(ciphertext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak, c.isGB)
			}
			subtle.XORBytes(plaintext, ciphertext, tweaks)
			concCipher.DecryptBlocks(plaintext, plaintext)
			subtle.XORBytes(plaintext, plaintext, tweaks)
			plaintext = plaintext[batchSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}

	for len(ciphertext) >= 2*blockSize {
		subtle.XORBytes(plaintext, ciphertext, tweak[:])
		c.k1.Decrypt(plaintext, plaintext)
		subtle.XORBytes(plaintext, plaintext, tweak[:])
		plaintext = plaintext[blockSize:]
		ciphertext = ciphertext[blockSize:]

		mul2(tweak, c.isGB)
	}

	if remain := len(ciphertext); remain >= blockSize {
		var x [blockSize]byte
		if remain > blockSize {
			var tt [blockSize]byte
			copy(tt[:], tweak[:])
			mul2(&tt, c.isGB)
			subtle.XORBytes(x[:], ciphertext, tt[:])
			c.k1.Decrypt(x[:], x[:])
			subtle.XORBytes(plaintext, x[:], tt[:])

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
		subtle.XORBytes(x[:], x[:], tweak[:])
		c.k1.Decrypt(x[:], x[:])
		subtle.XORBytes(plaintext, x[:], tweak[:])
	}
}

// Decrypt decrypts a sector of ciphertext and puts the result into plaintext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xts) DecryptSector(plaintext, ciphertext []byte, sectorNum uint64) {
	var tweak [blockSize]byte
	c.fillTweak(&tweak, sectorNum)
	c.Decrypt(plaintext, ciphertext, &tweak)
}

// mul2 multiplies tweak by 2 in GF(2¹²⁸) with an irreducible polynomial of
// x¹²⁸ + x⁷ + x² + x + 1.
func mul2(tweak *[blockSize]byte, isGB bool) {
	var carryIn byte
	if !isGB {
		// tweak[0] represents the coefficients of {x^7, x^6, ..., x^0}
		// tweak[15] represents the coefficients of {x^127, x^126, ..., x^120}
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
	} else {
		// GB/T 17964-2021, because of the bit-ordering, doubling is actually a right shift.
		// tweak[0] represents the coefficients of {x^0, x^1, ..., x^7}
		// tweak[15] represents the coefficients of {x^120, x^121, ..., x^127}
		for j := range tweak {
			carryOut := (tweak[j] << 7) & 0x80
			tweak[j] = (tweak[j] >> 1) + carryIn
			carryIn = carryOut
		}
		if carryIn != 0 {
			tweak[0] ^= 0xE1 //  1<<7 | 1<<6 | 1<<5 | 1
		}
	}
}
