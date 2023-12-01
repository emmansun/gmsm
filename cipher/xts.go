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

// Cipher contains an expanded key structure. It is unsafe for concurrent use.
type xts struct {
	b     _cipher.Block
	tweak [blockSize]byte
	isGB  bool // if true, follows GB/T 17964-2021
}

// blockSize is the block size that the underlying cipher must have. XTS is
// only defined for 16-byte ciphers.
const blockSize = 16

type xtsEncrypter xts

// xtsEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of XTS encryption, like sm4.
// NewXTSEncrypter will check for this interface and return the specific
// BlockMode if found.
type xtsEncAble interface {
	NewXTSEncrypter(encryptedTweak *[blockSize]byte, isGB bool) _cipher.BlockMode
}

// NewXTSEncrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes).
func NewXTSEncrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (_cipher.BlockMode, error) {
	return newXTSEncrypter(cipherFunc, key, tweakKey, tweak, false)
}

// NewXTSEncrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number.
func NewXTSEncrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (_cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	return NewXTSEncrypter(cipherFunc, key, tweakKey, tweak)
}

// NewGBXTSEncrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes).
// It follows GB/T 17964-2021.
func NewGBXTSEncrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (_cipher.BlockMode, error) {
	return newXTSEncrypter(cipherFunc, key, tweakKey, tweak, true)
}

// NewGBXTSEncrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number.
// It follows GB/T 17964-2021.
func NewGBXTSEncrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (_cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	return NewGBXTSEncrypter(cipherFunc, key, tweakKey, tweak)
}

func newXTSEncrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte, isGB bool) (_cipher.BlockMode, error) {
	if len(tweak) != blockSize {
		return nil, errors.New("xts: invalid tweak length")
	}

	k1, err := cipherFunc(key)
	if err != nil {
		return nil, err
	}
	if k1.BlockSize() != blockSize {
		return nil, errors.New("xts: cipher does not have a block size of 16")
	}

	k2, err := cipherFunc(tweakKey)
	if err != nil {
		return nil, err
	}

	if xtsable, ok := k1.(xtsEncAble); ok {
		var encryptedTweak [blockSize]byte
		k2.Encrypt(encryptedTweak[:], tweak)
		return xtsable.NewXTSEncrypter(&encryptedTweak, isGB), nil
	}

	c := &xts{
		b:    k1,
		isGB: isGB,
	}
	k2.Encrypt(c.tweak[:], tweak)
	return (*xtsEncrypter)(c), nil
}

type xtsDecrypter xts

// xtsDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of XTS encryption, like sm4.
// NewXTSDecrypter will check for this interface and return the specific
// BlockMode if found.
type xtsDecAble interface {
	NewXTSDecrypter(encryptedTweak *[blockSize]byte, isGB bool) _cipher.BlockMode
}

// NewXTSDecrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) for decryption.
func NewXTSDecrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (_cipher.BlockMode, error) {
	return newXTSDecrypter(cipherFunc, key, tweakKey, tweak, false)
}

// NewXTSDecrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number for decryption.
func NewXTSDecrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (_cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	return NewXTSDecrypter(cipherFunc, key, tweakKey, tweak)
}

// NewGBXTSDecrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) for decryption.
// It follows GB/T 17964-2021.
func NewGBXTSDecrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (_cipher.BlockMode, error) {
	return newXTSDecrypter(cipherFunc, key, tweakKey, tweak, true)
}

// NewGBXTSDecrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number for decryption.
// It follows GB/T 17964-2021.
func NewGBXTSDecrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (_cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	return NewGBXTSDecrypter(cipherFunc, key, tweakKey, tweak)
}

func newXTSDecrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte, isGB bool) (_cipher.BlockMode, error) {
	if len(tweak) != blockSize {
		return nil, errors.New("xts: invalid tweak length")
	}

	k1, err := cipherFunc(key)
	if err != nil {
		return nil, err
	}
	if k1.BlockSize() != blockSize {
		return nil, errors.New("xts: cipher does not have a block size of 16")
	}

	k2, err := cipherFunc(tweakKey)
	if err != nil {
		return nil, err
	}

	if xtsable, ok := k1.(xtsDecAble); ok {
		var encryptedTweak [blockSize]byte
		k2.Encrypt(encryptedTweak[:], tweak)
		return xtsable.NewXTSDecrypter(&encryptedTweak, isGB), nil
	}

	c := &xts{
		b:    k1,
		isGB: isGB,
	}
	k2.Encrypt(c.tweak[:], tweak)
	return (*xtsDecrypter)(c), nil
}

func (c *xtsEncrypter) BlockSize() int {
	return blockSize
}

// CryptBlocks encrypts a sector of plaintext and puts the result into ciphertext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xtsEncrypter) CryptBlocks(ciphertext, plaintext []byte) {
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("xts: plaintext length is smaller than the block size")
	}
	if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("xts: invalid buffer overlap")
	}

	lastCiphertext := ciphertext

	if concCipher, ok := c.b.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)
		for len(plaintext) >= batchSize {
			doubleTweaks(&c.tweak, tweaks, c.isGB)
			subtle.XORBytes(ciphertext, plaintext, tweaks)
			concCipher.EncryptBlocks(ciphertext, ciphertext)
			subtle.XORBytes(ciphertext, ciphertext, tweaks)
			plaintext = plaintext[batchSize:]
			lastCiphertext = ciphertext[batchSize-blockSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}

	for len(plaintext) >= blockSize {
		subtle.XORBytes(ciphertext, plaintext, c.tweak[:])
		c.b.Encrypt(ciphertext, ciphertext)
		subtle.XORBytes(ciphertext, ciphertext, c.tweak[:])
		plaintext = plaintext[blockSize:]
		lastCiphertext = ciphertext
		ciphertext = ciphertext[blockSize:]
		mul2(&c.tweak, c.isGB)
	}
	// is there a final partial block to handle?
	if remain := len(plaintext); remain > 0 {
		var x [blockSize]byte
		//Copy the final plaintext bytes
		copy(x[:], plaintext)
		//Steal ciphertext to complete the block
		copy(x[remain:], lastCiphertext[remain:blockSize])
		//Copy the final ciphertext bytes
		copy(ciphertext, lastCiphertext[:remain])
		//Merge the tweak into the input block
		subtle.XORBytes(x[:], x[:], c.tweak[:])
		//Encrypt the final block using K1
		c.b.Encrypt(x[:], x[:])
		//Merge the tweak into the output block
		subtle.XORBytes(lastCiphertext, x[:], c.tweak[:])
	}
}

func (c *xtsDecrypter) BlockSize() int {
	return blockSize
}

// CryptBlocks decrypts a sector of ciphertext and puts the result into plaintext.
// Plaintext and ciphertext must overlap entirely or not at all.
// Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
func (c *xtsDecrypter) CryptBlocks(plaintext, ciphertext []byte) {
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext) < blockSize {
		panic("xts: ciphertext length is smaller than the block size")
	}
	if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("xts: invalid buffer overlap")
	}

	if concCipher, ok := c.b.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(ciphertext) >= batchSize {
			doubleTweaks(&c.tweak, tweaks, c.isGB)
			subtle.XORBytes(plaintext, ciphertext, tweaks)
			concCipher.DecryptBlocks(plaintext, plaintext)
			subtle.XORBytes(plaintext, plaintext, tweaks)
			plaintext = plaintext[batchSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}

	for len(ciphertext) >= 2*blockSize {
		subtle.XORBytes(plaintext, ciphertext, c.tweak[:])
		c.b.Decrypt(plaintext, plaintext)
		subtle.XORBytes(plaintext, plaintext, c.tweak[:])
		plaintext = plaintext[blockSize:]
		ciphertext = ciphertext[blockSize:]

		mul2(&c.tweak, c.isGB)
	}

	if remain := len(ciphertext); remain >= blockSize {
		var x [blockSize]byte
		if remain > blockSize {
			var tt [blockSize]byte
			copy(tt[:], c.tweak[:])
			mul2(&tt, c.isGB)
			subtle.XORBytes(x[:], ciphertext, tt[:])
			c.b.Decrypt(x[:], x[:])
			subtle.XORBytes(plaintext, x[:], tt[:])

			//Retrieve the length of the final block
			remain -= blockSize

			//Copy the final ciphertext bytes
			copy(x[:], ciphertext[blockSize:])
			//Steal ciphertext to complete the block
			copy(x[remain:], plaintext[remain:blockSize])
			//Copy the final plaintext bytes
			copy(plaintext[blockSize:], plaintext)

			subtle.XORBytes(x[:], x[:], c.tweak[:])
			c.b.Decrypt(x[:], x[:])
			subtle.XORBytes(plaintext, x[:], c.tweak[:])
		} else {
			//The last block contains exactly 128 bits
			subtle.XORBytes(plaintext, ciphertext, c.tweak[:])
			c.b.Decrypt(plaintext, plaintext)
			subtle.XORBytes(plaintext, plaintext, c.tweak[:])
			// Maybe there are still ciphertext
			mul2(&c.tweak, c.isGB)
		}

	}
}

// mul2Generic multiplies tweak by 2 in GF(2¹²⁸) with an irreducible polynomial of
// x¹²⁸ + x⁷ + x² + x + 1.
func mul2Generic(tweak *[blockSize]byte, isGB bool) {
	var carryIn byte
	if !isGB {
		// the coefficient of x⁰ can be obtained by tweak[0] & 1
		// the coefficient of x⁷ can be obtained by tweak[0] >> 7
		// the coefficient of x¹²⁰ can be obtained by tweak[15] & 1
		// the coefficient of x¹²⁷ can be obtained by tweak[15] >> 7
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
		// GB/T 17964-2021, 
		// the coefficient of x⁰ can be obtained by tweak[0] >> 7
		// the coefficient of x⁷ can be obtained by tweak[0] & 1
		// the coefficient of x¹²⁰ can be obtained by tweak[15] >> 7
		// the coefficient of x¹²⁷ can be obtained by tweak[15] & 1
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
