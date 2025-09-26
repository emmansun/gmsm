package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
)

type StreamCipherCreator func(key, iv []byte) (cipher.Stream, error)

const (
	maxIVSize  = 32
	maxTagSize = 16
)

type mur struct {
	streamCipherCreator StreamCipherCreator

	tagSize int
	// productTable contains the first sixteen powers of the hash key.
	// However, they are in bit reversed order.
	productTable [16]ghashFieldElement
}

// NewMUR creates a new MUR (misuse-resistant AEAD mode) instance with a default tag size of 16 bytes.
// It takes a StreamCipherCreator function for generating the underlying stream cipher and an ghash key.
func NewMUR(streamCipherCreator StreamCipherCreator, hkey []byte) (*mur, error) {
	return NewMURWithTagSize(streamCipherCreator, hkey, 16)
}

// NewMURWithTagSize creates a new MUR (misuse-resistant AEAD mode) instance with the specified tag size.
func NewMURWithTagSize(streamCipherCreator StreamCipherCreator, hkey []byte, tagSize int) (*mur, error) {
	if len(hkey) != ghashBlockSize {
		return nil, errors.New("cipher: invalid hash key length")
	}
	if tagSize < 8 || tagSize > 16 {
		return nil, errors.New("cipher: invalid tag size")
	}

	c := &mur{}
	c.streamCipherCreator = streamCipherCreator
	c.tagSize = tagSize
	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := ghashFieldElement{
		byteorder.BEUint64(hkey[:8]),
		byteorder.BEUint64(hkey[8:ghashBlockSize]),
	}
	c.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		c.productTable[reverseBits(i)] = ghashDouble(&c.productTable[reverseBits(i/2)])
		c.productTable[reverseBits(i+1)] = ghashAdd(&c.productTable[reverseBits(i)], &x)
	}

	return c, nil
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (g *mur) Overhead() int {
	return g.tagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
// dst and additionalData may not overlap.
func (g *mur) Seal(iv, key1, key2, dst, plaintext, additionalData []byte) ([]byte, error) {
	ret, out := alias.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if alias.InexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	var (
		tmpIV [maxIVSize]byte
		tag   [maxTagSize]byte
		ivLen = len(iv)
	)

	if ivLen > maxIVSize {
		panic("cipher: iv too large")
	}

	copy(tmpIV[:], iv)
	g.murAuth(tmpIV[:], plaintext, additionalData)
	subtle.XORBytes(tmpIV[:], tmpIV[:], iv)
	tagStream, err := g.streamCipherCreator(key2, tmpIV[:ivLen])
	if err != nil {
		return nil, err
	}
	tagStream.XORKeyStream(tag[:g.tagSize], tag[:g.tagSize])

	clear(tmpIV[:])
	subtle.XORBytes(tmpIV[:], iv, tag[:])
	dataStream, err := g.streamCipherCreator(key1, tmpIV[:ivLen])
	if err != nil {
		return nil, err
	}
	dataStream.XORKeyStream(out, plaintext)
	copy(out[len(plaintext):], tag[:g.tagSize])
	return ret, nil
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap ciphertext.
// dst and additionalData may not overlap.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (g *mur) Open(iv, key1, key2, dst, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	ret, out := alias.SliceForAppend(dst, len(ciphertext)-g.tagSize)
	if alias.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("cipher: invalid buffer overlap of output and additional data")
	}
	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	var (
		tmpIV  [maxIVSize]byte
		calTag [maxTagSize]byte
		ivLen  = len(iv)
	)
	if ivLen > maxIVSize {
		panic("cipher: iv too large")
	}
	copy(tmpIV[:], tag)
	subtle.XORBytes(tmpIV[:], iv, tmpIV[:])
	dataStream, err := g.streamCipherCreator(key1, tmpIV[:ivLen])
	if err != nil {
		return nil, err
	}
	dataStream.XORKeyStream(out, ciphertext)

	clear(tmpIV[:])
	g.murAuth(tmpIV[:], out, additionalData)
	subtle.XORBytes(tmpIV[:], tmpIV[:], iv)
	tagStream, err := g.streamCipherCreator(key2, tmpIV[:ivLen])
	if err != nil {
		return nil, err
	}
	tagStream.XORKeyStream(calTag[:g.tagSize], calTag[:g.tagSize])

	if subtle.ConstantTimeCompare(tag, calTag[:g.tagSize]) != 1 {
		clear(out)
		return nil, errOpen
	}
	return ret, nil
}

func (g *mur) murAuth(out []byte, plaintext, additionalData []byte) {
	var tag [ghashBlockSize]byte
	tagField := ghashFieldElement{}
	ghashUpdate(&g.productTable, &tagField, additionalData)
	ghashUpdate(&g.productTable, &tagField, plaintext)
	lenBlock := make([]byte, 16)
	byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
	byteorder.BEPutUint64(lenBlock[8:], uint64(len(plaintext))*8)
	ghashUpdate(&g.productTable, &tagField, lenBlock)
	byteorder.BEPutUint64(tag[:], tagField.low)
	byteorder.BEPutUint64(tag[8:], tagField.high)
	copy(out, tag[:])
}
