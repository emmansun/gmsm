package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
)

type gxm struct {
	stream  cipher.Stream
	tagSize int
	tagMask [ghashBlockSize]byte
	// productTable contains the first sixteen powers of the hash key.
	// However, they are in bit reversed order.
	productTable [16]ghashFieldElement
}

// NewGXM creates a new GXM instance using the provided cipher stream and hash key.
// It uses the default tag size of 16 bytes.
func NewGXM(stream cipher.Stream, hkey []byte) (*gxm, error) {
	return NewGXMWithTagSize(stream, hkey, 16)
}

// NewGXMWithTagSize creates a new instance of GXM (Galois XOR Mode) with a specified tag size.
func NewGXMWithTagSize(stream cipher.Stream, hkey []byte, tagSize int) (*gxm, error) {
	if len(hkey) != ghashBlockSize {
		return nil, errors.New("cipher: invalid hash key length")
	}
	if tagSize < 8 || tagSize > 16 {
		return nil, errors.New("cipher: invalid tag size")
	}
	c := &gxm{}
	c.stream = stream
	c.tagSize = tagSize
	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := ghashFieldElement{
		byteorder.BEUint64(hkey[:8]),
		byteorder.BEUint64(hkey[8:blockSize]),
	}
	c.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		c.productTable[reverseBits(i)] = ghashDouble(&c.productTable[reverseBits(i/2)])
		c.productTable[reverseBits(i+1)] = ghashAdd(&c.productTable[reverseBits(i)], &x)
	}

	// encrypt zero block to get the tag mask
	stream.XORKeyStream(c.tagMask[:tagSize], c.tagMask[:tagSize])

	return c, nil
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (g *gxm) Overhead() int {
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
func (g *gxm) Seal(dst, plaintext, additionalData []byte) []byte {
	ret, out := alias.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if alias.InexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap of output and input")
	}
	if alias.AnyOverlap(out, additionalData) {
		panic("cipher: invalid buffer overlap of output and additional data")
	}

	g.stream.XORKeyStream(out, plaintext)
	g.gxmAuth(out[len(plaintext):], out[:len(plaintext)], additionalData)
	return ret
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
func (g *gxm) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
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

	var expectedTag [blockSize]byte
	g.gxmAuth(expectedTag[:], ciphertext, additionalData)

	// Use subtle.ConstantTimeCompare to avoid leaking timing information.
	if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		// We sometimes decrypt and authenticate concurrently, so we overwrite
		// dst in the event of a tag mismatch. To be consistent across platforms
		// and to avoid releasing unauthenticated plaintext, we clear the buffer
		// in the event of an error.
		clear(out)
		return nil, errOpen
	}
	g.stream.XORKeyStream(out, ciphertext)
	return ret, nil
}

func (g *gxm) gxmAuth(out, ciphertext, additionalData []byte) {
	var tag [ghashBlockSize]byte
	tagField := ghashFieldElement{}
	ghashUpdate(&g.productTable, &tagField, additionalData)
	ghashUpdate(&g.productTable, &tagField, ciphertext)
	lenBlock := make([]byte, 16)
	byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
	byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
	ghashUpdate(&g.productTable, &tagField, lenBlock)
	byteorder.BEPutUint64(tag[:], tagField.low)
	byteorder.BEPutUint64(tag[8:], tagField.high)
	subtle.XORBytes(tag[:], tag[:], g.tagMask[:])
	copy(out, tag[:g.tagSize])
}
