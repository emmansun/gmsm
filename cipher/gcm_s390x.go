// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego

package cipher

import (
	_cipher "crypto/cipher"
	_subtle "crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
)

// gcmAble is an interface implemented by ciphers that have a specific optimized
// implementation of GCM, like crypto/aes. NewGCM will check for this interface
// and return the specific AEAD if found.
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (_cipher.AEAD, error)
}

// gcmHashKey represents the 16-byte hash key required by the GHASH algorithm.
type gcmHashKey [16]byte

// gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	cipher    _cipher.Block
	nonceSize int
	tagSize   int
	hashKey   gcmHashKey
}

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
//
// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying Block was created by aes.NewCipher
// on systems with hardware support for AES. See the crypto/aes package documentation for details.
func NewGCM(cipher _cipher.Block) (_cipher.AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, gcmStandardNonceSize, gcmTagSize)
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length. The length must not
// be zero.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard nonce lengths. All other users should use
// NewGCM, which is faster and more resistant to misuse.
func NewGCMWithNonceSize(cipher _cipher.Block, size int) (_cipher.AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, size, gcmTagSize)
}

// NewGCMWithTagSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which generates tags with the given length.
//
// Tag sizes between 12 and 16 bytes are allowed.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard tag lengths. All other users should use
// NewGCM, which is more resistant to misuse.
func NewGCMWithTagSize(cipher _cipher.Block, tagSize int) (_cipher.AEAD, error) {
	return newGCMWithNonceAndTagSize(cipher, gcmStandardNonceSize, tagSize)
}

func newGCMWithNonceAndTagSize(cipher _cipher.Block, nonceSize, tagSize int) (_cipher.AEAD, error) {
	if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
		return nil, errors.New("cipher: incorrect tag size given to GCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
	}

	if cipher, ok := cipher.(gcmAble); ok {
		return cipher.NewGCM(nonceSize, tagSize)
	}

	if cipher.BlockSize() != gcmBlockSize {
		return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
	}

	var hk gcmHashKey
	cipher.Encrypt(hk[:], hk[:])

	g := &gcm{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize, hashKey: hk}

	return g, nil
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	gcmStandardNonceSize = 12
)

func (g *gcm) NonceSize() int {
	return g.nonceSize
}

func (g *gcm) Overhead() int {
	return g.tagSize
}

// gcmCount represents a 16-byte big-endian count value.
type gcmCount [16]byte

// inc increments the rightmost 32-bits of the count value by 1.
func (x *gcmCount) inc() {
	binary.BigEndian.PutUint32(x[len(x)-4:], binary.BigEndian.Uint32(x[len(x)-4:])+1)
}

// ghash uses the GHASH algorithm to hash data with the given key. The initial
// hash value is given by hash which will be updated with the new hash value.
// The length of data must be a multiple of 16-bytes.
//
//go:noescape
func ghash(key *gcmHashKey, hash *[16]byte, data []byte)

// paddedGHASH pads data with zeroes until its length is a multiple of
// 16-bytes. It then calculates a new value for hash using the GHASH algorithm.
func (g *gcm) paddedGHASH(hash *[16]byte, data []byte) {
	siz := len(data) &^ 0xf // align size to 16-bytes
	if siz > 0 {
		ghash(&g.hashKey, hash, data[:siz])
		data = data[siz:]
	}
	if len(data) > 0 {
		var s [16]byte
		copy(s[:], data)
		ghash(&g.hashKey, hash, s[:])
	}
}

// gcmLengths writes len0 || len1 as big-endian values to a 16-byte array.
func gcmLengths(len0, len1 uint64) [16]byte {
	v := [16]byte{}
	binary.BigEndian.PutUint64(v[0:], len0)
	binary.BigEndian.PutUint64(v[8:], len1)
	return v
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
func (g *gcm) auth(out, ciphertext, additionalData []byte, tagMask *[gcmTagSize]byte) {
	var hash [16]byte
	g.paddedGHASH(&hash, additionalData)
	g.paddedGHASH(&hash, ciphertext)
	lens := gcmLengths(uint64(len(additionalData))*8, uint64(len(ciphertext))*8)
	g.paddedGHASH(&hash, lens[:])

	copy(out, hash[:])
	for i := range out {
		out[i] ^= tagMask[i]
	}
}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
func (g *gcm) deriveCounter(nonce []byte) gcmCount {
	// GCM has two modes of operation with respect to the initial counter
	// state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
	// for nonces of other lengths. For a 96-bit nonce, the nonce, along
	// with a four-byte big-endian counter starting at one, is used
	// directly as the starting counter. For other nonce sizes, the counter
	// is computed by passing it through the GHASH function.
	var counter gcmCount
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		var hash [16]byte
		g.paddedGHASH(&hash, nonce)
		lens := gcmLengths(0, uint64(len(nonce))*8)
		g.paddedGHASH(&hash, lens[:])
		copy(counter[:], hash[:])
	}
	return counter
}

// counterCrypt crypts in to out using g.cipher in counter mode.
func (g *gcm) counterCrypt(out, in []byte, counter *gcmCount) {
	var mask [gcmBlockSize]byte

	for len(in) >= gcmBlockSize {
		g.cipher.Encrypt(mask[:], counter[:])
		counter.inc()

		subtle.XORBytes(out, in, mask[:])
		out = out[gcmBlockSize:]
		in = in[gcmBlockSize:]
	}

	if len(in) > 0 {
		g.cipher.Encrypt(mask[:], counter[:])
		counter.inc()
		subtle.XORBytes(out, in, mask[:])
	}
}

// Seal encrypts and authenticates plaintext. See the cipher.AEAD interface for
// details.
func (g *gcm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize()) {
		panic("crypto/cipher: message too large for GCM")
	}

	ret, out := alias.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if alias.InexactOverlap(out[:len(plaintext)], plaintext) {
		panic("crypto/cipher: invalid buffer overlap")
	}

	counter := g.deriveCounter(nonce)

	var tagMask [gcmBlockSize]byte
	g.cipher.Encrypt(tagMask[:], counter[:])
	counter.inc()

	var tagOut [gcmTagSize]byte
	g.counterCrypt(out, plaintext, &counter)
	g.auth(tagOut[:], out[:len(plaintext)], data, &tagMask)
	copy(out[len(plaintext):], tagOut[:])

	return ret
}

// Open authenticates and decrypts ciphertext. See the cipher.AEAD interface
// for details.
func (g *gcm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if g.tagSize < gcmMinimumTagSize {
		panic("crypto/cipher: incorrect GCM tag size")
	}
	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize())+uint64(g.tagSize) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	counter := g.deriveCounter(nonce)

	var tagMask [gcmBlockSize]byte
	g.cipher.Encrypt(tagMask[:], counter[:])
	counter.inc()

	var expectedTag [gcmTagSize]byte
	g.auth(expectedTag[:], ciphertext, data, &tagMask)

	ret, out := alias.SliceForAppend(dst, len(ciphertext))
	if alias.InexactOverlap(out, ciphertext) {
		panic("crypto/cipher: invalid buffer overlap")
	}

	if _subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		// The AESNI code decrypts and authenticates concurrently, and
		// so overwrites dst in the event of a tag mismatch. That
		// behavior is mimicked here in order to be consistent across
		// platforms.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	g.counterCrypt(out, ciphertext, &counter)
	return ret, nil
}
