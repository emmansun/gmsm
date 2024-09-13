// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm4

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"runtime"

	"github.com/emmansun/gmsm/internal/alias"
)

// Assert that sm4CipherAsm implements the gcmAble interface.
var _ gcmAble = (*sm4CipherAsm)(nil)

var errOpen = errors.New("cipher: message authentication failed")

//go:noescape
func gcmInit(productTable *[256]byte, h []byte)

//go:noescape
func gcmHash(output []byte, productTable *[256]byte, inp []byte, len int)

//go:noescape
func gcmMul(output []byte, productTable *[256]byte)

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	gcmStandardNonceSize = 12
)

type gcmAsm struct {
	cipher    *sm4CipherAsm
	nonceSize int
	tagSize   int
	// productTable contains pre-computed multiples of the binary-field
	// element used in GHASH.
	productTable [256]byte
}

// NewGCM returns the AES cipher wrapped in Galois Counter Mode. This is only
// called by [crypto/cipher.NewGCM] via the gcmAble interface.
func (c *sm4CipherAsm) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	var h1, h2 uint64
	g := &gcmAsm{cipher: c, nonceSize: nonceSize, tagSize: tagSize}

	hle := make([]byte, gcmBlockSize)

	c.Encrypt(hle, hle)

	// Reverse the bytes in each 8 byte chunk
	// Load little endian, store big endian
	if runtime.GOARCH == "ppc64le" {
		h1 = binary.LittleEndian.Uint64(hle[:8])
		h2 = binary.LittleEndian.Uint64(hle[8:])
	} else {
		h1 = binary.BigEndian.Uint64(hle[:8])
		h2 = binary.BigEndian.Uint64(hle[8:])
	}
	binary.BigEndian.PutUint64(hle[:8], h1)
	binary.BigEndian.PutUint64(hle[8:], h2)
	gcmInit(&g.productTable, hle)

	return g, nil
}

func (g *gcmAsm) NonceSize() int {
	return g.nonceSize
}

func (g *gcmAsm) Overhead() int {
	return g.tagSize
}

// deriveCounter computes the initial GCM counter state from the given nonce.
func (g *gcmAsm) deriveCounter(counter *[gcmBlockSize]byte, nonce []byte) {
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
}

const fourBlocksSize = 64
const eightBlocksSize = fourBlocksSize * 2

// counterCrypt encrypts in using SM4 in counter mode and places the result
// into out. counter is the initial count value and will be updated with the next
// count value. The length of out must be greater than or equal to the length
// of in.
func (g *gcmAsm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	var mask [eightBlocksSize]byte
	var counters [eightBlocksSize]byte

	for len(in) >= eightBlocksSize {
		for i := 0; i < 8; i++ {
			copy(counters[i*gcmBlockSize:(i+1)*gcmBlockSize], counter[:])
			gcmInc32(counter)
		}
		g.cipher.EncryptBlocks(mask[:], counters[:])
		subtle.XORBytes(out, in, mask[:])
		out = out[eightBlocksSize:]
		in = in[eightBlocksSize:]
	}

	if len(in) >= fourBlocksSize {
		for i := 0; i < 4; i++ {
			copy(counters[i*gcmBlockSize:(i+1)*gcmBlockSize], counter[:])
			gcmInc32(counter)
		}
		g.cipher.EncryptBlocks(mask[:], counters[:])
		subtle.XORBytes(out, in, mask[:fourBlocksSize])
		out = out[fourBlocksSize:]
		in = in[fourBlocksSize:]
	}

	if len(in) > 0 {
		blocks := (len(in) + gcmBlockSize - 1) / gcmBlockSize
		if blocks > 1 {
			for i := 0; i < blocks; i++ {
				copy(counters[i*gcmBlockSize:], counter[:])
				gcmInc32(counter)
			}
			g.cipher.EncryptBlocks(mask[:], counters[:])
		} else {
			g.cipher.Encrypt(mask[:], counter[:])
			gcmInc32(counter)
		}
		subtle.XORBytes(out, in, mask[:blocks*gcmBlockSize])
	}
}

// increments the rightmost 32-bits of the count value by 1.
func gcmInc32(counterBlock *[16]byte) {
	c := counterBlock[len(counterBlock)-4:]
	x := binary.BigEndian.Uint32(c) + 1
	binary.BigEndian.PutUint32(c, x)
}

// paddedGHASH pads data with zeroes until its length is a multiple of
// 16-bytes. It then calculates a new value for hash using the ghash
// algorithm.
func (g *gcmAsm) paddedGHASH(hash *[16]byte, data []byte) {
	if siz := len(data) - (len(data) % gcmBlockSize); siz > 0 {
		gcmHash(hash[:], &g.productTable, data[:], siz)
		data = data[siz:]
	}
	if len(data) > 0 {
		var s [16]byte
		copy(s[:], data)
		gcmHash(hash[:], &g.productTable, s[:], len(s))
	}
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
func (g *gcmAsm) auth(out, ciphertext, aad []byte, tagMask *[gcmTagSize]byte) {
	var hash [16]byte
	g.paddedGHASH(&hash, aad)
	g.paddedGHASH(&hash, ciphertext)
	lens := gcmLengths(uint64(len(aad))*8, uint64(len(ciphertext))*8)
	g.paddedGHASH(&hash, lens[:])
	subtle.XORBytes(out, hash[:], tagMask[:])
}

// Seal encrypts and authenticates plaintext. See the [cipher.AEAD] interface for
// details.
func (g *gcmAsm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*BlockSize {
		panic("cipher: message too large for GCM")
	}

	ret, out := alias.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if alias.InexactOverlap(out[:len(plaintext)], plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)

	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	g.counterCrypt(out, plaintext, &counter)
	g.auth(out[len(plaintext):], out[:len(plaintext)], data, &tagMask)

	return ret
}

// Open authenticates and decrypts ciphertext. See the [cipher.AEAD] interface
// for details.
func (g *gcmAsm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(BlockSize)+uint64(g.tagSize) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)

	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	var expectedTag [gcmTagSize]byte
	g.auth(expectedTag[:], ciphertext, data, &tagMask)

	ret, out := alias.SliceForAppend(dst, len(ciphertext))
	if alias.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		// clear(out)
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	g.counterCrypt(out, ciphertext, &counter)
	return ret, nil
}

func gcmLengths(len0, len1 uint64) [16]byte {
	return [16]byte{
		byte(len0 >> 56),
		byte(len0 >> 48),
		byte(len0 >> 40),
		byte(len0 >> 32),
		byte(len0 >> 24),
		byte(len0 >> 16),
		byte(len0 >> 8),
		byte(len0),
		byte(len1 >> 56),
		byte(len1 >> 48),
		byte(len1 >> 40),
		byte(len1 >> 32),
		byte(len1 >> 24),
		byte(len1 >> 16),
		byte(len1 >> 8),
		byte(len1),
	}
}
