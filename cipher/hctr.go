package cipher

import (
	_cipher "crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
)

// A LengthPreservingMode represents a block cipher running in a length preserving mode (HCTR,
// HCTR2 etc).
type LengthPreservingMode interface {
	// Encrypt encrypts a number of plaintext bytes. The length of
	// src must be NOT smaller than block size. Dst and src must overlap
	// entirely or not at all.
	//
	// If len(dst) < len(src), Encrypt should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, Encrypt will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to Encrypt behave NOT same as if the concatenation of
	// the src buffers was passed in a single run.
	Encrypt(dst, src []byte)

	// Decrypt decrypts a number of ciphertext bytes. The length of
	// src must be NOT smaller than block size. Dst and src must overlap
	// entirely or not at all.
	//
	// If len(dst) < len(src), Decrypt should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, Decrypt will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to Decrypt behave NOT same as if the concatenation of
	// the src buffers was passed in a single run.
	Decrypt(dst, src []byte)
}

// hctr represents a Varaible-Input-Length enciphering mode with a specific block cipher,
// and specific tweak and a hash key. See
// https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288
// GB/T 17964-2021 第11章 带泛杂凑函数的计数器工作模式
type hctr struct {
	cipher _cipher.Block
	tweak  [blockSize]byte
	hkey   [blockSize]byte
}

// NewHCTR returns a [LengthPreservingMode] which encrypts/decrypts useing the given [Block]
// in HCTR mode. The lenght of tweak and hash key must be the same as the [Block]'s block size.
func NewHCTR(cipher _cipher.Block, tweak, hkey []byte) (LengthPreservingMode, error) {
	if len(tweak) != blockSize || len(hkey) != blockSize {
		return nil, errors.New("hctr: invalid tweak and/or hash key length")
	}
	c := &hctr{}
	c.cipher = cipher
	copy(c.hkey[:], hkey)
	copy(c.tweak[:], tweak)
	return c, nil
}

func _mul2(v *[blockSize]byte) {
	var carryIn byte
	for j := range v {
		carryOut := (v[j] << 7) & 0x80
		v[j] = (v[j] >> 1) + carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		v[0] ^= 0xE1 //  1<<7 | 1<<6 | 1<<5 | 1
	}
}

// mul sets y to y*hkey.
func (h *hctr) mul(y *[blockSize]byte) {
	var z [blockSize]byte
	for _, i := range h.hkey {
		for k := 0; k < 8; k++ {
			if (i>>(7-k))&1 == 1 {
				subtle.XORBytes(z[:], z[:], y[:])
			}
			_mul2(y)
		}
	}
	copy(y[:], z[:])
}

// Universal Hash Function.
// Chapter 3.3 in https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288.
func (h *hctr) uhash(m []byte, dst *[blockSize]byte) {
	for k := 0; k < blockSize; k++ {
		dst[k] = 0
	}
	msg := m
	for len(msg) >= blockSize {
		subtle.XORBytes(dst[:], dst[:], msg[:blockSize])
		h.mul(dst)
		msg = msg[blockSize:]
	}
	var v [blockSize]byte
	if len(msg) > 0 {
		copy(v[:], msg)
		copy(v[len(msg):], h.tweak[:])
		subtle.XORBytes(dst[:], dst[:], v[:])
		h.mul(dst)
		copy(v[:], h.tweak[len(msg):])
		for i := len(msg); i < blockSize; i++ {
			v[i] = 0
		}
		subtle.XORBytes(dst[:], dst[:], v[:])
		h.mul(dst)
		for i := 0; i < len(msg); i++ {
			v[i] = 0
		}
	} else {
		subtle.XORBytes(dst[:], dst[:], h.tweak[:])
		h.mul(dst)
	}
	// (|M|)₂
	binary.BigEndian.PutUint64(v[8:], uint64(len(m)+blockSize)<<3)
	subtle.XORBytes(dst[:], dst[:], v[:])
	h.mul(dst)
}

func (h *hctr) Encrypt(ciphertext, plaintext []byte) {
	if len(ciphertext) < len(plaintext) {
		panic("hctr: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("hctr: plaintext length is smaller than the block size")
	}
	if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("hctr: invalid buffer overlap")
	}

	var z1, z2 [blockSize]byte

	// a) z1 generation
	h.uhash(plaintext[blockSize:], &z1)
	subtle.XORBytes(z1[:], z1[:], plaintext[:blockSize])
	// b) z2 generation
	h.cipher.Encrypt(z2[:], z1[:])
	// c) CTR
	subtle.XORBytes(z1[:], z1[:], z2[:])
	h.ctr(ciphertext[blockSize:], plaintext[blockSize:], &z1)
	// d) first ciphertext block generation
	h.uhash(ciphertext[blockSize:], &z1)
	subtle.XORBytes(ciphertext, z2[:], z1[:])
}

func (h *hctr) Decrypt(plaintext, ciphertext []byte) {
	if len(plaintext) < len(ciphertext) {
		panic("hctr: plaintext is smaller than cihpertext")
	}
	if len(ciphertext) < blockSize {
		panic("hctr: ciphertext length is smaller than the block size")
	}
	if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("hctr: invalid buffer overlap")
	}

	var z1, z2 [blockSize]byte

	// a) z2 generation
	h.uhash(ciphertext[blockSize:], &z2)
	subtle.XORBytes(z2[:], z2[:], ciphertext[:blockSize])
	// b) z1 generation
	h.cipher.Decrypt(z1[:], z2[:])
	// c) CTR
	subtle.XORBytes(z2[:], z2[:], z1[:])
	h.ctr(plaintext[blockSize:], ciphertext[blockSize:], &z2)
	// d) first plaintext block generation
	h.uhash(plaintext[blockSize:], &z2)
	subtle.XORBytes(plaintext, z2[:], z1[:])
}

func (h *hctr) ctr(dst, src []byte, baseCtr *[blockSize]byte) {
	ctr := make([]byte, blockSize)
	num := make([]byte, blockSize)
	i := uint64(1)

	if concCipher, ok := h.cipher.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		if len(src) >= batchSize {
			var ctrs []byte = make([]byte, batchSize)
			for len(src) >= batchSize {
				for j := 0; j < concCipher.Concurrency(); j++ {
					// (i)₂
					binary.BigEndian.PutUint64(num[blockSize-8:], i)
					subtle.XORBytes(ctrs[j*blockSize:], baseCtr[:], num)
					i++
				}
				concCipher.EncryptBlocks(ctrs, ctrs)
				subtle.XORBytes(dst, src, ctrs)
				src = src[batchSize:]
				dst = dst[batchSize:]
			}
		}
	}

	for len(src) > 0 {
		// (i)₂
		binary.BigEndian.PutUint64(num[blockSize-8:], i)
		subtle.XORBytes(ctr, baseCtr[:], num)
		h.cipher.Encrypt(ctr, ctr)
		n := subtle.XORBytes(dst, src, ctr)
		src = src[n:]
		dst = dst[n:]
		i++
	}
}
