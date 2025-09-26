package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
)

// A LengthPreservingMode represents a block cipher running in a length preserving mode (HCTR,
// HCTR2 etc).
type LengthPreservingMode interface {
	// EncryptBytes encrypts a number of plaintext bytes. The length of
	// src must be NOT smaller than block size. Dst and src must overlap
	// entirely or not at all.
	//
	// If len(dst) < len(src), EncryptBytes should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, Encrypt will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to EncryptBytes behave NOT same as if the concatenation of
	// the src buffers was passed in a single run.
	EncryptBytes(dst, src []byte)

	// DecryptBytes decrypts a number of ciphertext bytes. The length of
	// src must be NOT smaller than block size. Dst and src must overlap
	// entirely or not at all.
	//
	// If len(dst) < len(src), DecryptBytes should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, DecryptBytes will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to DecryptBytes behave NOT same as if the concatenation of
	// the src buffers was passed in a single run.
	DecryptBytes(dst, src []byte)

	// BlockSize returns the mode's block size.
	BlockSize() int
}

// hctr represents a Variable-Input-Length enciphering mode with a specific block cipher,
// and specific tweak and a hash key. See
// https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288
// GB/T 17964-2021 第11章 带泛杂凑函数的计数器工作模式
type hctr struct {
	cipher cipher.Block
	tweak  [blockSize]byte
	// productTable contains the first sixteen powers of the hash key.
	// However, they are in bit reversed order.
	productTable [16]ghashFieldElement
}

func (h *hctr) BlockSize() int {
	return blockSize
}

// NewHCTR returns a [LengthPreservingMode] which encrypts/decrypts using the given [Block]
// in HCTR mode. The length of tweak and hash key must be the same as the [Block]'s block size.
func NewHCTR(cipher cipher.Block, tweak, hkey []byte) (LengthPreservingMode, error) {
	if len(tweak) != blockSize || len(hkey) != blockSize {
		return nil, errors.New("cipher: invalid tweak and/or hash key length")
	}
	c := &hctr{}
	c.cipher = cipher
	copy(c.tweak[:], tweak)
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
	return c, nil
}

// mul sets y to y*H, where H is the GCM key, fixed during NewHCTR.
func (h *hctr) mul(y *ghashFieldElement) {
	ghashMul(&h.productTable, y)
}

func (h *hctr) updateBlock(block []byte, y *ghashFieldElement) {
	y.low ^= byteorder.BEUint64(block)
	y.high ^= byteorder.BEUint64(block[8:])
	h.mul(y)
}

// Universal Hash Function.
// Chapter 3.3 in https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288.
func (h *hctr) uhash(m []byte, out *[blockSize]byte) {
	var y ghashFieldElement
	msg := m
	// update blocks
	for len(msg) >= blockSize {
		h.updateBlock(msg, &y)
		msg = msg[blockSize:]
	}
	// update partial block & tweak
	if len(msg) > 0 {
		var partialBlock [blockSize]byte
		copy(partialBlock[:], msg)
		copy(partialBlock[len(msg):], h.tweak[:])
		h.updateBlock(partialBlock[:], &y)

		copy(partialBlock[:], h.tweak[len(msg):])
		for i := len(msg); i < blockSize; i++ {
			partialBlock[i] = 0
		}
		h.updateBlock(partialBlock[:], &y)
	} else {
		h.updateBlock(h.tweak[:], &y)
	}
	// update bit string length (|M|)₂
	y.high ^= uint64(len(m)+blockSize) * 8
	h.mul(&y)
	// output result
	byteorder.BEPutUint64(out[:], y.low)
	byteorder.BEPutUint64(out[8:], y.high)
}

func (h *hctr) EncryptBytes(ciphertext, plaintext []byte) {
	if len(ciphertext) < len(plaintext) {
		panic("cipher: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("cipher: plaintext length is smaller than the block size")
	}
	if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("cipher: invalid buffer overlap")
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

func (h *hctr) DecryptBytes(plaintext, ciphertext []byte) {
	if len(plaintext) < len(ciphertext) {
		panic("cipher: plaintext is smaller than cihpertext")
	}
	if len(ciphertext) < blockSize {
		panic("cipher: ciphertext length is smaller than the block size")
	}
	if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("cipher: invalid buffer overlap")
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
			var ctrs = make([]byte, batchSize)
			for len(src) >= batchSize {
				for j := 0; j < concCipher.Concurrency(); j++ {
					// (i)₂
					byteorder.BEPutUint64(num[blockSize-8:], i)
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
		byteorder.BEPutUint64(num[blockSize-8:], i)
		subtle.XORBytes(ctr, baseCtr[:], num)
		h.cipher.Encrypt(ctr, ctr)
		n := subtle.XORBytes(dst, src, ctr)
		src = src[n:]
		dst = dst[n:]
		i++
	}
}
