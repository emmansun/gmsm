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

// hctrFieldElement represents a value in GF(2¹²⁸). In order to reflect the HCTR
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//   the coefficient of x⁰ can be obtained by v.low >> 63.
//   the coefficient of x⁶³ can be obtained by v.low & 1.
//   the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//   the coefficient of x¹²⁷ can be obtained by v.high & 1.
type hctrFieldElement struct {
	low, high uint64
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// hctrAdd adds two elements of GF(2¹²⁸) and returns the sum.
func hctrAdd(x, y *hctrFieldElement) hctrFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return hctrFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// hctrDouble returns the result of doubling an element of GF(2¹²⁸).
func hctrDouble(x *hctrFieldElement) (double hctrFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

var hctrReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// hctr represents a Varaible-Input-Length enciphering mode with a specific block cipher,
// and specific tweak and a hash key. See
// https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288
// GB/T 17964-2021 第11章 带泛杂凑函数的计数器工作模式
type hctr struct {
	cipher _cipher.Block
	tweak  [blockSize]byte
	// productTable contains the first sixteen powers of the hash key.
	// However, they are in bit reversed order.
	productTable [16]hctrFieldElement
}

// NewHCTR returns a [LengthPreservingMode] which encrypts/decrypts useing the given [Block]
// in HCTR mode. The lenght of tweak and hash key must be the same as the [Block]'s block size.
func NewHCTR(cipher _cipher.Block, tweak, hkey []byte) (LengthPreservingMode, error) {
	if len(tweak) != blockSize || len(hkey) != blockSize {
		return nil, errors.New("hctr: invalid tweak and/or hash key length")
	}
	c := &hctr{}
	c.cipher = cipher
	copy(c.tweak[:], tweak)
	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := hctrFieldElement{
		binary.BigEndian.Uint64(hkey[:8]),
		binary.BigEndian.Uint64(hkey[8:blockSize]),
	}
	c.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		c.productTable[reverseBits(i)] = hctrDouble(&c.productTable[reverseBits(i/2)])
		c.productTable[reverseBits(i+1)] = hctrAdd(&c.productTable[reverseBits(i)], &x)
	}
	return c, nil
}

// mul sets y to y*H, where H is the GCM key, fixed during NewHCTR.
func (h *hctr) mul(y *hctrFieldElement) {
	var z hctrFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of hash key.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(hctrReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &h.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

func (h *hctr) updateBlock(block []byte, y *hctrFieldElement) {
	y.low ^= binary.BigEndian.Uint64(block)
	y.high ^= binary.BigEndian.Uint64(block[8:blockSize])
	h.mul(y)	
}

// Universal Hash Function.
// Chapter 3.3 in https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.470.5288.
func (h *hctr) uhash(m []byte, out *[blockSize]byte) {
	var y hctrFieldElement
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
	binary.BigEndian.PutUint64(out[:], y.low)
	binary.BigEndian.PutUint64(out[8:], y.high)
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
