// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/byteorder"
)

// GCM-SIV uses POLYVAL rather than GHASH. They differ in two ways:
// 1) Different field polynomials: POLYVAL uses x^128+x^127+x^126+x^121+1,
//    while GHASH uses x^128+x^7+x^2+x+1.
// 2) Different bit/byte interpretation of blocks.
//
// Per RFC 8452 Appendix A, POLYVAL can be implemented via GHASH by applying
// a byte-reversal mapping plus a multiply-by-x key transform. This file uses
// that mapping so we can reuse the GHASH-style multiply core.

const (
	gcmSIVBlockSize = 16
	gcmSIVNonceSize = 12
	gcmSIVTagSize   = 16
	gcmSIVMaxBytes  = 1 << 36
)

// enough for 8 blocks per batch, which is the max concurrency of any supported architecture
const maxConcurrency = 8

var (
	errInvalidBlockSize = errors.New("cipher: GCMSIV requires a 128-bit block cipher")
	errOpenFailed       = errors.New("cipher: message authentication failed")
)

type concurrentBlocks interface {
	Concurrency() int
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

type gcmsiv struct {
	newBlock func([]byte) (cipher.Block, error)
	key      []byte
	keyBlock cipher.Block
}

type ghashFieldElement struct {
	low, high uint64
}

type gcmSIVAble interface {
	NewGCMSIV(newBlock func([]byte) (cipher.Block, error), key []byte) (cipher.AEAD, error)
}

// NewGCMSIV returns an AEAD using the GCM-SIV construction.
// key is the key-generating key and newBlock creates a block cipher from raw key bytes.
func NewGCMSIV(newBlock func([]byte) (cipher.Block, error), key []byte) (cipher.AEAD, error) {
	if newBlock == nil {
		return nil, errors.New("cipher: nil block constructor")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("cipher: incorrect key length for GCMSIV")
	}
	keyBlock, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if keyBlock.BlockSize() != gcmSIVBlockSize {
		return nil, errInvalidBlockSize
	}
	if capable, ok := keyBlock.(gcmSIVAble); ok {
		return capable.NewGCMSIV(newBlock, append([]byte(nil), key...))
	}
	return &gcmsiv{newBlock: newBlock, key: append([]byte(nil), key...), keyBlock: keyBlock}, nil
}

func (g *gcmsiv) NonceSize() int { return gcmSIVNonceSize }

func (g *gcmsiv) Overhead() int { return gcmSIVTagSize }

func (g *gcmsiv) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmSIVNonceSize {
		panic("cipher: incorrect nonce length given to GCMSIV")
	}
	if uint64(len(plaintext)) > uint64(gcmSIVMaxBytes) {
		panic("cipher: message too large for GCMSIV")
	}
	if uint64(len(additionalData)) > uint64(gcmSIVMaxBytes) {
		panic("cipher: additional data too large for GCMSIV")
	}

	authKey, encKey := g.deriveMessageKeys(nonce)
	encBlock, err := g.newBlock(encKey)
	if err != nil {
		panic(err)
	}
	tag := g.computeTag(authKey, encBlock, nonce, additionalData, plaintext)

	ret, out := alias.SliceForAppend(dst, len(plaintext)+gcmSIVTagSize)
	if alias.InexactOverlap(out[:len(plaintext)], plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	if len(plaintext) > 0 {
		g.ctrXOR(encBlock, out[:len(plaintext)], plaintext, tag)
	}
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (g *gcmsiv) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmSIVNonceSize {
		panic("cipher: incorrect nonce length given to GCMSIV")
	}
	if len(ciphertext) < gcmSIVTagSize || uint64(len(ciphertext)) > uint64(gcmSIVMaxBytes+gcmSIVTagSize) {
		return nil, errOpenFailed
	}
	if uint64(len(additionalData)) > uint64(gcmSIVMaxBytes) {
		return nil, errOpenFailed
	}

	encrypted := ciphertext[:len(ciphertext)-gcmSIVTagSize]
	if uint64(len(encrypted)) > uint64(gcmSIVMaxBytes) {
		return nil, errOpenFailed
	}

	var tag [gcmSIVTagSize]byte
	copy(tag[:], ciphertext[len(ciphertext)-gcmSIVTagSize:])

	authKey, encKey := g.deriveMessageKeys(nonce)
	encBlock, err := g.newBlock(encKey)
	if err != nil {
		return nil, err
	}

	ret, out := alias.SliceForAppend(dst, len(encrypted))
	if alias.InexactOverlap(out, encrypted) {
		panic("cipher: invalid buffer overlap")
	}

	if len(encrypted) > 0 {
		g.ctrXOR(encBlock, out, encrypted, tag)
	}

	expected := g.computeTag(authKey, encBlock, nonce, additionalData, out)
	if subtle.ConstantTimeCompare(expected[:], tag[:]) != 1 {
		clear(out)
		return nil, errOpenFailed
	}
	return ret, nil
}

func (g *gcmsiv) deriveMessageKeys(nonce []byte) (authKey [16]byte, encKey []byte) {
	// RFC 8452 derives per-message keys from counter||nonce blocks, using the
	// first 8 bytes of each encrypted block.
	blocks := 4
	encKeyLen := 16
	if len(g.key) == 32 {
		blocks = 6
		encKeyLen = 32
	}
	encKey = make([]byte, encKeyLen)
	if capable, ok := g.keyBlock.(concurrentBlocks); ok {
		// WARNING: This implementation assumes Concurrency() returns a power-of-2 value
		// (typically 4 or 8). The batch logic below extracts blocks at fixed offsets that
		// may not align if Concurrency() deviates from expected values. For 256-bit keys
		// (blocks=6), only a second EncryptBlocks call occurs if Concurrency()==4.
		// Future implementations that return other Concurrency() values should audit this
		// logic to ensure all derived key material is correctly extracted.
		var counters [maxConcurrency * gcmSIVBlockSize]byte
		var mask [maxConcurrency * gcmSIVBlockSize]byte

		for i := 0; i < blocks; i++ {
			off := i * gcmSIVBlockSize
			byteorder.LEPutUint32(counters[off:], uint32(i))
			copy(counters[off+4:off+4+gcmSIVNonceSize], nonce)
		}
		concurrentBlocks := capable.Concurrency()
		capable.EncryptBlocks(mask[:concurrentBlocks*gcmSIVBlockSize], counters[:concurrentBlocks*gcmSIVBlockSize])
		copy(authKey[:8], mask[:8])
		copy(authKey[8:], mask[16:16+8])
		copy(encKey, mask[32:32+8])
		copy(encKey[8:], mask[48:48+8])
		if blocks == 6 {
			if concurrentBlocks == 4 {
				capable.EncryptBlocks(mask[4*gcmSIVBlockSize:maxConcurrency*gcmSIVBlockSize], counters[4*gcmSIVBlockSize:maxConcurrency*gcmSIVBlockSize])
			}
			copy(encKey[16:], mask[64:64+8])
			copy(encKey[24:], mask[80:80+8])
		}
		return authKey, encKey
	}

	var in [16]byte
	for i := 0; i < blocks; i++ {
		byteorder.LEPutUint32(in[:4], uint32(i))
		copy(in[4:], nonce)
		var out [16]byte
		g.keyBlock.Encrypt(out[:], in[:])

		switch i {
		case 0:
			copy(authKey[:8], out[:8])
		case 1:
			copy(authKey[8:], out[:8])
		default:
			off := (i - 2) * 8
			copy(encKey[off:off+8], out[:8])
		}
	}
	return authKey, encKey
}

func (g *gcmsiv) computeTag(authKey [16]byte, encBlock cipher.Block, nonce, additionalData, plaintext []byte) (tag [16]byte) {
	// POLYVAL authenticates padded AAD and plaintext plus the bit-length block.
	var lengthBlock [16]byte
	byteorder.LEPutUint64(lengthBlock[:8], uint64(len(additionalData))*8)
	byteorder.LEPutUint64(lengthBlock[8:], uint64(len(plaintext))*8)

	// computePolyval is implemented per-architecture; falls back to generic.
	s := computePolyval(authKey, additionalData, plaintext, lengthBlock)
	subtle.XORBytes(s[:gcmSIVNonceSize], s[:gcmSIVNonceSize], nonce)
	s[15] &= 0x7f
	encBlock.Encrypt(tag[:], s[:])
	return tag
}

// computePolyvalGeneric is the pure-Go POLYVAL implementation used on all
// architectures that lack a hardware CLMUL path.
func computePolyvalGeneric(authKey [16]byte, aad, plaintext []byte, lengthBlock [16]byte) (s [16]byte) {
	table := initPolyvalTable(authKey[:])
	var y ghashFieldElement
	polyvalUpdatePadded(&table, &y, aad)
	polyvalUpdatePadded(&table, &y, plaintext)
	polyvalUpdateBlocks(&table, &y, lengthBlock[:])
	return finalizePolyval(y)
}

func (g *gcmsiv) ctrXOR(block cipher.Block, dst, src []byte, tag [16]byte) {
	// Counter mode starts from tag|0x80 and increments the low 32 bits in
	// little-endian order, matching RFC 8452.
	tag[15] |= 0x80

	if capable, ok := block.(concurrentBlocks); ok {
		blocksSize := capable.Concurrency() * gcmSIVBlockSize
		var counters [maxConcurrency * gcmSIVBlockSize]byte
		var mask [maxConcurrency * gcmSIVBlockSize]byte

		for len(src) >= blocksSize {
			for i := 0; i < capable.Concurrency(); i++ {
				off := i * gcmSIVBlockSize
				copy(counters[off:off+gcmSIVBlockSize], tag[:])
				gcmsivInc32(&tag)
			}
			capable.EncryptBlocks(mask[:blocksSize], counters[:blocksSize])
			subtle.XORBytes(dst[:blocksSize], src[:blocksSize], mask[:blocksSize])
			src = src[blocksSize:]
			dst = dst[blocksSize:]
		}
	}

	var stream [gcmSIVBlockSize]byte
	for len(src) > 0 {
		block.Encrypt(stream[:], tag[:])
		todo := min(len(src), gcmSIVBlockSize)
		subtle.XORBytes(dst, src[:todo], stream[:])

		gcmsivInc32(&tag)

		src = src[todo:]
		dst = dst[todo:]
	}
}

func gcmsivInc32(counterBlock *[gcmSIVBlockSize]byte) {
	ctr := byteorder.LEUint32(counterBlock[:4])
	byteorder.LEPutUint32(counterBlock[:4], ctr+1)
}

func initPolyvalTable(h []byte) [16]ghashFieldElement {
	var hBlock [16]byte
	copy(hBlock[:], h)
	var hReversed [16]byte
	byteReverse16(&hReversed, &hBlock)
	hGHASH := ghashMulX(hReversed)

	var table [16]ghashFieldElement
	x := ghashFieldElement{low: byteorder.BEUint64(hGHASH[:8]), high: byteorder.BEUint64(hGHASH[8:])}
	table[8] = x
	for j := 4; j > 0; j /= 2 {
		table[j] = ghashDouble(&table[j*2])
	}
	for j := 2; j < 16; j *= 2 {
		for k := 1; k < j; k++ {
			table[j+k] = ghashAdd(&table[j], &table[k])
		}
	}
	return table
}

// finalizePolyval converts the accumulated GHASH-mapped state back to
// POLYVAL byte representation via a final byte-reversal.
func finalizePolyval(y ghashFieldElement) [16]byte {
	var reversed [16]byte
	byteorder.LEPutUint64(reversed[:8], y.high)
	byteorder.LEPutUint64(reversed[8:], y.low)
	return reversed
}

func polyvalUpdateBlocks(productTable *[16]ghashFieldElement, y *ghashFieldElement, blocks []byte) {
	for len(blocks) >= 16 {
		polyvalUpdateBlock(productTable, y, (*[16]byte)(blocks[:16]))
		blocks = blocks[16:]
	}
}

func polyvalUpdatePadded(productTable *[16]ghashFieldElement, y *ghashFieldElement, in []byte) {
	polyvalUpdateBlocks(productTable, y, in)
	if rem := len(in) % 16; rem != 0 {
		var block [16]byte
		copy(block[:], in[len(in)-rem:])
		polyvalUpdateBlock(productTable, y, &block)
	}
}

func polyvalUpdateBlock(productTable *[16]ghashFieldElement, y *ghashFieldElement, block *[16]byte) {
	var reversed [16]byte
	byteReverse16(&reversed, block)
	ghashUpdateBlock(productTable, y, &reversed)
}

func byteReverse16(out, in *[16]byte) {
	for i := 0; i < 16; i++ {
		out[i] = in[15-i]
	}
}

// ghashMulX multiplies a GHASH field element by x.
//
// Why this is just ghashDouble:
//  1. GHASH (SP 800-38D) uses the polynomial x^128 + x^7 + x^2 + x + 1,
//     with bit ordering that makes multiply-by-x equivalent to a 1-bit
//     right shift of the 128-bit value.
//  2. If the shifted-out bit is 1, reduction by the polynomial adds the
//     constant R = 0xe1 << 120. In the split (low, high) representation used
//     here, that appears as XOR with 0xe100000000000000 into low after shift.
//  3. ghashDouble performs exactly this shift+conditional-reduction step,
//     so ghashMulX(h) == ghashDouble(h) in this representation.
func ghashMulX(h [16]byte) [16]byte {
	x := ghashFieldElement{low: byteorder.BEUint64(h[:8]), high: byteorder.BEUint64(h[8:])}
	x2 := ghashDouble(&x)
	var out [16]byte
	byteorder.BEPutUint64(out[:8], x2.low)
	byteorder.BEPutUint64(out[8:], x2.high)
	return out
}

func ghashAdd(x, y *ghashFieldElement) ghashFieldElement {
	return ghashFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// ghashDouble is one multiply-by-x step in GHASH representation.
func ghashDouble(x *ghashFieldElement) (double ghashFieldElement) {
	msbSet := x.high&1 == 1
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1
	if msbSet {
		double.low ^= 0xe100000000000000
	}
	return
}

var ghashReductionTable = [16]uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

func ghashMul(productTable *[16]ghashFieldElement, y *ghashFieldElement) {
	var z ghashFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(ghashReductionTable[msw]) << 48

			t := &productTable[word&0xf]
			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}
	*y = z
}

func ghashUpdateBlock(productTable *[16]ghashFieldElement, y *ghashFieldElement, block *[16]byte) {
	y.low ^= byteorder.BEUint64(block[:8])
	y.high ^= byteorder.BEUint64(block[8:])
	ghashMul(productTable, y)
}
