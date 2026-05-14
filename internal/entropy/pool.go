// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import "github.com/emmansun/gmsm/internal/byteorder"

// entropyPool implements a twisted GFSR (Generalized Feedback Shift Register)
// based entropy pool per GM/T 0105-2021 Section 5.3 and Appendix A.3.
//
// The pool is an array of 128 × 32-bit words (512 bytes). Entropy is mixed in
// one word at a time using the primitive polynomial x¹²⁸+x¹⁰³+x⁷⁶+x⁵¹+x²⁵+x+1,
// which defines the tap positions for the feedback shift register. A twist
// operation based on the CRC-32 polynomial provides additional nonlinear mixing.
//
// On extraction, the full pool is compressed via SM3-based Hash_df (SM3_df per
// Appendix B) and the compressed output is fed back for forward secrecy.
type entropyPool struct {
	data    [poolWords]uint32
	pos     int // current word index (0 to poolWords-1)
	entropy int // estimated accumulated entropy in bits
}

const (
	// poolWords is the entropy pool size in 32-bit words.
	// Based on the primitive polynomial x¹²⁸+x¹⁰³+x⁷⁶+x⁵¹+x²⁵+x+1
	// per GM/T 0105-2021 Appendix A.3.
	poolWords = 128

	// poolBytes is the entropy pool size in bytes (512 bytes).
	poolBytes = poolWords * 4

	// minEntropyBits is the minimum entropy (in bits) required before
	// extraction, per GM/T 0105-2021 Section 5.3.
	minEntropyBits = 256
)

// twistTable is the twist table for the GFSR pool update, based on the
// CRC-32 polynomial per GM/T 0105-2021 Appendix A.3.
var twistTable = [8]uint32{
	0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
	0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278,
}

// addWord mixes a single 32-bit word g into the pool using the twisted GFSR
// update per GM/T 0105-2021 Appendix A.3:
//
//	temp = g ^ pool[j] ^ pool[(j+1)%N] ^ pool[(j+25)%N]
//	         ^ pool[(j+51)%N] ^ pool[(j+76)%N] ^ pool[(j+103)%N]
//	pool[j] = (temp >> 3) ^ twistTable[temp & 7]
//
// The tap positions {0, 1, 25, 51, 76, 103} are derived from the primitive
// polynomial x¹²⁸+x¹⁰³+x⁷⁶+x⁵¹+x²⁵+x+1.
//
// Since poolWords = 128 = 2^7, all modulo operations are replaced by
// bitwise AND with the mask (poolWords-1) = 127, which is equivalent and
// avoids division instructions.
func (p *entropyPool) addWord(g uint32) {
	j := p.pos
	temp := g ^
		p.data[j] ^
		p.data[(j+1)&(poolWords-1)] ^
		p.data[(j+25)&(poolWords-1)] ^
		p.data[(j+51)&(poolWords-1)] ^
		p.data[(j+76)&(poolWords-1)] ^
		p.data[(j+103)&(poolWords-1)]

	p.data[j] = (temp >> 3) ^ twistTable[temp&7]
	p.pos = (j + 1) & (poolWords - 1)
}

// add mixes input bytes into the pool. Input is processed in 32-bit big-endian
// words four at a time (loop unrolled) to improve instruction-level parallelism.
// Remaining bytes (< 4) are zero-padded into a final word.
// entropyBits is the estimated number of entropy bits in the input.
func (p *entropyPool) add(input []byte, entropyBits int) {
	// Process four words at a time for better throughput.
	for len(input) >= 16 {
		p.addWord(byteorder.BEUint32(input[0:]))
		p.addWord(byteorder.BEUint32(input[4:]))
		p.addWord(byteorder.BEUint32(input[8:]))
		p.addWord(byteorder.BEUint32(input[12:]))
		input = input[16:]
	}
	// Process remaining whole words.
	for len(input) >= 4 {
		p.addWord(byteorder.BEUint32(input))
		input = input[4:]
	}
	// Zero-pad and process the final partial word, if any.
	if len(input) > 0 {
		var buf [4]byte
		copy(buf[:], input)
		p.addWord(byteorder.BEUint32(buf[:]))
	}

	p.entropy += entropyBits
	if p.entropy > poolBytes*8 {
		p.entropy = poolBytes * 8
	}
}

// extract compresses the entire pool via SM3_df (Hash_df with SM3),
// feeds the result back into the pool for forward secrecy, and returns
// the compressed seed. The entropy estimate is reset after extraction.
//
// Panics if insufficient entropy has been accumulated (p.entropy < minEntropyBits).
func (p *entropyPool) extract() [SeedSize]byte {
	if p.entropy < minEntropyBits {
		panic("entropy: insufficient entropy in pool for extraction")
	}

	// Serialize pool words to bytes for Hash_df input.
	var poolData [poolBytes]byte
	for i, w := range p.data {
		byteorder.BEPutUint32(poolData[i*4:], w)
	}

	// Compress pool data using SM3-based Hash_df.
	// Output is 440 bits (55 bytes = SeedSize) per GM/T 0105-2021 Appendix B.
	compressed := hashDf(poolData[:], SeedSize)

	var seed [SeedSize]byte
	copy(seed[:], compressed)

	// Feed compression result back into the pool for forward secrecy.
	// This ensures that knowledge of the current seed does not reveal
	// future seeds, as the pool state has been irreversibly modified.
	p.add(seed[:], 0)

	// Reset entropy estimate conservatively.
	p.entropy = 0

	return seed
}
