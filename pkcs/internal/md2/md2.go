// Package md2 implements the MD2 hash algorithm as defined in RFC 1319.
//
// MD2 is cryptographically broken and should not be used for secure
// applications.
package md2

import (
	"errors"
	"hash"

	"github.com/emmansun/gmsm/internal/byteorder"
)

// Size the size of a MD2 checksum in bytes.
const Size = 16

// SizeBitSize the bit size of Size.
const SizeBitSize = 4

// BlockSize the blocksize of MD2 in bytes.
const BlockSize = 16

var piSubst = [256]byte{
	0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
	0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
	0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
	0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
	0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
	0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
	0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
	0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
	0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
	0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
	0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
	0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
	0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
	0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
	0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
	0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
}

// digest represents the partial evaluation of a checksum.
type digest struct {
	s   [Size]byte      // state
	c   [BlockSize]byte // checksum
	x   [BlockSize]byte // buffer
	nx  int
	len uint64
}

func (d *digest) Reset() {
	for i := range d.s {
		d.s[i] = 0
	}
	for i := range d.c {
		d.c[i] = 0
	}
	d.nx = 0
	d.len = 0
}

const (
	magic         = "md2\x01"
	marshaledSize = len(magic) + Size + BlockSize*2 + 8
)

func (d *digest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, marshaledSize))
}

func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, magic...)
	b = append(b, d.s[:]...)
	b = append(b, d.c[:]...)
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-d.nx)...)
	b = appendUint64(b, d.len)
	return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
		return errors.New("md2: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("md2: invalid hash state size")
	}
	b = b[len(magic):]
	b = b[copy(d.s[:], b[:Size]):]
	b = b[copy(d.c[:], b[:BlockSize]):]
	b = b[copy(d.x[:], b):]
	b, d.len = consumeUint64(b)
	d.nx = int(d.len % BlockSize)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	byteorder.BEPutUint64(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

// New returns a new hash.Hash computing the MD2 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	// Pad out to multiple of BlockSize bytes.
	var tmp [BlockSize]byte
	padLen := BlockSize - d.nx
	for i := 0; i < padLen; i++ {
		tmp[i] = byte(padLen)
	}
	d.Write(tmp[:padLen])
	// The previous write ensures that a whole number of
	// blocks (i.e. a multiple of 16 bytes) have been hashed.
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	// Append the checksum
	d.Write(d.c[:])

	var digest [Size]byte
	copy(digest[:], d.s[:])
	return digest
}

func block(dig *digest, p []byte) {
	var X [48]byte
	for i := 0; i <= len(p)-BlockSize; i += BlockSize {
		// Form encryption block from state, block, and state ^ block.
		copy(X[:16], dig.s[:])
		copy(X[16:32], p[i:i+BlockSize])
		for j := 0; j < BlockSize; j++ {
			X[32+j] = X[16+j] ^ X[j]
		}

		// Encrypt block (18 rounds)
		t := byte(0)
		for j := 0; j < 18; j++ {
			for k := 0; k < 48; k++ {
				X[k] ^= piSubst[t]
				t = X[k]
			}
			t = t + byte(j)
		}

		// Save state
		copy(dig.s[:], X[:16])

		// Update checksum
		t = dig.c[15]
		for j := 0; j < 16; j++ {
			dig.c[j] ^= piSubst[p[i+j]^t]
			t = dig.c[j]
		}
	}
}

// Sum returns the MD2 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
