// Package sm3 implements ShangMi(SM) sm3 hash algorithm.
package sm3

// [GM/T] SM3 GB/T 32905-2016

import (
	"errors"
	"hash"

	"github.com/emmansun/gmsm/internal/byteorder"
)

// Size the size of a SM3 checksum in bytes.
const Size = 32

// SizeBitSize the bit size of Size.
const SizeBitSize = 5

// BlockSize the blocksize of SM3 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x7380166f
	init1 = 0x4914b2b9
	init2 = 0x172442d7
	init3 = 0xda8a0600
	init4 = 0xa96f30bc
	init5 = 0x163138aa
	init6 = 0xe38dee4d
	init7 = 0xb0fb0e4e
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "sm3\x03"
	marshaledSize = len(magic) + 8*4 + chunk + 8
)

func (d *digest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, marshaledSize))
}

func (d *digest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, magic...)
	b = byteorder.BEAppendUint32(b, d.h[0])
	b = byteorder.BEAppendUint32(b, d.h[1])
	b = byteorder.BEAppendUint32(b, d.h[2])
	b = byteorder.BEAppendUint32(b, d.h[3])
	b = byteorder.BEAppendUint32(b, d.h[4])
	b = byteorder.BEAppendUint32(b, d.h[5])
	b = byteorder.BEAppendUint32(b, d.h[6])
	b = byteorder.BEAppendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = append(b, make([]byte, len(d.x)-d.nx)...)
	b = byteorder.BEAppendUint64(b, d.len)
	return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
		return errors.New("sm3: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("sm3: invalid hash state size")
	}
	b = b[len(magic):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	b, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], byteorder.BEUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], byteorder.BEUint32(b)
}

// New returns a new hash.Hash computing the SM3 checksum. The Hash
// also implements encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler to marshal and unmarshal the internal
// state of the hash.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Sum appends the current hash to in and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}
	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	byteorder.BEPutUint64(padlen[t:], len)
	d.Write(padlen)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	byteorder.BEPutUint32(digest[0:], d.h[0])
	byteorder.BEPutUint32(digest[4:], d.h[1])
	byteorder.BEPutUint32(digest[8:], d.h[2])
	byteorder.BEPutUint32(digest[12:], d.h[3])
	byteorder.BEPutUint32(digest[16:], d.h[4])
	byteorder.BEPutUint32(digest[20:], d.h[5])
	byteorder.BEPutUint32(digest[24:], d.h[6])
	byteorder.BEPutUint32(digest[28:], d.h[7])

	return digest
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int { return BlockSize }

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

// Kdf key derivation function using SM3, compliance with GB/T 32918.4-2016 5.4.3.
func (baseMD *digest) Kdf(z []byte, keyLen int) []byte {
	limit := uint64(keyLen+Size-1) / uint64(Size)
	if limit >= uint64(1<<32)-1 {
		panic("sm3: key length too long")
	}
	baseMD.Reset()
	baseMD.Write(z)
	return kdf(baseMD, keyLen, int(limit))
}

func kdfGeneric(baseMD *digest, keyLen int, limit int) []byte {
	var countBytes [4]byte
	var ct uint32 = 1
	k := make([]byte, keyLen)
	for i := 0; i < limit; i++ {
		byteorder.BEPutUint32(countBytes[:], ct)
		md := *baseMD
		md.Write(countBytes[:])
		h := md.checkSum()
		copy(k[i*Size:], h[:])
		ct++
	}
	return k
}

func Kdf(z []byte, keyLen int) []byte {
	baseMD := new(digest)
	return baseMD.Kdf(z, keyLen)
}
