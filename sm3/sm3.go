// Package sm3 implements ShangMi(SM) sm3 hash algorithm.
package sm3

// [GM/T] SM3 GB/T 32905-2016

import (
	"hash"

	"github.com/emmansun/gmsm/internal/sm3"
)

// Size the size of a SM3 checksum in bytes.
const Size = 32

// BlockSize the blocksize of SM3 in bytes.
const BlockSize = 64

// New returns a new hash.Hash computing the SM3 checksum. The Hash
// also implements encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler to marshal and unmarshal the internal
// state of the hash.
func New() hash.Hash {
	return sm3.New()
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	h := New()
	h.Write(data)
	var sum [Size]byte
	h.Sum(sum[:0])
	return sum
}

func Kdf(z []byte, keyLen int) []byte {
	return sm3.Kdf(z, keyLen)
}
