// Package zuc implements ShangMi(SM) zuc stream cipher and integrity algorithm.
package zuc

import (
	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/internal/zuc"
)

const (
	// IV size in bytes for zuc 128
	IVSize128 = 16
	// IV size in bytes for zuc 256
	IVSize256 = 23
	// number of words in a round
	RoundWords = 32
	// number of bytes in a word
	WordSize = 4
	WordMask = WordSize - 1
	// number of bytes in a round
	RoundBytes = RoundWords * WordSize
)

// NewCipher create a stream cipher based on key and iv aguments.
// The key must be 16 bytes long and iv must be 16 bytes long for zuc 128;
// or the key must be 32 bytes long and iv must be 23 bytes long for zuc 256;
// otherwise, an error will be returned.
func NewCipher(key, iv []byte) (cipher.SeekableStream, error) {
	return zuc.NewCipher(key, iv)
}

// NewEEACipher create a stream cipher based on key, count, bearer and direction arguments according specification.
// The key must be 16 bytes long and iv must be 16 bytes long, otherwise, an error will be returned.
// The count is the 32-bit counter value, the bearer is the 5-bit bearer identity and the direction is the 1-bit
// transmission direction flag.
func NewEEACipher(key []byte, count, bearer, direction uint32) (cipher.SeekableStream, error) {
	return zuc.NewEEACipher(key, count, bearer, direction)
}
