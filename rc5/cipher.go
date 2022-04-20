// Package rc5 handle rc5 symmetric encryption algorithm
package rc5

import (
	"crypto/cipher"
	"fmt"
)

// Reference: https://en.wikipedia.org/wiki/RC5
// http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the RC5 key, the wordSize arguement should be word size in bits,
// the r argument should be number of rounds.
func NewCipher(key []byte, wordSize, r uint) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, fmt.Errorf("rc5: invalid key size %d, we support 16/24/32 now", k)
	case 16, 24, 32:
		break
	}
	if r < 8 || r > 127 {
		return nil, fmt.Errorf("rc5: invalid rounds %d, should be between 8 and 127", r)
	}
	switch wordSize {
	case 32:
		return newCipher32(key, r)
	case 64:
		return newCipher64(key, r)
	default:
		return nil, fmt.Errorf("rc5: unsupported word size %d, support 32/64 now", wordSize)
	}
}

// NewCipher32 creates and returns a new cipher.Block with 32 bits word size.
// The key argument should be the RC5 key, the r argument should be number of rounds.
func NewCipher32(key []byte, r uint) (cipher.Block, error) {
	return NewCipher(key, 32, r)
}

// NewCipher64 creates and returns a new cipher.Block with 64 bits word size.
// The key argument should be the RC5 key, the r argument should be number of rounds.
func NewCipher64(key []byte, r uint) (cipher.Block, error) {
	return NewCipher(key, 64, r)
}
