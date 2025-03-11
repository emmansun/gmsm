// Package zuc provides implementations of the ZUC stream cipher and its related
// cryptographic functions.
package zuc

import (
	"hash"

	"github.com/emmansun/gmsm/internal/zuc"
)


// EIA is an interface that extends the hash.Hash interface with an additional
// Finish method, which finalizes the hash computation with a specified number
// of bits.
type EIA interface {
	hash.Hash
	Finish(p []byte, nbits int) []byte
}

// NewHash creates a new instance of the ZUC-based hash function with the given
// key and initialization vector (IV).
func NewHash(key, iv []byte) (EIA, error) {
	return zuc.NewHash(key, iv)
}

// NewEIAHash creates a new instance of the ZUC-based EIA (Encryption Integrity
// Algorithm) hash function with the given key, count, bearer, and direction.
func NewEIAHash(key []byte, count, bearer, direction uint32) (EIA, error) {
	return zuc.NewEIAHash(key, count, bearer, direction)
}

// NewHash256 creates a new instance of the ZUC256-based hash function with the
// given key, initialization vector (IV), and tag size.
func NewHash256(key, iv []byte, tagSize int) (EIA, error) {
	return zuc.NewHash256(key, iv, tagSize)
}
