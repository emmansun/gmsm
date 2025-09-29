// Package zuc implements ShangMi(SM) zuc stream cipher and integrity algorithm.
package zuc

import (
	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/internal/zuc"
)

const (
	// IV size in bytes for zuc 128
	IVSize128 = zuc.IVSize128
	// IV size in bytes for zuc 256
	IVSize256 = zuc.IVSize256
	// number of words in a round
	RoundWords = zuc.RoundWords
	// number of bytes in a word
	WordSize = zuc.WordSize
	// number of bytes in a round
	RoundBytes = zuc.RoundBytes
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

// NewCipherWithBucketSize create a new instance of the eea cipher with the specified
// bucket size. The bucket size is rounded up to the nearest multiple of RoundBytes.
//
// The implementation of this function is used for XORKeyStreamAt function optimization, which will keep states
// for seekable stream cipher once the bucketSize is greater than 0.
func NewCipherWithBucketSize(key, iv []byte, bucketSize int) (cipher.SeekableStream, error) {
	return zuc.NewCipherWithBucketSize(key, iv, bucketSize)
}

// NewEEACipherWithBucketSize creates a new instance of a seekable stream cipher
// for the EEA encryption algorithm with a specified bucket size. This function
// is typically used in mobile communication systems for secure data encryption.
//
// The implementation of this function is used for XORKeyStreamAt function optimization, which will keep states
// for seekable stream cipher once the bucketSize is greater than 0.
func NewEEACipherWithBucketSize(key []byte, count, bearer, direction uint32, bucketSize int) (cipher.SeekableStream, error) {
	return zuc.NewEEACipherWithBucketSize(key, count, bearer, direction, bucketSize)
}

// NewEmptyEEACipher creates and returns a new empty ZUC-EEA cipher instance.
// This function initializes an empty eea struct that can be used for
// unmarshaling a previously saved state using the UnmarshalBinary method.
// The returned cipher instance is not ready for encryption or decryption.
func NewEmptyEEACipher() cipher.SeekableStream {
	return zuc.NewEmptyCipher()
}

// UnmarshalEEACipher reconstructs a ZUC cipher instance from a serialized byte slice.
// It attempts to deserialize the provided data into a seekable stream cipher
// that can be used for encryption/decryption operations.
func UnmarshalEEACipher(data []byte) (cipher.SeekableStream, error) {
	return zuc.UnmarshalCipher(data)
}
