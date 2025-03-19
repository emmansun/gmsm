package cipher

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/cipher/xts"
)

// NewXTSEncrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes).
func NewXTSEncrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (cipher.BlockMode, error) {
	return xts.NewXTSEncrypter(cipherFunc, key, tweakKey, tweak, false)
}

// NewXTSEncrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number.
func NewXTSEncrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	byteorder.LEPutUint64(tweak[:8], sectorNum)
	return NewXTSEncrypter(cipherFunc, key, tweakKey, tweak)
}

// NewGBXTSEncrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes).
// It follows GB/T 17964-2021.
func NewGBXTSEncrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (cipher.BlockMode, error) {
	return xts.NewXTSEncrypter(cipherFunc, key, tweakKey, tweak, true)
}

// NewGBXTSEncrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number.
// It follows GB/T 17964-2021.
func NewGBXTSEncrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	byteorder.LEPutUint64(tweak[:8], sectorNum)
	return NewGBXTSEncrypter(cipherFunc, key, tweakKey, tweak)
}

// NewXTSDecrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) for decryption.
func NewXTSDecrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (cipher.BlockMode, error) {
	return xts.NewXTSDecrypter(cipherFunc, key, tweakKey, tweak, false)
}

// NewXTSDecrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number for decryption.
func NewXTSDecrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	byteorder.LEPutUint64(tweak[:8], sectorNum)
	return NewXTSDecrypter(cipherFunc, key, tweakKey, tweak)
}

// NewGBXTSDecrypter creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) for decryption.
// It follows GB/T 17964-2021.
func NewGBXTSDecrypter(cipherFunc CipherCreator, key, tweakKey, tweak []byte) (cipher.BlockMode, error) {
	return xts.NewXTSDecrypter(cipherFunc, key, tweakKey, tweak, true)
}

// NewGBXTSDecrypterWithSector creates a Cipher given a function for creating the underlying
// block cipher (which must have a block size of 16 bytes) with sector number for decryption.
// It follows GB/T 17964-2021.
func NewGBXTSDecrypterWithSector(cipherFunc CipherCreator, key, tweakKey []byte, sectorNum uint64) (cipher.BlockMode, error) {
	tweak := make([]byte, blockSize)
	byteorder.LEPutUint64(tweak[:8], sectorNum)
	return NewGBXTSDecrypter(cipherFunc, key, tweakKey, tweak)
}
