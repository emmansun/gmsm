//go:build !amd64 && !arm64
// +build !amd64,!arm64

package sm4

import "crypto/cipher"

// newCipher calls the newCipherGeneric function
// directly. Platforms with hardware accelerated
// implementations of SM4 should implement their
// own version of newCipher (which may then call
// newCipherGeneric if needed).
func newCipher(key []byte) (cipher.Block, error) {
	return newCipherGeneric(key)
}

// expandKey is used by BenchmarkExpand and should
// call an assembly implementation if one is available.
func expandKey(key []byte, enc, dec []uint32) {
	expandKeyGo(key, enc, dec)
}
