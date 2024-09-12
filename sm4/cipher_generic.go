//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le)

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
