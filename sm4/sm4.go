// Package sm4 implements ShangMi(SM) sm4 symmetric encryption algorithm.
package sm4

import (
	"crypto/cipher"
	"strconv"

	"github.com/emmansun/gmsm/internal/sm4"
)

// BlockSize the sm4 block size in bytes.
const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new [cipher.Block] implementation.
// The key argument should be the SM4 key, must be 16 bytes long.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16:
		break
	}
	return sm4.NewCipher(key)
}
