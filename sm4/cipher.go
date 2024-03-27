// Package sm4 implements ShangMi(SM) sm4 symmetric encryption algorithm.
package sm4

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/internal/alias"
)

// BlockSize the sm4 block size in bytes.
const BlockSize = 16

const rounds = 32

// A cipher is an instance of SM4 encryption using a particular key.
type sm4Cipher struct {
	enc [rounds]uint32
	dec [rounds]uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the SM4 key,
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, fmt.Errorf("sm4: invalid key size %d", k)
	case 16:
		break
	}
	return newCipher(key)
}

// newCipher creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (cipher.Block, error) {
	c := &sm4Cipher{}
	expandKeyGo(key, &c.enc, &c.dec)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockGo(&c.enc, dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockGo(&c.dec, dst, src)
}
