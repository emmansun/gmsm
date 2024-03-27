//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

type sm4CipherNI struct {
	sm4Cipher
}

func newCipherNI(key []byte) (cipher.Block, error) {
	c := &sm4CipherNIGCM{sm4CipherNI{sm4Cipher{}}}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0], INST_SM4)
	if supportsGFMUL {
		return c, nil
	}
	return &c.sm4CipherNI, nil
}

func (c *sm4CipherNI) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockAsm(&c.enc[0], &dst[0], &src[0], INST_SM4)
}

func (c *sm4CipherNI) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockAsm(&c.dec[0], &dst[0], &src[0], INST_SM4)
}
