//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
)

type sm4CipherNI struct {
	sm4Cipher
}

// sm4CipherNIGCM implements crypto/cipher.gcmAble so that crypto/cipher.NewGCM
// will use the optimised implementation in this file when possible. Instances
// of this type only exist when hasGCMAsm and hasSM4 returns true.
type sm4CipherNIGCM struct {
	sm4CipherNI
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
