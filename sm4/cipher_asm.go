// +build amd64

package sm4

import (
	"crypto/cipher"

	"golang.org/x/sys/cpu"
)

//go:noescape
func encryptBlocksAsm(xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(key *byte, ck, enc, dec *uint32)

type sm4CipherAsm struct {
	sm4Cipher
}

var supportsAES = cpu.X86.HasAES
var supportsGFMUL = cpu.X86.HasPCLMULQDQ

func newCipher(key []byte) (cipher.Block, error) {
	if !supportsAES {
		return newCipherGeneric(key)
	}
	c := sm4CipherAsm{sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0])
	if supportsAES && supportsGFMUL {
		return &sm4CipherGCM{c}, nil
	}
	return &c, nil
}

const FourBlocksSize = 64

func (c *sm4CipherAsm) BlockSize() int { return BlockSize }

func (c *sm4CipherAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	var src64 []byte = make([]byte, FourBlocksSize)
	var dst64 []byte = make([]byte, FourBlocksSize)
	copy(src64, src)
	encryptBlocksAsm(&c.enc[0], &dst64[0], &src64[0])
	copy(dst, dst64[:BlockSize])
}

func (c *sm4CipherAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	var src64 []byte = make([]byte, FourBlocksSize)
	var dst64 []byte = make([]byte, FourBlocksSize)
	copy(src64, src)
	encryptBlocksAsm(&c.dec[0], &dst64[0], &src64[0])
	copy(dst, dst64[:BlockSize])
}
