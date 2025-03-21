//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package sm4

import (
	"crypto/cipher"
	"os"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var supportSM4 = cpu.ARM64.HasSM4 && os.Getenv("DISABLE_SM4NI") != "1"
var supportsAES = cpuid.HasAES
var supportsGFMUL = cpuid.HasGFMUL
var useAVX2 = cpu.X86.HasAVX2
var useAVX = cpu.X86.HasAVX
var useAESNI4SingleBlock = os.Getenv("FORCE_SM4BLOCK_AESNI") == "1"

const (
	INST_AES int = iota
	INST_SM4
)

//go:noescape
func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)

//go:noescape
func encryptBlockAsm(xk *uint32, dst, src *byte, inst int)

//go:noescape
func expandKeyAsm(key *byte, ck, enc, dec *uint32, inst int)

type sm4CipherAsm struct {
	sm4Cipher
	batchBlocks int
	blocksSize  int
}

// sm4CipherGCM implements crypto/cipher.gcmAble so that crypto/cipher.NewGCM
// will use the optimised implementation in this file when possible. Instances
// of this type only exist when hasGCMAsm and hasAES returns true.
type sm4CipherGCM struct {
	sm4CipherAsm
}

func newCipher(key []byte) (cipher.Block, error) {
	if supportSM4 {
		return newCipherNI(key)
	}

	if !supportsAES {
		return newCipherGeneric(key)
	}

	blocks := 4
	if useAVX2 {
		blocks = 8
	}
	c := &sm4CipherGCM{sm4CipherAsm{sm4Cipher{}, blocks, blocks * BlockSize}}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
	if supportsGFMUL {
		return c, nil
	}
	return &c.sm4CipherAsm, nil
}

func (c *sm4CipherAsm) Concurrency() int { return c.batchBlocks }

func (c *sm4CipherAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	c.encrypt(dst, src)
}

func (c *sm4CipherAsm) encrypt(dst, src []byte) {
	if useAESNI4SingleBlock {
		encryptBlockAsm(&c.enc[0], &dst[0], &src[0], INST_AES)
	} else {
		encryptBlockGo(&c.enc, dst, src)
	}
}

func (c *sm4CipherAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	if useAESNI4SingleBlock {
		encryptBlockAsm(&c.dec[0], &dst[0], &src[0], INST_AES)
	} else {
		encryptBlockGo(&c.dec, dst, src)
	}
}

func (c *sm4CipherAsm) EncryptBlocks(dst, src []byte) {
	if len(src) < c.blocksSize {
		panic("sm4: input not full blocks")
	}
	if len(dst) < c.blocksSize {
		panic("sm4: output not full blocks")
	}
	if alias.InexactOverlap(dst[:c.blocksSize], src[:c.blocksSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlocksAsm(&c.enc[0], dst, src, INST_AES)
}

func (c *sm4CipherAsm) DecryptBlocks(dst, src []byte) {
	if len(src) < c.blocksSize {
		panic("sm4: input not full blocks")
	}
	if len(dst) < c.blocksSize {
		panic("sm4: output not full blocks")
	}
	if alias.InexactOverlap(dst[:c.blocksSize], src[:c.blocksSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlocksAsm(&c.dec[0], dst, src, INST_AES)
}

// expandKey is used by BenchmarkExpand to ensure that the asm implementation
// of key expansion is used for the benchmark when it is available.
func expandKey(key []byte, enc, dec []uint32) {
	if supportSM4 {
		expandKeyAsm(&key[0], &ck[0], &enc[0], &dec[0], INST_SM4)
	} else if supportsAES && useAESNI4SingleBlock {
		expandKeyAsm(&key[0], &ck[0], &enc[0], &dec[0], INST_AES)
	} else {
		expandKeyGo(key, (*[rounds]uint32)(enc), (*[rounds]uint32)(dec))
	}
}
