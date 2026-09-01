// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !purego && go1.28

package sm4

import (
	"crypto/cipher"
	"os"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// supportSM4 reports whether the Zvksed (vector SM4) and Zvbb (vrev8 byte
// swap) extensions are available.
var supportSM4 = cpu.RISCV64.HasZvksed && (cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb) && os.Getenv("DISABLE_SM4NI") != "1"

//go:noescape
func encryptBlockAsm(xk *uint32, dst, src *byte)

//go:noescape
func encryptBlocksAsm(xk *uint32, dst, src []byte)

//go:noescape
func expandKeyAsm(key *byte, enc, dec *uint32)

type sm4CipherAsm struct {
	sm4Cipher
	batchBlocks int
	blocksSize  int
}

func newCipher(key []byte) (cipher.Block, error) {
	if !supportSM4 {
		return newCipherGeneric(key)
	}
	c := &sm4CipherAsm{sm4Cipher{}, 4, 4 * BlockSize}
	expandKeyAsm(&key[0], &c.enc[0], &c.dec[0])
	return c, nil
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
	encryptBlockAsm(&c.enc[0], &dst[0], &src[0])
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
	encryptBlockAsm(&c.dec[0], &dst[0], &src[0])
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
	encryptBlocksAsm(&c.enc[0], dst, src)
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
	encryptBlocksAsm(&c.dec[0], dst, src)
}

// expandKey is used by BenchmarkExpand to ensure that the asm implementation
// of key expansion is used for the benchmark when it is available.
func expandKey(key []byte, enc, dec []uint32) {
	if supportSM4 {
		expandKeyAsm(&key[0], &enc[0], &dec[0])
	} else {
		expandKeyGo(key, (*[rounds]uint32)(enc), (*[rounds]uint32)(dec))
	}
}
