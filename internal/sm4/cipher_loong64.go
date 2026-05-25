// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var supportLASX = cpu.Loong64.HasLASX

const INST_AES = 0 // placeholder, not used for loong64

//go:noescape
func encryptBlocksAsm(xk *uint32, dst, src []byte, inst int)

type sm4CipherAsm struct {
	sm4Cipher
	batchBlocks int
	blocksSize  int
}

// sm4CipherGCM implements crypto/cipher.gcmAble so that crypto/cipher.NewGCM
// will use the optimised implementation in this file when possible.
type sm4CipherGCM struct {
	sm4CipherAsm
}

func newCipher(key []byte) (cipher.Block, error) {
	if !supportLASX {
		return newCipherGeneric(key)
	}
	c := &sm4CipherGCM{sm4CipherAsm{sm4Cipher{}, 8, 8 * BlockSize}}
	expandKeyGo(key, &c.enc, &c.dec)
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
	encryptBlockGo(&c.enc, dst, src)
}

func (c *sm4CipherAsm) encrypt(dst, src []byte) {
	encryptBlockGo(&c.enc, dst, src)
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
	encryptBlockGo(&c.dec, dst, src)
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

// expandKey is used by BenchmarkExpand to ensure the key expansion path is exercised.
func expandKey(key []byte, enc, dec []uint32) {
	expandKeyGo(key, (*[rounds]uint32)(enc), (*[rounds]uint32)(dec))
}
