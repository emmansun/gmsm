// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package sm4

import (
	"crypto/cipher"
	"runtime"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmGCMImpls returns the GCM variants for the AES/SM4-NI accelerated
// architectures:
//   - amd64/arm64: asm GHASH + asm block (sm4CipherGCM), pure-Go GHASH +
//     asm block (sm4CipherAsm), SM4-NI GHASH + SM4-NI block (sm4CipherNIGCM)
//   - ppc64x: asm GHASH + asm block (sm4CipherAsm/gcmAsm)
func asmGCMImpls() []diff.Implementation[[]byte] {
	var out []diff.Implementation[[]byte]
	newNIGCM := func() (cipher.AEAD, error) {
		c := &sm4CipherNIGCM{sm4CipherNI{sm4Cipher{}}}
		expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_SM4)
		return cipher.NewGCM(c)
	}
	if cpuid.HasAES {
		out = append(out, diff.Implementation[[]byte]{
			Name: "aesni-gcm",
			Run: diffGCMRunOf(func() (cipher.AEAD, error) {
				c := &sm4CipherGCM{sm4CipherAsm{sm4Cipher{}, 4, 4 * BlockSize}}
				expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
				return cipher.NewGCM(c)
			}),
		})
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			// pure-Go GHASH over the asm block (gcm_cipher_asm.go)
			out = append(out, diff.Implementation[[]byte]{
				Name: "asm-block-go-ghash-gcm",
				Run:  diffGCMRunOf(func() (cipher.AEAD, error) { return newDiffAESKey().NewGCM(12, 16) }),
			})
		}
	}
	if cpuid.HasSM4 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "sm4ni-gcm",
			Run:  diffGCMRunOf(newNIGCM),
		})
	}
	return out
}
