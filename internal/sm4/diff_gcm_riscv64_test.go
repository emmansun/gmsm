// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmGCMImpls returns the GCM variant for riscv64: the Zvksed block with the
// vectorized GHASH (gcm_zvksed_riscv64.go).
func asmGCMImpls() []diff.Implementation[[]byte] {
	var out []diff.Implementation[[]byte]
	if cpuid.HasSM4 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "zvksed-gcm",
			Run: diffGCMRunOf(func() (cipher.AEAD, error) {
				c := &sm4CipherNIGCM{sm4CipherNI{sm4Cipher{}}}
				expandKeyAsm(&katKey[0], &ck[0], &c.enc[0], &c.dec[0], INST_SM4)
				return cipher.NewGCM(c)
			}),
		})
	}
	return out
}
