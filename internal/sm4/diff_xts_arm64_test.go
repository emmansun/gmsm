// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmXTSImpls returns the direct XTS kernels for arm64: the AES based mode
// and the SM4 crypto extension (SM4-NI) based mode.
func asmXTSImpls() []diff.Implementation[[]byte] {
	var out []diff.Implementation[[]byte]
	if cpuid.HasAES {
		out = append(out, diff.Implementation[[]byte]{
			Name: "xts-aesni",
			Run: diffXTSRunOf(func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error) {
				c := newDiffAESKey()
				if enc {
					return c.NewXTSEncrypter(encryptedTweak, isGB), nil
				}
				return c.NewXTSDecrypter(encryptedTweak, isGB), nil
			}),
		})
	}
	if cpuid.HasSM4 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "xts-sm4ni",
			Run: diffXTSRunOf(func(tweak, encryptedTweak *[BlockSize]byte, isGB, enc bool) (cipher.BlockMode, error) {
				c := newDiffNIKey()
				if enc {
					return c.NewXTSEncrypter(encryptedTweak, isGB), nil
				}
				return c.NewXTSDecrypter(encryptedTweak, isGB), nil
			}),
		})
	}
	return out
}
