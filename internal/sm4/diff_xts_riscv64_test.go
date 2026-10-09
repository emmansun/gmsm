// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

package sm4

import (
	"crypto/cipher"
	"testing"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// asmXTSImpls returns the direct XTS kernels for riscv64: the Zvksed based
// mode.
func asmXTSImpls() []diff.Implementation[[]byte] {
	var out []diff.Implementation[[]byte]
	if cpuid.HasSM4 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "xts-zvksed",
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

func TestDiffXTSRVVBlockBoundaries(t *testing.T) {
	if !cpuid.HasSM4 {
		t.Skip("Zvksed is unavailable")
	}
	s := diff.ByteSuite("generic-xts", diffXTSRef)
	for _, impl := range asmXTSImpls() {
		s.Add(impl)
	}
	s.Run(t, diff.Domain{
		Lengths:       diff.Values(16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 80, 81, 128, 129),
		Tags:          []uint64{0, 1, 2, 3},
		CartesianTags: true,
		Alignments:    diff.CommonAlignments(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	})
}
