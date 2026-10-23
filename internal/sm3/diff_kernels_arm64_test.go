// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package sm3

import (
	"os"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// sm3BlockImpls returns the block kernels for arm64: the SHA extension
// based kernel and the SM3 crypto extension based kernel.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	out := []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
		{
			Name: "shaext-block",
			Run:  sm3BlockRunOf(blockARM64),
		},
	}
	if cpu.ARM64.HasSM3 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "sm3ni-block",
			Run: sm3BlockRunOf(func(dig *digest, p []byte) {
				blockSM3NI(dig.h[:], p, &_K[0])
			}),
		})
	}
	return out
}

// checkDispatch verifies that the block dispatch state is consistent with
// the CPU features (and the DISABLE environment knobs).
func checkDispatch(t *testing.T) {
	want := cpu.ARM64.HasSM3 && os.Getenv("DISABLE_SM3NI") != "1"
	if useSM3NI != want {
		t.Errorf("useSM3NI = %v, want %v", useSM3NI, want)
	}
}
