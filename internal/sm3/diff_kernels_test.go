// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// sm3BlockImpls returns the block kernels for amd64.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	out := []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
	}
	if useSSSE3 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "sse-block",
			Run:  sm3BlockRunOf(blockSIMD),
		})
	}
	if useAVX2 {
		out = append(out, diff.Implementation[[]byte]{
			Name: "avx2-block",
			Run:  sm3BlockRunOf(blockAVX2),
		})
	}
	return out
}

// checkDispatch verifies that the block dispatch state is consistent with
// the CPU features (and the DISABLE environment knobs).
func checkDispatch(t *testing.T) {
	if useAVX2 != (cpu.X86.HasAVX2 && cpu.X86.HasBMI2) {
		t.Errorf("useAVX2 = %v, want %v", useAVX2, cpu.X86.HasAVX2 && cpu.X86.HasBMI2)
	}
	if useSSSE3 != cpu.X86.HasSSSE3 {
		t.Errorf("useSSSE3 = %v, want %v", useSSSE3, cpu.X86.HasSSSE3)
	}
}
