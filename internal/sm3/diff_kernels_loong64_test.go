// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// sm3BlockImpls returns the block kernels for loong64.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	out := []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
		{
			Name: "asm-block",
			Run:  sm3BlockRunOf(blockAsm),
		},
	}
	if supportLSX {
		out = append(out, diff.Implementation[[]byte]{
			Name: "lsx-block",
			Run:  sm3BlockRunOf(blockLsx),
		})
	}
	return out
}

// checkDispatch verifies that the block dispatch state is consistent with
// the CPU features.
func checkDispatch(t *testing.T) {
	if supportLSX != cpu.Loong64.HasLSX {
		t.Errorf("supportLSX = %v, want %v", supportLSX, cpu.Loong64.HasLSX)
	}
	if supportLASX != cpu.Loong64.HasLASX {
		t.Errorf("supportLASX = %v, want %v", supportLASX, cpu.Loong64.HasLASX)
	}
}
