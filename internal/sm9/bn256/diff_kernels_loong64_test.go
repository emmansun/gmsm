// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package bn256

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffAsmBuild reports whether the accelerated backend is compiled in.
func diffAsmBuild() bool { return true }

// diffFPImpls returns the base-field kernel variants; the loong64 assembly
// has a single path for the base field kernels.
func diffFPImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{Name: "gfp-asm", Primary: true, Run: diffFieldImplRun},
	}
}

// diffSelectCopyImpls returns the select/copy variants; the loong64 assembly
// branches on supportLSX/supportLASX inside every primitive, so the LSX-only
// and scalar paths are forceable even on LASX hardware.
func diffSelectCopyImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name:      "movcond-lasx",
			Available: func() bool { return supportLASX },
			Primary:   supportLASX,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportLSX, true)
				diff.WithValue(t, &supportLASX, true)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
		{
			Name:      "movcond-lsx",
			Available: func() bool { return supportLSX },
			Primary:   supportLSX && !supportLASX,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportLSX, true)
				diff.WithValue(t, &supportLASX, false)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
		{
			Name:    "movcond-scalar",
			Primary: !supportLSX && !supportLASX,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportLSX, false)
				diff.WithValue(t, &supportLASX, false)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
	}
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state.
func checkDispatch(t *testing.T) {
	if supportLSX != cpu.Loong64.HasLSX {
		t.Errorf("supportLSX = %v, want %v", supportLSX, cpu.Loong64.HasLSX)
	}
	if supportLASX != cpu.Loong64.HasLASX {
		t.Errorf("supportLASX = %v, want %v", supportLASX, cpu.Loong64.HasLASX)
	}
}

// checkRequiredKernel validates the kernel classes this package owns.
func checkRequiredKernel(t *testing.T, name string) {}
