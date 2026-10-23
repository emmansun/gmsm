// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && !purego

package bn256

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffAsmBuild reports whether the accelerated backend is compiled in.
func diffAsmBuild() bool { return true }

// diffFPImpls returns the base-field kernel variants; the riscv64 assembly
// has a single path for the base field kernels.
func diffFPImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{Name: "gfp-asm", Primary: true, Run: diffFieldImplRun},
	}
}

// diffSelectCopyImpls returns the select/copy variants; the riscv64 wrappers
// dispatch on supportRVV at runtime (the V extension is optional), so both
// the RVV path and the pure-Go fallback are forceable.
func diffSelectCopyImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name:      "movcond-rvv",
			Available: func() bool { return supportRVV },
			Primary:   supportRVV,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportRVV, true)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
		{
			Name:    "movcond-scalar",
			Primary: !supportRVV,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportRVV, false)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
	}
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state.
func checkDispatch(t *testing.T) {
	if supportRVV != cpu.RISCV64.HasV {
		t.Errorf("supportRVV = %v, want %v", supportRVV, cpu.RISCV64.HasV)
	}
}

// checkRequiredKernel validates the kernel classes this package owns.
func checkRequiredKernel(t *testing.T, name string) {
	if name == "bn256-rvv" && !supportRVV {
		t.Errorf("bn256-rvv is required but the V extension is unavailable on this host")
	}
}
