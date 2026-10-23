// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package bn256

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffAsmBuild reports whether the accelerated backend is compiled in.
func diffAsmBuild() bool { return true }

// diffFPImpls returns the base-field kernel variants; the amd64 assembly
// dispatches between an ADX/BMI2 path and a scalar path at runtime, so both
// are forceable through supportADX.
func diffFPImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name:      "gfp-asm-adx",
			Available: func() bool { return supportADX },
			Primary:   supportADX,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportADX, true)
				return diffFieldImplRun(t, c, b)
			},
		},
		{
			Name:    "gfp-asm-scalar",
			Primary: !supportADX,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportADX, false)
				return diffFieldImplRun(t, c, b)
			},
		},
	}
}

// diffSelectCopyImpls returns the select/copy variants; the amd64 assembly
// branches on supportAVX2 inside every primitive.
func diffSelectCopyImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{
			Name:      "movcond-avx2",
			Available: func() bool { return supportAVX2 },
			Primary:   supportAVX2,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportAVX2, true)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
		{
			Name:    "movcond-scalar",
			Primary: !supportAVX2,
			Run: func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
				diff.WithValue(t, &supportAVX2, false)
				return diffSelectCopyImplRun(t, c, b)
			},
		},
	}
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state.
func checkDispatch(t *testing.T) {
	if want := cpu.X86.HasADX && cpu.X86.HasBMI2; supportADX != want {
		t.Errorf("supportADX = %v, want %v (HasADX=%v HasBMI2=%v)",
			supportADX, want, cpu.X86.HasADX, cpu.X86.HasBMI2)
	}
	if supportAVX2 != cpu.X86.HasAVX2 {
		t.Errorf("supportAVX2 = %v, want %v", supportAVX2, cpu.X86.HasAVX2)
	}
}

// checkRequiredKernel validates the kernel classes this package owns.
func checkRequiredKernel(t *testing.T, name string) {
	if name == "bn256-adx" && !supportADX {
		t.Errorf("bn256-adx is required but ADX/BMI2 is unavailable on this host")
	}
}
