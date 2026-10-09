// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host.
func diffDispatchAvailable() bool { return useLASX }

// diffMontMulConvention reports whether the NTT-domain multiplication and
// inverse-NTT kernels follow the scalar Montgomery convention of
// field_mont.go (true) or the generic kernels' plain convention (false).
func diffMontMulConvention() bool { return true }

// diffForceDispatch pins the dispatch variable to the accelerated path.
func diffForceDispatch(t testing.TB) {
	diff.WithValue(t, &useLASX, true)
}

// diffRejUniform is the arch-neutral handle for the loong64
// rejection-sampling kernel (engaged unconditionally by sampleNTT).
func diffRejUniform(buf []byte, a *nttElement, j int) int {
	return rejUniformLoong64(buf, a, j)
}

// checkDispatch asserts that the dispatch variable matches the CPU
// detection state.
func checkDispatch(t *testing.T) {
	if useLASX != cpu.Loong64.HasLASX {
		t.Errorf("useLASX = %v, want cpu.Loong64.HasLASX = %v", useLASX, cpu.Loong64.HasLASX)
	}
}

// diffCheckRequiredKernel validates the kernel classes this package owns.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mlkem-lasx":
		if !useLASX {
			t.Errorf("kernel %q required but LASX is unavailable", name)
		}
	}
}
