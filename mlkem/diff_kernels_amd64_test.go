// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mlkem

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host.
func diffDispatchAvailable() bool { return useAVX2 }

// diffMontMulConvention reports whether the NTT-domain multiplication and
// inverse-NTT kernels follow the scalar Montgomery convention of
// field_mont.go (true) or the generic kernels' plain convention (false).
func diffMontMulConvention() bool { return true }

// diffForceDispatch pins the dispatch variable to the accelerated path for
// the duration of one run, so that a future env knob cannot silently break
// the diff. It is only invoked when Available() already held, mirroring the
// bn256 pattern.
func diffForceDispatch(t testing.TB) {
	diff.WithValue(t, &useAVX2, true)
}

// diffRejUniform is the arch-neutral handle for the amd64 rejection-sampling
// kernel (engaged unconditionally by sampleNTT on this architecture).
func diffRejUniform(buf []byte, a *nttElement, j int) int {
	return rejUniformAMD64(buf, a, j)
}

// checkDispatch asserts that the dispatch variable matches the CPU
// detection state.
func checkDispatch(t *testing.T) {
	if useAVX2 != cpu.X86.HasAVX2 {
		t.Errorf("useAVX2 = %v, want cpu.X86.HasAVX2 = %v", useAVX2, cpu.X86.HasAVX2)
	}
}

// diffCheckRequiredKernel validates the kernel classes this package owns;
// unknown names belong to other packages and are ignored (see sm4).
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mlkem-avx2":
		if !useAVX2 {
			t.Errorf("kernel %q required but AVX2 is unavailable", name)
		}
	}
}
