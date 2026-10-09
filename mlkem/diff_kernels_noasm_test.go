// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !(amd64 || arm64 || loong64 || ppc64le || (riscv64 && go1.27)) || purego

package mlkem

import "testing"

// On the pure-Go build there is no accelerated backend to diff against, so
// the dispatch implementation lists are empty and the diff suites skip; the
// convention-independent convolution anchor still covers the generic
// pipeline.

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host.
func diffDispatchAvailable() bool { return false }

// diffMontMulConvention reports whether the NTT-domain multiplication and
// inverse-NTT kernels follow the scalar Montgomery convention of
// field_mont.go (true) or the generic kernels' plain convention (false).
func diffMontMulConvention() bool { return false }

// diffForceDispatch is a no-op on the pure-Go build.
func diffForceDispatch(t testing.TB) {}

// diffRejUniform falls back to the generic rejection-sampling kernel, which
// keeps TestDiffRejUniform's wiring meaningful on this build.
func diffRejUniform(buf []byte, a *nttElement, j int) int {
	return rejUniformGeneric(buf, a, j)
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state; the pure-Go build has no dispatch variables.
func checkDispatch(t *testing.T) {}

// diffCheckRequiredKernel validates the kernel classes this package owns;
// the pure-Go build has no native kernels to require.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mlkem-avx2", "mlkem-neon", "mlkem-lasx", "mlkem-ppc64le", "mlkem-rvv":
		t.Errorf("kernel %q required but this build has no native mlkem kernels", name)
	}
}
