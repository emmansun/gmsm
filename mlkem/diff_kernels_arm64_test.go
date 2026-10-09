// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mlkem

import "testing"

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host; the NEON backend is unconditional on arm64.
func diffDispatchAvailable() bool { return true }

// diffMontMulConvention reports whether the NTT-domain multiplication and
// inverse-NTT kernels follow the scalar Montgomery convention of
// field_mont.go (true) or the generic kernels' plain convention (false).
func diffMontMulConvention() bool { return true }

// diffForceDispatch is a no-op: there is no dispatch variable to pin.
func diffForceDispatch(t testing.TB) {}

// diffRejUniform is the arch-neutral handle for the arm64
// rejection-sampling kernel.
func diffRejUniform(buf []byte, a *nttElement, j int) int {
	return rejUniformARM64(buf, a, j)
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state; arm64 has no runtime dispatch.
func checkDispatch(t *testing.T) {}

// diffCheckRequiredKernel validates the kernel classes this package owns.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mlkem-neon":
		// The NEON backend is compiled in unconditionally; nothing to check.
	}
}
