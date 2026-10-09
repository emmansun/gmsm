// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !(amd64 || arm64 || loong64 || riscv64) || purego

package mldsa

import "testing"

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host; without architecture kernels the dispatch layer compiles down
// to the generic implementations.
func diffDispatchAvailable() bool { return false }

// diffForceDispatch is a no-op: there is no dispatch variable to pin.
func diffForceDispatch(t testing.TB) {}

// checkDispatch is a no-op: there is no runtime dispatch state.
func checkDispatch(t *testing.T) {}

// diffCheckRequiredKernel fails for any kernel class this package owns; a
// build without architecture kernels can never satisfy a kernel requirement.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mldsa-avx2", "mldsa-neon", "mldsa-lasx", "mldsa-rvv":
		t.Errorf("kernel %q required but no accelerated mldsa kernels are compiled in", name)
	}
}
