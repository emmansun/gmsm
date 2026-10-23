// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && !purego

package mldsa

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host.
func diffDispatchAvailable() bool { return hasRVV }

// diffForceDispatch pins the dispatch variable to the accelerated path.
func diffForceDispatch(t testing.TB) {
	diff.WithValue(t, &hasRVV, true)
}

// checkDispatch asserts that the dispatch variable matches the CPU
// detection state.
func checkDispatch(t *testing.T) {
	if hasRVV != cpu.RISCV64.HasV {
		t.Errorf("hasRVV = %v, want cpu.RISCV64.HasV = %v", hasRVV, cpu.RISCV64.HasV)
	}
}

// diffCheckRequiredKernel validates the kernel classes this package owns.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mldsa-rvv":
		if !hasRVV {
			t.Errorf("kernel %q required but RVV is unavailable", name)
		}
	}
}
