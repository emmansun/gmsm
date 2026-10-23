// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host.
func diffDispatchAvailable() bool { return useLASX }

// diffForceDispatch pins the dispatch variable to the accelerated path.
func diffForceDispatch(t testing.TB) {
	diff.WithValue(t, &useLASX, true)
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
	case "mldsa-lasx":
		if !useLASX {
			t.Errorf("kernel %q required but LASX is unavailable", name)
		}
	}
}
