// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import "testing"

// diffDispatchAvailable reports whether the runtime dispatch engages on
// this host; the arm64 kernels are engaged unconditionally.
func diffDispatchAvailable() bool { return true }

// diffForceDispatch is a no-op: the arm64 dispatch has no variable to pin.
func diffForceDispatch(t testing.TB) {}

// checkDispatch is a no-op: the arm64 dispatch has no runtime state.
func checkDispatch(t *testing.T) {}

// diffCheckRequiredKernel validates the kernel classes this package owns.
func diffCheckRequiredKernel(t *testing.T, name string) {
	switch name {
	case "mldsa-neon":
		// The NEON kernels are unconditional; nothing to check.
	}
}
