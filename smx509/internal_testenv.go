// Copyright 2026 The gmsm Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Minimal testenv stubs for smx509 tests adapted from Go stdlib.

package smx509

import (
	"os/exec"
	"testing"
)

// testenv provides stubs for internal/testenv functions used in stdlib tests.
var testenv = struct {
	Builder          func() string
	SkipFlaky        func(t testing.TB, issue int)
	Command          func(t testing.TB, name string, args ...string) *exec.Cmd
	MustHaveExecPath func(t testing.TB, name string)
	MustHaveGoRun    func(t testing.TB)
	GoToolPath       func(t testing.TB) string
}{
	Builder: func() string { return "" },
	SkipFlaky: func(t testing.TB, _ int) {
		t.Helper()
		t.Skip("skipping flaky test")
	},
	Command: func(t testing.TB, name string, args ...string) *exec.Cmd {
		t.Helper()
		return exec.Command(name, args...)
	},
	MustHaveExecPath: func(t testing.TB, name string) {
		t.Helper()
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("skipping: %s not found in PATH", name)
		}
	},
	MustHaveGoRun: func(t testing.TB) {
		t.Helper()
		t.Skip("skipping: go run not available in smx509 test environment")
	},
	GoToolPath: func(t testing.TB) string {
		return "go"
	},
}
