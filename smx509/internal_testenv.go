// Copyright 2026 The gmsm Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Minimal testenv stubs for smx509 tests adapted from Go stdlib.

package smx509

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
)

// testenv provides stubs for internal/testenv functions used in stdlib tests.
var testenv = struct {
	Builder               func() string
	SkipFlaky             func(t testing.TB, issue int)
	SkipIfShortAndSlow    func(t testing.TB)
	Executable            func(t testing.TB) string
	SyscallIsNotSupported func(err error) bool
	Command               func(t testing.TB, name string, args ...string) *exec.Cmd
	MustHaveExecPath      func(t testing.TB, name string)
	MustHaveGoRun         func(t testing.TB)
	GoToolPath            func(t testing.TB) string
}{
	Builder: func() string { return "" },
	SkipFlaky: func(t testing.TB, _ int) {
		t.Helper()
		t.Skip("skipping flaky test")
	},
	SkipIfShortAndSlow: func(t testing.TB) {
		if testing.Short() {
			switch runtime.GOARCH {
			case "arm", "mips", "mipsle", "mips64", "mips64le", "wasm":
				t.Helper()
				t.Skipf("skipping test in -short mode on %s", runtime.GOARCH)
			}
		}
	},
	Executable: func(t testing.TB) string {
		t.Helper()
		exe, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable error: %v", err)
		}
		return exe
	},
	SyscallIsNotSupported: func(err error) bool {
		if err == nil {
			return false
		}
		var errno syscall.Errno
		if errors.As(err, &errno) {
			switch errno {
			case syscall.EPERM, syscall.EROFS, syscall.EINVAL:
				return true
			}
		}
		return errors.Is(err, fs.ErrPermission) || errors.Is(err, errors.ErrUnsupported)
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
