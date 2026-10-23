// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || loong64 || riscv64)

package bn256

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// On the pure-Go build the production code itself is the generic fallback;
// there is no accelerated backend to diff against, so the implementation
// lists are empty and the diff suites skip.

// diffAsmBuild reports whether the accelerated backend is compiled in.
func diffAsmBuild() bool { return false }

// diffFPImpls returns the base-field kernel variants; unused on the pure-Go
// build.
func diffFPImpls() []diff.Implementation[[]byte] {
	return nil
}

// diffSelectCopyImpls returns the select/copy variants; unused on the
// pure-Go build.
func diffSelectCopyImpls() []diff.Implementation[[]byte] {
	return nil
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state; the pure-Go build has no dispatch variables.
func checkDispatch(t *testing.T) {}

// checkRequiredKernel validates the kernel classes this package owns; the
// pure-Go build has no kernel classes.
func checkRequiredKernel(t *testing.T, name string) {}
