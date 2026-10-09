// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (arm64 || ppc64 || ppc64le) && !purego

package bn256

import (
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// diffAsmBuild reports whether the accelerated backend is compiled in.
func diffAsmBuild() bool { return true }

// diffFPImpls returns the base-field kernel variants; these architectures
// have a single assembly path and no runtime dispatch for the base field.
func diffFPImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{Name: "gfp-asm", Primary: true, Run: diffFieldImplRun},
	}
}

// diffSelectCopyImpls returns the select/copy variants; these architectures
// have a single assembly path and no runtime dispatch for the primitives.
func diffSelectCopyImpls() []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{
		{Name: "movcond-asm", Primary: true, Run: diffSelectCopyImplRun},
	}
}

// checkDispatch asserts that the dispatch variables match the CPU detection
// state; these architectures have no runtime dispatch to check.
func checkDispatch(t *testing.T) {}

// checkRequiredKernel validates the kernel classes this package owns; these
// architectures have no optional kernel classes.
func checkRequiredKernel(t *testing.T, name string) {}
