// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

package sm3

import (
	"os"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// sm3BlockImpls returns the block kernels for riscv64: the scalar kernel
// and the Zvksh (vector SM3) based kernel.
func sm3BlockImpls() []diff.Implementation[[]byte] {
	out := []diff.Implementation[[]byte]{
		{
			Name: "public-block",
			Run:  sm3BlockRunOf(block),
		},
		{
			Name: "scalar-block",
			Run:  sm3BlockRunOf(blockRISCV64),
		},
	}
	if useZVKSHFeature() {
		out = append(out, diff.Implementation[[]byte]{
			Name: "zvksh-block",
			Run:  sm3BlockRunOf(blockZVKSH),
		})
	}
	return out
}

// useZVKSHFeature reports whether the Zvksh extension is present on the
// host, independent of the DISABLE_SM3NI environment knob.
func useZVKSHFeature() bool {
	return cpu.RISCV64.HasZvksh && (cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb)
}

// checkDispatch verifies that the block dispatch state is consistent with
// the CPU features (and the DISABLE environment knobs).
func checkDispatch(t *testing.T) {
	want := useZVKSHFeature() && os.Getenv("DISABLE_SM3NI") != "1"
	if useZVKSH != want {
		t.Errorf("useZVKSH = %v, want %v", useZVKSH, want)
	}
}
