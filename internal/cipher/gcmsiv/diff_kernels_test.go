// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || (riscv64 && go1.27)) && !purego

package cipher

import (
	"os"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// diffPolyvalRefFor wraps a run so that POLYVAL is computed by the pure-Go
// path, which is the trusted differential oracle. Forcing the generic
// fallback is always safe regardless of host features, so the reference is
// also used by the fuzz bodies; the override is restored via t.Cleanup.
func diffPolyvalRefFor(run diff.Run[[]byte]) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		diff.WithValue(t, &supportPolyvalAsm, false)
		return run(t, c, b)
	}
}

// diffPolyvalImpls returns the accelerated POLYVAL implementation through
// the natural public dispatch.
func diffPolyvalImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{{
		Name:      "polyval-asm",
		Run:       run,
		Available: func() bool { return supportPolyvalAsm },
		Primary:   true,
	}}
}

// diffGCMSIVRefFor wraps an AEAD run so that the tag computation takes the
// pure-Go POLYVAL path.
func diffGCMSIVRefFor(run diff.Run[[]byte]) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		diff.WithValue(t, &supportPolyvalAsm, false)
		return run(t, c, b)
	}
}

func diffGCMSIVReferenceSeal(seal func() []byte) []byte {
	old := supportPolyvalAsm
	supportPolyvalAsm = false
	defer func() { supportPolyvalAsm = old }()
	return seal()
}

// diffGCMSIVImpls returns the public AEAD implementation through the natural
// dispatch.
func diffGCMSIVImpls(run diff.Run[[]byte]) []diff.Implementation[[]byte] {
	return []diff.Implementation[[]byte]{{
		Name:      "public",
		Run:       run,
		Available: func() bool { return supportPolyvalAsm },
		Primary:   true,
	}}
}

// checkDispatch asserts that the dispatch variables are consistent with the
// CPU features of the host (and the DISABLE_GHASH knob).
func checkDispatch(t *testing.T) {
	wantPolyval := cpuid.HasGFMUL || cpu.RISCV64.HasZvkg || cpu.RISCV64.HasZvbc
	if supportPolyvalAsm != wantPolyval {
		t.Errorf("supportPolyvalAsm = %v, want %v", supportPolyvalAsm, wantPolyval)
	}
	wantGHASH := cpu.RISCV64.HasZvkg && (cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb) && os.Getenv("DISABLE_GHASH") != "1"
	if hasGHASH != wantGHASH {
		t.Errorf("hasGHASH = %v, want %v", hasGHASH, wantGHASH)
	}
}

// TestDiffRequiredKernels enforces kernel availability on CI runners that
// guarantee the CPU features. DIFF_REQUIRE holds a comma-separated list of
// kernel classes; the list may be shared across packages, and each package
// validates only the classes it owns (unknown names are ignored).
func TestDiffRequiredKernels(t *testing.T) {
	req := os.Getenv("DIFF_REQUIRE")
	if req == "" {
		t.Skip("DIFF_REQUIRE not set")
	}
	for _, name := range strings.Split(req, ",") {
		switch name {
		case "gcmsiv-polyval":
			if !supportPolyvalAsm {
				t.Errorf("kernel %q required but supportPolyvalAsm is false", name)
			}
		}
	}
}
