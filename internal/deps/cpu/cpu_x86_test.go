// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build 386 || amd64

package cpu_test

import (
	"testing"

	. "github.com/emmansun/gmsm/internal/deps/cpu"
)

func TestX86ifAVX2hasAVX(t *testing.T) {
	if X86.HasAVX2 && !X86.HasAVX {
		t.Fatalf("HasAVX expected true when HasAVX2 is true, got false")
	}
}

func TestX86ifAVX512FhasAVX2(t *testing.T) {
	if X86.HasAVX512F && !X86.HasAVX2 {
		t.Fatalf("HasAVX2 expected true when HasAVX512F is true, got false")
	}
}

func TestX86ifAVX512BWhasAVX512F(t *testing.T) {
	if X86.HasAVX512BW && !X86.HasAVX512F {
		t.Fatalf("HasAVX512F expected true when HasAVX512BW is true, got false")
	}
}

func TestX86ifAVX512VLhasAVX512F(t *testing.T) {
	if X86.HasAVX512VL && !X86.HasAVX512F {
		t.Fatalf("HasAVX512F expected true when HasAVX512VL is true, got false")
	}
}
