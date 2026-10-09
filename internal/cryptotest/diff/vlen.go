// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// VectorLengthBits returns the RISC-V vector register length (VLEN) in bits,
// or 0 when the platform has no vector extension.
func VectorLengthBits() int {
	if runtime.GOARCH == "riscv64" && cpu.RISCV64.HasV {
		return int(cpu.RISCV64.VLENB) * 8
	}
	return 0
}

// ExpectVectorLength fails the test unless the RISC-V vector register length
// equals wantBits. On non-riscv64 platforms it is skipped. CI uses this as a
// probe step to verify that a requested QEMU vlen property actually took
// effect; a matrix entry requesting vlen=256 that still reports VLEN=128
// must fail instead of silently testing the wrong geometry.
func ExpectVectorLength(t *testing.T, wantBits int) {
	t.Helper()
	if runtime.GOARCH != "riscv64" {
		t.Skip("VLEN probe only applies to riscv64")
	}
	if !cpu.RISCV64.HasV {
		t.Fatal("cpu.RISCV64.HasV is false; vector extension not enabled")
	}
	got := int(cpu.RISCV64.VLENB) * 8
	if got != wantBits {
		t.Fatalf("VLEN=%d bits (VLENB=%d bytes), want %d bits; QEMU CPU property did not take effect",
			got, cpu.RISCV64.VLENB, wantBits)
	}
	t.Logf("VLEN=%d bits (VLENB=%d bytes)", got, cpu.RISCV64.VLENB)
}
