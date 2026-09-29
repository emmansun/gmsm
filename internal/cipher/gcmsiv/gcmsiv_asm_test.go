// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || (riscv64 && go1.27)) && !purego

package cipher

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

func TestPolyvalTableInitAsm(t *testing.T) {
	if !supportPolyvalAsm {
		t.Skip("skipping test on unsupported CPU")
	}
	amd64Expected, _ := hex.DecodeString("87f00e25c6685b1a4e7a1d632f79d284c98a1346e911899ec98a1346e911899e298c3094abe125e631960b1bc5d961ec181a3b8f6e38440a181a3b8f6e38440a92ba923b49631f0c7e4b4bf6c8450857ecf1d9cd8126175becf1d9cd8126175bfc0e6f7ae0c1510c5cece7069f5f571ea0e2887c7f9e0612a0e2887c7f9e0612ee237ddddd694634da80497ef9cab6fe34a334a324a3f0ca34a334a324a3f0ca34ee209446f97afb6acda9f97b6c7f3e5e23896d3d9505c55e23896d3d9505c5559f5eb479b37218e52fee04c903c6f8b0b0b0b0b0b0b4e0b0b0b0b0b0b0b4e00123456789abcdeffedcba9876543210ffffffffffffffffffffffffffffffff")
	arm64Expected, _ := hex.DecodeString("4e7a1d632f79d28487f00e25c6685b1ac98a1346e911899ec98a1346e911899e31960b1bc5d961ec298c3094abe125e6181a3b8f6e38440a181a3b8f6e38440a7e4b4bf6c845085792ba923b49631f0cecf1d9cd8126175becf1d9cd8126175b5cece7069f5f571efc0e6f7ae0c1510ca0e2887c7f9e0612a0e2887c7f9e0612da80497ef9cab6feee237ddddd69463434a334a324a3f0ca34a334a324a3f0ca6acda9f97b6c7f3e34ee209446f97afb5e23896d3d9505c55e23896d3d9505c5e52fee04c903c6f8559f5eb479b37218b0b0b0b0b0b0b4e0b0b0b0b0b0b0b4e0fedcba98765432100123456789abcdefffffffffffffffffffffffffffffffff")

	var authKey = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	var table polyvalAsmTable
	polyvalTableInitAsm(&authKey, &table)
	switch runtime.GOARCH {
	case "arm64":
		if table != (polyvalAsmTable(arm64Expected)) {
			t.Errorf("unexpected table value: got %x, want %x", table, arm64Expected)
		}
	case "amd64":
		if table != (polyvalAsmTable(amd64Expected)) {
			t.Errorf("unexpected table value: got %x, want %x", table, amd64Expected)
		}
	case "riscv64":
		origGHASH := hasGHASH
		// Zvbc path: table must match amd64 exactly (same vclmul algorithm)
		hasGHASH = false
		var zvbcTable polyvalAsmTable
		polyvalTableInitAsm(&authKey, &zvbcTable)
		if zvbcTable != (polyvalAsmTable(amd64Expected)) {
			t.Errorf("Zvbc table mismatch:\n  got:  %x\n  want: %x", zvbcTable, amd64Expected)
		}
		// Zvkg path: stores byte-reversed H^1 at table[0:16]
		// The H^1 value is amd64Expected[224:240]; Zvkg byte-reverses it for vghsh.vv.
		if cpu.RISCV64.HasZvkg {
			hasGHASH = true
			var zvkgTable polyvalAsmTable
			polyvalTableInitAsm(&authKey, &zvkgTable)
			// Compute expected: reverse bytes of amd64 H^1
			var zvkgExpected [16]byte
			for i := 0; i < 16; i++ {
				zvkgExpected[i] = amd64Expected[224+15-i]
			}
			if !bytes.Equal(zvkgTable[:16], zvkgExpected[:]) {
				t.Errorf("Zvkg table key mismatch:\n  got:  %x\n  want: %x", zvkgTable[:16], zvkgExpected)
			}
		}
		hasGHASH = origGHASH
	}
}

// TestPolyvalRISCV64BothPaths cross-validates Zvkg and Zvbc code paths on riscv64
// by temporarily flipping hasGHASH. Both paths must produce identical POLYVAL output.
func TestPolyvalRISCV64BothPaths(t *testing.T) {
	if runtime.GOARCH != "riscv64" {
		t.Skip("riscv64-only test")
	}
	if !cpu.RISCV64.HasZvbc {
		t.Skip("requires Zvbc")
	}

	var authKey = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	blocks := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}

	// Force Zvbc path
	origGHASH := hasGHASH
	hasGHASH = false
	var tableZvbc polyvalAsmTable
	polyvalTableInitAsm(&authKey, &tableZvbc)
	var yZvbc [16]byte
	polyvalBlocksUpdateAsm(&tableZvbc, &yZvbc, blocks)

	if cpu.RISCV64.HasZvkg {
		// Force Zvkg path
		hasGHASH = true
		var tableZvkg polyvalAsmTable
		polyvalTableInitAsm(&authKey, &tableZvkg)
		var yZvkg [16]byte
		polyvalBlocksUpdateAsm(&tableZvkg, &yZvkg, blocks)

		if yZvbc != yZvkg {
			t.Errorf("Zvbc and Zvkg paths produce different results:\n  Zvbc: %x\n  Zvkg: %x", yZvbc, yZvkg)
		}
	}

	hasGHASH = origGHASH
}

func TestPolyvalBlocksUpdateAsm(t *testing.T) {
	if !supportPolyvalAsm {
		t.Skip("skipping test on unsupported CPU")
	}
	var authKey = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	var table polyvalAsmTable
	polyvalTableInitAsm(&authKey, &table)

	expected1, _ := hex.DecodeString("cc07e4605483f50fd35586290940202c")
	expected2, _ := hex.DecodeString("e07a52a82c82073210069f28dd621a5b")

	var y [16]byte
	var blocks = []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}
	polyvalBlocksUpdateAsm(&table, &y, blocks)
	if !bytes.Equal(y[:], expected1) {
		t.Errorf("unexpected result: got %x, want %x", y, expected1)
	}
	polyvalBlocksUpdateAsm(&table, &y, blocks)
	if !bytes.Equal(y[:], expected2) {
		t.Errorf("unexpected result: got %x, want %x", y, expected2)
	}
}
