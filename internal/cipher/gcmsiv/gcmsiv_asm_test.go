// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && !purego

package cipher

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"testing"
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
	}
}

func TestPolyvalBlocksUpdateAsm(t *testing.T) {
	if !supportPolyvalAsm {
		t.Skip("skipping test on unsupported CPU")
	}
	var authKey = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	var table polyvalAsmTable
	polyvalTableInitAsm(&authKey, &table)

	expected, _ := hex.DecodeString("b1aba232dd6c847586593756cb2644eb")

	var y [16]byte
	var blocks = []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	polyvalBlocksUpdateAsm(&table, &y, blocks)
	if !bytes.Equal(y[:], expected) {
		t.Errorf("unexpected result: got %x, want %x", y, expected)
	}
}
