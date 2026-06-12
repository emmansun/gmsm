// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && !purego

package cipher

import (
	"fmt"
	"testing"
)

func TestPolyvalTableInitAsm(t *testing.T) {
	if !supportPolyvalAsm {
		t.Skip("skipping test on unsupported CPU")
	}
	var authKey = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	var table polyvalAsmTable
	polyvalTableInitAsm(&authKey, &table)
	for i := range 16 {
		fmt.Printf("%x", table[i*16:(i+1)*16])
		fmt.Println()
	}
}
