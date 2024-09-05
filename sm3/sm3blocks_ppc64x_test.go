// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm3

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestTransposeMatrix(t *testing.T) {
	var m [4][8]uint32
	var k uint32 = 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = k
			k++
			fmt.Printf("%08x ", m[i][j])
		}
		fmt.Println()
	}
	input := [4]*[8]uint32{&m[0], &m[1], &m[2], &m[3]}
	transposeMatrix(&input[0])
	fmt.Println()
	fmt.Println()
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			fmt.Printf("%08x ", m[i][j])
		}
		fmt.Println()
	}
}

func TestCopyResultsBy4(t *testing.T) {
	var m [4][8]uint32
	var ret [128]byte
	var k uint32 = 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = k
			k++
			fmt.Printf("%08x ", m[i][j])
		}
		fmt.Println()
	}
	copyResultsBy4(&m[0][0], &ret[0])
	fmt.Printf("got: %x\n", ret[:])

	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			binary.BigEndian.PutUint32(ret[i*32+j*4:], m[i][j])
		}
	}
	fmt.Printf("expected %x\n", ret[:])
}
