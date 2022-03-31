// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/binary"
	"log"
	"os"	
	"github.com/emmansun/gmsm/sm2"
)

func main() {

	// Generate precomputed p256 tables.
	var pre [43][32 * 8]uint64
	basePoint := []uint64{
		0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05,
		0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd,
		0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000,
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 32; j++ {
		copy(t1, t2)
		for i := 0; i < 43; i++ {
			// The window size is 6 so we need to double 6 times.
			if i != 0 {
				for k := 0; k < 6; k++ {
					sm2.P256PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			sm2.P256Inverse(zInv, t1[8:12])
			sm2.P256Sqr(zInvSq, zInv, 1)
			sm2.P256Mul(zInv, zInv, zInvSq)
			sm2.P256Mul(t1[:4], t1[:4], zInvSq)
			sm2.P256Mul(t1[4:8], t1[4:8], zInv)
			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(pre[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2.P256PointDoubleAsm(t2, basePoint)
		} else {
			sm2.P256PointAddAsm(t2, t2, basePoint)
		}
	}

	var bin []byte

	// Dump the precomputed tables, flattened, little-endian.
	// These tables are used directly by assembly on little-endian platforms.
	// go:embedding the data into a string lets it be stored readonly.
	for i := range &pre {
		for _, v := range &pre[i] {
			var u8 [8]byte
			binary.LittleEndian.PutUint64(u8[:], v)
			bin = append(bin, u8[:]...)
		}
	}

	err := os.WriteFile("p256_asm_table.bin", bin, 0644)
	if err != nil {
		log.Fatal(err)
	}

}
