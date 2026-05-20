// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || loong64) && !purego

package sm3

import (
	"fmt"
	"testing"
)

func initState8() [8]*[8]uint32 {
	d := new(digest)
	d.Reset()
	var dig1 = d.h
	var dig2 = d.h
	var dig3 = d.h
	var dig4 = d.h
	var dig5 = d.h
	var dig6 = d.h
	var dig7 = d.h
	return [8]*[8]uint32{&d.h, &dig1, &dig2, &dig3, &dig4, &dig5, &dig6, &dig7}
}

func createOneBlockBy8() [8]*byte {
	var p1 [64]byte
	p1[0] = 0x61
	p1[1] = 0x62
	p1[2] = 0x63
	p1[3] = 0x80
	p1[63] = 0x18
	var p2 = p1
	var p3 = p1
	var p4 = p1
	var p5 = p1
	var p6 = p1
	var p7 = p1
	var p8 = p1
	return [8]*byte{&p1[0], &p2[0], &p3[0], &p4[0], &p5[0], &p6[0], &p7[0], &p8[0]}
}

func createTwoBlocksBy8() [8]*byte {
	var p1 [128]byte
	p1[0] = 0x61
	p1[1] = 0x62
	p1[2] = 0x63
	p1[3] = 0x64
	copy(p1[4:], p1[:4])
	copy(p1[8:], p1[:8])
	copy(p1[16:], p1[:16])
	copy(p1[32:], p1[:32])
	p1[64] = 0x80
	p1[126] = 0x02
	var p2 = p1
	var p3 = p1
	var p4 = p1
	var p5 = p1
	var p6 = p1
	var p7 = p1
	var p8 = p1
	return [8]*byte{&p1[0], &p2[0], &p3[0], &p4[0], &p5[0], &p6[0], &p7[0], &p8[0]}
}

func TestTransposeMatrix8x8(t *testing.T) {
	if !supportMult8 {
		t.Skip("supportMult8 is false")
	}
	var m [8][8]uint32
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = uint32(i*8 + j)
		}
	}
	input := [8]*[8]uint32{&m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &m[6], &m[7]}
	transposeMatrix8x8(&input[0])
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if m[j][i] != uint32(i*8+j) {
				t.Errorf("m[%d][%d] got %d", i, j, m[j][i])
			}
		}
	}
	transposeMatrix8x8(&input[0])
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if m[i][j] != uint32(i*8+j) {
				t.Errorf("m[%d][%d] got %d", i, j, m[i][j])
			}
		}
	}
}

func TestBlockMultBy8(t *testing.T) {
	if !supportMult8 {
		t.Skip("supportMult8 is false")
	}
	digs := initState8()
	p := createOneBlockBy8()
	buffer := make([]byte, preallocSizeBy8)
	blockMultBy8(&digs[0], &p[0], &buffer[0], 1)
	expected := "[66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0]"
	for i := 0; i < 8; i++ {
		s := fmt.Sprintf("%x", digs[i][:])
		if s != expected {
			t.Errorf("digs[%d] got %s", i, s)
		}
	}

	digs = initState8()
	p = createTwoBlocksBy8()
	blockMultBy8(&digs[0], &p[0], &buffer[0], 2)
	expected = "[debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732]"
	for i := 0; i < 8; i++ {
		s := fmt.Sprintf("%x", digs[i][:])
		if s != expected {
			t.Errorf("digs[%d] got %s", i, s)
		}
	}
}

func BenchmarkOneBlockBy8(b *testing.B) {
	if !supportMult8 {
		b.Skip("supportMult8 is false")
	}
	digs := initState8()
	p := createOneBlockBy8()
	buffer := make([]byte, preallocSizeBy8)
	b.SetBytes(64 * 8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockMultBy8(&digs[0], &p[0], &buffer[0], 1)
	}
}

func BenchmarkTwoBlocksBy8(b *testing.B) {
	if !supportMult8 {
		b.Skip("supportMult8 is false")
	}
	digs := initState8()
	p := createTwoBlocksBy8()
	buffer := make([]byte, preallocSizeBy8)
	b.SetBytes(64 * 2 * 8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockMultBy8(&digs[0], &p[0], &buffer[0], 2)
	}
}
