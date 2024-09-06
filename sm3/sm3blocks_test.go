// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || s390x || ppc64 || ppc64le) && !purego

package sm3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func initState4() [4]*[8]uint32 {
	d := new(digest)
	d.Reset()
	var dig1 = d.h
	var dig2 = d.h
	var dig3 = d.h
	return [4]*[8]uint32{&d.h, &dig1, &dig2, &dig3}
}

func createOneBlockBy4() [4]*byte {
	var p1 [64]byte
	p1[0] = 0x61
	p1[1] = 0x62
	p1[2] = 0x63
	p1[3] = 0x80
	p1[63] = 0x18
	var p2 = p1
	var p3 = p1
	var p4 = p1
	return [4]*byte{&p1[0], &p2[0], &p3[0], &p4[0]}
}

func createOneRandomBlockBy4() [4]*byte {
	var p1 = [64]byte{
		0x49, 0xcf, 0x14, 0x64, 0x9f, 0x32, 0x4a, 0x07,
		0xe0, 0xd5, 0xbb, 0x2a, 0x00, 0xf7, 0xf0, 0x5d,
		0x5f, 0x5b, 0xdd, 0x6d, 0x14, 0xdf, 0xf0, 0x28,
		0xe0, 0x71, 0x32, 0x7e, 0xc0, 0x31, 0x10, 0x45,
		0x90, 0xed, 0xdb, 0x18, 0xf9, 0x8b, 0x76, 0x3e,
		0x18, 0xbf, 0x38, 0x2f, 0xf7, 0xc3, 0x87, 0x5f,
		0x30, 0x27, 0x7f, 0x31, 0x79, 0xba, 0xeb, 0xd7,
		0x95, 0xe7, 0x85, 0x3f, 0xa6, 0x43, 0xfd, 0xf2,
	}

	var p2 = p1
	var p3 = p1
	var p4 = p1
	return [4]*byte{&p1[0], &p2[0], &p3[0], &p4[0]}
}

func createTwoBlocksBy4() [4]*byte {
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
	return [4]*byte{&p1[0], &p2[0], &p3[0], &p4[0]}
}

func TestBlockMultBy4(t *testing.T) {
	digs := initState4()
	p := createOneBlockBy4()
	buffer := make([]byte, preallocSizeBy4)
	blockMultBy4(&digs[0], &p[0], &buffer[0], 1)
	expected := "[66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0]"
	for i := 0; i < 4; i++ {
		s := fmt.Sprintf("%x", digs[i][:])
		if s != expected {
			t.Errorf("digs[%d] got %s", i, s)
		}
	}

	digs = initState4()
	p = createOneRandomBlockBy4()
	blockMultBy4(&digs[0], &p[0], &buffer[0], 1)
	expected = "[8c2b6dd5 cc894103 6ec67d69 6154d5fd 62f48fd 984112e3 9e63659e 542709af]"
	for i := 0; i < 4; i++ {
		s := fmt.Sprintf("%x", digs[i][:])
		if s != expected {
			t.Errorf("digs[%d] got %s", i, s)
		}
	}

	digs = initState4()
	p = createTwoBlocksBy4()
	blockMultBy4(&digs[0], &p[0], &buffer[0], 2)
	expected = "[debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732]"
	for i := 0; i < 4; i++ {
		s := fmt.Sprintf("%x", digs[i][:])
		if s != expected {
			t.Errorf("digs[%d] got %s", i, s)
		}
	}
}

func TestCopyResultsBy4(t *testing.T) {
	var m [4][8]uint32
	var ret, expected [128]byte
	var k uint32 = 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			m[i][j] = k
			k++
		}
	}
	copyResultsBy4(&m[0][0], &ret[0])

	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			binary.BigEndian.PutUint32(expected[i*32+j*4:], m[i][j])
		}
	}
	if !bytes.Equal(ret[:], expected[:]) {
		t.Errorf("got %x, expected %x\n", ret[:], expected[:])
	}
}

func BenchmarkOneBlockBy4(b *testing.B) {
	digs := initState4()
	p := createOneBlockBy4()
	buffer := make([]byte, preallocSizeBy4)
	b.SetBytes(64 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockMultBy4(&digs[0], &p[0], &buffer[0], 1)
	}
}

func BenchmarkTwoBlocksBy4(b *testing.B) {
	digs := initState4()
	p := createTwoBlocksBy4()
	buffer := make([]byte, preallocSizeBy4)
	b.SetBytes(64 * 2 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blockMultBy4(&digs[0], &p[0], &buffer[0], 2)
	}
}
