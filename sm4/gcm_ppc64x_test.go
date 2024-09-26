// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm4

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
)

func TestCmul(t *testing.T) {
	key := make([]byte, 16)
	c1 := &sm4CipherAsm{sm4Cipher{}, 4, 4 * BlockSize}
	expandKeyAsm(&key[0], &ck[0], &c1.enc[0], &c1.dec[0], INST_AES)
	hle := make([]byte, gcmBlockSize)
	c1.Encrypt(hle, hle)
	if fmt.Sprintf("%x", hle) != "9f1f7bff6f5511384d9430531e538fd3" {
		t.Errorf("1 got %x", hle)
	}
	var h1, h2 uint64
	// Reverse the bytes in each 8 byte chunk
	// Load little endian, store big endian
	if runtime.GOARCH == "ppc64le" {
		h1 = binary.LittleEndian.Uint64(hle[:8])
		h2 = binary.LittleEndian.Uint64(hle[8:])
	} else {
		h1 = binary.BigEndian.Uint64(hle[:8])
		h2 = binary.BigEndian.Uint64(hle[8:])
	}
	binary.BigEndian.PutUint64(hle[:8], h1)
	binary.BigEndian.PutUint64(hle[8:], h2)

	if fmt.Sprintf("%x", hle) != "3811556fff7b1f9fd38f531e5330944d" {
		t.Errorf("2 got %x", hle)
	}
	aead, _ := c1.NewGCM(12, 16)
	if runtime.GOARCH == "ppc64le" {
		for i := 0; i < 16; i++ {
			if fmt.Sprintf("%x", aead.(*gcmAsm).productTable[i*16:(i+1)*16]) != table[i] {
				t.Errorf("productTable %v got %x", i, aead.(*gcmAsm).productTable[i*16:(i+1)*16])
			}
		}
	}
}

var table = [16]string{
	"000000000000000000000000000000c2",
	"0000000000000000a71fa73ca660289b",
	"a71fa73ca660289b7022aadefef73efc",
	"7022aadefef73efc0000000000000000",
	"00000000000000009208acefd693f27f",
	"9208acefd693f27fc7223dce2c483080",
	"c7223dce2c4830800000000000000000",
	"000000000000000095c5b74db0d6c213",
	"95c5b74db0d6c213c8984b421897287c",
	"c8984b421897287c0000000000000000",
	"000000000000000050a174a4b5189613",
	"50a174a4b518961329a304696d059054",
	"29a304696d0590540000000000000000",
	"00000000000000000000000000000000",
	"00000000000000000000000000000000",
	"00000000000000000000000000000000",
}
