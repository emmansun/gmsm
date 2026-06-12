// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package sm4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/internal/byteorder"
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
	// Reverse the bytes in each 8 byte chunk.
	// On ppc64le: LXVD2X reverses bytes per dword, so pre-reverse in memory.
	// On ppc64 (BE): LXVD2X loads in natural order; BEUint64→BEPutUint64 is a no-op.
	if runtime.GOARCH == "ppc64le" {
		h1 = byteorder.LEUint64(hle[:8])
		h2 = byteorder.LEUint64(hle[8:])
	} else {
		h1 = byteorder.BEUint64(hle[:8])
		h2 = byteorder.BEUint64(hle[8:])
	}
	byteorder.BEPutUint64(hle[:8], h1)
	byteorder.BEPutUint64(hle[8:], h2)

	if runtime.GOARCH == "ppc64le" {
		if fmt.Sprintf("%x", hle) != "3811556fff7b1f9fd38f531e5330944d" {
			t.Errorf("2 got %x", hle)
		}
	} else {
		// ppc64 BE: no-op transform, hle stays as SM4 output
		if fmt.Sprintf("%x", hle) != "9f1f7bff6f5511384d9430531e538fd3" {
			t.Errorf("2 got %x", hle)
		}
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

func TestGcmSm4Init(t *testing.T) {
	var productTable [256]byte
	key := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected, _ := hex.DecodeString("efe02875211f104b6cc6398a88e02616832611ffa9ff365d832611ffa9ff365dd1990739ba1568a7b850c2b3d6faa70269c9c58a6cefcfa569c9c58a6cefcfa5c465caca557f2b72b1a41462debd1b0075c1dea88bc2307275c1dea88bc2307285f658150945b9720030ab912a73b71c85c6f38423360e6e85c6f38423360e6e70d7d26d60ba5e2e434c4acffae2f15b339b98a29a58af75339b98a29a58af75edeb6cd41b6c866aa116a5ff33dcbbc04cfdc92b28b03daa4cfdc92b28b03daabf7c2d4efddd55771c7e73c7aa8b732fa3025e8957562658a3025e89575626585444a9b72066aa2e99458213d6e8ef4ccd012ba4f68e4562cd012ba4f68e4562")
	generateProductTable(t, key[:], &productTable)
	if !bytes.Equal(productTable[:], expected) {
		t.Errorf("unexpected table value: got %x, want %x", table, expected)
	}
}

func generateProductTable(t *testing.T, key []byte, table *[256]byte) {
	t.Helper()
	c, err := newCipherGeneric(key[:])
	if err != nil {
		t.Fatal(err)
	}
	hle := make([]byte, gcmBlockSize)
	c.Encrypt(hle, hle)

	// Reverse the bytes in each 8 byte chunk
	// Load little endian, store big endian
	var h1, h2 uint64
	if runtime.GOARCH == "ppc64le" {
		h1 = byteorder.LEUint64(hle[:8])
		h2 = byteorder.LEUint64(hle[8:])
	} else {
		h1 = byteorder.BEUint64(hle[:8])
		h2 = byteorder.BEUint64(hle[8:])
	}
	byteorder.BEPutUint64(hle[:8], h1)
	byteorder.BEPutUint64(hle[8:], h2)
	gcmInit(table, hle)
}
