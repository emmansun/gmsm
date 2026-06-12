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
	expectedLE, _ := hex.DecodeString("000000000000000000000000000000c200000000000000005444a9b72066aa2e5444a9b72066aa2e99458213d6e8ef4c99458213d6e8ef4c00000000000000000000000000000000bf7c2d4efddd5577bf7c2d4efddd55771c7e73c7aa8b732f1c7e73c7aa8b732f00000000000000000000000000000000edeb6cd41b6c866aedeb6cd41b6c866aa116a5ff33dcbbc0a116a5ff33dcbbc00000000000000000000000000000000070d7d26d60ba5e2e70d7d26d60ba5e2e434c4acffae2f15b434c4acffae2f15b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	expectedBE, _ := hex.DecodeString("0000000000000000c20000000000000000000000000000002eaa6620b7a944542eaa6620b7a944544cefe8d6138245994cefe8d613824599000000000000000000000000000000007755ddfd4e2d7cbf7755ddfd4e2d7cbf2f738baac7737e1c2f738baac7737e1c000000000000000000000000000000006a866c1bd46cebed6a866c1bd46cebedc0bbdc33ffa516a1c0bbdc33ffa516a1000000000000000000000000000000002e5eba606dd2d7702e5eba606dd2d7705bf1e2facf4a4c435bf1e2facf4a4c430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	generateProductTable(t, key[:], &productTable)
	switch runtime.GOARCH {
	case "ppc64le":
		if !bytes.Equal(productTable[:], expectedLE) {
			t.Errorf("unexpected table value: got %x, want %x", productTable, expectedLE)
		}
	case "ppc64":
		if !bytes.Equal(productTable[:], expectedBE) {
			t.Errorf("unexpected table value: got %x, want %x", productTable, expectedBE)
		}
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

func TestGcmHash(t *testing.T) {
	var productTable [256]byte
	key := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	generateProductTable(t, key[:], &productTable)
	var y [16]byte
	var data = []byte{
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
		0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	gcmHash(y[:], &productTable, data, len(data))
	leExpected, _ := hex.DecodeString("4389ecf6c52b8496f9bd488c74b76d0a")
	if !bytes.Equal(y[:], leExpected) {
		t.Errorf("unexpected hash value: got %x, want %x", y[:], leExpected)
	}
}
