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

	if fmt.Sprintf("%x", hle) != "3811556fff7b1f9fd38f531e0530944d" {
		t.Errorf("2 got %x", hle)
	}
	aead, _ := c1.NewGCM(12, 16)
	for i := 0; i < 256; i += 16 {
		fmt.Printf("%x\n", aead.(*gcmAsm).productTable[i:i+16])
	}
}
