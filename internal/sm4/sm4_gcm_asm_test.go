// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && !purego

package sm4

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"testing"
)

func TestGcmSm4Init(t *testing.T) {
	if !(supportsGFMUL) {
		t.Skip("skipping test on unsupported CPU")
	}
	key := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	c, err := newCipherGeneric(key[:])
	if err != nil {
		t.Fatal(err)
	}
	c1 := c.(*sm4Cipher)
	var table [256]byte
	if supportSM4 {
		gcmSm4Init(&table, c1.enc[:], INST_SM4)
	} else if supportsAES {
		gcmSm4Init(&table, c1.enc[:], INST_AES)
	} else {
		t.Skip("skipping test on unsupported CPU")
	}

	amd64Expected, _ := hex.DecodeString("efe02875211f104b6cc6398a88e02616832611ffa9ff365d832611ffa9ff365dd1990739ba1568a7b850c2b3d6faa70269c9c58a6cefcfa569c9c58a6cefcfa5c465caca557f2b72b1a41462debd1b0075c1dea88bc2307275c1dea88bc2307285f658150945b9720030ab912a73b71c85c6f38423360e6e85c6f38423360e6e70d7d26d60ba5e2e434c4acffae2f15b339b98a29a58af75339b98a29a58af75edeb6cd41b6c866aa116a5ff33dcbbc04cfdc92b28b03daa4cfdc92b28b03daabf7c2d4efddd55771c7e73c7aa8b732fa3025e8957562658a3025e89575626585444a9b72066aa2e99458213d6e8ef4ccd012ba4f68e4562cd012ba4f68e4562")
	arm64Expected, _ := hex.DecodeString("6cc6398a88e02616efe02875211f104b832611ffa9ff365d832611ffa9ff365db850c2b3d6faa702d1990739ba1568a769c9c58a6cefcfa569c9c58a6cefcfa5b1a41462debd1b00c465caca557f2b7275c1dea88bc2307275c1dea88bc230720030ab912a73b71c85f658150945b97285c6f38423360e6e85c6f38423360e6e434c4acffae2f15b70d7d26d60ba5e2e339b98a29a58af75339b98a29a58af75a116a5ff33dcbbc0edeb6cd41b6c866a4cfdc92b28b03daa4cfdc92b28b03daa1c7e73c7aa8b732fbf7c2d4efddd5577a3025e8957562658a3025e895756265899458213d6e8ef4c5444a9b72066aa2ecd012ba4f68e4562cd012ba4f68e4562")
	switch runtime.GOARCH {
	case "arm64":
		if !bytes.Equal(table[:], arm64Expected) {
			t.Errorf("unexpected table value: got %x, want %x", table, arm64Expected)
		}
	case "amd64":
		if !bytes.Equal(table[:], amd64Expected) {
			t.Errorf("unexpected table value: got %x, want %x", table, amd64Expected)
		}
	}
}
