// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// TestSemanticsVectors replays the committed SM3 hash and KDF vectors. The
// hash cases cover the padding boundary, and each one is also fed to the
// hash in three uneven chunks: a streaming implementation that mishandles a
// buffered block boundary must disagree with the one-shot digest.
func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("sm3_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("SM3Hash", func(t *testing.T) { testHashVectors(t, suite) })
	t.Run("SM3KDF", func(t *testing.T) { testKDFVectors(t, suite) })
}

func testHashVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("SM3Hash")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			msg := semanticsHex(t, "msg", tc.Msg)
			want := semanticsHex(t, "expected", tc.Expected)

			got := Sum(msg)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("Sum() = %x, want %x: %s", got, want, tc.Comment)
			}

			h := New()
			cut1, cut2 := len(msg)/3, 2*len(msg)/3
			h.Write(msg[:cut1])
			h.Write(msg[cut1:cut2])
			h.Write(msg[cut2:])
			if streamed := h.Sum(nil); !bytes.Equal(streamed, want) {
				t.Fatalf("streamed Sum() = %x, want %x: %s", streamed, want, tc.Comment)
			}
		})
	}
}

func testKDFVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("SM3KDF")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			z := semanticsHex(t, "input", tc.Input)
			want := semanticsHex(t, "expected", tc.Expected)
			got := Kdf(z, tc.KeyLen)
			if !bytes.Equal(got, want) {
				t.Fatalf("Kdf(z, %d) = %x, want %x: %s", tc.KeyLen, got, want, tc.Comment)
			}
		})
	}
}

func semanticsHex(t *testing.T, name, value string) []byte {
	t.Helper()
	if value == "" {
		return nil
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return data
}
