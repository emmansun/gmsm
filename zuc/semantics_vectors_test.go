// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zuc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// TestSemanticsVectors replays the committed ZUC vectors. The EEA cases must
// produce the published keystream through both the frame API and the raw
// key/IV API, and seeking into the stream must agree with a sequential pass.
// The EIA cases must produce the published MAC through both entry points and
// across a split write. A panic on a rejected parameter counts as a failure.
func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("zuc_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ZUCEEA", func(t *testing.T) { testEEAVectors(t, suite) })
	t.Run("ZUCEEAInit", func(t *testing.T) { testEEAInitVectors(t, suite) })
	t.Run("ZUCEIA", func(t *testing.T) { testEIAVectors(t, suite) })
	t.Run("ZUC256EIA", func(t *testing.T) { testEIA256Vectors(t, suite) })
}

func testEEAVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("ZUCEEA")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := semanticsHex(t, "key", tc.Key)
			iv := semanticsHex(t, "nonce", tc.Nonce)
			input := semanticsHex(t, "input", tc.Input)
			want := semanticsHex(t, "expected", tc.Expected)

			frame, err := NewEEACipher(key, tc.Count, tc.Bearer, tc.Direction)
			if err != nil {
				t.Fatalf("NewEEACipher() error: %v: %s", err, tc.Comment)
			}
			got := make([]byte, len(input))
			semanticsCall(t, tc, func() { frame.XORKeyStream(got, input) })
			if !bytes.Equal(got, want) {
				t.Fatalf("frame XORKeyStream() = %x, want %x", got, want)
			}

			raw, err := NewCipher(key, iv)
			if err != nil {
				t.Fatalf("NewCipher() error: %v", err)
			}
			sequential := make([]byte, len(input))
			semanticsCall(t, tc, func() { raw.XORKeyStream(sequential, input) })
			if !bytes.Equal(sequential, want) {
				t.Fatalf("raw XORKeyStream() = %x, want %x: the frame IV derived in the generator and the one derived by the library disagree", sequential, want)
			}

			cut := len(input) / 2
			first := make([]byte, cut)
			second := make([]byte, len(input)-cut)
			semanticsCall(t, tc, func() {
				frame.XORKeyStreamAt(first, input[:cut], 0)
				frame.XORKeyStreamAt(second, input[cut:], uint64(cut))
			})
			if seeked := append(first, second...); !bytes.Equal(seeked, want) {
				t.Fatalf("XORKeyStreamAt() split at %d = %x, want %x", cut, seeked, want)
			}

			const offset = 7
			if len(input) > offset {
				tail := make([]byte, len(input)-offset)
				semanticsCall(t, tc, func() { frame.XORKeyStreamAt(tail, input[offset:], offset) })
				if !bytes.Equal(tail, want[offset:]) {
					t.Fatalf("XORKeyStreamAt(offset %d) = %x, want %x", offset, tail, want[offset:])
				}
			}
		})
	}
}

func testEEAInitVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("ZUCEEAInit")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := semanticsHex(t, "key", tc.Key)
			iv := semanticsHex(t, "nonce", tc.Nonce)
			err := semanticsCallErr(t, tc, func() error {
				_, err := NewCipher(key, iv)
				return err
			})
			if want := tc.Result == "valid"; (err == nil) != want {
				t.Fatalf("NewCipher(key %d bytes, iv %d bytes) error = %v, want valid=%v: %s",
					len(key), len(iv), err, want, tc.Comment)
			}
		})
	}
}

func testEIAVectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("ZUCEIA")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := semanticsHex(t, "key", tc.Key)
			iv := semanticsHex(t, "nonce", tc.Nonce)
			input := semanticsHex(t, "input", tc.Input)
			want := semanticsHex(t, "expected", tc.Expected)
			nbits := tc.BitLen
			if nbits == 0 {
				nbits = len(input) * 8
			}

			frame, err := NewEIAHash(key, tc.Count, tc.Bearer, tc.Direction)
			if err != nil {
				t.Fatalf("NewEIAHash() error: %v", err)
			}
			got := semanticsFinish(t, tc, frame, input, nbits)
			if !bytes.Equal(got, want) {
				t.Fatalf("frame Finish(%d bits) = %x, want %x: %s", nbits, got, want, tc.Comment)
			}

			raw, err := NewHash(key, iv)
			if err != nil {
				t.Fatalf("NewHash() error: %v", err)
			}
			got = semanticsFinish(t, tc, raw, input, nbits)
			if !bytes.Equal(got, want) {
				t.Fatalf("raw Finish(%d bits) = %x, want %x: the frame IV derived in the generator and the one derived by the library disagree", nbits, got, want)
			}

			cut := min(len(input)/2, nbits/8)
			split, err := NewHash(key, iv)
			if err != nil {
				t.Fatalf("NewHash() error: %v", err)
			}
			if _, err := split.Write(input[:cut]); err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			got = semanticsFinish(t, tc, split, input[cut:], nbits-cut*8)
			if !bytes.Equal(got, want) {
				t.Fatalf("split Finish(%d bits after a %d-byte write) = %x, want %x", nbits-cut*8, cut, got, want)
			}
		})
	}
}

func testEIA256Vectors(t *testing.T, suite *vectors.Suite) {
	group, err := suite.Group("ZUC256EIA")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			key := semanticsHex(t, "key", tc.Key)
			iv := semanticsHex(t, "nonce", tc.Nonce)
			input := semanticsHex(t, "input", tc.Input)
			want := semanticsHex(t, "expected", tc.Expected)

			var h EIA
			err := semanticsCallErr(t, tc, func() (err error) {
				h, err = NewHash256(key, iv, tc.TagSize)
				return err
			})
			if tc.Result == "invalid" {
				if err == nil {
					t.Fatalf("NewHash256() accepted tag %d, key %d bytes, iv %d bytes: %s",
						tc.TagSize, len(key), len(iv), tc.Comment)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewHash256() error: %v: %s", err, tc.Comment)
			}

			// Sum must return the full tag without disturbing the state.
			if _, err := h.Write(input); err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			if got := h.Sum(nil); !bytes.Equal(got, want) {
				t.Fatalf("Sum() = %x, want %x: %s", got, want, tc.Comment)
			}

			fresh, err := NewHash256(key, iv, tc.TagSize)
			if err != nil {
				t.Fatalf("NewHash256() error: %v", err)
			}
			got := semanticsFinish(t, tc, fresh, input, len(input)*8)
			if !bytes.Equal(got, want) {
				t.Fatalf("Finish(%d bits) = %x, want %x: %s", len(input)*8, got, want, tc.Comment)
			}
			if len(got) != tc.TagSize {
				t.Fatalf("Finish() returned %d bytes, want %d", len(got), tc.TagSize)
			}

			// Finish resets the instance, so a second call must repeat the tag.
			if got := semanticsFinish(t, tc, fresh, input, len(input)*8); !bytes.Equal(got, want) {
				t.Fatalf("second Finish() = %x, want %x after the internal reset", got, want)
			}
		})
	}
}

func semanticsFinish(t *testing.T, tc vectors.Case, h EIA, input []byte, nbits int) []byte {
	t.Helper()
	var mac []byte
	semanticsCall(t, tc, func() { mac = h.Finish(input, nbits) })
	return mac
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

// semanticsCallErr runs one vector call that reports an error and turns a
// panic into a test failure that names the case.
func semanticsCallErr(t *testing.T, tc vectors.Case, call func() error) (err error) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("tc%d panicked: %v", tc.TCID, p)
		}
	}()
	return call()
}

// semanticsCall runs one vector call and turns a panic into a test failure
// that names the case.
func semanticsCall(t *testing.T, tc vectors.Case, call func()) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("tc%d panicked: %v", tc.TCID, p)
		}
	}()
	call()
}
