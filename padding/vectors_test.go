// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package padding

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// TestPaddingVectors replays the committed padding vectors against both the
// variable-time and the constant-time unpadding paths. The two must agree on
// every verdict: a divergence is the padding-oracle hazard these vectors
// exist to prevent.
func TestPaddingVectors(t *testing.T) {
	suite, err := vectors.Load("padding.json")
	if err != nil {
		t.Fatal(err)
	}
	constructors := []struct {
		group string
		new   NewPaddingFunc
	}{
		{"PKCS7", NewPKCS7Padding},
		{"ANSIX923", NewANSIX923Padding},
		{"ISO9797M2", NewISO9797M2Padding},
		{"ISO9797M3", NewISO9797M3Padding},
		{"ZeroPadding", NewZeroPadding},
	}
	for _, c := range constructors {
		t.Run(c.group, func(t *testing.T) {
			group, err := suite.Group(c.group)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range group.Tests {
				t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
					pad := c.new(paddingBlockSize(t, tc))
					src := paddingHex(t, tc, "input", tc.Input)
					wantInvalid := tc.Result == "invalid"
					want := paddingHex(t, tc, "expected", tc.Expected)

					checkUnpad(t, tc, "Unpad", pad.Unpad, src, want, wantInvalid)
					checkUnpad(t, tc, "ConstantTimeUnpad", pad.ConstantTimeUnpad, src, want, wantInvalid)
				})
			}
		})
	}
}

func checkUnpad(t *testing.T, tc vectors.Case, name string, unpad func([]byte) ([]byte, error), src, want []byte, wantInvalid bool) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("%s panicked: %v", name, p)
		}
	}()
	got, err := unpad(src)
	if wantInvalid {
		if err == nil {
			t.Fatalf("%s accepted an invalid vector and returned %x: %s", name, got, tc.Comment)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s rejected a valid vector: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}

// paddingBlockSize reads the block size the vector was generated for.
func paddingBlockSize(t *testing.T, tc vectors.Case) uint {
	t.Helper()
	for _, flag := range tc.Flags {
		if !strings.HasPrefix(flag, "BlockSize") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(flag, "BlockSize"))
		if err != nil || n <= 0 {
			t.Fatalf("invalid block size flag %q", flag)
		}
		return uint(n)
	}
	t.Fatalf("vector has no BlockSize flag")
	return 0
}

func paddingHex(t *testing.T, tc vectors.Case, field, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("tc%d: %s is not hex: %v", tc.TCID, field, err)
	}
	return b
}
