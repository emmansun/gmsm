// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zucvectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the committed vector files")

// TestVectorsUpToDate pins the committed vector file to the deterministic
// output of the builders. Run `go test ./internal/cryptotest/zucvectors -run
// TestVectorsUpToDate -update` after changing a case so the regenerated
// vectors are reviewed like code.
func TestVectorsUpToDate(t *testing.T) {
	suite, err := BuildSuite()
	if err != nil {
		t.Fatal(err)
	}
	want, err := MarshalSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "vectors", "testdata", fileName)

	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		t.Logf("updated %s", path)
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run with -update to create it): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run `go test ./internal/cryptotest/zucvectors -run TestVectorsUpToDate -update` and review the diff", path)
	}
}

// TestFrameIV pins both frame IV layouts independently of the library. The
// EEA layout puts the bearer in the top five bits of the octet after the
// counter and the direction below it; the EIA layout leaves the bearer octet
// alone and carries the direction at the top of the second counter copy and
// in the fourteenth octet.
func TestFrameIV(t *testing.T) {
	eea := eeaFrameIV(0x66035492, 0xf, 1)
	wantEEA := []byte{
		0x66, 0x03, 0x54, 0x92,
		0x7c, 0x00, 0x00, 0x00,
		0x66, 0x03, 0x54, 0x92,
		0x7c, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(eea, wantEEA) {
		t.Fatalf("eeaFrameIV() = %x, want %x", eea, wantEEA)
	}

	eia := eiaFrameIV(0xa94059da, 0x0a, 1)
	wantEIA := []byte{
		0xa9, 0x40, 0x59, 0xda,
		0x50, 0x00, 0x00, 0x00,
		0xa9 ^ 0x80, 0x40, 0x59, 0xda,
		0x50, 0x00, 0x80, 0x00,
	}
	if !bytes.Equal(eia, wantEIA) {
		t.Fatalf("eiaFrameIV() = %x, want %x", eia, wantEIA)
	}

	zero := make([]byte, 16)
	if got := eeaFrameIV(0, 0, 0); !bytes.Equal(got, zero) {
		t.Fatalf("eeaFrameIV(0, 0, 0) = %x, want %x", got, zero)
	}
	if got := eiaFrameIV(0, 0, 0); !bytes.Equal(got, zero) {
		t.Fatalf("eiaFrameIV(0, 0, 0) = %x, want %x", got, zero)
	}
}

// TestSuiteGroups checks that every group the consumer test asks for exists
// exactly once.
func TestSuiteGroups(t *testing.T) {
	suite, err := BuildSuite()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ZUCEEA", "ZUCEEAInit", "ZUCEIA", "ZUC256EIA"} {
		if _, err := suite.Group(name); err != nil {
			t.Fatal(err)
		}
	}
}
