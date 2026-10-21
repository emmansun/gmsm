// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9vectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the committed vector files")

// TestVectorsUpToDate pins the committed vector file to the deterministic
// output of the builders. Run `go test ./internal/cryptotest/sm9vectors -run
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
		t.Fatalf("%s is stale: run `go test ./internal/cryptotest/sm9vectors -run TestVectorsUpToDate -update` and review the diff", path)
	}
}

// TestSuiteGroups checks that every group the consumer test asks for exists
// exactly once, so a rename cannot silently disable a set of cases.
func TestSuiteGroups(t *testing.T) {
	suite, err := BuildSuite()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"SM9SignatureVerify",
		"SM9Decrypt",
		"SM9SignMasterPublicKey",
		"SM9EncryptMasterPublicKey",
		"SM9SignPrivateKey",
		"SM9EncryptPrivateKey",
		"SM9SignMasterPrivateKey",
		"SM9EncryptMasterPrivateKey",
		"SM9ASN1KeyParse",
	} {
		if _, err := suite.Group(name); err != nil {
			t.Fatal(err)
		}
	}
}
