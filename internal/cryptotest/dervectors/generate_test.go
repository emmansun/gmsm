// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package dervectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

const fileName = "der_semantics.json"

var update = flag.Bool("update", false, "rewrite the committed vector file")

// TestVectorsUpToDate pins the committed vector file to the deterministic
// output of the builders. Run `go test ./internal/cryptotest/dervectors -run
// TestVectorsUpToDate -update` after changing a case so the regenerated
// vectors are reviewed like code.
func TestVectorsUpToDate(t *testing.T) {
	want, err := MarshalSuite(BuildSuite())
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
		t.Fatalf("%s is stale: run `go test ./internal/cryptotest/dervectors -run TestVectorsUpToDate -update` and review the diff", path)
	}
}

func TestSuiteLoads(t *testing.T) {
	suite, err := vectors.Load(fileName)
	if err != nil {
		t.Fatal(err)
	}
	if len(suite.Groups) != 4 {
		t.Fatalf("got %d groups, want 4", len(suite.Groups))
	}
}
