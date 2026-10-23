// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm4vectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

var update = flag.Bool("update", false, "rewrite the committed vector files")

// TestVectorsUpToDate pins the committed vector files to the deterministic
// output of the builders. Run `go test ./internal/cryptotest/sm4vectors -run
// TestVectorsUpToDate -update` after changing a case so the regenerated
// vectors are reviewed like code.
func TestVectorsUpToDate(t *testing.T) {
	t.Run("AEAD", func(t *testing.T) {
		suite, err := BuildAEADSuite()
		if err != nil {
			t.Fatal(err)
		}
		checkFile(t, aeadFileName, suite)
	})
	t.Run("Padding", func(t *testing.T) {
		suite, err := BuildPaddingSuite()
		if err != nil {
			t.Fatal(err)
		}
		checkFile(t, paddingFileName, suite)
	})
}

func checkFile(t *testing.T, name string, suite *vectors.Suite) {
	t.Helper()
	want, err := MarshalSuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "vectors", "testdata", name)

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
		t.Fatalf("%s is stale: run `go test ./internal/cryptotest/sm4vectors -run TestVectorsUpToDate -update` and review the diff", path)
	}
}
