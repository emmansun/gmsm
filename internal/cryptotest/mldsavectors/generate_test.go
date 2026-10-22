package mldsavectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the committed vector file")

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
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ML-DSA vectors are stale: run go test ./internal/cryptotest/mldsavectors -run TestVectorsUpToDate -update")
	}
}
