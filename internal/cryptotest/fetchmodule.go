// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptotest

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

// FetchModule fetches a module for interoperability tests. Network access must
// be explicitly enabled because ordinary package tests must remain offline.
func FetchModule(t *testing.T, module, version string) string {
	t.Helper()
	if os.Getenv("GO_TEST_EXTERNAL_NETWORK") != "1" {
		t.Skip("skipping external network test; set GO_TEST_EXTERNAL_NETWORK=1 to enable")
	}

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("skipping external module test: go tool not found")
	}
	out, err := exec.Command(goTool, "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	if gomodcache := string(bytes.TrimSpace(out)); gomodcache == "" {
		t.Setenv("GOMODCACHE", t.TempDir())
		t.Setenv("GOFLAGS", os.Getenv("GOFLAGS")+" -modcacherw")
	}

	output, err := exec.Command(goTool, "mod", "download", "-json", module+"@"+version).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to download %s@%s: %v\n%s", module, version, err, output)
	}
	var result struct {
		Dir string
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("failed to parse 'go mod download': %v\n%s", err, output)
	}
	return result.Dir
}
