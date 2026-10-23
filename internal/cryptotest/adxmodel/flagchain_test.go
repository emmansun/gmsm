// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package adxmodel

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckADOXChains(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		findings int
	}{
		{
			name: "clean adox chain",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	XORQ acc5, acc5
	ADOXQ AX, acc1
	ADOXQ res_ptr, acc2`,
		},
		{
			name: "stale of from sbb chain",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	SBBQ DX, acc0
	ADOXQ AX, acc1`,
			findings: 1,
		},
		{
			name: "stale of from shift",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	SHLQ $32, AX
	ADOXQ AX, acc1`,
			findings: 1,
		},
		{
			name: "logical op clears of",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	SBBQ DX, acc0
	XORQ acc0, acc0
	ADOXQ AX, acc1`,
		},
		{
			name: "adcx does not disturb of",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	XORQ acc5, acc5
	SBBQ DX, acc0
	ADCXQ AX, acc1
	ADOXQ AX, acc1`,
			findings: 1,
		},
		{
			name: "transparent instructions preserve chain",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	XORQ acc5, acc5
	ADOXQ AX, acc1
	MOVQ acc0, AX
	MULXQ (SI), AX, BX
	CMOVQCC AX, BX
	ADOXQ AX, acc2`,
		},
		{
			name: "of inherited at text entry",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	ADOXQ AX, acc1`,
			findings: 1,
		},
		{
			name: "new text resets the chain",
			src: `TEXT ·mul(SB),NOSPLIT,$0
	XORQ acc5, acc5
	ADOXQ AX, acc1
TEXT ·sqr(SB),NOSPLIT,$0
	ADOXQ AX, acc1`,
			findings: 1,
		},
	}
	for _, tc := range tests {
		got := CheckADOXChains([]byte(tc.src))
		if len(got) != tc.findings {
			t.Errorf("%s: got %d findings %v, want %d", tc.name, len(got), got, tc.findings)
		}
	}
}

// TestRepoAssembliesHaveCleanADOXChains is the static half of the issue #560
// defense: every ADOXQ in the repository must consume the OF channel it
// maintains (or an explicitly cleared flag), never the signed-overflow OF of a
// subtraction or shift. It runs on every architecture because it only reads
// assembly text.
func TestRepoAssembliesHaveCleanADOXChains(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var files int
	var findings []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".s" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		for _, f := range CheckADOXChains(src) {
			rel, _ := filepath.Rel(root, path)
			findings = append(findings, rel+":"+itoa(f.Line)+": ADOXQ after "+f.Producer)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no assembly files found; the repository root computation is wrong")
	}
	if len(findings) > 0 {
		t.Fatalf("ADOXQ consumes a foreign OF in %d place(s):\n%s", len(findings), strings.Join(findings, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
