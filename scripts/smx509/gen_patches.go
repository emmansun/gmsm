//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot get working directory: %v\n", err)
		os.Exit(1)
	}
	target := filepath.Join(repoRoot, "smx509")
	patchDir := filepath.Join(repoRoot, "scripts", "smx509", "patches")

	type patchDef struct {
		name  string
		files []string
	}

	patches := []patchDef{
		{"001-root-platform.patch", []string{"root_darwin.go", "root_linux.go"}},
		{"010-sm2-pqc-core.patch", []string{"x509.go", "parser.go", "verify.go"}},
		{"020-pkcs-keys.patch", []string{"pkcs8.go", "sec1.go"}},
		{"030-sm4-pem.patch", []string{"pem_decrypt.go"}},
	}

	// Extension files (new files, diff against empty)
	extFiles := []string{"cfca_csr.go", "csr_rsp.go", "explicit_curves.go", "verify_digest.go"}

	// gitDiff runs git diff --no-index using relative paths from repo root.
	// Relative paths ensure consistent diff headers across platforms (Windows/Linux).
	gitDiff := func(srcRel, dstRel string) ([]byte, error) {
		cmd := exec.Command("git", "diff", "--no-index", srcRel, dstRel)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			// exit code 1 means differences exist, which is expected
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return out, nil
			}
			return nil, err
		}
		return out, nil
	}

	// Relative path prefixes (forward slashes work on all platforms with git)
	srcRelPrefix := "scripts/smx509/baseline/"
	dstRelPrefix := "smx509/"

	for _, p := range patches {
		var combined []byte
		for _, f := range p.files {
			srcRel := srcRelPrefix + f + ".txt" // baseline uses .go.txt to avoid Go build
			dstRel := dstRelPrefix + f

			data, err := gitDiff(srcRel, dstRel)
			if err != nil {
				fmt.Printf("Error diffing %s: %v\n", f, err)
				continue
			}

			// Normalize path labels to canonical "a/smx509/<file>" / "b/smx509/<file>"
			data = fixPaths(data, f)

			if len(combined) > 0 {
				combined = append(combined, '\n')
			}
			combined = append(combined, data...)
		}

		outFile := filepath.Join(patchDir, p.name)
		if err := os.WriteFile(outFile, combined, 0644); err != nil {
			fmt.Printf("Error writing %s: %v\n", outFile, err)
		} else {
			fmt.Printf("Generated %s (%d bytes)\n", p.name, len(combined))
		}
	}

	// Extension files patch (new files, diff against empty)
	var extCombined []byte
	for _, f := range extFiles {
		dstFile := filepath.Join(target, f)

		// Create empty file for diff source
		tmpDir, _ := os.MkdirTemp("", "gen_patches_*")
		emptyFile := filepath.Join(tmpDir, "empty")
		os.WriteFile(emptyFile, []byte{}, 0644)

		cmd := exec.Command("git", "diff", "--no-index", emptyFile, dstFile)
		cmd.Dir = repoRoot
		data, err := cmd.CombinedOutput()
		os.RemoveAll(tmpDir)
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				fmt.Printf("Error diffing %s: %v\n", f, err)
				continue
			}
		}

		data = fixPaths(data, f)

		// Add new file mode header
		newFileHeader := []byte("new file mode 100644\n")
		if idx := bytes.Index(data, []byte("\nindex ")); idx >= 0 {
			data = append(data[:idx+1], append(newFileHeader, data[idx+1:]...)...)
		}
		// Replace --- "a/smx509/..." with --- /dev/null
		oldSrc := []byte(fmt.Sprintf(`--- "a/smx509/%s"`, f))
		data = bytes.Replace(data, oldSrc, []byte("--- /dev/null"), 1)

		if len(extCombined) > 0 {
			extCombined = append(extCombined, '\n')
		}
		extCombined = append(extCombined, data...)
	}

	outFile := filepath.Join(patchDir, "100-extensions.patch")
	if err := os.WriteFile(outFile, extCombined, 0644); err != nil {
		fmt.Printf("Error writing %s: %v\n", outFile, err)
	} else {
		fmt.Printf("Generated 100-extensions.patch (%d bytes)\n", len(extCombined))
	}
}

// fixPaths replaces git diff path labels with canonical "a/smx509/<file>" / "b/smx509/<file>".
// Only modifies the diff header lines (diff --git, ---, +++), not diff content.
func fixPaths(data []byte, filename string) []byte {
	canonical := func(side byte) []byte {
		return []byte(fmt.Sprintf(`"%s/smx509/%s"`, string(side), filename))
	}

	var result []byte
	for len(data) > 0 {
		// Find next newline
		nl := bytes.IndexByte(data, '\n')
		var line []byte
		if nl >= 0 {
			line = data[:nl]
			data = data[nl+1:]
			result = append(result, line...)
			result = append(result, '\n')
		} else {
			line = data
			data = nil
			result = append(result, line...)
		}

		// Only fix path labels in diff header lines
		switch {
		case bytes.HasPrefix(line, []byte("diff --git ")):
			// Format: diff --git a/path b/path
			result = result[:len(result)-len(line)-1] // remove what we just added
			fixed := fixDiffGitLine(line, canonical)
			result = append(result, fixed...)
			result = append(result, '\n')
		case bytes.HasPrefix(line, []byte("--- ")):
			result = result[:len(result)-len(line)-1]
			result = append(result, []byte("--- ")...)
			result = append(result, canonical('a')...)
			result = append(result, '\n')
		case bytes.HasPrefix(line, []byte("+++ ")):
			result = result[:len(result)-len(line)-1]
			result = append(result, []byte("+++ ")...)
			result = append(result, canonical('b')...)
			result = append(result, '\n')
		}
	}
	return result
}

// fixDiffGitLine fixes the "diff --git a/... b/..." line.
func fixDiffGitLine(line []byte, canonical func(byte) []byte) []byte {
	// Find the boundary between a-path and b-path.
	// Look for ` "b/` or ` "b\` (space + quote + b + path separator).
	s := string(line)
	bIdx := strings.LastIndex(s, ` "b/`)
	if bIdx < 0 {
		bIdx = strings.LastIndex(s, ` "b\`)
	}
	if bIdx < 0 {
		// Unquoted format: look for ` b/` or ` b\`
		bIdx = strings.LastIndex(s, " b/")
		if bIdx < 0 {
			bIdx = strings.LastIndex(s, " b\\")
		}
		if bIdx < 0 {
			return line
		}
	}

	var result []byte
	result = append(result, []byte("diff --git ")...)
	result = append(result, canonical('a')...)
	result = append(result, ' ')
	result = append(result, canonical('b')...)
	return result
}
