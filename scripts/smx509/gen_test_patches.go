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
	testPatchDir := filepath.Join(repoRoot, "scripts", "smx509", "test-patches")
	if err := os.MkdirAll(testPatchDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create test-patches dir: %v\n", err)
		os.Exit(1)
	}

	// Resolve GOROOT for stdlib test file access
	goroot := strings.TrimSpace(mustRun("go", "env", "GOROOT"))
	stdlibDir := filepath.Join(goroot, "src", "crypto", "x509")
	if _, err := os.Stat(stdlibDir); err != nil {
		fmt.Fprintf(os.Stderr, "stdlib dir not found: %s\n", stdlibDir)
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "gen_test_patches_*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// --- 010-testenv-stub.patch (new file, diff against empty) ---
	testenvFile := filepath.Join(target, "internal_testenv.go")
	extPatch := generateNewFilePatch(repoRoot, tmpDir, testenvFile, "internal_testenv.go")
	writePatch(testPatchDir, "010-testenv-stub.patch", extPatch)

	// --- 020-envvars-abs-path.patch (stdlib root_unix_test.go with package rename vs smx509) ---
	stdlibTestFile := filepath.Join(stdlibDir, "root_unix_test.go")
	preparedFile := filepath.Join(tmpDir, "root_unix_test.go")

	// Copy stdlib test file and rename package
	data, err := os.ReadFile(stdlibTestFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read stdlib test file: %v\n", err)
		os.Exit(1)
	}
	data = bytes.Replace(data, []byte("package x509"), []byte("package smx509"), 1)
	if err := os.WriteFile(preparedFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write prepared test file: %v\n", err)
		os.Exit(1)
	}

	dstFile := filepath.Join(target, "root_unix_test.go")
	diffPatch := generateDiffPatch(repoRoot, tmpDir, preparedFile, dstFile, "root_unix_test.go")
	writePatch(testPatchDir, "020-envvars-abs-path.patch", diffPatch)
}

// generateNewFilePatch creates a new-file git patch by diffing against an empty file.
func generateNewFilePatch(repoRoot, tmpDir, dstFile, canonicalName string) []byte {
	emptyFile := filepath.Join(tmpDir, "empty_"+canonicalName)
	os.WriteFile(emptyFile, []byte{}, 0644)

	cmd := exec.Command("git", "diff", "--no-index", emptyFile, dstFile)
	cmd.Dir = repoRoot
	data, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			fmt.Fprintf(os.Stderr, "Error diffing %s: %v\n", canonicalName, err)
			return nil
		}
	}

	data = fixPaths(data, canonicalName)

	// Add new file mode header
	newFileHeader := []byte("new file mode 100644\n")
	if idx := bytes.Index(data, []byte("\nindex ")); idx >= 0 {
		data = append(data[:idx+1], append(newFileHeader, data[idx+1:]...)...)
	}
	// Replace --- "a/smx509/..." with --- /dev/null
	oldSrc := []byte(fmt.Sprintf(`--- "a/smx509/%s"`, canonicalName))
	data = bytes.Replace(data, oldSrc, []byte("--- /dev/null"), 1)

	return data
}

// generateDiffPatch creates a diff patch between two existing files.
func generateDiffPatch(repoRoot, tmpDir, srcFile, dstFile, canonicalName string) []byte {
	// Write src to a temp location with a stable relative path for consistent headers
	srcRel := filepath.Join(tmpDir, "prepared_"+canonicalName)
	data, err := os.ReadFile(srcFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", srcFile, err)
		return nil
	}
	os.WriteFile(srcRel, data, 0644)

	cmd := exec.Command("git", "diff", "--no-index", srcFile, dstFile)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			out = fixPaths(out, canonicalName)
			return out
		}
		fmt.Fprintf(os.Stderr, "Error diffing %s: %v\n", canonicalName, err)
		return nil
	}
	return fixPaths(out, canonicalName)
}

func writePatch(dir, name string, data []byte) {
	if data == nil {
		fmt.Printf("Skipped %s (no data)\n", name)
		return
	}
	outFile := filepath.Join(dir, name)
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		fmt.Printf("Error writing %s: %v\n", name, err)
	} else {
		fmt.Printf("Generated %s (%d bytes)\n", name, len(data))
	}
}

func mustRun(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v: %v\n", name, args, err)
		os.Exit(1)
	}
	return string(out)
}

// fixPaths replaces git diff path labels with canonical "a/smx509/<file>" / "b/smx509/<file>".
// Only modifies the diff header lines (diff --git, ---, +++), not diff content.
func fixPaths(data []byte, filename string) []byte {
	canonical := func(side byte) []byte {
		return []byte(fmt.Sprintf(`"%s/smx509/%s"`, string(side), filename))
	}

	var result []byte
	for len(data) > 0 {
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

		switch {
		case bytes.HasPrefix(line, []byte("diff --git ")):
			result = result[:len(result)-len(line)-1]
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
	s := string(line)
	bIdx := strings.LastIndex(s, ` "b/`)
	if bIdx < 0 {
		bIdx = strings.LastIndex(s, ` "b\`)
	}
	if bIdx < 0 {
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
