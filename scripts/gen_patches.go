//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

func main() {
	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot get working directory: %v\n", err)
		os.Exit(1)
	}
	baseline := filepath.Join(repoRoot, ".tmp", "patch-baseline")
	target := filepath.Join(repoRoot, "smx509")
	patchDir := filepath.Join(repoRoot, "scripts", "smx509-patches")
	tmpDir := filepath.Join(repoRoot, ".tmp")

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

	rePath := regexp.MustCompile(`"([ab])/[^"]*"`)

	for _, p := range patches {
		var combined []byte
		for _, f := range p.files {
			srcFile := filepath.Join(baseline, f)
			dstFile := filepath.Join(target, f)
			tmpFile := filepath.Join(tmpDir, "tmp_diff.patch")

			cmd := exec.Command("git", "diff", "--no-index", "--output="+tmpFile, srcFile, dstFile)
			cmd.Dir = repoRoot
			cmd.Run() // exit code 1 means differences exist, which is expected

			data, err := os.ReadFile(tmpFile)
			if err != nil {
				fmt.Printf("Error reading %s: %v\n", tmpFile, err)
				continue
			}

			// Fix paths
			data = rePath.ReplaceAllFunc(data, func(match []byte) []byte {
				prefix := string(match[1]) // 'a' or 'b'
				return []byte(fmt.Sprintf(`"%s/smx509/%s"`, prefix, f))
			})

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

	// Extension files patch (new files)
	var extCombined []byte
	for _, f := range extFiles {
		dstFile := filepath.Join(target, f)
		emptyFile := filepath.Join(tmpDir, "empty_file")
		os.WriteFile(emptyFile, []byte{}, 0644)
		tmpFile := filepath.Join(tmpDir, "tmp_diff.patch")

		cmd := exec.Command("git", "diff", "--no-index", "--output="+tmpFile, emptyFile, dstFile)
		cmd.Dir = repoRoot
		cmd.Run()

		data, err := os.ReadFile(tmpFile)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", tmpFile, err)
			continue
		}

		data = rePath.ReplaceAllFunc(data, func(match []byte) []byte {
			prefix := string(match[1])
			return []byte(fmt.Sprintf(`"%s/smx509/%s"`, prefix, f))
		})

		// Add new file mode header and fix --- line to use /dev/null
		newFileHeader := []byte(fmt.Sprintf("new file mode 100644\n"))
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
