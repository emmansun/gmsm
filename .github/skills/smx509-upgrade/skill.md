---
name: smx509-upgrade
description: Guide through upgrading smx509 module when a new Go stable version is released. Covers stdlib crypto/x509 baseline update, patch conflict analysis and resolution, test file re-sync with custom fix re-application, and patch regeneration. Use when upgrading from Go 1.N to 1.N+1.
license: MIT
metadata:
  owner: gmsm
  targets:
    - smx509
    - scripts
    - crypto/x509
    - patch-management
    - go-upgrade
---

# smx509 Upgrade Skill — Go Stable Version Upgrade Workflow

> **Quick Reference**: See [`scripts/smx509/README.md`](../../../scripts/smx509/README.md) for directory structure, all 3 workflows (direct edit / minor upgrade / major upgrade), and command cheat sheet.

## Overview

This skill guides the upgrade of the `smx509` module when a new Go stable version is released (e.g., Go 1.25 → 1.26). The smx509 module is a clean fork of Go stdlib `crypto/x509` with declarative patches for SM2/PQC/SM4 extensions.

## Prerequisites

- New Go stable version installed locally (e.g., `go1.26` or via `go install`)
- `GOROOT` pointing to the new Go version
- Working tree clean on `develop` branch
- Baseline at `scripts/smx509/baseline/` (committed, from previous sync)

## Architecture Reference

```
scripts/smx509/
├── sync.ps1                  # Copies stdlib → smx509/ + applies patches
├── gen_patches.go             # Regenerates patches from baseline↔smx509 diff
├── baseline/                  # Go stdlib baseline (committed, version-pinned)
│   ├── x509.go
│   ├── parser.go
│   └── ... (19 files)
├── patches/                   # Declarative source patches (5 files)
│   ├── 001-root-platform.patch
│   ├── 010-sm2-pqc-core.patch
│   ├── 020-pkcs-keys.patch
│   ├── 030-sm4-pem.patch
│   └── 100-extensions.patch
├── test-patches/              # Declarative test patches (2 files)
│   ├── 010-testenv-stub.patch
│   └── 020-envvars-abs-path.patch
└── gen_test_patches.go        # Regenerates test patches from stdlib↔smx509 diff
```

**Patch numbering convention:**
- `001`: Platform-specific root stubs (darwin/linux)
- `010`: SM2 + PQC core integration (x509.go, parser.go, verify.go)
- `020`: PKCS#8 key encoding (pkcs8.go, sec1.go)
- `030`: SM4 PEM encryption (pem_decrypt.go)
- `100`: Extension files (new files: cfca_csr.go, verify_digest.go, etc.)

## Workflow Steps

### Step 1: Create Upgrade Branch

```bash
git checkout develop
git pull origin develop
git checkout -b upgrade-smx509-go1.N
```

### Step 2: Analyze stdlib Changes

Compare the new Go stdlib `crypto/x509/` against the current baseline:

```bash
# Copy new stdlib files to a temp location for comparison
mkdir -p .tmp/new-stdlib
cp $GOROOT/src/crypto/x509/*.go .tmp/new-stdlib/

# Diff against committed baseline
diff -r scripts/smx509/baseline/ .tmp/new-stdlib/ --brief
```

**Key questions to answer:**
1. Which files changed? (affects which patches may conflict)
2. Are there new files? (may need new patch or extension)
3. Are there deleted files? (unlikely for crypto/x509)
4. What's the nature of changes? (API additions, refactoring, security fixes)

### Step 3: Update Baseline

Replace the baseline with the new stdlib:

```bash
rm -rf scripts/smx509/baseline/
mkdir scripts/smx509/baseline/
pwsh scripts/smx509/sync.ps1 -TargetDir scripts/smx509/baseline -PackageName smx509 -NoPatch
```

### Step 4: Try Clean Rebuild

```bash
# Clean smx509/ source files (keep extension files and testdata)
# Re-run sync with new baseline
pwsh scripts/smx509/sync.ps1 -TargetDir smx509 -PackageName smx509
```

**Expected outcomes:**
- ✅ All patches apply cleanly → skip to Step 7
- ❌ Patch conflicts → proceed to Step 5

### Step 5: Resolve Patch Conflicts

For each failing patch, analyze the conflict:

#### 5.1 Check Which Patches Fail

```bash
# The sync script will stop at the first failing patch
# Use -DryRun to pre-validate all patches:
pwsh scripts/smx509/sync.ps1 -TargetDir smx509 -PackageName smx509 -DryRun
```

#### 5.2 Conflict Classification

| Type | Description | Resolution |
|------|-------------|------------|
| **Context shift** | Surrounding lines moved but logic unchanged | Regenerate patch against new baseline |
| **Semantic overlap** | stdlib changed same code we patched | Manual merge: keep our SM2/PQC logic + adopt stdlib changes |
| **New API** | stdlib added new functions/types | Usually no conflict; may need to extend our patches |
| **Refactoring** | stdlib restructured code | Major patch rewrite needed |

#### 5.3 Resolution Strategy

For each conflicted patch:

1. **Temporarily skip the patch** and let the clean baseline copy through
2. **Manually apply** our modifications to the new baseline file
3. **Regenerate** the patch using `gen_patches.go`

```bash
# After manual fixes in smx509/:
go run scripts/smx509/gen_patches.go
```

#### 5.4 SM2/PQC/SM4 Invariants

When resolving conflicts, these MUST be preserved:

- **SM2 OID constants**: `oidSignatureSM2WithSM3`, `oidPublicKeySM2`
- **SM2WithSM3 SignatureAlgorithm**: entry in `signatureAlgorithmDetails`, SM2 branch in `checkSignature`
- **PQC algorithms**: `MLDSA44/65/87`, `SLHDSASHA2128s` — same pattern as SM2
- **SM4 PEM**: `PEMCipherSM4` constant, SM4-CBC in `rfc1423Algos`
- **PKCS#8**: SM2/ML-DSA/SLH-DSA branches in `ParsePKCS8PrivateKey` and `MarshalPKCS8PrivateKey`
- **verify_digest.go**: `CheckSignatureWithDigest` with SHA1 rejection (matches `checkSignature` behavior)
- **Import rewrites**: `internal/godebug` → `github.com/emmansun/gmsm/internal/godebug`, same for `internal/goos`
- **Platform stubs**: `root_darwin.go` stays as stub (no CGO), `root_linux.go` stays simplified

### Step 6: Sync Test Files

Test files are synced automatically by `sync.ps1` (test file sync section). The script:
1. Copies `*_test.go` from stdlib `crypto/x509/` to `smx509/`
2. Copies `testdata/` from stdlib to `smx509/testdata/`
3. Renames `package x509` → `package smx509` in all test files
4. Applies declarative test patches from `scripts/smx509/test-patches/`

```bash
# Test-only sync (source files unchanged):
pwsh scripts/smx509/sync.ps1 -TestOnly

# Full sync (source + test):
pwsh scripts/smx509/sync.ps1
```

**Current test patches:**
- `010-testenv-stub.patch`: new file `internal_testenv.go` (stub for `internal/testenv`)
- `020-envvars-abs-path.patch`: fixes TestEnvVars `SSL_CERT_FILE` to use absolute paths

After sync, verify custom test fixes are preserved:
- `root_unix_test.go`: TestEnvVars uses `filepath.Join(tmpDir, testFile)` for SSL_CERT_FILE
- `internal_testenv.go`: stub for `internal/testenv` replacement
- Package name: all `*_test.go` must have `package smx509`

**If test patches need updating** (stdlib changed the affected code):
```bash
# Manually fix test files in smx509/
# Then regenerate test patches:
go run scripts/smx509/gen_test_patches.go
```

### Step 7: Validate

```bash
# Build all platforms
go build ./...
GOOS=linux go build ./...
GOOS=darwin go build ./...
GOOS=darwin GOARCH=arm64 go build ./...

# Run tests
go test ./smx509/...
go test ./pkcs7/... ./cfca/... ./pkcs8/...

# Full project test
go test ./...
```

### Step 8: Regenerate Patches

```bash
# Source patches
go run scripts/smx509/gen_patches.go

# Test patches
go run scripts/smx509/gen_test_patches.go
```

Verify all 5 patches are regenerated:
- `001-root-platform.patch`
- `010-sm2-pqc-core.patch`
- `020-pkcs-keys.patch`
- `030-sm4-pem.patch`
- `100-extensions.patch`

### Step 9: Commit and Merge

```bash
git add -A
git commit -m "feat(smx509): upgrade to Go 1.N stdlib baseline

- Update .tmp/patch-baseline to Go 1.N
- Regenerate all smx509 patches
- Sync test files from stdlib
- Re-apply custom test fixes"

# After CI passes:
git checkout develop
git merge --no-ff upgrade-smx509-go1.N
git push origin develop
```

## Common Pitfalls

1. **`gen_patches.go` must run from repo root** — it uses `os.Getwd()` to resolve paths
2. **Baseline is committed** — `scripts/smx509/baseline/` is version-controlled, update it explicitly on Go upgrade
3. **`sync.ps1` defaults to `smx509`** — `-TargetDir` and `-PackageName` can be omitted for standard usage
4. **PowerShell git ExitCode=1** — PowerShell treats git stderr as error; check actual output, not exit code
5. **Test files NOT in source patches** — `*_test.go` changes are in `test-patches/`, not in `patches/`
6. **`internal/` imports** — any new `internal/*` or `crypto/internal/*` imports in stdlib must be added to `ImportRewriteMap` in `sync.ps1`
7. **Test patches must be regenerated** — if stdlib changed `root_unix_test.go` or test files referencing `testenv`, run `gen_test_patches.go`

## Decision Checklist

Before merging, verify:
- [ ] All patches apply cleanly on fresh baseline
- [ ] `go build ./...` passes on linux/darwin/windows × amd64/arm64
- [ ] `go test ./smx509/...` passes
- [ ] `go test ./pkcs7/... ./cfca/... ./pkcs8/...` passes
- [ ] `gen_patches.go` output matches committed patches (CI check)
- [ ] `gen_test_patches.go` output matches committed test-patches
- [ ] Test files have correct `package smx509`
- [ ] Custom test fixes are re-applied
- [ ] `ImportRewriteMap` updated if stdlib added new internal imports
