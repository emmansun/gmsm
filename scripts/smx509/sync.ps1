param(
    [string]$GoRoot = "",
    [string]$PatchDir = "",
    [string]$TestPatchDir = "",
    [string]$TargetDir = "smx509",
    [string]$PackageName = "",
    [switch]$RawUpstream,
    [switch]$AllowUnresolvedInternal,
    [switch]$NoPatch,
    [switch]$DryRun,
    [switch]$TestOnly,
    [string[]]$Files = @(
        "cert_pool.go",
        "oid.go",
        "parser.go",
        "pem_decrypt.go",
        "pkcs1.go",
        "pkcs8.go",
        "root.go",
        "root_aix.go",
        "root_bsd.go",
        "root_darwin.go",
        "root_linux.go",
        "root_plan9.go",
        "root_solaris.go",
        "root_unix.go",
        "root_wasm.go",
        "root_windows.go",
        "sec1.go",
        "verify.go",
        "x509.go"
    )
)

$ErrorActionPreference = "Stop"

$ImportRewriteMap = @{
    "internal/godebug" = "github.com/emmansun/gmsm/internal/godebug"
    "internal/goos" = "github.com/emmansun/gmsm/internal/goos"
}

function Get-ForbiddenInternalImports([string]$Content) {
    $matches = [regex]::Matches($Content, '"([^"]+)"')
    $bad = New-Object System.Collections.Generic.HashSet[string]
    foreach ($m in $matches) {
        $pkg = $m.Groups[1].Value
        if ($pkg -match '^(internal/|crypto/internal/)') {
            [void]$bad.Add($pkg)
        }
    }
    return @($bad)
}

function Rewrite-ImportsAndValidate([string]$FilePath, [switch]$AllowUnresolved, [string]$PackageName) {
    $content = Get-Content -Raw -LiteralPath $FilePath
    $updated = $content

    if (-not [string]::IsNullOrWhiteSpace($PackageName) -and $PackageName -ne 'x509') {
        $updated = $updated -replace '(?m)^package x509\b', ('package ' + $PackageName)
    }

    foreach ($k in $ImportRewriteMap.Keys) {
        $from = '"' + [regex]::Escape($k) + '"'
        $to = '"' + $ImportRewriteMap[$k] + '"'
        $updated = [regex]::Replace($updated, $from, $to)
    }

    $forbidden = Get-ForbiddenInternalImports -Content $updated
    if ($forbidden.Count -gt 0) {
        $list = ($forbidden | Sort-Object) -join ", "
        if ($AllowUnresolved) {
            Write-Warning (("Unresolved internal imports in {0}: {1}") -f $FilePath, $list)
        } else {
            throw (("Unresolved internal imports in {0}: {1}. Add mappings in ImportRewriteMap.") -f $FilePath, $list)
        }
    }

    if ($updated -ne $content) {
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($FilePath, $updated, $enc)
    }
}

function Get-RepoRoot {
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir)) {
        $scriptPath = $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($scriptPath)) {
            throw "Cannot resolve script directory."
        }
        $scriptDir = Split-Path -Parent $scriptPath
    }
    return (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

function Resolve-GoRoot([string]$Value) {
    if (![string]::IsNullOrWhiteSpace($Value)) {
        return (Resolve-Path $Value).Path
    }

    $goroot = (& go env GOROOT).Trim()
    if ([string]::IsNullOrWhiteSpace($goroot)) {
        throw "Cannot resolve GOROOT. Pass -GoRoot explicitly."
    }
    return (Resolve-Path $goroot).Path
}

function Apply-Patches([string]$RepoRoot, [string]$Dir, [switch]$CheckOnly) {
    if (!(Test-Path -LiteralPath $Dir)) {
        Write-Host "Patch directory not found: $Dir"
        return
    }

    $patches = Get-ChildItem -LiteralPath $Dir -File -Filter "*.patch" | Sort-Object Name
    if ($patches.Count -eq 0) {
        Write-Host "No patch files found in $Dir"
        return
    }

    foreach ($patch in $patches) {
        $args = @("-C", $RepoRoot, "apply", "--whitespace=nowarn")
        if ($CheckOnly) {
            $args += "--check"
        }
        $args += $patch.FullName

        Write-Host (("Applying patch: {0}") -f $patch.Name)
        & git @args
        if ($LASTEXITCODE -ne 0) {
            throw (("Failed to apply patch: {0}") -f $patch.Name)
        }
    }
}

$repoRoot = Get-RepoRoot
$resolvedGoRoot = Resolve-GoRoot -Value $GoRoot

if ([string]::IsNullOrWhiteSpace($PatchDir)) {
    $PatchDir = $null
} elseif (!(Split-Path -IsAbsolute $PatchDir)) {
    $PatchDir = Join-Path $repoRoot $PatchDir
}

$srcDir = Join-Path $resolvedGoRoot "src\crypto\x509"
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    throw "TargetDir cannot be empty."
}
if (Split-Path -IsAbsolute $TargetDir) {
    $dstDir = $TargetDir
} else {
    $dstDir = Join-Path $repoRoot $TargetDir
}

if (!(Test-Path -LiteralPath $srcDir)) {
    throw "Source directory not found: $srcDir"
}
if (!(Test-Path -LiteralPath $dstDir)) {
    New-Item -ItemType Directory -Path $dstDir | Out-Null
}

$targetLeaf = Split-Path -Leaf $dstDir
if ([string]::IsNullOrWhiteSpace($PatchDir)) {
    $PatchDir = Join-Path $repoRoot ("scripts\" + $targetLeaf + "\patches")
}
if ([string]::IsNullOrWhiteSpace($TestPatchDir)) {
    $TestPatchDir = Join-Path $repoRoot ("scripts\" + $targetLeaf + "\test-patches")
}
if ([string]::IsNullOrWhiteSpace($PackageName)) {
    if ($targetLeaf -ieq "x509") {
        $PackageName = "x509"
    } else {
        $PackageName = "smx509"
    }
}

Write-Host "Repo root:    $repoRoot"
Write-Host "GOROOT:       $resolvedGoRoot"
Write-Host "Source dir:   $srcDir"
Write-Host "Target dir:   $dstDir"
Write-Host "Package:      $PackageName"
Write-Host "Patch dir:    $PatchDir"
Write-Host "Test patches: $TestPatchDir"

# --- Source file sync ---
if (-not $TestOnly) {
    foreach ($file in $Files) {
        $src = Join-Path $srcDir $file
        $dstFile = $file
        if ($NoPatch) {
            $dstFile = $file + ".txt"  # baseline files use .go.txt to avoid Go build
        }
        $dst = Join-Path $dstDir $dstFile

        if (!(Test-Path -LiteralPath $src)) {
            throw (("Missing upstream file: {0}") -f $src)
        }

        Write-Host (("Sync file: {0}") -f $file)
        Copy-Item -LiteralPath $src -Destination $dst -Force
        if (-not $RawUpstream) {
            Rewrite-ImportsAndValidate -FilePath $dst -AllowUnresolved:$AllowUnresolvedInternal -PackageName $PackageName
        }
    }

    if (-not $NoPatch) {
        Apply-Patches -RepoRoot $repoRoot -Dir $PatchDir -CheckOnly:$DryRun
    } else {
        Write-Host "Skipping source patch application due to -NoPatch"
    }
}

# --- Test file sync ---
Write-Host ""
Write-Host "=== Test file sync ==="

# Auto-detect test files from stdlib
$testFiles = Get-ChildItem -LiteralPath $srcDir -Filter "*_test.go" -File | ForEach-Object { $_.Name }
Write-Host (("Found {0} test files in stdlib") -f $testFiles.Count)

# Copy test files and rename package
foreach ($tf in $testFiles) {
    $src = Join-Path $srcDir $tf
    $dst = Join-Path $dstDir $tf
    Write-Host (("Sync test file: {0}") -f $tf)
    Copy-Item -LiteralPath $src -Destination $dst -Force
    if ($PackageName -ne "x509") {
        $content = Get-Content -Raw -LiteralPath $dst
        $updated = $content -replace '(?m)^package x509\b', ('package ' + $PackageName)
        if ($updated -ne $content) {
            $enc = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($dst, $updated, $enc)
        }
    }
}

# Copy testdata directory
$srcTestdata = Join-Path $srcDir "testdata"
$dstTestdata = Join-Path $dstDir "testdata"
if (Test-Path -LiteralPath $srcTestdata) {
    Write-Host "Sync testdata directory"
    if (Test-Path -LiteralPath $dstTestdata) {
        Remove-Item -LiteralPath $dstTestdata -Recurse -Force
    }
    Copy-Item -LiteralPath $srcTestdata -Destination $dstTestdata -Recurse -Force
}

# Apply test patches
if (-not $NoPatch) {
    Apply-Patches -RepoRoot $repoRoot -Dir $TestPatchDir -CheckOnly:$DryRun
} else {
    Write-Host "Skipping test patch application due to -NoPatch"
}

Write-Host (("{0} sync completed.") -f $targetLeaf)
