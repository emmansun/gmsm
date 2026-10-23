// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package diff implements differential testing for the multi-architecture
// kernels in this repository: assembly/SIMD implementations and the public
// dispatch paths are executed side by side with an in-repo generic reference
// over a declaratively defined input domain (lengths, alignments, overlaps,
// deterministic input patterns) and must agree bit-exactly.
//
// A Suite is always local to the API shape under test; there is no global
// registration. Every implementation execution materializes its own guarded
// buffers so implementations cannot influence each other through shared
// memory. Failures report a stable case ID, the full case descriptor, the
// first divergent byte and an exact rerun command.
//
// The package is only linked into test binaries; its flags are registered
// for the go test command line.
package diff

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var (
	flagSeed    = flag.Uint64("diff.seed", 0, "master seed mixed into deterministic random case inputs (default 0 = fixed corpus)")
	flagDump    = flag.Bool("diff.dump", false, "dump full got/want buffers on differential mismatch")
	flagProfile = flag.String("diff.profile", "", "case profile: smoke, pr or extended (default: smoke with -short, otherwise pr)")
)

// MasterSeed returns the -diff.seed flag value.
func MasterSeed() uint64 { return *flagSeed }

// DumpBuffers returns the -diff.dump flag value.
func DumpBuffers() bool { return *flagDump }

// Profile selects how much of a Domain is enumerated.
type Profile uint8

const (
	// ProfileSmoke covers a bounded subset: key boundary lengths, a small
	// curated alignment set, none/exact overlaps and two patterns. It is
	// the default with -short and keeps PR CI fast.
	ProfileSmoke Profile = iota
	// ProfilePR covers all declared lengths, overlaps and patterns with the
	// curated alignment set. It is the default without -short.
	ProfilePR
	// ProfileExtended enumerates the full declared domain, including all
	// declared alignment pairs and seed variations. Enable with
	// -diff.profile=extended or DIFF_PROFILE=extended.
	ProfileExtended
)

// CurrentProfile resolves the active profile from -diff.profile, then
// DIFF_PROFILE, then testing.Short().
func CurrentProfile() Profile {
	switch strings.ToLower(*flagProfile) {
	case "smoke":
		return ProfileSmoke
	case "pr":
		return ProfilePR
	case "extended":
		return ProfileExtended
	}
	switch strings.ToLower(os.Getenv("DIFF_PROFILE")) {
	case "smoke":
		return ProfileSmoke
	case "pr":
		return ProfilePR
	case "extended":
		return ProfileExtended
	}
	if testing.Short() {
		return ProfileSmoke
	}
	return ProfilePR
}
