// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package vectors defines a Wycheproof-style JSON schema for adversarial
// cryptographic test vectors and loads the committed vector files.
//
// Two kinds of suites share the schema:
//
//   - Semantics suites (valid/invalid/acceptable) pin specification behaviour,
//     e.g. which encodings a parser must reject.
//   - Kernel suites pin exact field/kernel outputs for inputs that sit on
//     rare carry/sign boundaries. Those boundaries are unreachable by random
//     differential fuzzing (the trigger probability can be as low as 2^-33,
//     see issue #560), so the inputs are constructed rather than sampled,
//     and the expected output is the exact result of the reference model.
package vectors

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed testdata/*.json
var files embed.FS

// Suite is one committed vector file.
type Suite struct {
	// Schema identifies the schema revision, e.g. "gmsm-kernel-vectors/v1".
	Schema string `json:"schema"`
	// Algorithm names the primitive under test, e.g. "sm2p256v1".
	Algorithm string `json:"algorithm"`
	// Generator describes how the vectors were produced and how to
	// regenerate them.
	Generator string `json:"generator,omitempty"`
	// Groups partitions the tests by API shape and execution requirements.
	Groups []Group `json:"testGroups"`
}

// Group is a set of cases that share an API shape and the same execution
// requirements.
type Group struct {
	// Type is the operation under test, e.g. "FieldMul".
	Type string `json:"type"`
	// Arch lists the GOARCH values the group is meaningful on. Empty means
	// any architecture.
	Arch []string `json:"arch,omitempty"`
	// Features lists CPU features required to execute the group, e.g.
	// "adx", "bmi2". Empty means no feature requirement.
	Features []string `json:"features,omitempty"`
	// Comment documents why the group exists and how the cases were built.
	Comment string `json:"comment,omitempty"`
	Tests   []Case `json:"tests"`
}

// Case is one test vector. Field values are fixed-width big-endian hex so
// they are independent of the host word order and limb representation.
type Case struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment,omitempty"`
	Flags   []string `json:"flags,omitempty"`
	// A and B are the operands; B is empty for unary operations.
	A string `json:"a"`
	B string `json:"b,omitempty"`
	// Expected is the exact result of the reference implementation.
	Expected string `json:"expected"`
}

// Load unmarshals a committed vector file by name, e.g.
// "sm2ec_p256_mul_bmi2.json".
func Load(name string) (*Suite, error) {
	data, err := files.ReadFile("testdata/" + name)
	if err != nil {
		return nil, fmt.Errorf("vectors: %w", err)
	}
	var s Suite
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("vectors: parsing %s: %w", name, err)
	}
	if len(s.Groups) == 0 {
		return nil, fmt.Errorf("vectors: %s has no test groups", name)
	}
	return &s, nil
}

// Group returns the single group of the given type. It reports an error when
// the group is absent, which guards against silently skipping a suite after a
// rename.
func (s *Suite) Group(typ string) (*Group, error) {
	var found *Group
	for i := range s.Groups {
		if s.Groups[i].Type != typ {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("vectors: %s contains multiple %q groups", s.Algorithm, typ)
		}
		found = &s.Groups[i]
	}
	if found == nil {
		types := make([]string, len(s.Groups))
		for i := range s.Groups {
			types[i] = s.Groups[i].Type
		}
		sort.Strings(types)
		return nil, fmt.Errorf("vectors: %s has no %q group (have %v)", s.Algorithm, typ, types)
	}
	return found, nil
}

// Requires reports whether the group can run on the given architecture and
// feature set, and lists the constraints that are not satisfied. An unknown
// feature name is an error rather than a silent skip, so a typo in a vector
// file cannot disable a group.
func (g *Group) Requires(goarch string, has map[string]bool) (bool, []string, error) {
	var missing []string
	if len(g.Arch) > 0 {
		ok := false
		for _, a := range g.Arch {
			if a == goarch {
				ok = true
			}
		}
		if !ok {
			missing = append(missing, "arch="+goarch)
		}
	}
	for _, f := range g.Features {
		supported, known := has[f]
		if !known {
			return false, nil, fmt.Errorf("vectors: unknown feature %q in group %q", f, g.Type)
		}
		if !supported {
			missing = append(missing, "feature="+f)
		}
	}
	return len(missing) == 0, missing, nil
}

// DecodeHex32 decodes a fixed-width, 32-byte big-endian hex value, the
// representation used by every 256-bit field element in the suites.
func DecodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("vectors: %q is not 64 hex characters", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("vectors: %w", err)
	}
	copy(out[:], b)
	return out, nil
}
