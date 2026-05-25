// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || arm64 || loong64)

package keccakx4

import "crypto/sha3"

// SHAKE128x4 provides 4 parallel SHAKE128 XOF instances.
// The generic implementation uses 4 independent crypto/sha3.SHAKE128.
type SHAKE128x4 struct {
	states [4]*sha3.SHAKE
}

// AbsorbSeed absorbs a shared seed followed by per-lane 2-byte indices.
// This matches the ML-KEM/ML-DSA ExpandA pattern:
//
//	lane[i] = SHAKE128(seed || indices[i][0] || indices[i][1])
//
// The seed length + 2 must be less than RateSHAKE128 (168).
func (s *SHAKE128x4) AbsorbSeed(seed []byte, indices [4][2]byte) {
	for i := range 4 {
		s.states[i] = sha3.NewSHAKE128()
		s.states[i].Write(seed)
		s.states[i].Write(indices[i][:])
	}
}

// Squeeze reads len(out0) bytes from each lane.
func (s *SHAKE128x4) Squeeze(out0, out1, out2, out3 []byte) {
	s.states[0].Read(out0)
	s.states[1].Read(out1)
	s.states[2].Read(out2)
	s.states[3].Read(out3)
}

// Reset clears the state for reuse.
func (s *SHAKE128x4) Reset() {
	s.states = [4]*sha3.SHAKE{}
}

// SHAKE256x4 provides 4 parallel SHAKE256 XOF instances.
// The generic implementation uses 4 independent crypto/sha3.SHAKE256.
type SHAKE256x4 struct {
	states [4]*sha3.SHAKE
}

// AbsorbSeed absorbs a shared seed followed by per-lane suffixes.
// The total length of seed + max(suffix) must be less than RateSHAKE256 (136).
func (s *SHAKE256x4) AbsorbSeed(seed []byte, suffixes [4][]byte) {
	for i := range 4 {
		s.states[i] = sha3.NewSHAKE256()
		s.states[i].Write(seed)
		s.states[i].Write(suffixes[i])
	}
}

// Squeeze reads len(out0) bytes from each lane.
func (s *SHAKE256x4) Squeeze(out0, out1, out2, out3 []byte) {
	s.states[0].Read(out0)
	s.states[1].Read(out1)
	s.states[2].Read(out2)
	s.states[3].Read(out3)
}

// Reset clears the state for reuse.
func (s *SHAKE256x4) Reset() {
	s.states = [4]*sha3.SHAKE{}
}
