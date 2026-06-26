// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || loong64) && !purego

package keccakx4

// SHAKE128x4 provides 4 parallel SHAKE128 XOF instances
// using SIMD-accelerated Permute4.
type SHAKE128x4 struct {
	state    State4
	squeezed bool
}

// AbsorbSeed absorbs a shared seed followed by per-lane 2-byte indices.
// This matches the ML-KEM/ML-DSA ExpandA pattern:
//
//	lane[i] = SHAKE128(seed || indices[i][0] || indices[i][1])
//
// The seed length + 2 must be less than RateSHAKE128 (168).
func (s *SHAKE128x4) AbsorbSeed(seed []byte, indices [4][2]byte) {
	s.state = State4{}
	s.squeezed = false

	// Build 4 padded input blocks
	var blocks [4][RateSHAKE128]byte
	for i := range 4 {
		copy(blocks[i][:], seed)
		blocks[i][len(seed)] = indices[i][0]
		blocks[i][len(seed)+1] = indices[i][1]
		// SHAKE128 padding: 0x1F domain separator
		blocks[i][len(seed)+2] = 0x1F
		// Final bit at last byte of rate block
		blocks[i][RateSHAKE128-1] |= 0x80
	}

	XORIn4(&s.state, blocks[0][:], blocks[1][:], blocks[2][:], blocks[3][:], RateSHAKE128)
	Permute4(&s.state)
	s.squeezed = true
}

// Squeeze reads len(out0) bytes from each lane.
// Each call extracts one rate block and permutes for the next.
func (s *SHAKE128x4) Squeeze(out0, out1, out2, out3 []byte) {
	if !s.squeezed {
		panic("keccakx4: must call AbsorbSeed before Squeeze")
	}
	CopyOut4(&s.state, out0, out1, out2, out3, RateSHAKE128)
	Permute4(&s.state)
}

// Reset clears the state for reuse.
func (s *SHAKE128x4) Reset() {
	s.state = State4{}
	s.squeezed = false
}

// SHAKE256x4 provides 4 parallel SHAKE256 XOF instances
// using SIMD-accelerated Permute4.
type SHAKE256x4 struct {
	state    State4
	squeezed bool
}

// AbsorbSeed absorbs a shared seed followed by per-lane suffixes.
// The total length of seed + max(suffix) must be less than RateSHAKE256 (136).
func (s *SHAKE256x4) AbsorbSeed(seed []byte, suffixes [4][]byte) {
	s.state = State4{}
	s.squeezed = false

	var blocks [4][RateSHAKE256]byte
	for i := range 4 {
		copy(blocks[i][:], seed)
		msgLen := len(seed) + copy(blocks[i][len(seed):], suffixes[i])
		// SHAKE256 padding
		blocks[i][msgLen] = 0x1F
		blocks[i][RateSHAKE256-1] |= 0x80
	}

	XORIn4(&s.state, blocks[0][:], blocks[1][:], blocks[2][:], blocks[3][:], RateSHAKE256)
	Permute4(&s.state)
	s.squeezed = true
}

// Squeeze reads len(out0) bytes from each lane.
// Each call extracts one rate block and permutes for the next.
func (s *SHAKE256x4) Squeeze(out0, out1, out2, out3 []byte) {
	if !s.squeezed {
		panic("keccakx4: must call AbsorbSeed before Squeeze")
	}
	CopyOut4(&s.state, out0, out1, out2, out3, RateSHAKE256)
	Permute4(&s.state)
}

// Reset clears the state for reuse.
func (s *SHAKE256x4) Reset() {
	s.state = State4{}
	s.squeezed = false
}
