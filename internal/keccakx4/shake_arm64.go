// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package keccakx4

import (
	"crypto/sha3"
	"runtime"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// useSHA3 is true on Apple Silicon (darwin + ARM64HasSHA3).
// On those systems crypto/sha3 benefits from the hardware SHA3 extension,
// so 4× sequential SHA3 is already optimal; the NEON path is not needed.
var useSHA3 = cpu.ARM64.HasSHA3 && runtime.GOOS == "darwin"

// SHAKE128x4 provides 4 parallel SHAKE128 XOF instances.
// On Apple Silicon (useSHA3=true) uses 4× crypto/sha3.
// On other ARM64 uses NEON-accelerated Permute4.
type SHAKE128x4 struct {
	state    State4
	squeezed bool
	sha3s    [4]*sha3.SHAKE
}

// AbsorbSeed absorbs a shared seed followed by per-lane 2-byte indices.
// The seed length + 2 must be less than RateSHAKE128 (168).
func (s *SHAKE128x4) AbsorbSeed(seed []byte, indices [4][2]byte) {
	if useSHA3 {
		for i := range 4 {
			s.sha3s[i] = sha3.NewSHAKE128()
			s.sha3s[i].Write(seed)
			s.sha3s[i].Write(indices[i][:])
		}
		return
	}
	s.state = State4{}
	s.squeezed = false
	var blocks [4][RateSHAKE128]byte
	for i := range 4 {
		copy(blocks[i][:], seed)
		blocks[i][len(seed)] = indices[i][0]
		blocks[i][len(seed)+1] = indices[i][1]
		blocks[i][len(seed)+2] = 0x1F
		blocks[i][RateSHAKE128-1] |= 0x80
	}
	XORIn4(&s.state, blocks[0][:], blocks[1][:], blocks[2][:], blocks[3][:], RateSHAKE128)
	Permute4(&s.state)
	s.squeezed = true
}

// Squeeze reads len(out0) bytes from each lane.
func (s *SHAKE128x4) Squeeze(out0, out1, out2, out3 []byte) {
	if useSHA3 {
		s.sha3s[0].Read(out0)
		s.sha3s[1].Read(out1)
		s.sha3s[2].Read(out2)
		s.sha3s[3].Read(out3)
		return
	}
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
	s.sha3s = [4]*sha3.SHAKE{}
}

// SHAKE256x4 provides 4 parallel SHAKE256 XOF instances.
// On Apple Silicon uses 4× crypto/sha3; on other ARM64 uses NEON Permute4.
type SHAKE256x4 struct {
	state    State4
	squeezed bool
	sha3s    [4]*sha3.SHAKE
}

// AbsorbSeed absorbs a shared seed followed by per-lane suffixes.
// The total length of seed + max(suffix) must be less than RateSHAKE256 (136).
func (s *SHAKE256x4) AbsorbSeed(seed []byte, suffixes [4][]byte) {
	if useSHA3 {
		for i := range 4 {
			s.sha3s[i] = sha3.NewSHAKE256()
			s.sha3s[i].Write(seed)
			s.sha3s[i].Write(suffixes[i])
		}
		return
	}
	s.state = State4{}
	s.squeezed = false
	var blocks [4][RateSHAKE256]byte
	for i := range 4 {
		copy(blocks[i][:], seed)
		msgLen := len(seed) + copy(blocks[i][len(seed):], suffixes[i])
		blocks[i][msgLen] = 0x1F
		blocks[i][RateSHAKE256-1] |= 0x80
	}
	XORIn4(&s.state, blocks[0][:], blocks[1][:], blocks[2][:], blocks[3][:], RateSHAKE256)
	Permute4(&s.state)
	s.squeezed = true
}

// Squeeze reads len(out0) bytes from each lane.
func (s *SHAKE256x4) Squeeze(out0, out1, out2, out3 []byte) {
	if useSHA3 {
		s.sha3s[0].Read(out0)
		s.sha3s[1].Read(out1)
		s.sha3s[2].Read(out2)
		s.sha3s[3].Read(out3)
		return
	}
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
	s.sha3s = [4]*sha3.SHAKE{}
}
