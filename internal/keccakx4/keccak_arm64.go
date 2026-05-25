// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package keccakx4

import "encoding/binary"

// Permute4 applies 24 rounds of Keccak-f[1600] to all 4 interleaved states
// using NEON 2-wide parallel processing (2 passes of 2 instances each).
func Permute4(state *State4) {
	permute4NEON(state)
}

// XORIn4 XORs rate bytes from each input into the corresponding state lanes.
func XORIn4(state *State4, in0, in1, in2, in3 []byte, rate int) {
	lanes := rate / 8
	for i := range lanes {
		off := i * 8
		state[i*4+0] ^= binary.LittleEndian.Uint64(in0[off:])
		state[i*4+1] ^= binary.LittleEndian.Uint64(in1[off:])
		state[i*4+2] ^= binary.LittleEndian.Uint64(in2[off:])
		state[i*4+3] ^= binary.LittleEndian.Uint64(in3[off:])
	}
}

// CopyOut4 copies rate bytes from each state into the corresponding output.
func CopyOut4(state *State4, out0, out1, out2, out3 []byte, rate int) {
	lanes := rate / 8
	for i := range lanes {
		off := i * 8
		binary.LittleEndian.PutUint64(out0[off:], state[i*4+0])
		binary.LittleEndian.PutUint64(out1[off:], state[i*4+1])
		binary.LittleEndian.PutUint64(out2[off:], state[i*4+2])
		binary.LittleEndian.PutUint64(out3[off:], state[i*4+3])
	}
}

//go:noescape
func permute4NEON(state *State4)
