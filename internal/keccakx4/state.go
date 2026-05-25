// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package keccakx4 provides a 4-lane parallel Keccak-f[1600] implementation
// for accelerating ML-KEM and ML-DSA SHAKE operations.
//
// The state is lane-interleaved: state[i*4+j] = lane i of state j,
// allowing each 256-bit SIMD register to hold one Keccak lane across all 4 states.
package keccakx4

const (
	// RateSHAKE128 is the rate of SHAKE128 in bytes: (1600 - 2*128) / 8 = 168.
	RateSHAKE128 = 168
	// RateSHAKE256 is the rate of SHAKE256 in bytes: (1600 - 2*256) / 8 = 136.
	RateSHAKE256 = 136
)

// State4 holds 4 interleaved Keccak-f[1600] states.
// Layout: state[i*4+j] = lane i of state j (i ∈ [0,24], j ∈ [0,3]).
type State4 [100]uint64

// Pad4 applies SHAKE padding to all 4 states.
// absorbedBytes is how many bytes have been written into the current block.
// rate is the sponge rate in bytes.
func Pad4(state *State4, absorbedBytes, rate int) {
	// SHAKE domain separator: 0x1F at position absorbedBytes
	laneIdx := absorbedBytes / 8
	byteIdx := absorbedBytes % 8
	pad := uint64(0x1F) << (byteIdx * 8)
	state[laneIdx*4+0] ^= pad
	state[laneIdx*4+1] ^= pad
	state[laneIdx*4+2] ^= pad
	state[laneIdx*4+3] ^= pad

	// Final bit: 0x80 at last byte of rate
	lastLane := (rate - 1) / 8
	lastByte := (rate - 1) % 8
	final := uint64(0x80) << (lastByte * 8)
	state[lastLane*4+0] ^= final
	state[lastLane*4+1] ^= final
	state[lastLane*4+2] ^= final
	state[lastLane*4+3] ^= final
}

// rotationOffsets contains the ρ rotation amounts for each lane (x+5*y indexing).
var rotationOffsets = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// roundConstants contains the 24 Keccak-f[1600] round constants.
var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
	0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}
