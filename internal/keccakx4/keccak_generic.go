// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build purego || !(amd64 || loong64)

package keccakx4

import "math/bits"

// Permute4 applies 24 rounds of Keccak-f[1600] to all 4 interleaved states.
func Permute4(state *State4) {
	permute4Generic(state)
}

func permute4Generic(state *State4) {
	for round := range 24 {
		keccakRound4(state, roundConstants[round])
	}
}

func keccakRound4(state *State4, rc uint64) {
	// θ step
	var c [5]uint64
	var d [5]uint64

	// Process each of 4 states independently for θ
	for s := range 4 {
		// Compute column parities
		for x := range 5 {
			c[x] = state[x*4+s]
			for y := 1; y < 5; y++ {
				c[x] ^= state[(x+y*5)*4+s]
			}
		}
		// Compute D
		for x := range 5 {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		// XOR D into state
		for x := range 5 {
			for y := range 5 {
				state[(x+y*5)*4+s] ^= d[x]
			}
		}

		// ρ and π steps combined
		var b [25]uint64
		for x := range 5 {
			for y := range 5 {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(state[(x+y*5)*4+s], rotationOffsets[x+y*5])
			}
		}

		// χ step
		for x := range 5 {
			for y := range 5 {
				state[(x+y*5)*4+s] = b[x+y*5] ^ (^b[(x+1)%5+y*5] & b[(x+2)%5+y*5])
			}
		}

		// ι step (only for lane 0,0)
		if s == 0 {
			state[0] ^= rc
		} else {
			state[s] ^= rc
		}
	}
}
