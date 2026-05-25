// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package keccakx4

import "unsafe"

// Permute4 applies 24 rounds of Keccak-f[1600] to all 4 interleaved states.
// Uses LASX to process all 4 states in parallel with all 25 lanes in registers.
func Permute4(state *State4) {
	permute4LASX(state)
}

// XORIn4 XORs rate bytes from each input into the corresponding state lanes.
func XORIn4(state *State4, in0, in1, in2, in3 []byte, rate int) {
	xorIn4LASX(state, unsafe.SliceData(in0), unsafe.SliceData(in1), unsafe.SliceData(in2), unsafe.SliceData(in3), rate/8)
}

// CopyOut4 copies rate bytes from each state into the corresponding output.
func CopyOut4(state *State4, out0, out1, out2, out3 []byte, rate int) {
	copyOut4LASX(state, unsafe.SliceData(out0), unsafe.SliceData(out1), unsafe.SliceData(out2), unsafe.SliceData(out3), rate/8)
}

//go:noescape
func permute4LASX(state *State4)

//go:noescape
func copyOut4LASX(state *State4, out0, out1, out2, out3 *byte, lanes int)

//go:noescape
func xorIn4LASX(state *State4, in0, in1, in2, in3 *byte, lanes int)
