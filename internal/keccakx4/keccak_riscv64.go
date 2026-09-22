// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.27 && !purego

package keccakx4

import (
	"encoding/binary"
	"unsafe"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var (
	hasV    = cpu.RISCV64.HasV
	hasZvbb = cpu.RISCV64.HasZvbb
)

//go:noescape
func permute4RVV128(state *State4)

//go:noescape
func permute4RVV256(state *State4)

//go:noescape
func copyOut4RVV(state *State4, out0, out1, out2, out3 *byte, lanes int)

//go:noescape
func xorIn4RVV(state *State4, in0, in1, in2, in3 *byte, lanes int)

var permute4 = permute4Generic

func init() {
	if hasZvbb {
		if cpu.RISCV64.VLENB >= 32 {
			permute4 = permute4RVV256
		} else {
			permute4 = permute4RVV128
		}
	}
}

// Permute4 applies 24 rounds of Keccak-f[1600] to all 4 interleaved states.
// Uses Zvbb to process all 4 states in parallel; falls back to pure Go if Zvbb is unavailable.
func Permute4(state *State4) {
	permute4(state)
}

// XORIn4 XORs rate bytes from each input into the corresponding state lanes.
func XORIn4(state *State4, in0, in1, in2, in3 []byte, rate int) {
	lanes := rate / 8
	if hasV {
		xorIn4RVV(state, unsafe.SliceData(in0), unsafe.SliceData(in1), unsafe.SliceData(in2), unsafe.SliceData(in3), lanes)
		return
	}
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
	if hasV {
		copyOut4RVV(state, unsafe.SliceData(out0), unsafe.SliceData(out1), unsafe.SliceData(out2), unsafe.SliceData(out3), lanes)
		return
	}
	for i := range lanes {
		off := i * 8
		binary.LittleEndian.PutUint64(out0[off:], state[i*4+0])
		binary.LittleEndian.PutUint64(out1[off:], state[i*4+1])
		binary.LittleEndian.PutUint64(out2[off:], state[i*4+2])
		binary.LittleEndian.PutUint64(out3[off:], state[i*4+3])
	}
}
