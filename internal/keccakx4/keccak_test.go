// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package keccakx4

import (
	"crypto/sha3"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// keccakF1600 applies the standard Keccak-f[1600] permutation to a single state.
// Used as reference for testing.
func keccakF1600(state *[25]uint64) {
	// Use crypto/sha3 indirectly by going through SHAKE128.
	// Instead, implement the standard algorithm for direct comparison.
	for round := range 24 {
		keccakRound1(state, roundConstants[round])
	}
}

func keccakRound1(state *[25]uint64, rc uint64) {
	var c [5]uint64
	var d [5]uint64

	// θ
	for x := range 5 {
		c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
	}
	for x := range 5 {
		d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
	}
	for i := range 25 {
		state[i] ^= d[i%5]
	}

	// ρ and π
	var b [25]uint64
	for x := range 5 {
		for y := range 5 {
			b[y+5*((2*x+3*y)%5)] = rotl64(state[x+y*5], rotationOffsets[x+y*5])
		}
	}

	// χ
	for x := range 5 {
		for y := range 5 {
			state[x+y*5] = b[x+y*5] ^ (^b[(x+1)%5+y*5] & b[(x+2)%5+y*5])
		}
	}

	// ι
	state[0] ^= rc
}

func rotl64(x uint64, n int) uint64 {
	return (x << n) | (x >> (64 - n))
}

func TestPermute4MatchesScalar(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 99))

	for iter := range 100 {
		// Generate random interleaved state
		var state4 State4
		for i := range state4 {
			state4[i] = rng.Uint64()
		}

		// Deinterleave into 4 independent states
		var states [4][25]uint64
		for lane := range 25 {
			for s := range 4 {
				states[s][lane] = state4[lane*4+s]
			}
		}

		// Apply scalar keccakf to each state independently
		for s := range 4 {
			keccakF1600(&states[s])
		}

		// Apply x4 permutation
		Permute4(&state4)

		// Compare
		for lane := range 25 {
			for s := range 4 {
				if state4[lane*4+s] != states[s][lane] {
					t.Fatalf("iter=%d lane=%d state=%d: got %016x, want %016x",
						iter, lane, s, state4[lane*4+s], states[s][lane])
				}
			}
		}
	}
}

func TestXORIn4AndCopyOut4(t *testing.T) {
	var state State4
	rate := 168 // SHAKE128

	in0 := make([]byte, rate)
	in1 := make([]byte, rate)
	in2 := make([]byte, rate)
	in3 := make([]byte, rate)

	rng := rand.New(rand.NewPCG(1, 2))
	for i := range rate {
		in0[i] = byte(rng.UintN(256))
		in1[i] = byte(rng.UintN(256))
		in2[i] = byte(rng.UintN(256))
		in3[i] = byte(rng.UintN(256))
	}

	XORIn4(&state, in0, in1, in2, in3, rate)

	// Verify each lane matches
	for i := range rate / 8 {
		off := i * 8
		want0 := binary.LittleEndian.Uint64(in0[off:])
		want1 := binary.LittleEndian.Uint64(in1[off:])
		want2 := binary.LittleEndian.Uint64(in2[off:])
		want3 := binary.LittleEndian.Uint64(in3[off:])
		if state[i*4+0] != want0 {
			t.Fatalf("lane %d state 0: got %016x want %016x", i, state[i*4+0], want0)
		}
		if state[i*4+1] != want1 {
			t.Fatalf("lane %d state 1: got %016x want %016x", i, state[i*4+1], want1)
		}
		if state[i*4+2] != want2 {
			t.Fatalf("lane %d state 2: got %016x want %016x", i, state[i*4+2], want2)
		}
		if state[i*4+3] != want3 {
			t.Fatalf("lane %d state 3: got %016x want %016x", i, state[i*4+3], want3)
		}
	}

	// CopyOut should recover the same data
	out0 := make([]byte, rate)
	out1 := make([]byte, rate)
	out2 := make([]byte, rate)
	out3 := make([]byte, rate)
	CopyOut4(&state, out0, out1, out2, out3, rate)

	for i := range rate {
		if out0[i] != in0[i] || out1[i] != in1[i] || out2[i] != in2[i] || out3[i] != in3[i] {
			t.Fatalf("byte %d: CopyOut4 mismatch", i)
		}
	}
}

func TestSHAKE128x4MatchesScalar(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	indices := [4][2]byte{{0, 0}, {1, 0}, {2, 0}, {0, 1}}

	var xof SHAKE128x4
	xof.AbsorbSeed(seed, indices)

	var out [4][168]byte
	xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])

	// Compare with scalar SHAKE128
	for lane := range 4 {
		scalar := sha3.NewSHAKE128()
		scalar.Write(seed)
		scalar.Write(indices[lane][:])
		var expected [168]byte
		scalar.Read(expected[:])
		if out[lane] != expected {
			t.Errorf("lane %d: SHAKE128x4 output mismatch with scalar", lane)
			t.Logf("  got:  %x...", out[lane][:16])
			t.Logf("  want: %x...", expected[:16])
		}
	}
}

func TestSHAKE256x4MatchesScalar(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 0x80)
	}

	suffixes := [4][]byte{{0}, {1}, {2}, {3}}

	var xof SHAKE256x4
	xof.AbsorbSeed(seed, suffixes)

	var out [4][136]byte
	xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])

	for lane := range 4 {
		scalar := sha3.NewSHAKE256()
		scalar.Write(seed)
		scalar.Write(suffixes[lane])
		var expected [136]byte
		scalar.Read(expected[:])
		if out[lane] != expected {
			t.Errorf("lane %d: SHAKE256x4 output mismatch with scalar", lane)
			t.Logf("  got:  %x...", out[lane][:16])
			t.Logf("  want: %x...", expected[:16])
		}
	}
}

func TestSHAKE128x4MultiSqueeze(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	indices := [4][2]byte{{5, 2}, {3, 1}, {0, 0}, {7, 6}}

	var xof SHAKE128x4
	xof.AbsorbSeed(seed, indices)

	// Squeeze 3 blocks
	var out [4][168 * 3]byte
	xof.Squeeze(out[0][:168], out[1][:168], out[2][:168], out[3][:168])
	xof.Squeeze(out[0][168:336], out[1][168:336], out[2][168:336], out[3][168:336])
	xof.Squeeze(out[0][336:], out[1][336:], out[2][336:], out[3][336:])

	for lane := range 4 {
		scalar := sha3.NewSHAKE128()
		scalar.Write(seed)
		scalar.Write(indices[lane][:])
		var expected [168 * 3]byte
		scalar.Read(expected[:])
		if out[lane] != expected {
			t.Errorf("lane %d: multi-squeeze mismatch", lane)
		}
	}
}

func BenchmarkPermute4(b *testing.B) {
	var state State4
	b.SetBytes(200 * 4) // 4 states × 200 bytes each
	for b.Loop() {
		Permute4(&state)
	}
}

func BenchmarkSHAKE128x4Squeeze(b *testing.B) {
	seed := make([]byte, 32)
	indices := [4][2]byte{{0, 0}, {1, 0}, {2, 0}, {0, 1}}
	var out [4][168]byte

	b.SetBytes(168 * 4)
	for b.Loop() {
		var xof SHAKE128x4
		xof.AbsorbSeed(seed, indices)
		xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])
	}
}

func BenchmarkSHAKE128x4Squeeze4Blocks(b *testing.B) {
	seed := make([]byte, 32)
	indices := [4][2]byte{{0, 0}, {1, 0}, {2, 0}, {0, 1}}
	var out [4][168]byte

	b.SetBytes(168 * 4 * 4) // 4 blocks × 4 lanes
	for b.Loop() {
		var xof SHAKE128x4
		xof.AbsorbSeed(seed, indices)
		xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])
		xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])
		xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])
		xof.Squeeze(out[0][:], out[1][:], out[2][:], out[3][:])
	}
}
