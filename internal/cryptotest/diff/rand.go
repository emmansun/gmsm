// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

// PRNG is a small deterministic random generator (SplitMix64). It is used
// instead of math/rand so that generated inputs do not depend on the Go
// version's rand implementation and stay reproducible across Go releases
// and architectures.
type PRNG struct{ s uint64 }

// NewPRNG returns a PRNG seeded with seed.
func NewPRNG(seed uint64) *PRNG { return &PRNG{s: seed} }

// Next returns the next pseudo-random 64-bit value.
func (p *PRNG) Next() uint64 {
	p.s += 0x9e3779b97f4a7c15
	z := p.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Fill fills b with pseudo-random bytes.
func (p *PRNG) Fill(b []byte) {
	for i := 0; i < len(b); {
		v := p.Next()
		for j := 0; j < 8 && i < len(b); j, i = j+1, i+1 {
			b[i] = byte(v >> (8 * j))
		}
	}
}
