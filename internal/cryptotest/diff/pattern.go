// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

// Pattern fills case input buffers deterministically. Pattern values are
// compared by name in case IDs, so the same name must always mean the same
// fill behavior.
type Pattern struct {
	// Name identifies the pattern in case descriptors and case IDs.
	Name string
	// Fill writes the pattern content into b. r is deterministic per case.
	Fill func(b []byte, r *PRNG)
}

// Zero fills with 0x00 bytes.
func Zero() Pattern {
	return Pattern{"zero", func(b []byte, _ *PRNG) {
		for i := range b {
			b[i] = 0
		}
	}}
}

// Ones fills with 0xff bytes.
func Ones() Pattern {
	return Pattern{"ones", func(b []byte, _ *PRNG) {
		for i := range b {
			b[i] = 0xff
		}
	}}
}

// Repeat returns a pattern that fills with the same byte.
func Repeat(v byte) Pattern {
	return Pattern{"repeat-" + hexByte(v), func(b []byte, _ *PRNG) {
		for i := range b {
			b[i] = v
		}
	}}
}

// SingleBit returns a pattern that sets bit bit (LSB numbering, 0-7) in
// every byte.
func SingleBit(bit uint) Pattern {
	v := byte(1) << bit
	return Pattern{"single-bit-" + hexByte(v), func(b []byte, _ *PRNG) {
		for i := range b {
			b[i] = v
		}
	}}
}

// DeterministicRandom fills with PRNG bytes derived from the case seed.
func DeterministicRandom() Pattern {
	return Pattern{"random", func(b []byte, r *PRNG) { r.Fill(b) }}
}

// DefaultPatterns returns the recommended pattern set: structured boundary
// values plus deterministic random input.
func DefaultPatterns() []Pattern {
	return []Pattern{
		Zero(),
		Ones(),
		Repeat(0x55),
		SingleBit(0),
		SingleBit(7),
		DeterministicRandom(),
	}
}

func hexByte(b byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0xf]})
}
