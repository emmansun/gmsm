// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zuc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// The EEA keys and IVs are pinned constants so that every case is
// reproducible from its descriptor alone. The 128-bit key is the first
// specification KAT key; the 256-bit key and the ZUC-256 IV are derived
// deterministically from it.
var (
	diffEEAKey128 = func() []byte {
		k, err := hex.DecodeString(katEEAVectors[0].key)
		if err != nil {
			panic(err)
		}
		return k
	}()
	diffEEAKey256 = func() []byte {
		k := make([]byte, 32)
		copy(k, diffEEAKey128)
		for i := 16; i < 32; i++ {
			k[i] = diffEEAKey128[i-16] ^ 0x5A
		}
		return k
	}()
	diffEEAIV128 = construcIV4EEA(0x66035492, 0xf, 0)
	diffEEAIV256 = func() []byte {
		iv := make([]byte, IVSize256)
		diff.NewPRNG(0x5A5543454541).Fill(iv)
		return iv
	}()
	diffEEABucket = 4 * RoundBytes // state bucket size for the bucketed variants
)

// diffEEANewCipher builds the EEA cipher for a case. Tag bit 2 selects a
// bucketed cipher (state snapshots for seek), tag bit 3 selects ZUC-256.
func diffEEANewCipher(c diff.Case) (*eea, error) {
	key, iv := diffEEAKey128, diffEEAIV128
	if c.Tag&8 != 0 {
		key, iv = diffEEAKey256, diffEEAIV256
	}
	if c.Tag&4 != 0 {
		return NewCipherWithBucketSize(key, iv, diffEEABucket)
	}
	return NewCipher(key, iv)
}

// TestDiffStandardVector anchors the public EEA dispatch path to the ZUC
// specification KATs before the differential suites run.
func TestDiffStandardVector(t *testing.T) {
	for i, tv := range katEEAVectors {
		key, err := hex.DecodeString(tv.key)
		if err != nil {
			t.Fatal(err)
		}
		in, err := hex.DecodeString(tv.in)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(tv.out)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewEEACipher(key, tv.count, tv.bearer, tv.direction)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(in))
		copy(out, in)
		c.XORKeyStream(out, out)
		if !bytes.Equal(out, want) {
			t.Fatalf("public dispatch does not reproduce EEA vector %d: got %x", i, out)
		}
	}
}

// diffEEAStreamRunOf wraps an EEA constructor into a diff.Run applying one
// of four XORKeyStream call patterns (tag bits 0-1): a single call, a
// two-way split, a one-byte call followed by the rest (exercising the
// remainder buffer carry-over), and a three-way split.
func diffEEAStreamRunOf(newCipher func(diff.Case) (*eea, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		e, err := newCipher(c)
		if err != nil {
			t.Fatalf("failed to construct EEA cipher: %v", err)
		}
		n := len(b.Src)
		dst := b.Dst[:n]
		switch c.Tag & 3 {
		case 0:
			e.XORKeyStream(dst, b.Src)
		case 1:
			mid := n / 2
			e.XORKeyStream(dst[:mid], b.Src[:mid])
			e.XORKeyStream(dst[mid:], b.Src[mid:])
		case 2:
			if n > 0 {
				e.XORKeyStream(dst[:1], b.Src[:1])
				e.XORKeyStream(dst[1:], b.Src[1:])
			}
		case 3:
			m1 := n / 3
			m2 := 2 * n / 3
			e.XORKeyStream(dst[:m1], b.Src[:m1])
			e.XORKeyStream(dst[m1:m2], b.Src[m1:m2])
			e.XORKeyStream(dst[m2:], b.Src[m2:])
		}
		return append([]byte(nil), dst...)
	}
}

// diffEEASeekOffsets are the XORKeyStreamAt offsets: exact round multiples,
// one-off remainders, the bucket boundary neighbourhood and a long offset
// that forces the seek discard loop.
var diffEEASeekOffsets = []uint64{0, 1, RoundBytes, RoundBytes + 1,
	RoundBytes*4 - 1, RoundBytes * 4, RoundBytes*4 + 1, 1000}

// diffEEASeekRunOf wraps an EEA constructor into a diff.Run performing one
// random-access XORKeyStreamAt call at the offset selected by tag bits 0-2.
func diffEEASeekRunOf(newCipher func(diff.Case) (*eea, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		e, err := newCipher(c)
		if err != nil {
			t.Fatalf("failed to construct EEA cipher: %v", err)
		}
		e.XORKeyStreamAt(b.Dst[:len(b.Src)], b.Src, diffEEASeekOffsets[c.Tag&7])
		return append([]byte(nil), b.Dst[:len(b.Src)]...)
	}
}

// diffEEADomain pairs sixteen message lengths with the sixteen tag values
// (index-mod pairing), so every call pattern / bucket / key-size combination
// of the stream suite and every offset / bucket combination of the seek
// suite is exercised. ZUC-256 seek coverage is intentionally omitted: the
// seek logic is key-size independent and the ZUC-256 keystream is covered by
// the stream suite.
func diffEEADomain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 384, 512),
		Tags:       []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap(), diff.ExactOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffEEAStream checks the public EEA dispatch path (the asm keystream
// generator when the host supports it) against the forced pure-Go path, across
// call splitting, remainder-buffer carry-over, state buckets and both key sizes.
func TestDiffEEAStream(t *testing.T) {
	run := diffEEAStreamRunOf(diffEEANewCipher)
	s := diff.ByteSuite("generic-eea", diffEEARefFor(run))
	for _, impl := range diffEEAImpls(run) {
		s.Add(impl)
	}
	s.Run(t, diffEEADomain())
}

// FuzzDiffEEAStream fuzzes the EEA stream path. The reference forces only the
// pure-Go fallback, which is safe regardless of host features; the asm
// implementation runs through the natural dispatch without any override.
func FuzzDiffEEAStream(f *testing.F) {
	run := diffEEAStreamRunOf(diffEEANewCipher)
	s := diff.ByteSuite("generic-eea", diffEEARefFor(run))
	for _, impl := range diffEEAImpls(run) {
		s.Add(impl)
	}
	s.Fuzz(f, diffEEADomain())
}

// TestDiffEEASeek checks XORKeyStreamAt — seek forward, backward resets and
// bucketed fast-forward — against the forced pure-Go path.
func TestDiffEEASeek(t *testing.T) {
	run := diffEEASeekRunOf(diffEEANewCipher)
	s := diff.ByteSuite("generic-eea", diffEEARefFor(run))
	for _, impl := range diffEEAImpls(run) {
		s.Add(impl)
	}
	s.Run(t, diffEEADomain())
}

// FuzzDiffEEASeek fuzzes the random-access path; every offset from the fuzz
// payload is mapped onto the legal offset set.
func FuzzDiffEEASeek(f *testing.F) {
	run := diffEEASeekRunOf(diffEEANewCipher)
	s := diff.ByteSuite("generic-eea", diffEEARefFor(run))
	for _, impl := range diffEEAImpls(run) {
		s.Add(impl)
	}
	s.Fuzz(f, diffEEADomain())
}

// TestDispatchSelectedImplementation verifies that the dispatch variables are
// consistent with the host CPU features. ZUC dispatches through a single
// switch per algorithm (supportsAES for the keystream, supportsGFMUL for the
// MAC block); the accelerated path is additionally diffed directly by the
// EEA/EIA suites whenever it is available.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}
