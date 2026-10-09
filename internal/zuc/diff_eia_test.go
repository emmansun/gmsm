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

// The EIA keys and IVs are pinned constants derived deterministically from
// the EEA key material, so that every case is reproducible from its
// descriptor alone.
var (
	diffEIAKey = func() []byte {
		k := make([]byte, 16)
		for i, v := range diffEEAKey128 {
			k[i] = v ^ 0x33
		}
		return k
	}()
	diffEIAIV = func() []byte {
		iv := make([]byte, IVSize128)
		diff.NewPRNG(0x454941313238).Fill(iv)
		return iv
	}()
	diffEIA256Key = func() []byte {
		k := make([]byte, 32)
		copy(k, diffEEAKey256)
		for i := range k {
			k[i] ^= 0x3C
		}
		return k
	}()
	diffEIA256IV = func() []byte {
		iv := make([]byte, IVSize256)
		diff.NewPRNG(0x454941323536).Fill(iv)
		return iv
	}()
)

// diffEIAHasher is the minimal MAC interface shared by ZUC128Mac and
// ZUC256Mac.
type diffEIAHasher interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
	Finish(p []byte, nbits int) []byte
}

func diffEIA128NewHash() (diffEIAHasher, error) {
	return NewHash(diffEIAKey, diffEIAIV)
}

func diffEIA256NewHash(tagSize int) (diffEIAHasher, error) {
	return NewHash256(diffEIA256Key, diffEIA256IV, tagSize)
}

// TestDiffStandardVectorEIA anchors the public EIA dispatch path to the ZUC
// specification KAT before the differential suites run.
func TestDiffStandardVectorEIA(t *testing.T) {
	kat := katEIAVectors[0]
	h, err := NewEIAHash(kat.key, kat.count, kat.bearer, kat.direction)
	if err != nil {
		t.Fatal(err)
	}
	mac := h.Finish(kat.in, kat.nbits)
	want, err := hex.DecodeString(kat.mac)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mac, want) {
		t.Fatalf("public dispatch does not reproduce the EIA KAT: got %x", mac)
	}
}

// diffEIAWriteChunks feeds p to the MAC using the chunking pattern selected
// by pattern (tag bits 0-1): a single write, per-byte writes and two
// multi-byte chunk sizes, so the 16-byte internal buffer is exercised with
// every fill state.
func diffEIAWriteChunks(h diffEIAHasher, p []byte, pattern uint64) {
	switch pattern & 3 {
	case 0:
		h.Write(p)
	case 1:
		for i := range p {
			h.Write(p[i : i+1])
		}
	case 2:
		for i := 0; i < len(p); i += 17 {
			end := min(i+17, len(p))
			h.Write(p[i:end])
		}
	case 3:
		for i := 0; i < len(p); i += 13 {
			end := min(i+13, len(p))
			h.Write(p[i:end])
		}
	}
}

// diffEIAMessageRunOf wraps a MAC constructor into a diff.Run hashing the
// whole message with the chunking pattern from tag bits 0-1 and returning
// Sum (byte-aligned checkSum with a possibly non-empty buffer tail).
func diffEIAMessageRunOf(newHash func() (diffEIAHasher, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		h, err := newHash()
		if err != nil {
			t.Fatalf("failed to construct EIA hash: %v", err)
		}
		diffEIAWriteChunks(h, b.Src, c.Tag)
		return h.Sum(nil)
	}
}

// diffEIA256TagSizes maps the tag-size index (tag bits 2-3) onto the
// supported ZUC-256 tag sizes; index 3 repeats the largest tag.
var diffEIA256TagSizes = [4]int{4, 8, 16, 16}

// diffEIA256MessageRunOf is the ZUC-256 variant of the message runner; tag
// bits 2-3 select the tag size, tag bits 0-1 the chunking pattern.
func diffEIA256MessageRunOf(newHash func(tagSize int) (diffEIAHasher, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		h, err := newHash(diffEIA256TagSizes[(c.Tag>>2)%4])
		if err != nil {
			t.Fatalf("failed to construct EIA-256 hash: %v", err)
		}
		diffEIAWriteChunks(h, b.Src, c.Tag)
		return h.Sum(nil)
	}
}

// diffEIABitCases pairs message buffer lengths with Finish bit lengths
// covering the checkSum tail boundaries: 0/1/7 remainder bits, whole 32-bit
// and 64-bit words, the >2-keywords branch above 64 bits and a long
// multi-chunk message. The buffer always holds at least (nbits+7)/8 bytes.
var diffEIABitCases = []struct {
	bufLen int
	nbits  int
}{
	{16, 0}, {16, 1}, {16, 7}, {16, 9}, {16, 33},
	{16, 65}, {17, 71}, {17, 129}, {127, 1000},
}

// diffEIABitsRunOf wraps a MAC constructor into a diff.Run hashing the bit
// length selected by the tag via Finish (which resets the MAC afterwards).
func diffEIABitsRunOf(newHash func() (diffEIAHasher, error)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		h, err := newHash()
		if err != nil {
			t.Fatalf("failed to construct EIA hash: %v", err)
		}
		return h.Finish(b.Src, int(c.Tag))
	}
}

func diffEIADomain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256),
		Tags:       []uint64{0, 1, 2, 3}, // write chunking pattern
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

func diffEIA256Domain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256),
		Tags:       []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, // size index (bits 2-3) | pattern (bits 0-1)
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

func diffEIABitsDomain() diff.Domain {
	lengths := make([]int, len(diffEIABitCases))
	tags := make([]uint64, len(diffEIABitCases))
	for i, bc := range diffEIABitCases {
		lengths[i] = bc.bufLen
		tags[i] = uint64(bc.nbits)
	}
	return diff.Domain{
		Lengths:    lengths,
		Tags:       tags, // bit length for Finish, paired by index
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

func diffEIAAddImpls(s *diff.Suite[[]byte], run diff.Run[[]byte]) {
	for _, impl := range diffEIAImpls(run) {
		s.Add(impl)
	}
}

// TestDiffEIA128Message checks the ZUC-128 MAC against the forced pure-Go
// path, across write chunking and buffered partial blocks. The keyword
// generation inside the MAC also dispatches on supportsAES, which the
// reference forces to the generic path as well.
func TestDiffEIA128Message(t *testing.T) {
	run := diffEIAMessageRunOf(diffEIA128NewHash)
	s := diff.ByteSuite("generic-eia", diffEIARefFor(run))
	diffEIAAddImpls(s, run)
	s.Run(t, diffEIADomain())
}

// TestDiffEIA128Bits checks the bit-granular Finish paths (the checkSum
// tail is shared generic code; the absorbed blocks dispatch to the asm MAC
// rounds whenever the write chunking produces full 16-byte blocks).
func TestDiffEIA128Bits(t *testing.T) {
	run := diffEIABitsRunOf(diffEIA128NewHash)
	s := diff.ByteSuite("generic-eia", diffEIARefFor(run))
	diffEIAAddImpls(s, run)
	s.Run(t, diffEIABitsDomain())
}

// TestDiffEIA256 checks the ZUC-256 MAC for all three tag sizes against the
// forced pure-Go path. The checkSum tail is shared generic code, so no
// separate bit-granular suite is needed beyond the message suite.
func TestDiffEIA256(t *testing.T) {
	run := diffEIA256MessageRunOf(diffEIA256NewHash)
	s := diff.ByteSuite("generic-eia256", diffEIARefFor(run))
	diffEIAAddImpls(s, run)
	s.Run(t, diffEIA256Domain())
}

// FuzzDiffEIA128Message fuzzes the ZUC-128 MAC message path.
func FuzzDiffEIA128Message(f *testing.F) {
	run := diffEIAMessageRunOf(diffEIA128NewHash)
	s := diff.ByteSuite("generic-eia", diffEIARefFor(run))
	diffEIAAddImpls(s, run)
	s.Fuzz(f, diffEIADomain())
}

// FuzzDiffEIA128Bits fuzzes the bit-granular Finish paths; fuzz payloads map
// onto the declared bit-length cases and the buffer grows if needed.
func FuzzDiffEIA128Bits(f *testing.F) {
	run := diffEIABitsRunOf(diffEIA128NewHash)
	s := diff.ByteSuite("generic-eia", diffEIARefFor(run),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			bc := diffEIABitCases[c.Tag%uint64(len(diffEIABitCases))]
			c.Tag = uint64(bc.nbits)
			if need := (bc.nbits + 7) / 8; c.SrcLen < need {
				c.SrcLen = need
			}
			return true
		}))
	diffEIAAddImpls(s, run)
	s.Fuzz(f, diffEIABitsDomain())
}

// FuzzDiffEIA256 fuzzes the ZUC-256 MAC across all tag sizes.
func FuzzDiffEIA256(f *testing.F) {
	run := diffEIA256MessageRunOf(diffEIA256NewHash)
	s := diff.ByteSuite("generic-eia256", diffEIARefFor(run))
	diffEIAAddImpls(s, run)
	s.Fuzz(f, diffEIA256Domain())
}
