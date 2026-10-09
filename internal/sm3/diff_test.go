// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import (
	"testing"

	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// genericDigest is a test-local pure-Go SM3 reference that always absorbs
// data through blockGeneric, independent of the dispatching block().
type genericDigest struct {
	d digest
}

func newGenericDigest() *genericDigest {
	g := &genericDigest{}
	g.d.Reset()
	return g
}

func (g *genericDigest) Write(p []byte) (int, error) {
	d := &g.d
	nn := len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return nn, nil
}

func (g *genericDigest) Sum(in []byte) []byte {
	d := &g.d
	length := d.len
	// Padding, identical to digest.checkSum but absorbed through the
	// blockGeneric based write above.
	var tmp [chunk + 8]byte
	tmp[0] = 0x80
	var t uint64
	if length%chunk < 56 {
		t = 56 - length%chunk
	} else {
		t = chunk + 56 - length%chunk
	}
	length <<= 3
	padlen := tmp[:t+8]
	byteorder.BEPutUint64(padlen[t:], length)
	g.Write(padlen)

	out := in
	for _, v := range d.h {
		out = byteorder.BEAppendUint32(out, v)
	}
	return out
}

// sm3DigestHasher is the minimal hash interface used by the digest suite.
type sm3DigestHasher interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
}

// TestDiffStandardVector anchors the generic reference to the GB/T 32905-2016
// KAT before it is used as the differential oracle.
func TestDiffStandardVector(t *testing.T) {
	want := []byte{
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
	}
	got := newGenericDigest()
	got.Write([]byte("abc"))
	if !equalBytes(got.Sum(nil), want) {
		t.Fatalf("generic reference does not reproduce the KAT: got %x", got.Sum(nil))
	}
	pub := New()
	pub.Write([]byte("abc"))
	if !equalBytes(pub.Sum(nil), want) {
		t.Fatalf("public dispatch does not reproduce the KAT: got %x", pub.Sum(nil))
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sm3BlockRunOf wraps a block kernel into a diff.Run. Tag selects the number
// of preliminary blocks absorbed with the generic kernel, so that the
// kernels are exercised from non-initial states.
func sm3BlockRunOf(fn func(dig *digest, p []byte)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		d := new(digest)
		d.Reset()
		if c.Tag > 0 {
			var pre [chunk]byte
			diff.NewPRNG(c.Seed ^ 0x50524542).Fill(pre[:])
			for i := uint64(0); i < c.Tag; i++ {
				blockGeneric(d, pre[:])
			}
		}
		fn(d, b.Src)
		out := make([]byte, Size)
		for i, v := range d.h {
			byteorder.BEPutUint32(out[i*4:], v)
		}
		return out
	}
}

func sm3BlockRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	return sm3BlockRunOf(blockGeneric)(t, c, b)
}

func sm3BlockDomain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(64, 128, 192, 256, 320, 512, 1024, 2048, 4096),
		Tags:       []uint64{0, 1, 2}, // preliminary generic blocks
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffSM3Block checks the block kernels (and the dispatching block) of
// the current architecture against the pure-Go kernel.
func TestDiffSM3Block(t *testing.T) {
	s := diff.ByteSuite("generic-block", sm3BlockRef)
	for _, impl := range sm3BlockImpls() {
		s.Add(impl)
	}
	s.Run(t, sm3BlockDomain())
}

// FuzzDiffSM3Block fuzzes the block kernels; lengths are normalized to whole
// blocks, which is the kernel contract, and the fuzzed Tag is bounded to the
// domain's preliminary-block range to keep the loop in sm3BlockRunOf finite.
func FuzzDiffSM3Block(f *testing.F) {
	s := diff.ByteSuite("generic-block", sm3BlockRef,
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 3
			c.SrcLen -= c.SrcLen % chunk
			return c.SrcLen > 0
		}),
	)
	for _, impl := range sm3BlockImpls() {
		s.Add(impl)
	}
	s.Fuzz(f, sm3BlockDomain())
}

// sm3DigestRunOf wraps a hash constructor into a diff.Run. Tag selects the
// write chunk size (0 = single write).
func sm3DigestRunOf(newHash func() sm3DigestHasher) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		h := newHash()
		chunkSize := int(c.Tag)
		if chunkSize == 0 || len(b.Src) == 0 {
			h.Write(b.Src)
		} else {
			for i := 0; i < len(b.Src); i += chunkSize {
				end := i + chunkSize
				if end > len(b.Src) {
					end = len(b.Src)
				}
				h.Write(b.Src[i:end])
			}
		}
		return h.Sum(nil)
	}
}

func sm3DigestRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	return sm3DigestRunOf(func() sm3DigestHasher { return newGenericDigest() })(t, c, b)
}

func sm3DigestDomain() diff.Domain {
	return diff.Domain{
		Lengths:    diff.Values(0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512, 1024, 4096, 4097),
		Tags:       []uint64{0, 1, 17, 64}, // write chunk size, 0 = single write
		Alignments: diff.SingleAlignment(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

// TestDiffSM3Digest checks the public digest path against the pure-Go
// reference, including chunked writes and buffered partial blocks.
func TestDiffSM3Digest(t *testing.T) {
	s := diff.ByteSuite("generic-digest", sm3DigestRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run:  sm3DigestRunOf(func() sm3DigestHasher { return New() }),
	})
	s.Run(t, sm3DigestDomain())
}

// FuzzDiffSM3Digest fuzzes the public digest path; no implementation mutates
// global dispatch state, so this is safe for fuzz bodies.
func FuzzDiffSM3Digest(f *testing.F) {
	s := diff.ByteSuite("generic-digest", sm3DigestRef)
	s.Add(diff.Implementation[[]byte]{
		Name: "public",
		Run:  sm3DigestRunOf(func() sm3DigestHasher { return New() }),
	})
	s.Fuzz(f, sm3DigestDomain())
}

// TestDispatchSelectedImplementation verifies that the block dispatch state
// is consistent with the CPU features of the host. CI reruns it in separate
// go test processes with DISABLE_SM3NI=1 etc. to cover the other states;
// every selectable kernel is additionally diffed directly by TestDiffSM3Block.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}
