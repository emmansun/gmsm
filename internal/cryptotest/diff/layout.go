// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"bytes"
	"fmt"
	"testing"
)

// guardSize is the number of guard bytes placed before and after every
// exposed region. Guards detect out-of-bounds writes by the code under test.
const guardSize = 32

// guardSeed salts the guard sentinel so that it differs between cases and
// between the leading and trailing guard of the same allocation.
const guardSeed = 0xC0FFEE ^ 0x5EED

type guardRegion struct {
	got  []byte // the guard bytes inside the backing allocation
	want []byte // the expected sentinel, captured at materialize time
}

// Buffers is the per-execution materialization of a Case. Every
// implementation execution receives a freshly materialized Buffers so that
// in-place implementations cannot influence subsequent implementations
// through shared memory.
type Buffers struct {
	// Src and Dst are the exposed views honoring the case alignment and
	// overlap geometry. Dst is prefilled with deterministic junk so that a
	// failure to write the output is detectable.
	Src, Dst []byte

	SrcBacking []byte
	DstBacking []byte // nil when shared with SrcBacking

	guards []guardRegion
}

// Materialize allocates fresh backing storage for c and returns the exposed
// Src/Dst views. Src is filled from c.Content (falling back to c.Pattern for
// the remainder and when Content is nil); Dst is filled with deterministic
// junk. For OverlapExact, SrcLen and DstLen must be equal and DstAlign is
// ignored (there is a single shared region).
func Materialize(c Case) *Buffers {
	switch c.Overlap.Kind {
	case OverlapNone:
		srcB, src := newRegion(c.SrcLen, c.SrcAlign)
		dstB, dst := newRegion(c.DstLen, c.DstAlign)
		b := &Buffers{Src: src, Dst: dst, SrcBacking: srcB, DstBacking: dstB}
		b.addGuard(srcB[:guardSize+c.SrcAlign], c.Seed, 1)
		b.addGuard(srcB[len(srcB)-guardSize:], c.Seed, 2)
		b.addGuard(dstB[:guardSize+c.DstAlign], c.Seed, 3)
		b.addGuard(dstB[len(dstB)-guardSize:], c.Seed, 4)
		b.fill(c)
		return b
	default:
		srcStart, dstStart, total := sharedLayout(c)
		backing := make([]byte, total)
		b := &Buffers{
			Src:        backing[srcStart : srcStart+c.SrcLen : srcStart+c.SrcLen],
			Dst:        backing[dstStart : dstStart+c.DstLen : dstStart+c.DstLen],
			SrcBacking: backing,
		}
		b.addGuard(backing[:minInt(srcStart, dstStart)], c.Seed, 5)
		b.addGuard(backing[len(backing)-guardSize:], c.Seed, 6)
		if c.Overlap.Kind == OverlapDisjoint && c.Overlap.Shift > 0 {
			b.addGuard(backing[dstStart+c.DstLen:srcStart], c.Seed, 7)
		}
		b.fill(c)
		return b
	}
}

// addGuard fills the guard region with its sentinel bytes and registers it
// for verification. want is an independent copy of the sentinel, so that
// clobbering region is detected even if the overwrite keeps the bytes
// self-consistent.
func (b *Buffers) addGuard(region []byte, seed, idx uint64) {
	want := sentinel(seed, idx, len(region))
	copy(region, want)
	b.guards = append(b.guards, guardRegion{region, want})
}

// newRegion returns a backing allocation with guardSize bytes on both sides
// of a region of length n positioned at offset alignment.
func newRegion(n, alignment int) ([]byte, []byte) {
	backing := make([]byte, guardSize+alignment+n+guardSize)
	return backing, backing[guardSize+alignment : guardSize+alignment+n : guardSize+alignment+n]
}

// sharedLayout computes the src/dst offsets inside a single backing
// allocation for the shared-allocation overlap kinds.
func sharedLayout(c Case) (srcStart, dstStart, total int) {
	switch c.Overlap.Kind {
	case OverlapExact:
		srcStart = guardSize + c.SrcAlign
		dstStart = srcStart
	case OverlapDstAfterSrc:
		srcStart = guardSize + c.SrcAlign
		dstStart = srcStart + c.Overlap.Shift
	case OverlapDstBeforeSrc:
		dstStart = guardSize + c.DstAlign
		srcStart = dstStart + c.Overlap.Shift
	case OverlapDisjoint:
		dstStart = guardSize + c.DstAlign
		srcStart = dstStart + c.DstLen + c.Overlap.Shift
	default:
		panic(fmt.Sprintf("diff: unsupported shared overlap kind %d", c.Overlap.Kind))
	}
	end := srcStart + c.SrcLen
	if d := dstStart + c.DstLen; d > end {
		end = d
	}
	return srcStart, dstStart, end + guardSize
}

// fill writes the src content and the dst junk prefill.
func (b *Buffers) fill(c Case) {
	// For shared backing, initialize output-only bytes first. Source bytes
	// take precedence in the overlap so the implementation receives the
	// declared input pattern even for exact in-place cases.
	NewPRNG(^c.Seed ^ 0xA5A5A5A5A5A5A5A5).Fill(b.Dst)
	for i := range b.Src {
		b.Src[i] = 0
	}
	if len(c.Content) > 0 {
		n := copy(b.Src, c.Content)
		c.Pattern.Fill(b.Src[n:], NewPRNG(c.Seed^uint64(n)))
	} else {
		c.Pattern.Fill(b.Src, NewPRNG(c.Seed))
	}
}

// sentinel returns the expected guard content for the given case and guard
// index.
func sentinel(seed uint64, idx uint64, length int) []byte {
	want := make([]byte, length)
	NewPRNG(seed ^ guardSeed ^ idx).Fill(want)
	return want
}

// Verify checks that all guard regions around the exposed buffers are intact.
// It must be called after the implementation executed, typically deferred.
func (b *Buffers) Verify(t testing.TB, c Case) {
	t.Helper()
	for i, g := range b.guards {
		if !bytes.Equal(g.got, g.want) {
			off := firstDiff(g.got, g.want)
			t.Errorf("guard region %d clobbered (case %s): first difference at offset %d, want %x, got %x",
				i, c.ID(), off, g.want[maxInt(0, off-8):minInt(len(g.want), off+8)],
				g.got[maxInt(0, off-8):minInt(len(g.got), off+8)])
		}
	}
}

func firstDiff(a, b []byte) int {
	n := minInt(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
