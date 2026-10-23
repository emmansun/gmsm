// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import "fmt"

// OverlapKind describes how the dst and src buffers are positioned relative
// to each other in memory. The framework materializes both geometries; an
// implementation with a documented panic contract for an illegal geometry
// must panic (see WithPanicContract).
type OverlapKind uint8

const (
	// OverlapNone: dst and src live in separate backing allocations.
	OverlapNone OverlapKind = iota
	// OverlapExact: dst and src are the identical slice (in-place).
	OverlapExact
	// OverlapDstAfterSrc: one backing allocation; dst starts Shift bytes
	// after src, so the buffers partially overlap.
	OverlapDstAfterSrc
	// OverlapDstBeforeSrc: one backing allocation; dst starts Shift bytes
	// before src, so the buffers partially overlap.
	OverlapDstBeforeSrc
	// OverlapDisjoint: one backing allocation; dst and src are disjoint
	// with Shift padding bytes between them (dst first).
	OverlapDisjoint
)

// OverlapCase declares one overlap geometry.
type OverlapCase struct {
	Kind  OverlapKind
	Shift int
}

// Overlap geometry constructors.
func NoOverlap() OverlapCase              { return OverlapCase{Kind: OverlapNone} }
func ExactOverlap() OverlapCase           { return OverlapCase{Kind: OverlapExact} }
func DstAfterSrc(shift int) OverlapCase   { return OverlapCase{OverlapDstAfterSrc, shift} }
func DstBeforeSrc(shift int) OverlapCase  { return OverlapCase{OverlapDstBeforeSrc, shift} }
func DisjointOverlap(pad int) OverlapCase { return OverlapCase{OverlapDisjoint, pad} }

func (o OverlapCase) String() string {
	switch o.Kind {
	case OverlapNone:
		return "none"
	case OverlapExact:
		return "exact"
	case OverlapDstAfterSrc:
		return fmt.Sprintf("dst-after-src(%d)", o.Shift)
	case OverlapDstBeforeSrc:
		return fmt.Sprintf("dst-before-src(%d)", o.Shift)
	case OverlapDisjoint:
		return fmt.Sprintf("disjoint(%d)", o.Shift)
	}
	return fmt.Sprintf("overlap-%d(%d)", o.Kind, o.Shift)
}

// idSchemaVersion is mixed into every case ID; bumping it invalidates all
// previously reported IDs at once when the descriptor encoding changes.
const idSchemaVersion = 1

// Case is one logical differential test input. Case values are independent
// of implementations, architecture and execution order: the same logical
// input yields the same ID on every platform.
type Case struct {
	SrcLen   int
	DstLen   int // output region length
	SrcAlign int // byte offset applied to the src slice inside its backing
	DstAlign int // byte offset applied to the dst slice inside its backing
	Overlap  OverlapCase
	Pattern  Pattern
	// Seed feeds the DeterministicRandom pattern and the dst junk prefill.
	Seed uint64
	// Tag is a free-form semantic parameter of the API shape under test
	// (e.g. stream offset, bit length, mode selector). It participates in
	// the case descriptor and ID.
	Tag uint64
	// Content optionally provides the exact src bytes; when shorter than
	// SrcLen the remainder is filled by Pattern, when nil Pattern fills
	// everything.
	Content []byte
}

// Descriptor returns the canonical, human-readable description of the case.
func (c Case) Descriptor() string {
	return fmt.Sprintf("len=%d dst=%d srcAlign=%d dstAlign=%d overlap=%s pattern=%s seed=%#x tag=%d",
		c.SrcLen, c.DstLen, c.SrcAlign, c.DstAlign, c.Overlap, c.Pattern.Name, c.Seed, c.Tag)
}

// ID returns a stable short identifier for the case. It mixes the schema
// version, all case parameters and the seed, but never the implementation,
// the architecture or the execution order.
func (c Case) ID() string {
	h := fnv1a64a(uint64(idSchemaVersion))
	h = fnvMix(h, uint64(c.SrcLen))
	h = fnvMix(h, uint64(c.DstLen))
	h = fnvMix(h, uint64(c.SrcAlign))
	h = fnvMix(h, uint64(c.DstAlign))
	h = fnvMix(h, uint64(c.Overlap.Kind))
	h = fnvMix(h, uint64(c.Overlap.Shift))
	h = fnvString(h, c.Pattern.Name)
	h = fnvMix(h, c.Seed)
	h = fnvMix(h, c.Tag)
	contentLen := minInt(len(c.Content), c.SrcLen)
	h = fnvMix(h, uint64(contentLen))
	for _, b := range c.Content[:contentLen] {
		h = fnvMix(h, uint64(b))
	}
	return fmt.Sprintf("DT-%08X", uint32(h^(h>>32)))
}

// validOverlapAlignment reports whether the declared pointer alignments can
// coexist with the requested relative buffer geometry.
func validOverlapAlignment(c Case) bool {
	mod16 := func(n int) int { return (n%16 + 16) % 16 }
	switch c.Overlap.Kind {
	case OverlapNone:
		return true
	case OverlapExact:
		return c.SrcLen == c.DstLen && c.SrcAlign == c.DstAlign
	case OverlapDstAfterSrc:
		return c.Overlap.Shift > 0 && c.Overlap.Shift < minInt(c.SrcLen, c.DstLen) &&
			mod16(c.SrcAlign+c.Overlap.Shift) == mod16(c.DstAlign)
	case OverlapDstBeforeSrc:
		return c.Overlap.Shift > 0 && c.Overlap.Shift < minInt(c.SrcLen, c.DstLen) &&
			mod16(c.DstAlign+c.Overlap.Shift) == mod16(c.SrcAlign)
	case OverlapDisjoint:
		return c.Overlap.Shift >= 0 &&
			mod16(c.DstAlign+c.DstLen+c.Overlap.Shift) == mod16(c.SrcAlign)
	default:
		return false
	}
}

// SubtestName returns the go test subtest name for the case.
func (c Case) SubtestName() string { return "case_" + c.ID() }

func fnv1a64a(seed uint64) uint64 { return seed ^ uint64(0xcbf29ce484222325) }

func fnvMix(h uint64, v uint64) uint64 {
	h ^= v
	return h * 0x100000001b3
}

func fnvString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h = fnvMix(h, uint64(s[i]))
	}
	return fnvMix(h, 0xff)
}
