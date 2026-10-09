// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"encoding/binary"
	"testing"
)

// fuzzHeaderLen is the size of the fixed-size fuzz payload header:
// seed(8) | srcLen(4) | dstLen(4) | srcAlign(1) | dstAlign(1) |
// overlapKind(1) | overlapShift(4) | patternIdx(1) | tag(4)
const fuzzHeaderLen = 8 + 4 + 4 + 1 + 1 + 1 + 4 + 1 + 4

// Fuzz wires the suite to a Go native fuzz target. The seed corpus is
// derived from the smoke profile of d, so structured boundary cases always
// run as ordinary unit tests. Fuzzed payloads are decoded back into the
// legal input domain (lengths clamped, geometry and pattern selected from
// the payload), and the comparison runs against the reference like any other
// case.
//
// Clamping contract: SrcLen/DstLen are clamped into the domain, but Tag is
// passed through as an arbitrary uint32 — it is a semantic parameter, not a
// domain index. If a Run derives an allocation size, loop bound or buffer
// index from Tag, the suite MUST register WithNormalize to map the fuzzed
// tag back onto the declared value list; otherwise a fuzzed tag can produce
// gigabyte allocations or unbounded loops that hang the fuzz worker.
//
// Corpus persistence: the fuzz engine writes failing (and minimized failing)
// inputs to testdata/fuzz/<FuzzName>/ inside the package directory; commit
// them to turn them into permanent regression cases. Interesting-but-passing
// inputs stay in the build cache; scheduled CI jobs upload the cache as
// artifacts for inspection.
//
// The fuzz body must not force an accelerated kernel the host may not
// support, since that would execute instructions the CPU lacks; register
// one fuzz target per implementation pair whose kernels are available on
// the runner. Forcing the pure-Go fallback for the reference (as the ZUC
// suites do) is always safe.
func (s *Suite[O]) Fuzz(f *testing.F, d Domain) {
	for _, c := range Enumerate(d, ProfileSmoke) {
		f.Add(encodeCase(c))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, ok := decodeCase(d, payload)
		if !ok {
			return
		}
		if s.normalize != nil && !s.normalize(&c) {
			return
		}
		s.RunCase(t, c)
	})
}

// encodeCase serializes a case into a fuzz payload. The content is generated
// deterministically from the case seed so that committed seed corpus entries
// are self-contained.
func encodeCase(c Case) []byte {
	content := make([]byte, c.SrcLen)
	if len(c.Content) > 0 {
		copy(content, c.Content)
	} else {
		c.Pattern.Fill(content, NewPRNG(c.Seed))
	}
	out := make([]byte, fuzzHeaderLen+len(content))
	binary.LittleEndian.PutUint64(out[0:], c.Seed)
	binary.LittleEndian.PutUint32(out[8:], uint32(c.SrcLen))
	binary.LittleEndian.PutUint32(out[12:], uint32(c.DstLen))
	out[16] = byte(c.SrcAlign)
	out[17] = byte(c.DstAlign)
	out[18] = byte(c.Overlap.Kind)
	binary.LittleEndian.PutUint32(out[19:], uint32(c.Overlap.Shift))
	out[23] = 0 // pattern index resolved by decodeCase
	binary.LittleEndian.PutUint32(out[24:], uint32(c.Tag))
	copy(out[fuzzHeaderLen:], content)
	return out
}

// decodeCase parses a fuzz payload back into a legal case for d, clamping
// all fields into the declared domain. It returns false when the payload
// cannot be interpreted.
func decodeCase(d Domain, payload []byte) (Case, bool) {
	if len(payload) < fuzzHeaderLen {
		return Case{}, false
	}
	seed := binary.LittleEndian.Uint64(payload[0:])
	srcLen := int(int32(binary.LittleEndian.Uint32(payload[8:])))
	dstLen := int(int32(binary.LittleEndian.Uint32(payload[12:])))
	srcAlign := int(payload[16]) % 16
	dstAlign := int(payload[17]) % 16
	kind := OverlapKind(payload[18])
	shiftRaw := binary.LittleEndian.Uint32(payload[19:])
	patternIdx := int(payload[23])
	tag := uint64(uint32(binary.LittleEndian.Uint32(payload[24:])))
	content := payload[fuzzHeaderLen:]

	if len(d.Lengths) == 0 || len(d.Overlaps) == 0 || len(d.Patterns) == 0 {
		return Case{}, false
	}
	lo, hi := minMaxInts(d.Lengths)
	srcLen = clampInt(srcLen, lo, hi)
	if len(d.DstLengths) > 0 {
		dlo, dhi := minMaxInts(d.DstLengths)
		dstLen = clampInt(dstLen, dlo, dhi)
	} else {
		dstLen = srcLen
	}
	oc := d.Overlaps[int(kind)%len(d.Overlaps)]
	align := AlignmentCase{Src: srcAlign, Dst: dstAlign}
	switch oc.Kind {
	case OverlapNone:
		oc.Shift = 0
	case OverlapExact:
		if srcLen != dstLen {
			return Case{}, false
		}
		dstAlign = srcAlign
		oc.Shift = 0
	case OverlapDstAfterSrc, OverlapDstBeforeSrc:
		limit := minInt(srcLen, dstLen)
		if limit <= 1 {
			return Case{}, false
		}
		oc.Shift = 1 + int(shiftRaw%uint32(limit-1))
		if oc.Kind == OverlapDstAfterSrc {
			dstAlign = (srcAlign + oc.Shift) % 16
		} else {
			srcAlign = (dstAlign + oc.Shift) % 16
		}
	case OverlapDisjoint:
		oc.Shift = int(shiftRaw % uint32(srcLen+1))
		srcAlign = (dstAlign + dstLen + oc.Shift) % 16
	default:
		return Case{}, false
	}
	align = AlignmentCase{Src: srcAlign, Dst: dstAlign}
	master := MasterSeed()
	return Case{
		SrcLen:   srcLen,
		DstLen:   dstLen,
		SrcAlign: align.Src,
		DstAlign: align.Dst,
		Overlap:  oc,
		Pattern:  d.Patterns[patternIdx%len(d.Patterns)],
		Seed:     seed ^ master,
		Tag:      tag,
		Content:  content,
	}, true
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func minMaxInts(vs []int) (int, int) {
	lo, hi := vs[0], vs[0]
	for _, v := range vs[1:] {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return lo, hi
}
