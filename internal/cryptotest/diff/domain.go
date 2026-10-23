// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

// AlignmentCase declares independent src/dst byte alignment offsets. The
// offsets are applied inside the guarded backing allocations, so an offset
// of k shifts the slice data pointer by k bytes relative to the allocator's
// natural alignment.
type AlignmentCase struct{ Src, Dst int }

// Domain declaratively defines the legal input space of one API shape. The
// framework enumerates the cross product of all dimensions, subsampled
// according to the active Profile.
type Domain struct {
	// Lengths are the src lengths to enumerate.
	Lengths []int
	// DstLengths optionally overrides output lengths, paired by index with
	// Lengths (index modulo len(DstLengths)). nil means DstLen == SrcLen.
	DstLengths []int
	// Tags optionally provides a free-form semantic parameter (stream
	// offset, bit length, mode selector), paired by index with Lengths.
	// nil means 0.
	Tags []uint64
	// CartesianTags enumerates every tag for each length instead of pairing by index.
	CartesianTags bool
	// Alignments enumerates src/dst alignment pairs.
	Alignments []AlignmentCase
	// Overlaps enumerates the aliasing geometries to exercise.
	Overlaps []OverlapCase
	// Patterns enumerates the input fill patterns.
	Patterns []Pattern
	// Seeds provides additional per-case seed variations for the
	// DeterministicRandom pattern and the dst junk prefill. nil means one
	// seed per case. Every seed is mixed with the -diff.seed master seed.
	Seeds []uint64
}

// Values returns vs unchanged (helper for literal domains).
func Values(vs ...int) []int { return vs }

// Around returns center-radius .. center+radius inclusive, clamped at >= 0.
func Around(center, radius int) []int {
	var out []int
	for n := maxInt(0, center-radius); n <= center+radius; n++ {
		out = append(out, n)
	}
	return out
}

// Sweep returns min..max inclusive with the given step.
func Sweep(min, max, step int) []int {
	var out []int
	for n := min; n <= max; n += step {
		out = append(out, n)
	}
	return out
}

// SingleAlignment returns the fully aligned src/dst pair.
func SingleAlignment() []AlignmentCase { return []AlignmentCase{{0, 0}} }

// CommonAlignments returns a curated alignment set that covers unaligned
// loads/stores in both directions without the full 16x16 cross product.
func CommonAlignments() []AlignmentCase {
	return []AlignmentCase{
		{0, 0},
		{1, 0},
		{0, 1},
		{1, 1},
		{7, 15},
		{15, 7},
	}
}

// AllAlignments returns the full src/dst alignment cross product 0..max.
// Use it only in extended/nightly profiles; it is a caller responsibility
// which alignment set a Domain declares.
func AllAlignments(max int) []AlignmentCase {
	var out []AlignmentCase
	for s := 0; s <= max; s++ {
		for d := 0; d <= max; d++ {
			out = append(out, AlignmentCase{s, d})
		}
	}
	return out
}

// Enumerate returns the cases implied by d for the given profile. Case order
// is deterministic and the same logical case yields the same ID regardless
// of profile; profiles only control how many of the declared cases run.
//
// Profile selection per dimension:
//   - lengths: Smoke keeps at most 12 evenly spaced entries, PR/Extended all
//   - alignments: Smoke keeps the first 3 declared pairs, PR/Extended all
//   - overlaps: Smoke keeps only OverlapNone/OverlapExact, PR/Extended all
//   - patterns: Smoke keeps the first 2 declared patterns, PR/Extended all
//   - seeds: Smoke keeps the first declared seed, PR/Extended all
func Enumerate(d Domain, p Profile) []Case {
	indices := make([]int, len(d.Lengths))
	for i := range indices {
		indices[i] = i
	}
	if p == ProfileSmoke && len(indices) > 12 {
		indices = indices[:12]
		for i := range indices {
			indices[i] = i * len(d.Lengths) / 12
		}
	}
	alignments := d.Alignments
	if p == ProfileSmoke && len(alignments) > 3 {
		alignments = alignments[:3]
	}
	overlaps := d.Overlaps
	if p == ProfileSmoke {
		var sub []OverlapCase
		for _, o := range d.Overlaps {
			if o.Kind == OverlapNone || o.Kind == OverlapExact {
				sub = append(sub, o)
			}
		}
		if len(sub) == 0 {
			sub = []OverlapCase{NoOverlap()}
		}
		overlaps = sub
	}
	patterns := d.Patterns
	if p == ProfileSmoke && len(patterns) > 2 {
		patterns = patterns[:2]
	}
	seeds := d.Seeds
	if p == ProfileSmoke && len(seeds) > 1 {
		seeds = seeds[:1]
	}
	if seeds == nil {
		seeds = []uint64{0}
	}
	master := MasterSeed()

	var out []Case
	for _, i := range indices {
		n := d.Lengths[i]
		dstLen := n
		if len(d.DstLengths) > 0 {
			dstLen = d.DstLengths[i%len(d.DstLengths)]
		}
		tag := uint64(0)
		if len(d.Tags) > 0 {
			tag = d.Tags[i%len(d.Tags)]
		}
		for _, a := range alignments {
			for _, o := range overlaps {
				c := Case{
					SrcLen: n, DstLen: dstLen,
					SrcAlign: a.Src, DstAlign: a.Dst,
					Overlap: o, Pattern: Zero(), Seed: 0, Tag: tag,
				}
				if o.Kind == OverlapExact && a.Src != a.Dst {
					continue
				}
				if !validOverlapAlignment(c) {
					continue
				}
				for _, pat := range patterns {
					for _, s := range seeds {
						c.Pattern = pat
						c.Seed = s ^ master
						if d.CartesianTags && len(d.Tags) > 0 {
							for _, tag := range d.Tags {
								c.Tag = tag
								out = append(out, c)
							}
						} else {
							out = append(out, c)
						}
					}
				}
			}
		}
	}
	return out
}
