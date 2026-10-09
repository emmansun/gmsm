// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// captureTB wraps a *testing.T while capturing Errorf calls, so that
// intentionally-failing suite runs can be asserted without failing the
// outer test.
type captureTB struct {
	*testing.T
	errs   []string
	failed bool
}

func (c *captureTB) Errorf(format string, args ...any) {
	c.failed = true
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

func (c *captureTB) Failed() bool { return c.failed }

func TestCaseIDStability(t *testing.T) {
	pat := DeterministicRandom()
	a := Case{SrcLen: 17, DstLen: 17, SrcAlign: 1, DstAlign: 15, Overlap: ExactOverlap(), Pattern: pat, Seed: 42, Tag: 3}
	b := Case{SrcLen: 17, DstLen: 17, SrcAlign: 1, DstAlign: 15, Overlap: ExactOverlap(), Pattern: pat, Seed: 42, Tag: 3}
	if a.ID() != b.ID() {
		t.Fatalf("identical logical cases have different IDs: %s vs %s", a.ID(), b.ID())
	}
	for _, mutate := range []func(*Case){
		func(c *Case) { c.SrcLen++ },
		func(c *Case) { c.DstLen++ },
		func(c *Case) { c.SrcAlign++ },
		func(c *Case) { c.DstAlign++ },
		func(c *Case) { c.Overlap = DstAfterSrc(1) },
		func(c *Case) { c.Pattern = Zero() },
		func(c *Case) { c.Seed++ },
		func(c *Case) { c.Tag++ },
	} {
		c := a
		mutate(&c)
		if c.ID() == a.ID() {
			t.Errorf("case ID unchanged after mutation: %s", c.Descriptor())
		}
	}
	if !strings.HasPrefix(a.ID(), "DT-") {
		t.Fatalf("unexpected ID format: %s", a.ID())
	}
}

func TestMaterializeGeometry(t *testing.T) {
	c := Case{SrcLen: 16, DstLen: 16, Overlap: NoOverlap(), Pattern: Zero(), Seed: 7}
	b := Materialize(c)
	if len(b.Src) == 0 || len(b.Dst) == 0 {
		t.Fatal("empty materialized buffers")
	}
	// Separate allocations must not alias.
	dst0 := b.Dst[0]
	b.Src[0] = 1
	if b.Dst[0] != dst0 {
		t.Fatal("separate allocations alias")
	}
	b.Verify(t, c)

	// Exact overlap: same slice.
	c.Overlap = ExactOverlap()
	b = Materialize(c)
	b.Src[3] = 9
	if b.Dst[3] != 9 {
		t.Fatal("exact overlap buffers do not alias")
	}
	b.Verify(t, c)

	// Dst after src with shift 1: dst[0] == src[1].
	c.Overlap = DstAfterSrc(1)
	b = Materialize(c)
	b.Src[1] = 0xAB
	if b.Dst[0] != 0xAB {
		t.Fatalf("dst-after-src geometry wrong: dst[0]=%#x", b.Dst[0])
	}
	b.Verify(t, c)

	// Dst before src with shift 1: dst[1] == src[0].
	c.Overlap = DstBeforeSrc(1)
	b = Materialize(c)
	b.Src[0] = 0xCD
	if b.Dst[1] != 0xCD {
		t.Fatalf("dst-before-src geometry wrong: dst[1]=%#x", b.Dst[1])
	}
	b.Verify(t, c)

	// Disjoint with pad 5: buffers do not touch.
	c.Overlap = DisjointOverlap(5)
	b = Materialize(c)
	if &b.Src[0] == &b.Dst[0] {
		t.Fatal("disjoint buffers alias")
	}
	b.Verify(t, c)
}

func TestMaterializeOverlapPreservesSourcePattern(t *testing.T) {
	cases := []Case{
		{SrcLen: 16, DstLen: 16, Overlap: ExactOverlap(), Pattern: Ones(), Seed: 1},
		{SrcLen: 16, DstLen: 16, SrcAlign: 0, DstAlign: 3, Overlap: DstAfterSrc(3), Pattern: Ones(), Seed: 2},
		{SrcLen: 16, DstLen: 16, SrcAlign: 3, DstAlign: 0, Overlap: DstBeforeSrc(3), Pattern: Ones(), Seed: 3},
		{SrcLen: 16, DstLen: 16, SrcAlign: 3, DstAlign: 0, Overlap: DisjointOverlap(3), Pattern: Ones(), Seed: 4},
	}
	for _, c := range cases {
		b := Materialize(c)
		for i, got := range b.Src {
			if got != 0xff {
				t.Fatalf("%s: Src[%d]=%#x, want pattern byte 0xff", c.Overlap, i, got)
			}
		}
	}
}

func TestEnumerateOnlyValidOverlapAlignments(t *testing.T) {
	d := Domain{
		Lengths:    []int{16},
		Alignments: CommonAlignments(),
		Overlaps: []OverlapCase{
			ExactOverlap(), DstAfterSrc(1), DstBeforeSrc(1), DisjointOverlap(3),
		},
		Patterns: []Pattern{Zero()},
	}
	for _, c := range Enumerate(d, ProfilePR) {
		if !validOverlapAlignment(c) {
			t.Errorf("enumerated impossible geometry: %s", c.Descriptor())
		}
	}
}

func TestCaseIDIncludesEffectiveContent(t *testing.T) {
	a := Case{SrcLen: 4, DstLen: 4, Overlap: NoOverlap(), Pattern: Zero(), Content: []byte{1, 2, 3, 4}}
	b := a
	b.Content = []byte{1, 2, 3, 5}
	if a.ID() == b.ID() {
		t.Fatal("case ID did not change with explicit input content")
	}
	b.Content = []byte{1, 2, 3, 4, 9}
	if a.ID() != b.ID() {
		t.Fatal("content beyond SrcLen changed the effective-input case ID")
	}
}

func TestGuardClobberDetected(t *testing.T) {
	c := Case{SrcLen: 16, DstLen: 16, Overlap: NoOverlap(), Pattern: Zero(), Seed: 1}
	b := Materialize(c)
	// Simulate a 1-byte overwrite in the trailing guard of dst.
	b.DstBacking[len(b.DstBacking)-guardSize] ^= 0xFF
	ct := &captureTB{T: t}
	b.Verify(ct, c)
	if !ct.failed {
		t.Fatal("guard verification did not detect the overrun")
	}
	if !strings.Contains(ct.errs[0], "guard region") {
		t.Fatalf("unexpected guard message: %s", ct.errs[0])
	}
}

func TestGuardPaddingClobberDetected(t *testing.T) {
	cases := []struct {
		name string
		c    Case
	}{
		{"separate", Case{SrcLen: 16, DstLen: 16, SrcAlign: 1, DstAlign: 15, Overlap: NoOverlap(), Pattern: Zero()}},
		{"exact", Case{SrcLen: 16, DstLen: 16, SrcAlign: 1, DstAlign: 1, Overlap: ExactOverlap(), Pattern: Zero()}},
		{"disjoint", Case{SrcLen: 16, DstLen: 16, SrcAlign: 3, Overlap: DisjointOverlap(3), Pattern: Zero()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := Materialize(tc.c)
			switch tc.c.Overlap.Kind {
			case OverlapNone:
				b.DstBacking[guardSize+tc.c.DstAlign-1] ^= 0xff
			case OverlapExact:
				b.SrcBacking[guardSize+tc.c.SrcAlign-1] ^= 0xff
			case OverlapDisjoint:
				b.SrcBacking[guardSize+tc.c.DstLen] ^= 0xff
			}
			ct := &captureTB{T: t}
			b.Verify(ct, tc.c)
			if !ct.failed {
				t.Fatal("guard verification did not detect a padding overwrite")
			}
		})
	}
}

func TestSuiteDetectsDivergence(t *testing.T) {
	ref := func(t testing.TB, c Case, b *Buffers) []byte {
		out := make([]byte, len(b.Src))
		copy(out, b.Src)
		return out
	}
	s := ByteSuite("generic", ref)
	s.Add(Implementation[[]byte]{
		Name: "broken-kernel",
		Run: func(t testing.TB, c Case, b *Buffers) []byte {
			out := make([]byte, len(b.Src))
			copy(out, b.Src)
			if len(out) > 5 {
				out[5] ^= 0x80 // injected divergence
			}
			return out
		},
	})
	// Zero out the master seed influence for a deterministic report.
	ct := &captureTB{T: t}
	s.RunCase(ct, Case{SrcLen: 16, DstLen: 16, Overlap: NoOverlap(), Pattern: DeterministicRandom(), Seed: 9})
	if !ct.failed {
		t.Fatal("suite did not detect the injected divergence")
	}
	msg := strings.Join(ct.errs, "\n")
	for _, want := range []string{"differential mismatch", "impl=broken-kernel", "ref=generic", "DT-", "offset 5", "diff.seed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnostics missing %q:\n%s", want, msg)
		}
	}
}

func TestSuitePanicContract(t *testing.T) {
	ref := func(t testing.TB, c Case, b *Buffers) []byte {
		if c.Tag == 1 {
			panic("boom: invalid")
		}
		return nil
	}
	s := ByteSuite("generic", ref,
		WithPanicContract[[]byte](func(c Case) PanicExpectation {
			return PanicExpectation{Required: c.Tag == 1, Contains: "boom"}
		}),
	)
	s.Add(Implementation[[]byte]{Name: "ok", Run: ref})
	ct := &captureTB{T: t}
	s.RunCase(ct, Case{SrcLen: 4, DstLen: 4, Overlap: NoOverlap(), Pattern: Zero(), Tag: 1})
	if ct.failed {
		t.Fatalf("expected matching panics to pass:\n%s", strings.Join(ct.errs, "\n"))
	}
	// A required panic that never happens must be reported.
	s2 := ByteSuite("generic", func(t testing.TB, c Case, b *Buffers) []byte { return nil },
		WithPanicContract[[]byte](func(c Case) PanicExpectation {
			return PanicExpectation{Required: c.Tag == 1, Contains: "boom"}
		}),
	)
	s2.Add(Implementation[[]byte]{Name: "ok", Run: ref})
	ct2 := &captureTB{T: t}
	s2.RunCase(ct2, Case{SrcLen: 4, DstLen: 4, Overlap: NoOverlap(), Pattern: Zero(), Tag: 1})
	if !ct2.failed {
		t.Fatal("missing required panic was not reported")
	}
	if !strings.Contains(strings.Join(ct2.errs, "\n"), "expected panic") {
		t.Fatalf("unexpected message: %s", strings.Join(ct2.errs, "\n"))
	}
}

func TestSuiteRequiredUnavailable(t *testing.T) {
	s := ByteSuite("generic", func(t testing.TB, c Case, b *Buffers) []byte { return nil })
	s.Add(Implementation[[]byte]{
		Name:      "needs-feature",
		Run:       func(t testing.TB, c Case, b *Buffers) []byte { return nil },
		Available: func() bool { return false },
		Required:  true,
	})
	ct := &captureTB{T: t}
	s.RunCase(ct, Case{SrcLen: 4, DstLen: 4, Overlap: NoOverlap(), Pattern: Zero()})
	if !ct.failed {
		t.Fatal("required-but-unavailable implementation was not reported")
	}
	if !strings.Contains(strings.Join(ct.errs, "\n"), "marked required") {
		t.Fatalf("unexpected message: %s", strings.Join(ct.errs, "\n"))
	}
}

func TestSuiteRestoresDispatchBetweenExecutions(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic=%v", panics), func(t *testing.T) {
			dispatch := true
			calls := 0
			run := func(t testing.TB, c Case, b *Buffers) []byte {
				if panics {
					panic("expected")
				}
				return b.Src
			}
			s := ByteSuite("reference", func(t testing.TB, c Case, b *Buffers) []byte {
				WithValue(t, &dispatch, false)
				return run(t, c, b)
			})
			s.Add(Implementation[[]byte]{
				Name: "accelerated", Available: func() bool { return dispatch },
				Run: func(t testing.TB, c Case, b *Buffers) []byte {
					calls++
					WithValue(t, &dispatch, false)
					return run(t, c, b)
				},
			})
			s.Add(Implementation[[]byte]{
				Name: "second", Available: func() bool { return dispatch },
				Run: func(t testing.TB, c Case, b *Buffers) []byte {
					calls++
					return run(t, c, b)
				},
			})
			s.RunCase(t, Case{SrcLen: 16, DstLen: 16, Overlap: NoOverlap(), Pattern: Zero()})
			if calls != 2 || !dispatch {
				t.Fatalf("calls=%d dispatch=%v, want 2 and true", calls, dispatch)
			}
		})
	}
}

func TestProfileSubsetting(t *testing.T) {
	d := Domain{
		Lengths:    Sweep(0, 64, 1),
		Alignments: CommonAlignments(),
		Overlaps:   []OverlapCase{NoOverlap(), ExactOverlap(), DstAfterSrc(1)},
		Patterns:   DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
	smoke := Enumerate(d, ProfileSmoke)
	pr := Enumerate(d, ProfilePR)
	ext := Enumerate(d, ProfileExtended)
	if !(len(smoke) < len(pr) && len(pr) <= len(ext)) {
		t.Fatalf("profile sizes not ordered: smoke=%d pr=%d extended=%d", len(smoke), len(pr), len(ext))
	}
	validGeometries := 0
	for _, n := range d.Lengths {
		for _, a := range d.Alignments {
			for _, overlap := range d.Overlaps {
				if validOverlapAlignment(Case{
					SrcLen: n, DstLen: n, SrcAlign: a.Src, DstAlign: a.Dst, Overlap: overlap,
				}) {
					validGeometries++
				}
			}
		}
	}
	wantExtended := validGeometries * len(d.Patterns) * len(d.Seeds)
	if len(ext) != wantExtended {
		t.Fatalf("extended enumeration has %d cases, want valid geometry cross product %d", len(ext), wantExtended)
	}
	// Smoke must only contain none/exact overlaps.
	for _, c := range smoke {
		if c.Overlap.Kind != OverlapNone && c.Overlap.Kind != OverlapExact {
			t.Fatalf("smoke profile contains overlap %s", c.Overlap)
		}
	}
}

func TestSmokePreservesPairedDomain(t *testing.T) {
	d := Domain{
		Lengths: Sweep(0, 19, 1), Alignments: SingleAlignment(),
		Overlaps: []OverlapCase{NoOverlap()}, Patterns: []Pattern{Zero()},
	}
	for i := range d.Lengths {
		d.DstLengths = append(d.DstLengths, i+32)
		d.Tags = append(d.Tags, uint64(i+10))
	}
	prIDs := make(map[string]bool)
	for _, c := range Enumerate(d, ProfilePR) {
		prIDs[c.ID()] = true
	}
	for _, c := range Enumerate(d, ProfileSmoke) {
		if c.DstLen != c.SrcLen+32 || c.Tag != uint64(c.SrcLen+10) || !prIDs[c.ID()] {
			t.Fatalf("smoke changed a paired domain case: %s", c.Descriptor())
		}
	}
}

func TestCartesianTagsCoverage(t *testing.T) {
	d := Domain{
		Lengths: []int{16, 32}, CartesianTags: true,
		Alignments: SingleAlignment(), Overlaps: []OverlapCase{NoOverlap()}, Patterns: []Pattern{Zero()},
	}
	for tag := uint64(0); tag < 13; tag++ {
		d.Tags = append(d.Tags, tag)
	}
	for _, profile := range []Profile{ProfileSmoke, ProfilePR, ProfileExtended} {
		seen := make(map[[2]uint64]bool)
		for _, c := range Enumerate(d, profile) {
			seen[[2]uint64{uint64(c.SrcLen), c.Tag}] = true
		}
		for _, length := range d.Lengths {
			for _, tag := range d.Tags {
				if !seen[[2]uint64{uint64(length), tag}] {
					t.Fatalf("profile %d omitted length %d tag %d", profile, length, tag)
				}
			}
		}
	}
}

func TestPRNGDeterministic(t *testing.T) {
	a := NewPRNG(1234)
	b := NewPRNG(1234)
	x := make([]byte, 100)
	y := make([]byte, 100)
	a.Fill(x)
	b.Fill(y)
	if !bytes.Equal(x, y) {
		t.Fatal("PRNG output not deterministic for the same seed")
	}
	if bytes.Equal(x, make([]byte, 100)) {
		t.Fatal("PRNG produced all zeros")
	}
}

func TestFuzzRoundtrip(t *testing.T) {
	d := Domain{
		Lengths:  []int{0, 1, 16, 4096},
		Tags:     []uint64{0, 7},
		Overlaps: []OverlapCase{NoOverlap(), ExactOverlap(), DstAfterSrc(3)},
		Patterns: DefaultPatterns(),
	}
	for _, c := range Enumerate(d, ProfilePR) {
		payload := encodeCase(c)
		got, ok := decodeCase(d, payload)
		if !ok {
			t.Fatalf("decode failed for %s", c.ID())
		}
		if got.SrcLen != c.SrcLen || got.DstLen != c.DstLen || got.Tag != c.Tag ||
			got.SrcAlign != c.SrcAlign || got.DstAlign != c.DstAlign ||
			got.Overlap.Kind != c.Overlap.Kind {
			t.Fatalf("roundtrip mismatch: got %s, want %s", got.Descriptor(), c.Descriptor())
		}
	}
	// Out-of-range and truncated payloads must decode legally or be dropped.
	big := make([]byte, 128)
	for i := range big {
		big[i] = 0xFF
	}
	c, ok := decodeCase(d, big)
	if !ok {
		t.Fatal("all-0xFF payload should decode")
	}
	lo, hi := minMaxInts(d.Lengths)
	if c.SrcLen < lo || c.SrcLen > hi {
		t.Fatalf("decoded srcLen %d outside domain [%d,%d]", c.SrcLen, lo, hi)
	}
	if _, ok := decodeCase(d, []byte{1, 2, 3}); ok {
		t.Fatal("truncated payload should be dropped")
	}
}
