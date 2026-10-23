// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// The mldsa field kernels share one convention: the architecture assembly
// (amd64 AVX2, arm64 NEON, loong64 LASX, riscv64 RVV) and the pure-Go
// implementation agree coefficient for coefficient, so the generic kernels
// double as the differential reference on every build. In addition, the
// independent Barrett-reduction oracle in field_barrett.go provides a second
// reference for the NTT kernels that also runs under purego, where the
// dispatch layer compiles down to the generic kernels anyway.
//
// The bit-pack/decode encoders follow the same scheme: the generic kernels
// are the reference and the per-architecture dispatch wrappers are checked
// against them, including the unconditional arm64 encoder assembly.

const diffPolyBytes = 4 * n // marshaled size of one polynomial

// diffRingFrom interprets src as 256 little-endian uint32 coefficients
// reduced mod q. It is the common way to derive a polynomial from a case
// buffer, keeping every coefficient inside the kernels' input domain.
func diffRingFrom(src []byte) ringElement {
	return diffCoeffsFrom(src, q)
}

// diffCoeffsFrom is diffRingFrom with a caller-chosen bound; it is used for
// the bit-pack kernels whose input coefficients must fit a narrower range.
func diffCoeffsFrom(src []byte, bound uint32) ringElement {
	var f ringElement
	for i := range f {
		f[i] = fieldElement(binary.LittleEndian.Uint32(src[i*4:]) % bound)
	}
	return f
}

// diffNTTFrom is diffRingFrom for the distinct nttElement type.
func diffNTTFrom(src []byte) nttElement {
	return nttElement(diffRingFrom(src))
}

func diffGuardValue[T ringElement | nttElement | [n]int32](t testing.TB, c diff.Case, alignment int, value T) *T {
	t.Helper()
	return &diffGuardSlice(t, c, alignment, []T{value})[0]
}

func diffGuardSlice[T ringElement | nttElement | [n]int32](t testing.TB, c diff.Case, alignment int, values []T) []T {
	t.Helper()
	alignment -= alignment % int(unsafe.Alignof(values[0]))
	storageCase := diff.Case{
		DstLen: len(values) * int(unsafe.Sizeof(values[0])), DstAlign: alignment,
		Overlap: diff.NoOverlap(), Pattern: diff.Zero(), Seed: c.Seed,
	}
	buffers := diff.Materialize(storageCase)
	ptr := (*T)(unsafe.Pointer(&buffers.Dst[0]))
	t.Cleanup(func() { buffers.Verify(t, c) })
	storage := unsafe.Slice(ptr, len(values))
	copy(storage, values)
	return storage
}

func diffMarshalRing(f *ringElement) []byte {
	out := make([]byte, 4*len(f))
	for i, v := range f {
		binary.LittleEndian.PutUint32(out[i*4:], uint32(v))
	}
	return out
}

func diffMarshalNTT(f *nttElement) []byte {
	return diffMarshalRing((*ringElement)(f))
}

// diffMarshalRings concatenates the marshaled forms of a poly slice, e.g.
// the hint vector produced by vectorMakeHint.
func diffMarshalRings(fs []ringElement) []byte {
	out := make([]byte, 0, 4*n*len(fs))
	for i := range fs {
		out = append(out, diffMarshalRing(&fs[i])...)
	}
	return out
}

func diffMarshalInt32s(a *[n]int32) []byte {
	out := make([]byte, 4*n)
	for i, v := range a {
		binary.LittleEndian.PutUint32(out[i*4:], uint32(v))
	}
	return out
}

// diffJunkRings prefills dst with deterministic mod-q junk so that a kernel
// that fails to write part of its output becomes detectable.
func diffJunkRings(dst []ringElement, seed uint64) {
	raw := make([]byte, 4*len(dst)*n)
	diff.NewPRNG(seed ^ 0x4A554E4B).Fill(raw)
	for i := range dst {
		for j := range dst[i] {
			dst[i][j] = fieldElement(binary.LittleEndian.Uint32(raw[(i*n+j)*4:]) % q)
		}
	}
}

func diffJunkNTT(a *nttElement, seed uint64) {
	raw := make([]byte, 4*n)
	diff.NewPRNG(seed ^ 0x4A554E4B).Fill(raw)
	for j := range a {
		a[j] = fieldElement(binary.LittleEndian.Uint32(raw[j*4:]) % q)
	}
}

// diffJunkInt32 prefills a raw int32 polynomial (decompose output domain).
func diffJunkInt32(a *[n]int32, seed uint64) {
	raw := make([]byte, 4*n)
	diff.NewPRNG(seed ^ 0x494E5433).Fill(raw)
	for i := range a {
		a[i] = int32(binary.LittleEndian.Uint32(raw[i*4:]))
	}
}

// diffDomain builds the standard domain for fixed-size polynomial kernels.
// The lengths slice carries one entry per tag value so that Enumerate pairs
// every tag with at least one case.
func diffDomain(lengths []int, dstLengths []int, tags []uint64) diff.Domain {
	return diff.Domain{
		Lengths:    lengths,
		DstLengths: dstLengths,
		Tags:       tags,
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	}
}

func diffRepeatLengths(count, length int) []int {
	out := make([]int, count)
	for i := range out {
		out[i] = length
	}
	return out
}

// diffDispatchImpl wraps a Run closure that drives the arch-neutral
// dispatch functions; forcing and availability come from the
// per-architecture diff_kernels_*_test.go hooks.
func diffDispatchImpl(name string, run diff.Run[[]byte]) diff.Implementation[[]byte] {
	return diff.Implementation[[]byte]{
		Name:      name,
		Run:       run,
		Available: diffDispatchAvailable,
		Primary:   diffDispatchAvailable(),
	}
}

func diffSkipIfNoDispatch(t testing.TB) {
	t.Helper()
	if !diffDispatchAvailable() {
		t.Skip("no accelerated mldsa kernels available on this host")
	}
}

// ---- forward NTT ----

func diffNTTRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f := diffRingFrom(b.Src)
	internalNTTGeneric(&f)
	return diffMarshalRing(&f)
}

func diffNTTImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src))
	internalNTT(f)
	return diffMarshalRing(f)
}

// diffNTTBarrettImplRun is the independent Barrett-reduction oracle from
// field_barrett.go; it is available on every build, including purego.
func diffNTTBarrettImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f := diffRingFrom(b.Src)
	out := barrettNTT(f)
	return diffMarshalNTT(&out)
}

// TestDiffNTT checks the architecture NTT kernel against the pure-Go
// implementation and the independent Barrett oracle.
func TestDiffNTT(t *testing.T) {
	s := diff.ByteSuite("internalNTTGeneric", diffNTTRef)
	s.Add(diff.Implementation[[]byte]{Name: "barrett-oracle", Run: diffNTTBarrettImplRun})
	s.Add(diffDispatchImpl("dispatch-ntt", diffNTTImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, diffPolyBytes), nil, nil))
}

// FuzzDiffNTT fuzzes the NTT kernels; SrcLen is always two packed
// polynomials and no Tag is used, so no normalization is required.
func FuzzDiffNTT(f *testing.F) {
	s := diff.ByteSuite("internalNTTGeneric", diffNTTRef)
	s.Add(diff.Implementation[[]byte]{Name: "barrett-oracle", Run: diffNTTBarrettImplRun})
	s.Add(diffDispatchImpl("dispatch-ntt", diffNTTImplRun))
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, diffPolyBytes), nil, nil))
}

// ---- inverse NTT ----

func diffInverseNTTRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f := diffNTTFrom(b.Src)
	internalInverseNTTGeneric(&f)
	return diffMarshalNTT(&f)
}

func diffInverseNTTImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
	internalInverseNTT(f)
	return diffMarshalNTT(f)
}

// diffInverseNTTBarrettImplRun scales the Barrett oracle's output by r, the
// factor the Montgomery inverse NTT keeps in the coefficients; the product
// matches the generic kernel exactly on every input.
func diffInverseNTTBarrettImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	m := diffNTTFrom(b.Src)
	ib := inverseBarrettNTT(m)
	for i := range ib {
		ib[i] = fieldElement(uint64(ib[i]) * r % q)
	}
	return diffMarshalRing(&ib)
}

// TestDiffInverseNTT checks the architecture inverse NTT kernel against the
// generic implementation and the scaled Barrett oracle.
func TestDiffInverseNTT(t *testing.T) {
	s := diff.ByteSuite("internalInverseNTTGeneric", diffInverseNTTRef)
	s.Add(diff.Implementation[[]byte]{Name: "barrett-oracle", Run: diffInverseNTTBarrettImplRun})
	s.Add(diffDispatchImpl("dispatch-intt", diffInverseNTTImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, diffPolyBytes), nil, nil))
}

// ---- NTT-domain multiplication ----

func diffNTTMulRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	lhs := diffNTTFrom(b.Src)
	rhs := diffNTTFrom(b.Src[diffPolyBytes:])
	var out nttElement
	nttMulGeneric(&out, &lhs, &rhs)
	return diffMarshalNTT(&out)
}

func diffNTTMulImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	lhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
	rhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src[diffPolyBytes:]))
	out := diffGuardValue(t, c, c.DstAlign, nttElement{})
	diffJunkNTT(out, c.Seed)
	nttMul(out, lhs, rhs)
	return diffMarshalNTT(out)
}

// TestDiffNTTMul checks the architecture pointwise NTT multiplication
// against the generic kernel.
func TestDiffNTTMul(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("nttMulGeneric", diffNTTMulRef)
	s.Add(diffDispatchImpl("dispatch-nttmul", diffNTTMulImplRun))
	s.Run(t, diffDomain([]int{2 * diffPolyBytes}, []int{diffPolyBytes}, nil))
}

func diffNTTMulAccRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	lhs := diffNTTFrom(b.Src)
	rhs := diffNTTFrom(b.Src[diffPolyBytes:])
	acc := diffNTTFrom(b.Dst)
	nttMulAccGeneric(&acc, &lhs, &rhs)
	return diffMarshalNTT(&acc)
}

func diffNTTMulAccImplRunOf(mulAcc func(acc, lhs, rhs *nttElement)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		diffForceDispatch(t)
		lhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
		rhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src[diffPolyBytes:]))
		acc := diffGuardValue(t, c, c.DstAlign, diffNTTFrom(b.Dst))
		mulAcc(acc, lhs, rhs)
		return diffMarshalNTT(acc)
	}
}

// TestDiffNTTMulAcc checks the accumulating NTT multiplication; the
// accumulator starts from deterministic junk so that a kernel adding on top
// of a wrong base is detected.
func TestDiffNTTMulAcc(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("nttMulAccGeneric", diffNTTMulAccRef)
	s.Add(diffDispatchImpl("dispatch-nttmulacc", diffNTTMulAccImplRunOf(nttMulAcc)))
	s.Run(t, diffDomain([]int{2 * diffPolyBytes}, []int{diffPolyBytes}, nil))
}

// FuzzDiffNTTMulAcc fuzzes the accumulating NTT multiplication.
func FuzzDiffNTTMulAcc(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("nttMulAccGeneric", diffNTTMulAccRef)
	s.Add(diffDispatchImpl("dispatch-nttmulacc", diffNTTMulAccImplRunOf(nttMulAcc)))
	s.Fuzz(f, diffDomain([]int{2 * diffPolyBytes}, []int{diffPolyBytes}, nil))
}

// ---- matrix row/vector multiplication ----

// diffMatRowVecMulRunOf wraps a matrix-row/vector kernel; Tag selects the
// vector length k in 1..8, covering every parameter set of the three
// ML-DSA variants.
func diffMatRowVecMulRunOf(impl func(dst, vec, matRow *nttElement, len int)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		k := int(c.Tag%8) + 1
		vec := diffGuardSlice(t, c, c.SrcAlign, make([]nttElement, k))
		mat := diffGuardSlice(t, c, c.SrcAlign, make([]nttElement, k))
		for i := 0; i < k; i++ {
			vec[i] = diffNTTFrom(b.Src[i*diffPolyBytes:])
			mat[i] = diffNTTFrom(b.Src[8*diffPolyBytes+i*diffPolyBytes:])
		}
		dst := diffGuardValue(t, c, c.DstAlign, nttElement{})
		diffJunkNTT(dst, c.Seed)
		impl(dst, &vec[0], &mat[0], k)
		return diffMarshalNTT(dst)
	}
}

// TestDiffMatRowVecMul checks the architecture matrix-row/vector product
// against the generic kernel for vector lengths 1..8.
func TestDiffMatRowVecMul(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("nttMatRowVecMulGeneric", diffMatRowVecMulRunOf(nttMatRowVecMulGeneric))
	s.Add(diffDispatchImpl("dispatch-matrowvecmul", diffMatRowVecMulRunOf(nttMatRowVecMul)))
	s.Run(t, diffDomain(diffRepeatLengths(8, 16*diffPolyBytes), nil, []uint64{0, 1, 2, 3, 4, 5, 6, 7}))
}

// ---- poly add/sub ----

func diffPolyAddSubRunOf(add func(dst, src *ringElement), sub func(dst, src *ringElement)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		dst := diffGuardValue(t, c, c.DstAlign, diffRingFrom(b.Dst))
		src := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src))
		if c.Tag%2 == 0 {
			add(dst, src)
		} else {
			sub(dst, src)
		}
		return diffMarshalRing(dst)
	}
}

// TestDiffPolyAddSub checks the architecture add/sub kernels against the
// generic ones; Tag selects the operation.
func TestDiffPolyAddSub(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("polyAddGeneric", diffPolyAddSubRunOf(polyAddGeneric, polySubGeneric))
	s.Add(diffDispatchImpl("dispatch-addsub", diffPolyAddSubRunOf(polyAddAssign, polySubAssign)))
	s.Run(t, diffDomain(diffRepeatLengths(2, diffPolyBytes), []int{diffPolyBytes}, []uint64{0, 1}))
}

// FuzzDiffPolyAddSub fuzzes the add/sub kernels; Tag is bounded to the
// operation selector.
func FuzzDiffPolyAddSub(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("polyAddGeneric", diffPolyAddSubRunOf(polyAddGeneric, polySubGeneric),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 2
			return true
		}),
	)
	s.Add(diffDispatchImpl("dispatch-addsub", diffPolyAddSubRunOf(polyAddAssign, polySubAssign)))
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, diffPolyBytes), []int{diffPolyBytes}, []uint64{0, 1}))
}

// ---- infinity norms ----

var diffNorms = [4]int{0, 1, 1024, (q - 1) / 2}

func diffInfinityNormRunOf(impl func(a *ringElement, norm int) int) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		norm := diffNorms[c.Tag%4]
		f := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src))
		res := impl(f, norm)
		var out [4]byte
		binary.LittleEndian.PutUint32(out[:], uint32(res))
		return out[:]
	}
}

// TestDiffInfinityNorm checks the architecture infinity-norm kernel against
// the generic one; Tag selects the caller-provided starting norm.
func TestDiffInfinityNorm(t *testing.T) {
	diffSkipIfNoDispatch(t)
	ref := func(a *ringElement, norm int) int { return polyInfinityNormGeneric(a, norm) }
	impl := func(a *ringElement, norm int) int { return polyInfinityNorm(a, norm) }
	s := diff.ByteSuite("polyInfinityNormGeneric", diffInfinityNormRunOf(ref))
	s.Add(diffDispatchImpl("dispatch-infnorm", diffInfinityNormRunOf(impl)))
	s.Run(t, diffDomain(diffRepeatLengths(4, diffPolyBytes), nil, []uint64{0, 1, 2, 3}))
}

func diffInfinityNormSignedRunOf(impl func(a *[n]int32, norm int) int) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		norm := diffNorms[c.Tag%2]
		a := diffGuardValue(t, c, c.SrcAlign, [n]int32{})
		for i := range a {
			a[i] = int32(binary.LittleEndian.Uint32(b.Src[i*4:]))
		}
		res := impl(a, norm)
		var out [4]byte
		binary.LittleEndian.PutUint32(out[:], uint32(res))
		return out[:]
	}
}

// TestDiffInfinityNormSigned checks the architecture signed infinity-norm
// kernel (gamma1 domain) against the generic one.
func TestDiffInfinityNormSigned(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("polyInfinityNormSignedGeneric", diffInfinityNormSignedRunOf(polyInfinityNormSignedGeneric))
	s.Add(diffDispatchImpl("dispatch-infnormsigned", diffInfinityNormSignedRunOf(polyInfinityNormSigned)))
	s.Run(t, diffDomain(diffRepeatLengths(2, diffPolyBytes), nil, []uint64{0, 1}))
}

// ---- decompose (r0 extraction) ----

func diffDecomposeRunOf(impl func(dst *[n]int32, w, cs2 *ringElement, gamma2 uint32)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var gamma2 uint32 = gamma2QMinus1Div32
		if c.Tag%2 == 1 {
			gamma2 = gamma2QMinus1Div88
		}
		w := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src))
		cs2 := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src[diffPolyBytes:]))
		dst := diffGuardValue(t, c, c.DstAlign, [n]int32{})
		diffJunkInt32(dst, c.Seed)
		impl(dst, w, cs2, gamma2)
		return diffMarshalInt32s(dst)
	}
}

// TestDiffDecomposeSubToR0 checks the architecture r0-extraction kernel
// against the generic one; Tag selects gamma2.
func TestDiffDecomposeSubToR0(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("decomposeSubToR0Generic", diffDecomposeRunOf(decomposeSubToR0Generic))
	s.Add(diffDispatchImpl("dispatch-decompose", diffDecomposeRunOf(decomposeSubToR0)))
	s.Run(t, diffDomain(diffRepeatLengths(2, 2*diffPolyBytes), nil, []uint64{0, 1}))
}

// FuzzDiffDecomposeSubToR0 fuzzes the r0-extraction kernel; Tag is bounded
// to the gamma2 selector.
func FuzzDiffDecomposeSubToR0(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("decomposeSubToR0Generic", diffDecomposeRunOf(decomposeSubToR0Generic),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 2
			return true
		}),
	)
	s.Add(diffDispatchImpl("dispatch-decompose", diffDecomposeRunOf(decomposeSubToR0)))
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, 2*diffPolyBytes), nil, []uint64{0, 1}))
}

// ---- useHint / makeHint ----

func diffUseHintRunOf(impl func(dst, h, r *ringElement, gamma2 uint32)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		var gamma2 uint32 = gamma2QMinus1Div32
		if c.Tag%2 == 1 {
			gamma2 = gamma2QMinus1Div88
		}
		h := diffGuardValue(t, c, c.SrcAlign, diffCoeffsFrom(b.Src, 2))
		r := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src[diffPolyBytes:]))
		dst := diffGuardValue(t, c, c.DstAlign, ringElement{})
		raw := make([]byte, 4*n)
		diff.NewPRNG(c.Seed ^ 0x4A554E4B).Fill(raw)
		for j := range dst {
			dst[j] = fieldElement(binary.LittleEndian.Uint32(raw[j*4:]) % q)
		}
		impl(dst, h, r, gamma2)
		return diffMarshalRing(dst)
	}
}

// TestDiffUseHint checks the architecture hint-correction kernel against the
// generic one; Tag selects gamma2 and the hint bits come from Src.
func TestDiffUseHint(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("useHintPolyGeneric", diffUseHintRunOf(useHintPolyGeneric))
	s.Add(diffDispatchImpl("dispatch-usehint", diffUseHintRunOf(useHintPoly)))
	s.Run(t, diffDomain(diffRepeatLengths(2, 2*diffPolyBytes), nil, []uint64{0, 1}))
}

// diffMakeHintParams maps a tag onto k in 1..4 and the gamma2 selector.
func diffMakeHintParams(tag uint64) (k int, gamma2 uint32) {
	k = int(tag%4) + 1
	gamma2 = gamma2QMinus1Div32
	if tag/4%2 == 1 {
		gamma2 = gamma2QMinus1Div88
	}
	return k, gamma2
}

func diffMakeHintRunOf(impl func(ct0, cs2, w, hint []ringElement, gamma2 uint32)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		k, gamma2 := diffMakeHintParams(c.Tag)
		ct0 := diffGuardSlice(t, c, c.SrcAlign, make([]ringElement, k))
		cs2 := diffGuardSlice(t, c, c.SrcAlign, make([]ringElement, k))
		w := diffGuardSlice(t, c, c.SrcAlign, make([]ringElement, k))
		hint := diffGuardSlice(t, c, c.DstAlign, make([]ringElement, k))
		for i := 0; i < k; i++ {
			ct0[i] = diffRingFrom(b.Src[i*diffPolyBytes:])
			cs2[i] = diffRingFrom(b.Src[4*diffPolyBytes+i*diffPolyBytes:])
			w[i] = diffRingFrom(b.Src[8*diffPolyBytes+i*diffPolyBytes:])
		}
		diffJunkRings(hint[:], c.Seed)
		impl(ct0[:k], cs2[:k], w[:k], hint[:k], gamma2)
		return diffMarshalRings(hint[:k])
	}
}

// TestDiffMakeHint checks the architecture hint-computation kernel against
// the generic one; Tag selects the vector length and gamma2.
func TestDiffMakeHint(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("vectorMakeHintGeneric", diffMakeHintRunOf(vectorMakeHintGeneric))
	s.Add(diffDispatchImpl("dispatch-makehint", diffMakeHintRunOf(vectorMakeHint)))
	s.Run(t, diffDomain(diffRepeatLengths(8, 12*diffPolyBytes), nil, []uint64{0, 1, 2, 3, 4, 5, 6, 7}))
}

// ---- bit pack / bit unpack ----

var diffBitPackSizes = [6]int{encodingSize4, encodingSize4, encodingSize6, encodingSize6, encodingSize18, encodingSize20}

// diffBitPackInput derives the encoder input for a case: Tag selects the
// encoder and maps the coefficients into that encoder's input domain.
func diffBitPackInput(c diff.Case, b *diff.Buffers) (ringElement, int) {
	bound := uint32(q)
	switch c.Tag % 6 {
	case 0:
		bound = 16
	case 2:
		bound = 44
	case 4, 5:
		gamma1 := uint32(1 << 17)
		if c.Tag%6 == 5 {
			gamma1 = 1 << 19
		}
		f := diffCoeffsFrom(b.Src, 2*gamma1)
		for i := range f {
			f[i] = fieldSub(fieldElement(gamma1), f[i])
		}
		return f, diffBitPackSizes[c.Tag%6]
	}
	return diffCoeffsFrom(b.Src, bound), diffBitPackSizes[c.Tag%6]
}

func diffBitPackBoundaryPattern() diff.Pattern {
	values := []uint32{
		0, 1, 15, 16, 43, 44,
		gamma2QMinus1Div32 - 1, gamma2QMinus1Div32, gamma2QMinus1Div32 + 1,
		gamma2QMinus1Div88 - 1, gamma2QMinus1Div88, gamma2QMinus1Div88 + 1,
		q - gamma2QMinus1Div32 - 1, q - gamma2QMinus1Div32, q - gamma2QMinus1Div32 + 1,
		q - gamma2QMinus1Div88 - 1, q - gamma2QMinus1Div88, q - gamma2QMinus1Div88 + 1,
		q - 1, 1<<18 - 1, 1<<20 - 1,
	}
	return diff.Pattern{Name: "encoder-boundaries", Fill: func(raw []byte, _ *diff.PRNG) {
		for i := 0; i+4 <= len(raw); i += 4 {
			binary.LittleEndian.PutUint32(raw[i:], values[i/4%len(values)])
		}
	}}
}

func TestDiffInputDomains(t *testing.T) {
	for tag := uint64(0); tag < 8; tag++ {
		k, gamma2 := diffMakeHintParams(tag)
		wantGamma2 := uint32(gamma2QMinus1Div32)
		if tag >= 4 {
			wantGamma2 = gamma2QMinus1Div88
		}
		if k != int(tag%4)+1 || gamma2 != wantGamma2 {
			t.Fatalf("makeHint tag %d: k=%d gamma2=%d", tag, k, gamma2)
		}
	}
	values := []uint32{0, 15, 43, gamma2QMinus1Div32 + 1, gamma2QMinus1Div88 + 1, q - 1, 1<<18 - 1, 1<<20 - 1}
	raw := make([]byte, diffPolyBytes)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(raw[i*4:], values[i%len(values)])
	}
	for tag := uint64(0); tag < 6; tag++ {
		poly, size := diffBitPackInput(diff.Case{Tag: tag}, &diff.Buffers{Src: raw})
		if size != diffBitPackSizes[tag] {
			t.Fatalf("bitPack tag %d: size=%d", tag, size)
		}
		for i, coeff := range poly {
			switch tag {
			case 0:
				if coeff >= 16 {
					t.Fatalf("4-bit input out of range: %d", coeff)
				}
			case 2:
				if coeff >= 44 {
					t.Fatalf("6-bit input out of range: %d", coeff)
				}
			case 1, 3:
				if coeff != fieldElement(values[i%len(values)]%q) {
					t.Fatalf("HighBits tag %d: input %d was narrowed", tag, i)
				}
			case 4, 5:
				gamma1 := fieldElement(1 << 17)
				if tag == 5 {
					gamma1 = 1 << 19
				}
				if coeff >= q || fieldSub(gamma1, coeff) >= 2*gamma1 {
					t.Fatalf("signed bitPack tag %d: input %d out of range: %d", tag, i, coeff)
				}
			}
		}
	}
}

func diffBitPackRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f, size := diffBitPackInput(c, b)
	buf := make([]byte, size)
	diff.NewPRNG(c.Seed ^ 0x4250544B).Fill(buf) // junk prefill
	switch c.Tag % 6 {
	case 0:
		simpleBitPack4BitsGeneric(buf, &f)
	case 1:
		simpleBitPack4BitsHighBitsGeneric(buf, &f, gamma2QMinus1Div32)
	case 2:
		simpleBitPack6BitsGeneric(buf, &f)
	case 3:
		simpleBitPack6BitsHighBitsGeneric(buf, &f, gamma2QMinus1Div88)
	case 4:
		bitPackSignedTwoPower17Generic(buf, &f)
	default:
		bitPackSignedTwoPower19Generic(buf, &f)
	}
	return buf
}

func diffBitPackImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	value, _ := diffBitPackInput(c, b)
	f := diffGuardValue(t, c, c.SrcAlign, value)
	switch c.Tag % 6 {
	case 0:
		return simpleBitPack4Bits(b.Dst[:0], f)
	case 1:
		simpleBitPack4BitsHighBits(b.Dst[:encodingSize4], f, gamma2QMinus1Div32)
		return b.Dst[:encodingSize4]
	case 2:
		return simpleBitPack6Bits(b.Dst[:0], f)
	case 3:
		simpleBitPack6BitsHighBits(b.Dst[:encodingSize6], f, gamma2QMinus1Div88)
		return b.Dst[:encodingSize6]
	case 4:
		return bitPackSignedTwoPower17(b.Dst[:0], f)
	default:
		return bitPackSignedTwoPower19(b.Dst[:0], f)
	}
}

// TestDiffBitPack checks the architecture encoders against the generic ones;
// Tag selects one of the six FIPS 204 encodings used by the signature paths.
func TestDiffBitPack(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("simpleBitPack*Generic", diffBitPackRef)
	s.Add(diffDispatchImpl("dispatch-bitpack", diffBitPackImplRun))
	s.Run(t, diff.Domain{
		Lengths:    diffRepeatLengths(6, diffPolyBytes),
		DstLengths: []int{encodingSize4, encodingSize4, encodingSize6, encodingSize6, encodingSize18, encodingSize20},
		Tags:       []uint64{0, 1, 2, 3, 4, 5},
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   append(diff.DefaultPatterns(), diffBitPackBoundaryPattern()),
		Seeds:      []uint64{0, 1},
	})
}

func diffBitUnpackRunOf(impl func(b []byte, f *ringElement)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		f := diffGuardValue(t, c, c.DstAlign, ringElement{})
		impl(b.Src, f)
		return diffMarshalRing(f)
	}
}

func diffBitUnpackRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	if c.Tag%2 == 0 {
		return diffBitUnpackRunOf(bitUnpackSignedTwoPower17Generic)(t, c, b)
	}
	return diffBitUnpackRunOf(bitUnpackSignedTwoPower19Generic)(t, c, b)
}

func diffBitUnpackImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	if c.Tag%2 == 0 {
		return diffBitUnpackRunOf(bitUnpackSignedTwoPower17)(t, c, b)
	}
	return diffBitUnpackRunOf(bitUnpackSignedTwoPower19)(t, c, b)
}

// TestDiffBitUnpack checks the architecture signature decoders against the
// generic ones; Tag selects the 2^17 / 2^19 variant.
func TestDiffBitUnpack(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("bitUnpackSignedTwoPower*Generic", diffBitUnpackRef)
	s.Add(diffDispatchImpl("dispatch-bitunpack", diffBitUnpackImplRun))
	s.Run(t, diffDomain([]int{encodingSize18, encodingSize20}, nil, []uint64{0, 1}))
}

// FuzzDiffBitUnpack fuzzes the signature decoders; Tag is bounded to the
// variant selector and SrcLen is repaired to that variant's encoding size.
func FuzzDiffBitUnpack(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("bitUnpackSignedTwoPower*Generic", diffBitUnpackRef,
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 2
			if c.Tag == 0 {
				c.SrcLen = encodingSize18
			} else {
				c.SrcLen = encodingSize20
			}
			return true
		}),
	)
	s.Add(diffDispatchImpl("dispatch-bitunpack", diffBitUnpackImplRun))
	s.Fuzz(f, diffDomain([]int{encodingSize18, encodingSize20}, nil, []uint64{0, 1}))
}

// ---- convention-independent anchors ----

// diffNegacyclicMul computes the schoolbook negacyclic product f·g in
// Z_q[X]/(X²⁵⁶+1); it is independent of any NTT convention.
func diffNegacyclicMul(a, b *ringElement) ringElement {
	var acc [n]int64
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			v := int64(uint64(a[i]) * uint64(b[j]) % q)
			if i+j < n {
				acc[i+j] += v
			} else {
				acc[i+j-n] -= v
			}
		}
	}
	var out ringElement
	for i := range out {
		out[i] = fieldElement(((acc[i] % q) + q) % q)
	}
	return out
}

// TestDiffNTTConvolutionAnchor anchors the whole NTT pipeline through the
// public dispatch against the schoolbook negacyclic product: the r⁻¹ factor
// of the Montgomery multiplication and the compensating r factor of the
// Montgomery inverse NTT cancel inside the pipeline. It runs on every
// build, including purego.
func TestDiffNTTConvolutionAnchor(t *testing.T) {
	raw := make([]byte, 2*diffPolyBytes)
	diff.NewPRNG(0xC0FE ^ diff.MasterSeed()).Fill(raw)
	f := diffRingFrom(raw[:diffPolyBytes])
	g := diffRingFrom(raw[diffPolyBytes:])

	want := diffNegacyclicMul(&f, &g)

	nt := f
	internalNTT(&nt)
	gt := g
	internalNTT(&gt)
	var m nttElement
	nttMul(&m, (*nttElement)(&nt), (*nttElement)(&gt))
	back := m
	internalInverseNTT(&back)

	for i := range back {
		if back[i] != want[i] {
			t.Fatalf("convolution anchor mismatch at %d: got %d, want %d", i, back[i], want[i])
		}
	}
}

// ---- dispatch observability ----

// TestDispatchSelectedImplementation verifies that the dispatch state is
// consistent with the CPU features of the host.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}

// TestDiffRequiredKernels fails if the kernels named in the DIFF_REQUIRE
// environment variable are unavailable on this host. It mirrors the sm4
// mechanism: CI runs the diff suites on native hardware with the expected
// kernel names so that a silent dispatch fallback cannot go unnoticed.
func TestDiffRequiredKernels(t *testing.T) {
	req := os.Getenv("DIFF_REQUIRE")
	if req == "" {
		t.Skip("DIFF_REQUIRE not set")
	}
	for _, name := range strings.Split(req, ",") {
		diffCheckRequiredKernel(t, name)
	}
}
