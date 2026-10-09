// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mlkem

import (
	"crypto/sha3"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// The mlkem field kernels come in two conventions:
//
//   - the plain kernels (forward NTT, polyAdd/SubAssign, the ring encoders,
//     CBD sampling, rejection sampling) operate directly on mod-q values;
//     the pure-Go implementations double as the differential reference,
//   - the NTT-domain kernels follow per-architecture conventions: the
//     amd64/arm64/loong64/riscv64 assembly keeps the scalar Montgomery
//     convention of field_mont.go (products and inverse-NTT output carry an
//     r factor that cancels inside the pipeline), while ppc64le follows the
//     generic kernels' convention. The keygen variant of the accumulating
//     multiplication produces plain-domain results on every architecture,
//     because its result is encoded directly during key generation.
//
// Consequently the plain-kernel suites compare the dispatch path against
// the generic kernel, the Montgomery-convention suites select their
// reference through the diffMontMulConvention hook, the keygen suite always
// references nttMulAccGeneric, and the convention-independent
// TestDiffNTTConvolutionAnchor covers every build including purego.

// diffRingFrom interprets src as 256 little-endian uint16 coefficients
// reduced mod q. It is the common way to derive a polynomial from a case
// buffer, keeping every coefficient inside the kernels' input domain.
func diffRingFrom(src []byte) ringElement {
	var f ringElement
	for i := range f {
		f[i] = fieldElement(binary.LittleEndian.Uint16(src[i*2:]) % q)
	}
	return f
}

// diffNTTFrom is diffRingFrom for the distinct nttElement type.
func diffNTTFrom(src []byte) nttElement {
	return nttElement(diffRingFrom(src))
}

func diffGuardValue[T ringElement | nttElement](t testing.TB, c diff.Case, alignment int, value T) *T {
	t.Helper()
	return &diffGuardSlice(t, c, alignment, []T{value})[0]
}

func diffGuardSlice[T ringElement | nttElement](t testing.TB, c diff.Case, alignment int, values []T) []T {
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
	out := make([]byte, 2*len(f))
	for i, v := range f {
		binary.LittleEndian.PutUint16(out[i*2:], uint16(v))
	}
	return out
}

func diffMarshalNTT(f *nttElement) []byte {
	return diffMarshalRing((*ringElement)(f))
}

// diffMarshalRings concatenates the marshaled forms of a poly slice, e.g.
// the destination vector of decodeAndDecompressU10/U11.
func diffMarshalRings(fs []ringElement) []byte {
	out := make([]byte, 0, 2*n*len(fs))
	for i := range fs {
		out = append(out, diffMarshalRing(&fs[i])...)
	}
	return out
}

// diffJunkRings prefills dst with deterministic mod-q junk so that a kernel
// that fails to write part of its output becomes detectable.
func diffJunkRings(dst []ringElement, seed uint64) {
	raw := make([]byte, 2*len(dst)*n)
	diff.NewPRNG(seed ^ 0x4A554E4B).Fill(raw)
	for i := range dst {
		for j := range dst[i] {
			dst[i][j] = fieldElement(binary.LittleEndian.Uint16(raw[(i*n+j)*2:]) % q)
		}
	}
}

func diffJunkNTT(a *nttElement, seed uint64) {
	raw := make([]byte, 2*n)
	diff.NewPRNG(seed ^ 0x4A554E4B).Fill(raw)
	for j := range a {
		a[j] = fieldElement(binary.LittleEndian.Uint16(raw[j*2:]) % q)
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
		t.Skip("no accelerated mlkem kernels available on this host")
	}
}

// ---- forward NTT (plain convention) ----

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

// TestDiffNTT checks the architecture NTT kernel against the pure-Go
// implementation. Both produce plain-domain coefficients, so the outputs
// are directly comparable.
func TestDiffNTT(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("internalNTTGeneric", diffNTTRef)
	s.Add(diffDispatchImpl("dispatch-ntt", diffNTTImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, 512), nil, nil))
}

// FuzzDiffNTT fuzzes the NTT kernels; SrcLen is always 512 (two packed
// polynomials) and no Tag is used, so no normalization is required.
func FuzzDiffNTT(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("internalNTTGeneric", diffNTTRef)
	s.Add(diffDispatchImpl("dispatch-ntt", diffNTTImplRun))
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, 512), nil, nil))
}

// ---- inverse NTT (per-architecture convention) ----

func diffInverseNTTRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f := diffNTTFrom(b.Src)
	if diffMontMulConvention() {
		internalMontInverseNTT(&f)
	} else {
		internalInverseNTTGeneric(&f)
	}
	return diffMarshalNTT(&f)
}

func diffInverseNTTImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
	internalInverseNTT(f)
	return diffMarshalNTT(f)
}

// TestDiffInverseNTT checks the architecture inverse NTT kernel against the
// scalar Montgomery kernel (Montgomery-convention architectures) or the
// generic kernel (ppc64le); both leave the architecture's characteristic
// scaling in the coefficients.
func TestDiffInverseNTT(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("inverse-ntt", diffInverseNTTRef)
	s.Add(diffDispatchImpl("dispatch-intt", diffInverseNTTImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, 512), nil, nil))
}

// ---- NTT-domain multiplication (per-architecture convention) ----

func diffNTTMulRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	lhs := diffNTTFrom(b.Src)
	rhs := diffNTTFrom(b.Src[512:])
	var out nttElement
	if diffMontMulConvention() {
		nttMontMul(&out, &lhs, &rhs)
	} else {
		nttMulGeneric(&out, &lhs, &rhs)
	}
	return diffMarshalNTT(&out)
}

func diffNTTMulImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	lhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
	rhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src[512:]))
	out := diffGuardValue(t, c, c.DstAlign, nttElement{})
	diffJunkNTT(out, c.Seed)
	nttMul(out, lhs, rhs)
	return diffMarshalNTT(out)
}

// TestDiffNTTMul checks the architecture pointwise NTT multiplication
// against the scalar Montgomery kernel (Montgomery-convention
// architectures) or the generic kernel (ppc64le).
func TestDiffNTTMul(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("ntt-mul", diffNTTMulRef)
	s.Add(diffDispatchImpl("dispatch-nttmul", diffNTTMulImplRun))
	s.Run(t, diffDomain([]int{1024}, []int{512}, nil))
}

func diffNTTMulAccRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	lhs := diffNTTFrom(b.Src)
	rhs := diffNTTFrom(b.Src[512:])
	acc := diffNTTFrom(b.Dst)
	if diffMontMulConvention() {
		nttMontMulAcc(&acc, &lhs, &rhs)
	} else {
		nttMulAccGeneric(&acc, &lhs, &rhs)
	}
	return diffMarshalNTT(&acc)
}

func diffNTTMulAccImplRunOf(mulAcc func(acc, lhs, rhs *nttElement)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		diffForceDispatch(t)
		lhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src))
		rhs := diffGuardValue(t, c, c.SrcAlign, diffNTTFrom(b.Src[512:]))
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
	s := diff.ByteSuite("ntt-mulacc", diffNTTMulAccRef)
	s.Add(diffDispatchImpl("dispatch-nttmulacc", diffNTTMulAccImplRunOf(nttMulAcc)))
	s.Run(t, diffDomain([]int{1024}, []int{512}, nil))
}

// FuzzDiffNTTMulAcc fuzzes the accumulating NTT multiplication.
func FuzzDiffNTTMulAcc(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("ntt-mulacc", diffNTTMulAccRef)
	s.Add(diffDispatchImpl("dispatch-nttmulacc", diffNTTMulAccImplRunOf(nttMulAcc)))
	s.Fuzz(f, diffDomain([]int{1024}, []int{512}, nil))
}

// TestDiffNTTMulAccKeyGen checks the keygen variant of the accumulating NTT
// multiplication. Its result is encoded directly during key generation, so
// it produces plain-domain coefficients on every architecture and always
// references the generic accumulating kernel.
func TestDiffNTTMulAccKeyGen(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("nttMulAccGeneric", diffNTTMulAccKeyGenRef)
	s.Add(diffDispatchImpl("dispatch-nttmulacckg", diffNTTMulAccImplRunOf(nttMulAccKeyGen)))
	s.Run(t, diffDomain([]int{1024}, []int{512}, nil))
}

func diffNTTMulAccKeyGenRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	lhs := diffNTTFrom(b.Src)
	rhs := diffNTTFrom(b.Src[512:])
	acc := diffNTTFrom(b.Dst)
	nttMulAccGeneric(&acc, &lhs, &rhs)
	return diffMarshalNTT(&acc)
}

// ---- poly add/sub (plain convention) ----

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
	s := diff.ByteSuite("polyAddAssignGeneric", diffPolyAddSubRunOf(polyAddAssignGeneric, polySubAssignGeneric))
	s.Add(diffDispatchImpl("dispatch-addsub", diffPolyAddSubRunOf(polyAddAssign, polySubAssign)))
	s.Run(t, diffDomain(diffRepeatLengths(2, 512), nil, []uint64{0, 1}))
}

// FuzzDiffPolyAddSub fuzzes the add/sub kernels; Tag is bounded to the
// operation selector.
func FuzzDiffPolyAddSub(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("polyAddAssignGeneric", diffPolyAddSubRunOf(polyAddAssignGeneric, polySubAssignGeneric),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 2
			return true
		}),
	)
	s.Add(diffDispatchImpl("dispatch-addsub", diffPolyAddSubRunOf(polyAddAssign, polySubAssign)))
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, 512), nil, []uint64{0, 1}))
}

// ---- ring compression + encoding (plain convention) ----

var diffEncodeSizes = [5]int{encodingSize1, encodingSize4, encodingSize5, encodingSize10, encodingSize11}

func diffRingEncodeRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	f := diffRingFrom(b.Src)
	switch c.Tag {
	case 0:
		// ByteEncode1 only sets bits, so the destination must be cleared
		// first (the dispatching wrapper does the same).
		clear(b.Dst)
		ringCompressAndEncode1Generic(b.Dst[:encodingSize1], &f)
	case 1:
		ringCompressAndEncode4Generic(b.Dst[:encodingSize4], &f)
	case 2:
		ringCompressAndEncode(b.Dst[:0], &f, 5)
	case 3:
		ringCompressAndEncode10Generic(b.Dst[:encodingSize10], &f)
	default:
		ringCompressAndEncode(b.Dst[:0], &f, 11)
	}
	return b.Dst[:diffEncodeSizes[c.Tag]]
}

func diffRingEncodeImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := diffGuardValue(t, c, c.SrcAlign, diffRingFrom(b.Src))
	var out []byte
	switch c.Tag {
	case 0:
		out = ringCompressAndEncode1(b.Dst[:0], f)
	case 1:
		out = ringCompressAndEncode4(b.Dst[:0], f)
	case 2:
		out = ringCompressAndEncode5(b.Dst[:0], f)
	case 3:
		out = ringCompressAndEncode10(b.Dst[:0], f)
	default:
		out = ringCompressAndEncode11(b.Dst[:0], f)
	}
	return out
}

// TestDiffRingEncode checks the architecture Compress/ByteEncode kernels
// against the generic ones; Tag selects d in {1, 4, 5, 10, 11}.
func TestDiffRingEncode(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("ringCompressAndEncode*Generic", diffRingEncodeRef)
	s.Add(diffDispatchImpl("dispatch-encode", diffRingEncodeImplRun))
	s.Run(t, diff.Domain{
		Lengths:    diffRepeatLengths(5, 512),
		DstLengths: []int{encodingSize1, encodingSize4, encodingSize5, encodingSize10, encodingSize11},
		Tags:       []uint64{0, 1, 2, 3, 4},
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	})
}

// FuzzDiffRingEncode fuzzes the encode kernels; Tag is bounded to the d
// selector and DstLen is repaired to the encoding size of that d.
func FuzzDiffRingEncode(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("ringCompressAndEncode*Generic", diffRingEncodeRef,
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 5
			c.DstLen = diffEncodeSizes[c.Tag]
			return true
		}),
	)
	s.Add(diffDispatchImpl("dispatch-encode", diffRingEncodeImplRun))
	s.Fuzz(f, diff.Domain{
		Lengths:    diffRepeatLengths(5, 512),
		DstLengths: []int{encodingSize1, encodingSize4, encodingSize5, encodingSize10, encodingSize11},
		Tags:       []uint64{0, 1, 2, 3, 4},
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	})
}

// ---- ring decode + decompress (plain convention) ----

func diffRingDecodeRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	var f ringElement
	if c.Tag == 0 {
		ringDecodeAndDecompress4Generic((*[encodingSize4]byte)(b.Src), &f)
	} else {
		f = ringDecodeAndDecompress(b.Src, 5)
	}
	return diffMarshalRing(&f)
}

func diffRingDecodeImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := diffGuardValue(t, c, c.DstAlign, ringElement{})
	diffJunkRings(unsafe.Slice(f, 1), c.Seed)
	if c.Tag == 0 {
		ringDecodeAndDecompress4((*[encodingSize4]byte)(b.Src), f)
	} else {
		*f = ringDecodeAndDecompress5((*[encodingSize5]byte)(b.Src))
	}
	return diffMarshalRing(f)
}

// TestDiffRingDecode checks the architecture ByteDecode/Decompress kernels
// against the generic ones; Tag selects d in {4, 5}.
func TestDiffRingDecode(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("ringDecodeAndDecompress*Generic", diffRingDecodeRef)
	s.Add(diffDispatchImpl("dispatch-decode", diffRingDecodeImplRun))
	s.Run(t, diffDomain([]int{encodingSize4, encodingSize5}, nil, []uint64{0, 1}))
}

// ---- decodeAndDecompressU10/U11 (plain convention) ----

// diffDecodeUParams maps a tag onto the u/k parameters of the vector
// decoders: bit 0 selects u10/u11, bits 1-2 select k in 1..4.
func diffDecodeUParams(tag uint64) (u10 bool, k int) {
	u10 = tag%2 == 0
	k = int(tag/2)%4 + 1
	return u10, k
}

func diffDecodeURunOf(u10Impl func(dst []ringElement, c []byte), u11Impl func(dst []ringElement, c []byte)) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		u10, k := diffDecodeUParams(c.Tag)
		dst := diffGuardSlice(t, c, c.DstAlign, make([]ringElement, k))
		diffJunkRings(dst[:], c.Seed)
		if u10 {
			u10Impl(dst[:k], b.Src)
		} else {
			u11Impl(dst[:k], b.Src)
		}
		return diffMarshalRings(dst[:k])
	}
}

// TestDiffDecodeAndDecompressU checks the architecture vector decoders used
// during decapsulation against the generic ones; Tag selects u and k.
func TestDiffDecodeAndDecompressU(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("decodeAndDecompressU*Generic", diffDecodeURunOf(decodeAndDecompressU10Generic, decodeAndDecompressU11Generic))
	s.Add(diffDispatchImpl("dispatch-decodeu", diffDecodeURunOf(decodeAndDecompressU10, decodeAndDecompressU11)))
	s.Run(t, diff.Domain{
		Lengths:    []int{encodingSize10, encodingSize11, 2 * encodingSize10, 2 * encodingSize11, 3 * encodingSize10, 3 * encodingSize11, 4 * encodingSize10, 4 * encodingSize11},
		Tags:       []uint64{0, 1, 2, 3, 4, 5, 6, 7},
		Alignments: diff.CommonAlignments(),
		Overlaps:   []diff.OverlapCase{diff.NoOverlap()},
		Patterns:   diff.DefaultPatterns(),
		Seeds:      []uint64{0, 1},
	})
}

// ---- samplePolyCBD (plain convention) ----

func diffSamplePolyCBDRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	eta := byte(2 + c.Tag%2)
	prf := sha3.NewSHAKE256()
	prf.Write(b.Src)
	prf.Write([]byte{byte(c.Seed)})
	var B [maxBytesOf64Mulη]byte
	prf.Read(B[:64*eta])
	f := samplePolyCBDGeneric(B[:64*eta], eta)
	return diffMarshalRing(&f)
}

func diffSamplePolyCBDImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	f := samplePolyCBD(b.Src, byte(c.Seed), byte(2+c.Tag%2))
	return diffMarshalRing(&f)
}

// TestDiffSamplePolyCBD checks the architecture CBD sampling kernels against
// the generic one; Tag selects eta in {2, 3}, the seed byte comes from the
// case seed.
func TestDiffSamplePolyCBD(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("samplePolyCBDGeneric", diffSamplePolyCBDRef)
	s.Add(diffDispatchImpl("dispatch-cbd", diffSamplePolyCBDImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, 32), nil, []uint64{0, 1}))
}

// ---- rejection sampling (plain convention) ----

// diffRejUniformRunOf wraps a rejection-sampling kernel. Tag selects the
// starting index j (bounded so that the kernel's maximum write of 16
// coefficients stays in range); the untouched junk prefix of a must match,
// which detects writes at the wrong offset.
func diffRejUniformRunOf(rej func(buf []byte, a *nttElement, j int) int) diff.Run[[]byte] {
	return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
		j := int(c.Tag % 240)
		a := diffGuardValue(t, c, c.DstAlign, nttElement{})
		diffJunkNTT(a, c.Seed)
		cnt := rej(b.Src, a, j)
		out := diffMarshalNTT(a)
		return append(out, byte(cnt))
	}
}

// TestDiffRejUniform checks the architecture rejection-sampling kernel
// against the generic one.
func TestDiffRejUniform(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("rejUniformGeneric", diffRejUniformRunOf(rejUniformGeneric))
	s.Add(diff.Implementation[[]byte]{
		Name:      "dispatch-rejuniform",
		Run:       diffRejUniformRunOf(diffRejUniform),
		Available: diffDispatchAvailable,
		Primary:   diffDispatchAvailable(),
	})
	s.Run(t, diffDomain(diffRepeatLengths(7, 24), nil, []uint64{0, 1, 7, 33, 96, 175, 239}))
}

// FuzzDiffRejUniform fuzzes the rejection-sampling kernel; Tag is bounded to
// the legal start-index range and SrcLen stays on the 24-byte fast path.
func FuzzDiffRejUniform(f *testing.F) {
	diffSkipIfNoDispatch(f)
	s := diff.ByteSuite("rejUniformGeneric", diffRejUniformRunOf(rejUniformGeneric),
		diff.WithNormalize[[]byte](func(c *diff.Case) bool {
			c.Tag %= 240
			return true
		}),
	)
	s.Add(diff.Implementation[[]byte]{
		Name:      "dispatch-rejuniform",
		Run:       diffRejUniformRunOf(diffRejUniform),
		Available: diffDispatchAvailable,
		Primary:   diffDispatchAvailable(),
	})
	s.Fuzz(f, diffDomain(diffRepeatLengths(2, 24), nil, []uint64{0, 100}))
}

// ---- sampleNTT / sampleNTTx4 (plain convention) ----

// diffSampleNTTRefRun mirrors the pure-Go sampleNTT driver on top of the
// generic rejection-sampling kernel; it is the reference for the expanded
// matrix sampling on every architecture.
func diffSampleNTTRefRun(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewSHAKE128()
	B.Write(rho)
	var domain [2]byte
	domain[0], domain[1] = ii, jj
	B.Write(domain[:])

	var a nttElement
	var j int
	var batch [168]byte
	for j < n {
		B.Read(batch[:])
		for off := 0; off < len(batch) && j < n; off += 24 {
			j += rejUniformGeneric(batch[off:off+24], &a, j)
		}
	}
	return a
}

func diffSampleNTTIndices(c diff.Case) (ii, jj byte) {
	return byte(1 + c.Tag%7), byte(1 + (c.Tag/7)%7)
}

func diffSampleNTTRef(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	ii, jj := diffSampleNTTIndices(c)
	a := diffSampleNTTRefRun(b.Src, ii, jj)
	return diffMarshalNTT(&a)
}

func diffSampleNTTImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	ii, jj := diffSampleNTTIndices(c)
	a := sampleNTT(b.Src, ii, jj)
	return diffMarshalNTT(&a)
}

// TestDiffSampleNTT checks the architecture matrix-entry sampling (XOF
// driver plus rejection kernel) against the pure-Go reference.
func TestDiffSampleNTT(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("rejUniformGeneric+SHAKE128", diffSampleNTTRef)
	s.Add(diffDispatchImpl("dispatch-samplentt", diffSampleNTTImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(3, 32), nil, []uint64{0, 1, 2}))
}

func diffSampleNTTx4Indices(c diff.Case) [4][2]byte {
	raw := make([]byte, 8)
	diff.NewPRNG(c.Seed ^ 0x58344E54).Fill(raw)
	var indices [4][2]byte
	for i := range indices {
		indices[i][0] = 1 + raw[2*i]%7
		indices[i][1] = 1 + raw[2*i+1]%7
	}
	return indices
}

func diffSampleNTTx4Ref(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	indices := diffSampleNTTx4Indices(c)
	var out []byte
	for lane := range indices {
		a := diffSampleNTTRefRun(b.Src, indices[lane][0], indices[lane][1])
		out = append(out, diffMarshalNTT(&a)...)
	}
	return out
}

func diffSampleNTTx4ImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	diffForceDispatch(t)
	indices := diffSampleNTTx4Indices(c)
	results := sampleNTTx4(b.Src, indices)
	var out []byte
	for lane := range results {
		out = append(out, diffMarshalNTT(&results[lane])...)
	}
	return out
}

// TestDiffSampleNTTx4 checks the four-lane matrix sampling against four
// scalar reference invocations.
func TestDiffSampleNTTx4(t *testing.T) {
	diffSkipIfNoDispatch(t)
	s := diff.ByteSuite("4x sampleNTT", diffSampleNTTx4Ref)
	s.Add(diffDispatchImpl("dispatch-samplenttx4", diffSampleNTTx4ImplRun))
	s.Run(t, diffDomain(diffRepeatLengths(2, 32), nil, []uint64{0, 1}))
}

// ---- convention-independent anchors ----

// diffNegacyclicMul computes the schoolbook negacyclic product f·g in
// Z_q[X]/(X²⁵⁶+1); it is independent of any NTT convention.
func diffNegacyclicMul(a, b *ringElement) ringElement {
	var acc [n]int64
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			v := int64(uint32(a[i]) * uint32(b[j]) % q)
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
// public dispatch against the schoolbook negacyclic product. The anchor is
// convention-independent: on asm builds the r⁻¹ factor of the Montgomery
// multiplication and the compensating r factor of the Montgomery inverse
// NTT cancel, and on pure-Go builds the plain kernels compose directly.
// It runs on every build, including purego.
func TestDiffNTTConvolutionAnchor(t *testing.T) {
	raw := make([]byte, 1024)
	diff.NewPRNG(0xC0FE ^ diff.MasterSeed()).Fill(raw)
	f := diffRingFrom(raw[:512])
	g := diffRingFrom(raw[512:])

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
