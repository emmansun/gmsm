// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package bn256

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
)

// bn256 selects one accelerated backend per architecture via build tags; the
// generic pure-Go fallback is build-tag complementary and therefore not
// compiled on accelerated builds. The oracles are consequently independent of
// the package arithmetic: big.Int field arithmetic for the base field
// kernels, test-local generic implementations for the select/copy primitives
// and a big.Int affine curve reference for the G1 point operations. The
// per-architecture dispatch state (supportADX, supportAVX2, supportLSX/
// supportLASX, supportRVV) is forceable through diff.WithValue, so the
// accelerated and scalar code paths within one architecture are diffed as
// well. The per-architecture implementation lists live in the
// diff_kernels_*_test.go files.

// diffKATPK is the public key scalar of the GB/T pairing vector used by
// bn_pair_test.go (Test_Pairing_A2); TestDiffStandardVector anchors on the
// same value.
const diffKATPK = "0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"

// diffKATB is a second fixed scalar for the bilinearity anchor.
const diffKATB = "0123456789ABCDEF" + "FEDCBA9876543210" +
	"0123456789ABCDEF" + "FEDCBA9876543210"

// diffR is the Montgomery constant R = 2^256 reduced mod p.
var diffR = new(big.Int).Lsh(big.NewInt(1), 256)

// diffGx/diffGy are the affine coordinates of curveGen decoded from the
// Montgomery form; TestDiffStandardVector anchors them to the curve.
var (
	diffGx *big.Int
	diffGy *big.Int
)

func init() {
	diffR.Mod(diffR, p)
	x, y := &gfP{}, &gfP{}
	montDecode(x, &curveGen.x)
	montDecode(y, &curveGen.y)
	diffGx = diffGfpToInt(x)
	diffGy = diffGfpToInt(y)
}

func diffGfpToInt(e *gfP) *big.Int {
	v := new(big.Int)
	for i := 3; i >= 0; i-- {
		v.Lsh(v, 64)
		v.Or(v, new(big.Int).SetUint64(e[i]))
	}
	return v
}

func diffMustInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bn256: invalid test constant " + s)
	}
	return v
}

// TestDiffStandardVector anchors the reference constants and the package's
// public path before they serve as differential oracles: the generator is on
// the reference curve, [Order]G1 is the point at infinity, the reference
// agrees with the package on [2]G, the GB/T pairing vector holds, and the
// pairing is bilinear.
func TestDiffStandardVector(t *testing.T) {
	// The generator is on the reference curve y² = x³ + 5.
	lhs := new(big.Int).Mul(diffGy, diffGy)
	lhs.Mod(lhs, p)
	rhs := new(big.Int).Mul(diffGx, diffGx)
	rhs.Mul(rhs, diffGx)
	rhs.Add(rhs, big.NewInt(5))
	rhs.Mod(rhs, p)
	if lhs.Cmp(rhs) != 0 {
		t.Fatal("standard generator is not on the reference curve y² = x³ + 5")
	}
	// Package marshaling agrees with the reference encoding.
	g := &diffRefPoint{x: diffGx, y: diffGy}
	if !bytes.Equal(g.bytes(), Gen1.Marshal()) {
		t.Fatal("package Marshal of the generator differs from the reference encoding")
	}
	// [Order]G1 is the point at infinity.
	gn, err := (&G1{}).ScalarBaseMult(NormalizeScalar(Order.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !gn.IsInfinity() {
		t.Fatal("[Order]G1 is not the point at infinity")
	}
	// Reference and package agree on [2]G.
	g2pkg := (&G1{}).Double(Gen1)
	g2pkg.p.MakeAffine()
	if !bytes.Equal(diffRefDouble(g).bytes(), diffCurveAffineBE(g2pkg.p)) {
		t.Fatal("reference and package disagree on [2]G")
	}
	// GB/T pairing vector (same anchor as Test_Pairing_A2).
	pk := diffMustInt(diffKATPK)
	g2 := &G2{}
	if _, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes())); err != nil {
		t.Fatal(err)
	}
	if ret := pairing(g2.p, curveGen); *ret != *expected1 {
		t.Fatal("pairing KAT mismatch")
	}
	// Bilinearity: e([a]G1, [b]G2) == e(G1, G2)^(a·b).
	a := diffMustInt(diffKATPK)
	bb := diffMustInt(diffKATB)
	g1a := &G1{}
	if _, err := g1a.ScalarBaseMult(NormalizeScalar(a.Bytes())); err != nil {
		t.Fatal(err)
	}
	g2b := &G2{}
	if _, err := g2b.ScalarBaseMult(NormalizeScalar(bb.Bytes())); err != nil {
		t.Fatal(err)
	}
	k := new(big.Int).Mul(a, bb)
	k.Mod(k, Order)
	want, err := ScalarMultGT(Pair(Gen1, Gen2), k.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if *Pair(g1a, g2b).p != *want.p {
		t.Fatal("bilinearity check failed: e([a]G1,[b]G2) != e(G1,G2)^(ab)")
	}
}

// ---------------------------------------------------------------------------
// Base field kernels: asm vs big.Int reference.
// ---------------------------------------------------------------------------

func diffFieldReduce(b []byte) []byte {
	v := new(big.Int).SetBytes(b)
	v.Mod(v, p)
	return v.FillBytes(make([]byte, 32))
}

// diffGFpFromBE decodes a canonical big-endian value into raw limbs.
func diffGFpFromBE(b []byte) gfP {
	var e gfP
	gfpUnmarshal(&e, (*[32]byte)(b))
	return e
}

func diffGFpBE(e *gfP) []byte {
	var out [32]byte
	gfpMarshal(&out, e)
	return out[:]
}

// diffFieldTags: 0=Mul 1=Sqr 2=Sqr³ 3=Add 4=Sub 5=Double 6=Triple 7=Neg
// 8=FromMont 9=Marshal(Montgomery limbs) 10=Unmarshal roundtrip.
const diffFieldTags = 11

func diffFieldImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	t.Helper()
	aBE := diffFieldReduce(b.Src[:32])
	bBE := diffFieldReduce(b.Src[32:])
	a := diffGFpFromBE(aBE)
	bv := diffGFpFromBE(bBE)
	aM := diffGFpFromBE(aBE)
	montEncode(&aM, &aM)
	var r gfP
	switch c.Tag % diffFieldTags {
	case 0:
		bM := diffGFpFromBE(bBE)
		montEncode(&bM, &bM)
		gfpMul(&r, &aM, &bM)
		gfpFromMont(&r, &r)
		return diffGFpBE(&r)
	case 1:
		gfpSqr(&r, &aM, 1)
		gfpFromMont(&r, &r)
		return diffGFpBE(&r)
	case 2:
		gfpSqr(&r, &aM, 3)
		gfpFromMont(&r, &r)
		return diffGFpBE(&r)
	case 3:
		gfpAdd(&r, &a, &bv)
		return diffGFpBE(&r)
	case 4:
		gfpSub(&r, &a, &bv)
		return diffGFpBE(&r)
	case 5:
		gfpDouble(&r, &a)
		return diffGFpBE(&r)
	case 6:
		gfpTriple(&r, &a)
		return diffGFpBE(&r)
	case 7:
		gfpNeg(&r, &a)
		return diffGFpBE(&r)
	case 8:
		gfpFromMont(&r, &aM)
		return diffGFpBE(&r)
	case 9:
		return diffGFpBE(&aM)
	default:
		// Unmarshal+Marshal roundtrip of the canonical value.
		return diffGFpBE(&a)
	}
}

func diffFieldRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	a := new(big.Int).SetBytes(diffFieldReduce(b.Src[:32]))
	bv := new(big.Int).SetBytes(diffFieldReduce(b.Src[32:]))
	r := new(big.Int)
	switch c.Tag % diffFieldTags {
	case 0:
		r.Mul(a, bv)
	case 1:
		r.Mul(a, a)
	case 2:
		r.Exp(a, big.NewInt(8), nil)
	case 3:
		r.Add(a, bv)
	case 4:
		r.Sub(a, bv)
	case 5:
		r.Lsh(a, 1)
	case 6:
		r.Mul(a, big.NewInt(3))
	case 7:
		r.Sub(p, a)
	case 8:
		r.Set(a)
	case 9:
		r.Mul(a, diffR)
	default:
		r.Set(a)
	}
	r.Mod(r, p)
	return r.FillBytes(make([]byte, 32))
}

func diffFieldDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{64}, // two 32-byte base field elements
		Tags:          []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

func diffAddAll(s *diff.Suite[[]byte], impls []diff.Implementation[[]byte]) {
	for _, im := range impls {
		s.Add(im)
	}
}

// TestDiffFieldKernels checks the base-field kernels against the big.Int
// reference; on amd64 both the ADX and the scalar dispatch path participate.
func TestDiffFieldKernels(t *testing.T) {
	impls := diffFPImpls()
	if len(impls) == 0 {
		t.Skip("no accelerated base field kernels on this build")
	}
	s := diff.ByteSuite("big-int-gfp", diffFieldRefRun)
	diffAddAll(s, impls)
	s.Run(t, diffFieldDomain())
}

// FuzzDiffFieldKernels fuzzes the base-field kernels; no Tag value changes
// the buffer sizes, so no normalization is required.
func FuzzDiffFieldKernels(f *testing.F) {
	impls := diffFPImpls()
	if len(impls) == 0 {
		f.Skip("no accelerated base field kernels on this build")
	}
	s := diff.ByteSuite("big-int-gfp", diffFieldRefRun)
	diffAddAll(s, impls)
	s.Fuzz(f, diffFieldDomain())
}

// ---------------------------------------------------------------------------
// Select/copy primitives: asm (and dispatch variants) vs generic reference.
// ---------------------------------------------------------------------------

func diffGfPRaw(b []byte) gfP {
	return gfP{
		binary.LittleEndian.Uint64(b[0:8]),
		binary.LittleEndian.Uint64(b[8:16]),
		binary.LittleEndian.Uint64(b[16:24]),
		binary.LittleEndian.Uint64(b[24:32]),
	}
}

func diffDumpGfP(e *gfP) []byte {
	out := make([]byte, 32)
	binary.LittleEndian.PutUint64(out[0:8], e[0])
	binary.LittleEndian.PutUint64(out[8:16], e[1])
	binary.LittleEndian.PutUint64(out[16:24], e[2])
	binary.LittleEndian.PutUint64(out[24:32], e[3])
	return out
}

func diffGfP2Raw(b []byte) *gfP2 {
	return &gfP2{x: diffGfPRaw(b[:32]), y: diffGfPRaw(b[32:64])}
}

func diffDumpGfP2(e *gfP2) []byte {
	return append(diffDumpGfP(&e.x), diffDumpGfP(&e.y)...)
}

func diffGfP4Raw(b []byte) *gfP4 {
	return &gfP4{x: *diffGfP2Raw(b[:64]), y: *diffGfP2Raw(b[64:128])}
}

func diffDumpGfP4(e *gfP4) []byte {
	return append(diffDumpGfP2(&e.x), diffDumpGfP2(&e.y)...)
}

func diffGfP6Raw(b []byte) *gfP6 {
	return &gfP6{x: *diffGfP2Raw(b[:64]), y: *diffGfP2Raw(b[64:128]), z: *diffGfP2Raw(b[128:192])}
}

func diffDumpGfP6(e *gfP6) []byte {
	out := diffDumpGfP2(&e.x)
	out = append(out, diffDumpGfP2(&e.y)...)
	return append(out, diffDumpGfP2(&e.z)...)
}

func diffGfP12Raw(b []byte) *gfP12 {
	return &gfP12{x: *diffGfP4Raw(b[:128]), y: *diffGfP4Raw(b[128:256]), z: *diffGfP4Raw(b[256:384])}
}

func diffDumpGfP12(e *gfP12) []byte {
	out := diffDumpGfP4(&e.x)
	out = append(out, diffDumpGfP4(&e.y)...)
	return append(out, diffDumpGfP4(&e.z)...)
}

func diffCurvePointRaw(b []byte) *curvePoint {
	return &curvePoint{x: diffGfPRaw(b[:32]), y: diffGfPRaw(b[32:64]),
		z: diffGfPRaw(b[64:96]), t: diffGfPRaw(b[96:128])}
}

func diffDumpCurvePoint(e *curvePoint) []byte {
	out := diffDumpGfP(&e.x)
	out = append(out, diffDumpGfP(&e.y)...)
	out = append(out, diffDumpGfP(&e.z)...)
	return append(out, diffDumpGfP(&e.t)...)
}

func diffTwistPointRaw(b []byte) *twistPoint {
	return &twistPoint{x: *diffGfP2Raw(b[:64]), y: *diffGfP2Raw(b[64:128]),
		z: *diffGfP2Raw(b[128:192]), t: *diffGfP2Raw(b[192:256])}
}

func diffDumpTwistPoint(e *twistPoint) []byte {
	out := diffDumpGfP2(&e.x)
	out = append(out, diffDumpGfP2(&e.y)...)
	out = append(out, diffDumpGfP2(&e.z)...)
	return append(out, diffDumpGfP2(&e.t)...)
}

// diffRefMovCond is the generic reference: res = a if cond != 0, else b.
func diffRefMovCond[T any](res, a, b *T, cond int) {
	if cond != 0 {
		*res = *a
	} else {
		*res = *b
	}
}

// diffSelectCopyTags: 0/1=gfP12MovCond 2/3=curvePointMovCond
// 4/5=twistPointMovCond (cond = 1-tag%2) 6=gfp12Copy 7=gfp6Copy 8=gfp4Copy
// 9=gfp2Copy 10=gfpCopy 11=MovCond aliased res==a,cond=1 12=res==a,cond=0.
const diffSelectCopyTags = 13

func diffSelectCopyImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	t.Helper()
	switch tag := c.Tag % diffSelectCopyTags; {
	case tag <= 5:
		cond := 1 - int(tag)%2
		var out []byte
		switch {
		case tag <= 1:
			a := diffGfP12Raw(b.Src[:384])
			bv := diffGfP12Raw(b.Src[384:])
			r := &gfP12{}
			gfP12MovCond(r, a, bv, cond)
			out = diffDumpGfP12(r)
		case tag <= 3:
			a := diffCurvePointRaw(b.Src[:128])
			bv := diffCurvePointRaw(b.Src[128:256])
			r := &curvePoint{}
			curvePointMovCond(r, a, bv, cond)
			out = diffDumpCurvePoint(r)
		default:
			a := diffTwistPointRaw(b.Src[:256])
			bv := diffTwistPointRaw(b.Src[256:512])
			r := &twistPoint{}
			twistPointMovCond(r, a, bv, cond)
			out = diffDumpTwistPoint(r)
		}
		return out
	case tag == 6:
		r := &gfP12{}
		gfp12Copy(r, diffGfP12Raw(b.Src[:384]))
		return diffDumpGfP12(r)
	case tag == 7:
		r := &gfP6{}
		gfp6Copy(r, diffGfP6Raw(b.Src[:192]))
		return diffDumpGfP6(r)
	case tag == 8:
		r := &gfP4{}
		gfp4Copy(r, diffGfP4Raw(b.Src[:128]))
		return diffDumpGfP4(r)
	case tag == 9:
		r := &gfP2{}
		gfp2Copy(r, diffGfP2Raw(b.Src[:64]))
		return diffDumpGfP2(r)
	case tag == 10:
		in := diffGfPRaw(b.Src[:32])
		r := gfP{}
		gfpCopy(&r, &in)
		return diffDumpGfP(&r)
	default:
		// Aliased destination: res == a (the MovCond "a" input).
		a := diffGfP12Raw(b.Src[:384])
		bv := diffGfP12Raw(b.Src[384:])
		gfP12MovCond(a, a, bv, 1-int(tag)%2)
		return diffDumpGfP12(a)
	}
}

func diffSelectCopyRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	t.Helper()
	switch tag := c.Tag % diffSelectCopyTags; {
	case tag <= 5:
		cond := 1 - int(tag)%2
		var out []byte
		switch {
		case tag <= 1:
			a := diffGfP12Raw(b.Src[:384])
			bv := diffGfP12Raw(b.Src[384:])
			r := &gfP12{}
			diffRefMovCond(r, a, bv, cond)
			out = diffDumpGfP12(r)
		case tag <= 3:
			a := diffCurvePointRaw(b.Src[:128])
			bv := diffCurvePointRaw(b.Src[128:256])
			r := &curvePoint{}
			diffRefMovCond(r, a, bv, cond)
			out = diffDumpCurvePoint(r)
		default:
			a := diffTwistPointRaw(b.Src[:256])
			bv := diffTwistPointRaw(b.Src[256:512])
			r := &twistPoint{}
			diffRefMovCond(r, a, bv, cond)
			out = diffDumpTwistPoint(r)
		}
		return out
	case tag == 6:
		r := *diffGfP12Raw(b.Src[:384])
		return diffDumpGfP12(&r)
	case tag == 7:
		r := *diffGfP6Raw(b.Src[:192])
		return diffDumpGfP6(&r)
	case tag == 8:
		r := *diffGfP4Raw(b.Src[:128])
		return diffDumpGfP4(&r)
	case tag == 9:
		r := *diffGfP2Raw(b.Src[:64])
		return diffDumpGfP2(&r)
	case tag == 10:
		r := diffGfPRaw(b.Src[:32])
		return diffDumpGfP(&r)
	default:
		a := diffGfP12Raw(b.Src[:384])
		bv := diffGfP12Raw(b.Src[384:])
		diffRefMovCond(a, a, bv, 1-int(tag)%2)
		return diffDumpGfP12(a)
	}
}

func diffSelectCopyDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{768}, // two 384-byte gfP12 values cover every kernel
		Tags:          []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// TestDiffSelectCopy checks the constant-time select and copy primitives;
// on dispatch architectures every dispatch state participates (amd64 AVX2,
// loong64 LSX/LASX, riscv64 RVV).
func TestDiffSelectCopy(t *testing.T) {
	impls := diffSelectCopyImpls()
	if len(impls) == 0 {
		t.Skip("no accelerated select/copy primitives on this build")
	}
	s := diff.ByteSuite("generic-movcond-copy", diffSelectCopyRefRun)
	diffAddAll(s, impls)
	s.Run(t, diffSelectCopyDomain())
}

// FuzzDiffSelectCopy fuzzes the select/copy primitives.
func FuzzDiffSelectCopy(f *testing.F) {
	impls := diffSelectCopyImpls()
	if len(impls) == 0 {
		f.Skip("no accelerated select/copy primitives on this build")
	}
	s := diff.ByteSuite("generic-movcond-copy", diffSelectCopyRefRun)
	diffAddAll(s, impls)
	s.Fuzz(f, diffSelectCopyDomain())
}

// ---------------------------------------------------------------------------
// G1 point operations: package paths vs independent big.Int affine reference.
// ---------------------------------------------------------------------------

// diffRefPoint is an affine G1 point with an explicit infinity flag; the
// reference deliberately avoids the package's field and point code. The
// canonical encoding is x||y (64 bytes), with the point at infinity encoded
// as x=0, y=1 — the same convention the package uses in MakeAffine.
type diffRefPoint struct {
	x, y *big.Int
	inf  bool
}

func diffRefInfinity() *diffRefPoint { return &diffRefPoint{inf: true} }

func (q *diffRefPoint) bytes() []byte {
	out := make([]byte, 64)
	if q.inf {
		out[63] = 1
		return out
	}
	q.x.FillBytes(out[:32])
	q.y.FillBytes(out[32:])
	return out
}

func (q *diffRefPoint) neg() *diffRefPoint {
	if q.inf {
		return q
	}
	y := new(big.Int).Sub(p, q.y)
	y.Mod(y, p)
	return &diffRefPoint{x: q.x, y: y}
}

// diffRefAdd computes q+r with the affine chord formula (a = 0, b = 5).
func diffRefAdd(q, r *diffRefPoint) *diffRefPoint {
	switch {
	case q.inf:
		return r
	case r.inf:
		return q
	}
	if q.x.Cmp(r.x) == 0 {
		sum := new(big.Int).Add(q.y, r.y)
		sum.Mod(sum, p)
		if sum.Sign() == 0 {
			return diffRefInfinity()
		}
		return diffRefDouble(q)
	}
	num := new(big.Int).Sub(r.y, q.y)
	num.Mod(num, p)
	den := new(big.Int).Sub(r.x, q.x)
	den.Mod(den, p)
	den.ModInverse(den, p)
	l := num.Mul(num, den)
	l.Mod(l, p)
	lsq := new(big.Int).Mul(l, l)
	lsq.Mod(lsq, p)
	x3 := new(big.Int).Sub(lsq, q.x)
	x3.Sub(x3, r.x)
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(q.x, x3)
	y3.Mul(y3, l)
	y3.Sub(y3, q.y)
	y3.Mod(y3, p)
	return &diffRefPoint{x: x3, y: y3}
}

// diffRefDouble computes q+q with the affine tangent formula.
func diffRefDouble(q *diffRefPoint) *diffRefPoint {
	if q.inf {
		return q
	}
	num := new(big.Int).Mul(q.x, q.x)
	num.Mul(num, big.NewInt(3))
	num.Mod(num, p)
	den := new(big.Int).Lsh(q.y, 1)
	den.Mod(den, p)
	den.ModInverse(den, p)
	l := num.Mul(num, den)
	l.Mod(l, p)
	lsq := new(big.Int).Mul(l, l)
	lsq.Mod(lsq, p)
	x3 := new(big.Int).Sub(lsq, q.x)
	x3.Sub(x3, q.x)
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(q.x, x3)
	y3.Mul(y3, l)
	y3.Sub(y3, q.y)
	y3.Mod(y3, p)
	return &diffRefPoint{x: x3, y: y3}
}

// diffRefScalarMult computes k·q with an MSB-first double-and-add ladder.
func diffRefScalarMult(q *diffRefPoint, k *big.Int) *diffRefPoint {
	r := diffRefInfinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = diffRefDouble(r)
		if k.Bit(i) == 1 {
			r = diffRefAdd(r, q)
		}
	}
	return r
}

func diffRefScalarBase(k *big.Int) *diffRefPoint {
	return diffRefScalarMult(&diffRefPoint{x: diffGx, y: diffGy}, k)
}

func diffScalarReduce(b []byte) []byte {
	v := new(big.Int).SetBytes(b)
	v.Mod(v, Order)
	return v.FillBytes(make([]byte, 32))
}

// diffScalarNonZero maps zero to one: the base points of the point-op tags
// must be finite, so the scalars deriving them are kept non-zero.
func diffScalarNonZero(b []byte) []byte {
	if new(big.Int).SetBytes(b).Sign() == 0 {
		return diffScalarReduce([]byte{1})
	}
	return b
}

var diffInfEncoding = func() []byte {
	out := make([]byte, 64)
	out[63] = 1
	return out
}()

// diffImplPoint decodes a reference-derived encoding into a package point.
func diffImplPoint(t testing.TB, enc []byte) *curvePoint {
	t.Helper()
	if bytes.Equal(enc, diffInfEncoding) {
		q := &curvePoint{}
		q.SetInfinity()
		return q
	}
	return &curvePoint{x: *newGFpFromBytes(enc[:32]), y: *newGFpFromBytes(enc[32:]),
		z: *one, t: *one}
}

// diffCurveAffineBE renders a canonicalized package point as x||y.
func diffCurveAffineBE(c *curvePoint) []byte {
	x, y := &gfP{}, &gfP{}
	montDecode(x, &c.x)
	montDecode(y, &c.y)
	out := make([]byte, 64)
	gfpMarshal((*[32]byte)(out[:32]), x)
	gfpMarshal((*[32]byte)(out[32:]), y)
	return out
}

// diffPointTags: 0=Add(P1,P2) 1=Add(P1,P1) 2=Add(P1,-P1) 3=Double(P1)
// 4=Double(P2) 5=Add(∞,P1) 6=Add(P1,∞) 7=Double(∞) 8=ScalarMult(P1,k2)
// 9=ScalarBaseMult(k2).
const diffPointTags = 10

func diffPointImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	t.Helper()
	k1nz := diffScalarNonZero(diffScalarReduce(b.Src[:32]))
	k2nz := diffScalarNonZero(diffScalarReduce(b.Src[32:]))
	k2 := diffScalarReduce(b.Src[32:])
	p1 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k1nz)).bytes())
	p2 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k2nz)).bytes())
	inf := &curvePoint{}
	inf.SetInfinity()
	var q *curvePoint
	switch c.Tag % diffPointTags {
	case 0:
		q = &curvePoint{}
		q.Add(p1, p2)
	case 1:
		q = &curvePoint{}
		q.Add(p1, p1)
	case 2:
		neg := &curvePoint{}
		neg.Neg(p1)
		q = &curvePoint{}
		q.Add(p1, neg)
	case 3:
		q = &curvePoint{}
		q.Double(p1)
	case 4:
		q = &curvePoint{}
		q.Double(p2)
	case 5:
		q = &curvePoint{}
		q.Add(inf, p1)
	case 6:
		q = &curvePoint{}
		q.Add(p1, inf)
	case 7:
		q = &curvePoint{}
		q.Double(inf)
	case 8:
		base := &G1{}
		base.p = p1
		out, err := (&G1{}).ScalarMult(base, k2)
		if err != nil {
			t.Fatalf("ScalarMult failed: %v", err)
		}
		q = out.p
	default:
		out, err := (&G1{}).ScalarBaseMult(k2)
		if err != nil {
			t.Fatalf("ScalarBaseMult failed: %v", err)
		}
		q = out.p
	}
	q.MakeAffine()
	return diffCurveAffineBE(q)
}

func diffPointRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	t.Helper()
	k1nz := diffScalarNonZero(diffScalarReduce(b.Src[:32]))
	k2nz := diffScalarNonZero(diffScalarReduce(b.Src[32:]))
	k2 := new(big.Int).SetBytes(diffScalarReduce(b.Src[32:]))
	p1 := diffRefScalarBase(new(big.Int).SetBytes(k1nz))
	p2 := diffRefScalarBase(new(big.Int).SetBytes(k2nz))
	var q *diffRefPoint
	switch c.Tag % diffPointTags {
	case 0:
		q = diffRefAdd(p1, p2)
	case 1:
		q = diffRefAdd(p1, p1)
	case 2:
		q = diffRefAdd(p1, p1.neg())
	case 3:
		q = diffRefDouble(p1)
	case 4:
		q = diffRefDouble(p2)
	case 5:
		q = diffRefAdd(diffRefInfinity(), p1)
	case 6:
		q = diffRefAdd(p1, diffRefInfinity())
	case 7:
		q = diffRefDouble(diffRefInfinity())
	case 8:
		q = diffRefScalarMult(p1, k2)
	default:
		q = diffRefScalarBase(k2)
	}
	return q.bytes()
}

func diffPointDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{64}, // base scalar + multiplier
		Tags:          []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// diffPointImpls returns the point-arithmetic implementations; the point
// formulas are plain Go on every build and call the field kernels under the
// hood, so one implementation per build suffices.
func diffPointImpls() []diff.Implementation[[]byte] {
	if !diffAsmBuild() {
		return nil
	}
	return []diff.Implementation[[]byte]{
		{Name: "bn256-g1", Primary: true, Run: diffPointImplRun},
	}
}

// TestDiffPointOps checks the complete point formulas and the scalar
// multiplication paths against an independent big.Int affine reference,
// including infinity and equal-input flavors.
func TestDiffPointOps(t *testing.T) {
	impls := diffPointImpls()
	if len(impls) == 0 {
		t.Skip("no accelerated point arithmetic on this build")
	}
	s := diff.ByteSuite("big-int-affine-g1", diffPointRefRun)
	diffAddAll(s, impls)
	s.Run(t, diffPointDomain())
}

// FuzzDiffPointOps fuzzes the G1 point operations.
func FuzzDiffPointOps(f *testing.F) {
	impls := diffPointImpls()
	if len(impls) == 0 {
		f.Skip("no accelerated point arithmetic on this build")
	}
	s := diff.ByteSuite("big-int-affine-g1", diffPointRefRun)
	diffAddAll(s, impls)
	s.Fuzz(f, diffPointDomain())
}

// ---------------------------------------------------------------------------
// Dispatch observability and required kernels.
// ---------------------------------------------------------------------------

// TestDispatchSelectedImplementation verifies that the dispatch variables
// match the CPU detection state.
func TestDispatchSelectedImplementation(t *testing.T) {
	checkDispatch(t)
}

// TestDiffRequiredKernels enforces kernel availability on CI runners that
// guarantee the CPU features (native hardware, SDE, QEMU with the extension
// enabled). DIFF_REQUIRE holds a comma-separated list of kernel classes; the
// list may be shared across packages, and each package validates only the
// classes it owns (unknown names are ignored).
func TestDiffRequiredKernels(t *testing.T) {
	req := os.Getenv("DIFF_REQUIRE")
	if req == "" {
		t.Skip("DIFF_REQUIRE not set")
	}
	for _, name := range strings.Split(req, ",") {
		checkRequiredKernel(t, name)
	}
}
