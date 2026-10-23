// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || loong64 || riscv64 || s390x || ppc64le) && !purego

package sm2ec

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/diff"
	"github.com/emmansun/gmsm/internal/sm2ec/fiat"
)

// On the accelerated builds the package has a single assembly backend and no
// runtime CPU dispatch, so there is one implementation per suite and no
// DIFF_REQUIRE kernel classes. The fiat package (the purego production
// backend) and an independent big.Int curve reference serve as the oracles.

// Curve parameters used by the test-local references. They are anchored to
// the package's standard generator encoding by TestDiffStandardVector.
var (
	diffP      = diffMustInt("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
	diffN      = diffMustInt("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
	diffCurveA = new(big.Int).Sub(diffP, big.NewInt(3))
	diffGx     = diffMustInt("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
	diffGy     = diffMustInt("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
)

// diffRRBase is R² mod p, used to move a value into the Montgomery domain.
var diffRRBase = p256Element{0x0000000200000003, 0x00000002ffffffff,
	0x0000000100000001, 0x0000000400000002}

// diffStdG is the SEC 1 uncompressed encoding of the SM2 standard generator.
var diffStdG = []byte{
	0x04,
	0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
	0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
	0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
	0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
}

func diffMustInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2ec: invalid test constant " + s)
	}
	return v
}

// TestDiffStandardVector anchors the big.Int reference constants and the
// package's public path to the standard generator before they are used as
// the differential oracle: the reference ladder reproduces the generator and
// its group order, and the package agrees on both.
func TestDiffStandardVector(t *testing.T) {
	g := diffRefPointFromBytes(diffStdG)
	if !bytes.Equal(g.bytes(), diffStdG) {
		t.Fatalf("reference roundtrip of the standard generator failed: %x", g.bytes())
	}
	// [n]G is the point at infinity.
	if !bytes.Equal(diffRefScalarBase(diffN).bytes(), []byte{0}) {
		t.Fatal("reference [n]G is not the point at infinity")
	}
	gpkg, err := NewSM2P256Point().SetBytes(diffStdG)
	if err != nil {
		t.Fatalf("SetBytes(generator) failed: %v", err)
	}
	if !bytes.Equal(NewSM2P256Point().SetGenerator().Bytes(), diffStdG) {
		t.Fatal("package SetGenerator does not reproduce the standard generator encoding")
	}
	if !bytes.Equal(diffRefDouble(g).bytes(), gpkg.Double(gpkg).Bytes()) {
		t.Fatal("reference and package disagree on [2]G")
	}
}

// ---------------------------------------------------------------------------
// Base field kernels: asm vs fiat reference.
// ---------------------------------------------------------------------------

// diffFieldFromBE decodes a big-endian 32-byte value into little-endian limbs.
func diffFieldFromBE(b []byte) (e p256Element) {
	e[3] = binary.BigEndian.Uint64(b[0:8])
	e[2] = binary.BigEndian.Uint64(b[8:16])
	e[1] = binary.BigEndian.Uint64(b[16:24])
	e[0] = binary.BigEndian.Uint64(b[24:32])
	return e
}

// diffFieldToBE encodes little-endian limbs back into big-endian bytes.
func diffFieldToBE(e *p256Element) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[0:], e[3])
	binary.BigEndian.PutUint64(out[8:], e[2])
	binary.BigEndian.PutUint64(out[16:], e[1])
	binary.BigEndian.PutUint64(out[24:], e[0])
	return out
}

// diffFieldReduce reduces a case byte string to a canonical field element.
func diffFieldReduce(b []byte) []byte {
	v := new(big.Int).SetBytes(b)
	v.Mod(v, diffP)
	return v.FillBytes(make([]byte, 32))
}

// diffFieldNonZero maps zero to one: the p256NegCond kernels compute p-val
// speculatively, so their contract requires a non-zero input on every
// architecture.
func diffFieldNonZero(b []byte) []byte {
	if new(big.Int).SetBytes(b).Sign() == 0 {
		return diffFieldReduce([]byte{1})
	}
	return b
}

// diffFEMont converts a canonical encoding into the Montgomery domain.
func diffFEMont(v []byte) p256Element {
	e := diffFieldFromBE(v)
	p256Mul(&e, &e, &diffRRBase)
	return e
}

// diffFECannon converts a Montgomery-domain element to its canonical encoding.
func diffFECannon(e *p256Element) []byte {
	p256FromMont(e, e)
	be := diffFieldToBE(e)
	return be[:]
}

// diffFieldImplRun applies one base-field asm kernel per Tag:
// 0=Mul(a,b) 1=Sqr(a) 2=Sqr³(a) 3=Add(a,b) 4=FromMont(a) 5=NegCond(a,1)
// 6=NegCond(a,0) 7=Sqr(a) via Mul.
func diffFieldImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	a := diffFieldFromBE(diffFieldReduce(b.Src[:32]))
	bv := diffFieldFromBE(diffFieldReduce(b.Src[32:]))
	aM, bM := diffFEMont(diffFieldReduce(b.Src[:32])), diffFEMont(diffFieldReduce(b.Src[32:]))
	var r p256Element
	switch c.Tag % 8 {
	case 0:
		p256Mul(&r, &aM, &bM)
		return diffFECannon(&r)
	case 1:
		p256Sqr(&r, &aM, 1)
		return diffFECannon(&r)
	case 2:
		p256Sqr(&r, &aM, 3)
		return diffFECannon(&r)
	case 3:
		p256Add(&r, &a, &bv)
		be := diffFieldToBE(&r)
		return be[:]
	case 4:
		p256FromMont(&r, &aM)
		be := diffFieldToBE(&r)
		return be[:]
	case 5:
		r = diffFieldFromBE(diffFieldNonZero(diffFieldReduce(b.Src[:32])))
		p256NegCond(&r, 1)
		be := diffFieldToBE(&r)
		return be[:]
	case 6:
		r = diffFieldFromBE(diffFieldNonZero(diffFieldReduce(b.Src[:32])))
		p256NegCond(&r, 0)
		be := diffFieldToBE(&r)
		return be[:]
	default:
		p256Mul(&r, &aM, &aM)
		return diffFECannon(&r)
	}
}

func diffFieldRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	ea := new(fiat.SM2P256Element)
	eb := new(fiat.SM2P256Element)
	if _, err := ea.SetBytes(diffFieldReduce(b.Src[:32])); err != nil {
		t.Fatalf("invalid reference element: %v", err)
	}
	if _, err := eb.SetBytes(diffFieldReduce(b.Src[32:])); err != nil {
		t.Fatalf("invalid reference element: %v", err)
	}
	switch c.Tag % 8 {
	case 0:
		ea.Mul(ea, eb)
	case 1:
		ea.Square(ea)
	case 2:
		ea.Square(ea)
		ea.Square(ea)
		ea.Square(ea)
	case 3:
		ea.Add(ea, eb)
	case 4:
		// identity: SetBytes + Bytes is FromMont + ToBytes
	case 5:
		if _, err := ea.SetBytes(diffFieldNonZero(diffFieldReduce(b.Src[:32]))); err != nil {
			t.Fatalf("invalid reference element: %v", err)
		}
		neg := new(fiat.SM2P256Element)
		ea = neg.Sub(neg, ea)
	case 6:
		if _, err := ea.SetBytes(diffFieldNonZero(diffFieldReduce(b.Src[:32]))); err != nil {
			t.Fatalf("invalid reference element: %v", err)
		}
	default:
		ea.Square(ea)
	}
	return ea.Bytes()
}

func diffFieldDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{64}, // two 32-byte base field elements
		Tags:          []uint64{0, 1, 2, 3, 4, 5, 6, 7},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// TestDiffFieldKernels checks the base-field assembly kernels against the
// fiat reference implementation.
func TestDiffFieldKernels(t *testing.T) {
	s := diff.ByteSuite("fiat-sm2p256-element", diffFieldRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffFieldImplRun})
	s.Run(t, diffFieldDomain())
}

// FuzzDiffFieldKernels fuzzes the base-field asm kernels; no Tag value can
// change the buffer sizes, so no normalization is required.
func FuzzDiffFieldKernels(f *testing.F) {
	s := diff.ByteSuite("fiat-sm2p256-element", diffFieldRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffFieldImplRun})
	s.Fuzz(f, diffFieldDomain())
}

// ---------------------------------------------------------------------------
// Scalar field kernels: asm vs fiat reference.
// ---------------------------------------------------------------------------

func diffOrdFromBE(b []byte) (e p256OrdElement) {
	e[3] = binary.BigEndian.Uint64(b[0:8])
	e[2] = binary.BigEndian.Uint64(b[8:16])
	e[1] = binary.BigEndian.Uint64(b[16:24])
	e[0] = binary.BigEndian.Uint64(b[24:32])
	return e
}

func diffOrdToBE(e *p256OrdElement) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[0:], e[3])
	binary.BigEndian.PutUint64(out[8:], e[2])
	binary.BigEndian.PutUint64(out[16:], e[1])
	binary.BigEndian.PutUint64(out[24:], e[0])
	return out
}

func diffScalarReduce(b []byte) []byte {
	v := new(big.Int).SetBytes(b)
	v.Mod(v, diffN)
	return v.FillBytes(make([]byte, 32))
}

// diffOrdImplRun applies one scalar-field asm kernel per Tag:
// 0=OrdMul(a,b) 1=OrdSqr(a) 2=OrdSqr⁴(a) 3=OrdReduce(a).
func diffOrdImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	switch c.Tag % 4 {
	case 0, 1, 2:
		aM := diffOrdFromBE(b.Src[:32])
		p256OrdMul(&aM, &aM, RR)
		var res p256OrdElement
		switch c.Tag % 4 {
		case 0:
			bM := diffOrdFromBE(b.Src[32:])
			p256OrdMul(&bM, &bM, RR)
			p256OrdMul(&res, &aM, &bM)
		case 1:
			p256OrdSqr(&res, &aM, 1)
		default:
			p256OrdSqr(&res, &aM, 4)
		}
		return p256OrderFromMont(&res)
	default:
		s := diffOrdFromBE(b.Src[:32])
		p256OrdReduce(&s)
		be := diffOrdToBE(&s)
		return be[:]
	}
}

func diffOrdRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	switch c.Tag % 4 {
	case 0, 1, 2:
		ea := new(fiat.SM2P256OrderElement)
		eb := new(fiat.SM2P256OrderElement)
		if _, err := ea.SetBytes(diffScalarReduce(b.Src[:32])); err != nil {
			t.Fatalf("invalid reference scalar: %v", err)
		}
		if _, err := eb.SetBytes(diffScalarReduce(b.Src[32:])); err != nil {
			t.Fatalf("invalid reference scalar: %v", err)
		}
		switch c.Tag % 4 {
		case 0:
			ea.Mul(ea, eb)
		case 1:
			ea.Square(ea)
		default:
			ea.Square(ea)
			ea.Square(ea)
			ea.Square(ea)
			ea.Square(ea)
		}
		return ea.Bytes()
	default:
		v := new(big.Int).SetBytes(b.Src[:32])
		v.Mod(v, diffN)
		return v.FillBytes(make([]byte, 32))
	}
}

func diffOrdDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{64}, // two 32-byte scalar field elements
		Tags:          []uint64{0, 1, 2, 3},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// TestDiffOrdKernels checks the scalar-field assembly kernels against the
// fiat reference implementation.
func TestDiffOrdKernels(t *testing.T) {
	s := diff.ByteSuite("fiat-sm2p256-order-element", diffOrdRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffOrdImplRun})
	s.Run(t, diffOrdDomain())
}

// FuzzDiffOrdKernels fuzzes the scalar-field asm kernels.
func FuzzDiffOrdKernels(f *testing.F) {
	s := diff.ByteSuite("fiat-sm2p256-order-element", diffOrdRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffOrdImplRun})
	s.Fuzz(f, diffOrdDomain())
}

// ---------------------------------------------------------------------------
// Point operations: asm backend vs independent big.Int affine reference.
// ---------------------------------------------------------------------------

// diffRefPoint is an affine curve point with an explicit infinity flag; the
// reference deliberately avoids the package's field and point code.
type diffRefPoint struct {
	x, y *big.Int
	inf  bool
}

func diffRefInfinity() *diffRefPoint { return &diffRefPoint{inf: true} }

func diffRefPointFromBytes(b []byte) *diffRefPoint {
	if len(b) == 1 && b[0] == 0 {
		return diffRefInfinity()
	}
	return &diffRefPoint{
		x: new(big.Int).SetBytes(b[1:33]),
		y: new(big.Int).SetBytes(b[33:65]),
	}
}

// bytes returns the canonical SEC 1 encoding (uncompressed or infinity).
func (p *diffRefPoint) bytes() []byte {
	if p.inf {
		return []byte{0}
	}
	out := make([]byte, 65)
	out[0] = 4
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:65])
	return out
}

func (p *diffRefPoint) neg() *diffRefPoint {
	if p.inf {
		return p
	}
	return &diffRefPoint{x: p.x, y: new(big.Int).Sub(diffP, p.y)}
}

func diffRefMod(v *big.Int) *big.Int { return v.Mod(v, diffP) }

// diffRefAdd computes q+r with the affine formulas.
func diffRefAdd(q, r *diffRefPoint) *diffRefPoint {
	switch {
	case q.inf:
		return r
	case r.inf:
		return q
	}
	if q.x.Cmp(r.x) == 0 {
		if new(big.Int).Add(q.y, r.y).Mod(new(big.Int).Add(q.y, r.y), diffP).Sign() == 0 {
			return diffRefInfinity()
		}
		return diffRefDouble(q)
	}
	num := diffRefMod(new(big.Int).Sub(r.y, q.y))
	den := diffRefMod(new(big.Int).Sub(r.x, q.x))
	den.ModInverse(den, diffP)
	l := diffRefMod(num.Mul(num, den))
	lsq := diffRefMod(new(big.Int).Mul(l, l))
	x3 := diffRefMod(new(big.Int).Sub(lsq, q.x))
	x3.Sub(x3, r.x)
	y3 := diffRefMod(new(big.Int).Sub(q.x, x3))
	y3.Mul(y3, l)
	y3.Sub(y3, q.y)
	return &diffRefPoint{x: diffRefMod(x3), y: diffRefMod(y3)}
}

// diffRefDouble computes q+q with the affine doubling formula (a = p-3).
func diffRefDouble(q *diffRefPoint) *diffRefPoint {
	if q.inf {
		return q
	}
	num := diffRefMod(new(big.Int).Mul(q.x, q.x))
	num.Mul(num, big.NewInt(3))
	num.Add(num, diffCurveA)
	den := diffRefMod(new(big.Int).Lsh(q.y, 1))
	den.ModInverse(den, diffP)
	l := diffRefMod(num.Mul(num, den))
	lsq := diffRefMod(new(big.Int).Mul(l, l))
	x3 := diffRefMod(new(big.Int).Sub(lsq, q.x))
	x3.Sub(x3, q.x)
	y3 := diffRefMod(new(big.Int).Sub(q.x, x3))
	y3.Mul(y3, l)
	y3.Sub(y3, q.y)
	return &diffRefPoint{x: diffRefMod(x3), y: diffRefMod(y3)}
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

// diffImplPoint decodes a reference-derived encoding with the package API.
func diffImplPoint(t testing.TB, enc []byte) *SM2P256Point {
	t.Helper()
	p, err := NewSM2P256Point().SetBytes(enc)
	if err != nil {
		t.Fatalf("SetBytes(%x) failed: %v", enc, err)
	}
	return p
}

func diffCaseScalars(b *diff.Buffers) (k1, k2, k1raw, k2raw []byte) {
	k1raw = append([]byte(nil), b.Src[:32]...)
	k2raw = append([]byte(nil), b.Src[32:]...)
	return diffScalarReduce(k1raw), diffScalarReduce(k2raw), k1raw, k2raw
}

// Point op tags: 0=Add(P1,P2) 1=Add(P1,P1) 2=Add(P1,-P1) 3=Double(P1)
// 4=Double(P2) 5=Add(inf,P1) 6=Add(P1,inf) 7=Select(P1,P2,1) 8=Select(P1,P2,0).
const diffPointOpTags = 9

func diffPointOpsImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	k1, k2, _, _ := diffCaseScalars(b)
	p1 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k1)).bytes())
	p2 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k2)).bytes())
	var q *SM2P256Point
	switch c.Tag % diffPointOpTags {
	case 0:
		q = NewSM2P256Point().Add(p1, p2)
	case 1:
		q = NewSM2P256Point().Add(p1, p1)
	case 2:
		q = NewSM2P256Point().Add(p1, p1Neg(t, p1))
	case 3:
		q = NewSM2P256Point().Double(p1)
	case 4:
		q = NewSM2P256Point().Double(p2)
	case 5:
		q = NewSM2P256Point().Add(NewSM2P256Point(), p1)
	case 6:
		q = NewSM2P256Point().Add(p1, NewSM2P256Point())
	case 7:
		q = NewSM2P256Point().Select(p1, p2, 1)
	default:
		q = NewSM2P256Point().Select(p1, p2, 0)
	}
	return q.Bytes()
}

// p1Neg negates a package point by feeding -y through the package decoder.
func p1Neg(t testing.TB, p *SM2P256Point) *SM2P256Point {
	t.Helper()
	enc := p.Bytes()
	if len(enc) == 1 {
		return diffImplPoint(t, enc) // -inf = inf
	}
	negY := new(big.Int).SetBytes(enc[33:])
	negY.Sub(diffP, negY).Mod(negY, diffP)
	out := make([]byte, 0, 65)
	out = append(out, enc[:33]...)
	out = append(out, negY.FillBytes(make([]byte, 32))...)
	return diffImplPoint(t, out)
}

func diffPointOpsRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	k1, k2, _, _ := diffCaseScalars(b)
	p1 := diffRefPointFromBytes(diffRefScalarBase(new(big.Int).SetBytes(k1)).bytes())
	p2 := diffRefPointFromBytes(diffRefScalarBase(new(big.Int).SetBytes(k2)).bytes())
	var q *diffRefPoint
	switch c.Tag % diffPointOpTags {
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
		q = p1
	default:
		q = p2
	}
	return q.bytes()
}

func diffPointOpsDomain() diff.Domain {
	return diff.Domain{
		Lengths:       []int{64}, // two 32-byte scalars
		Tags:          []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	}
}

// TestDiffPointOps checks the package point operations (which exercise the
// point add/double/select assembly kernels) against an independent big.Int
// affine reference, including infinity and equal-input flavors.
func TestDiffPointOps(t *testing.T) {
	s := diff.ByteSuite("big-int-affine", diffPointOpsRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffPointOpsImplRun})
	s.Run(t, diffPointOpsDomain())
}

// FuzzDiffPointOps fuzzes the point operations.
func FuzzDiffPointOps(f *testing.F) {
	s := diff.ByteSuite("big-int-affine", diffPointOpsRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffPointOpsImplRun})
	s.Fuzz(f, diffPointOpsDomain())
}

// Scalar mult tags: 0=ScalarMult(k1·G, k2) 1=ScalarBaseMult(k2)
// 2=ScalarMult(k2·G, k1).
const diffScalarMultTags = 3

func diffScalarMultImplRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	k1, k2, k1raw, k2raw := diffCaseScalars(b)
	p1 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k1)).bytes())
	p2 := diffImplPoint(t, diffRefScalarBase(new(big.Int).SetBytes(k2)).bytes())
	var q *SM2P256Point
	var err error
	switch c.Tag % diffScalarMultTags {
	case 0:
		q, err = NewSM2P256Point().ScalarMult(p1, k2raw)
	case 1:
		q, err = NewSM2P256Point().ScalarBaseMult(k2raw)
	default:
		q, err = NewSM2P256Point().ScalarMult(p2, k1raw)
	}
	if err != nil {
		t.Fatalf("scalar mult failed: %v", err)
	}
	return q.Bytes()
}

func diffScalarMultRefRun(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
	k1, k2, _, _ := diffCaseScalars(b)
	base1 := diffRefScalarBase(new(big.Int).SetBytes(k1))
	base2 := diffRefScalarBase(new(big.Int).SetBytes(k2))
	var q *diffRefPoint
	switch c.Tag % diffScalarMultTags {
	case 0:
		q = diffRefScalarMult(base1, new(big.Int).SetBytes(k2))
	case 1:
		q = diffRefScalarBase(new(big.Int).SetBytes(k2))
	default:
		q = diffRefScalarMult(base2, new(big.Int).SetBytes(k1))
	}
	return q.bytes()
}

// TestDiffScalarMult checks the public scalar multiplication paths against
// the big.Int reference ladder, including zero scalars (point at infinity)
// and scalars that require the modular reduction.
func TestDiffScalarMult(t *testing.T) {
	s := diff.ByteSuite("big-int-affine-ladder", diffScalarMultRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffScalarMultImplRun})
	s.Run(t, diff.Domain{
		Lengths:       []int{64}, // base scalar + multiplier
		Tags:          []uint64{0, 1, 2},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	})
}

// FuzzDiffScalarMult fuzzes the scalar multiplication paths.
func FuzzDiffScalarMult(f *testing.F) {
	s := diff.ByteSuite("big-int-affine-ladder", diffScalarMultRefRun)
	s.Add(diff.Implementation[[]byte]{Name: "sm2p256-asm", Run: diffScalarMultImplRun})
	s.Fuzz(f, diff.Domain{
		Lengths:       []int{64},
		Tags:          []uint64{0, 1, 2},
		CartesianTags: true,
		Alignments:    diff.SingleAlignment(),
		Overlaps:      []diff.OverlapCase{diff.NoOverlap()},
		Patterns:      diff.DefaultPatterns(),
		Seeds:         []uint64{0, 1},
	})
}
