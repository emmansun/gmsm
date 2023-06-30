package bn256

import (
	"math/big"
)

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where u²=-2, beta=-2.
type gfP2 struct {
	x, y gfP // value is xu+y.
}

func gfP2Decode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montDecode(&out.x, &in.x)
	montDecode(&out.y, &in.y)
	return out
}

func (e *gfP2) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	gfp2Copy(e, a)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x = *zero
	e.y = *zero
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x = *zero
	e.y = *one
	return e
}

func (e *gfP2) SetU() *gfP2 {
	e.x = *one
	e.y = *zero
	return e
}

func (e *gfP2) SetFrobConstant() *gfP2 {
	e.x = *zero
	e.y = *frobConstant
	return e
}

func (e *gfP2) IsZero() bool {
	return e.x == *zero && e.y == *zero
}

func (e *gfP2) IsOne() bool {
	return e.x == *zero && e.y == *one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(&a.y)
	gfpNeg(&e.x, &a.x)
	return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
	gfpNeg(&e.x, &a.x)
	gfpNeg(&e.y, &a.y)
	return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &b.x)
	gfpAdd(&e.y, &a.y, &b.y)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	gfpSub(&e.x, &a.x, &b.x)
	gfpSub(&e.y, &a.y, &b.y)
	return e
}

func (e *gfP2) Double(a *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &a.x)
	gfpAdd(&e.y, &a.y, &a.y)
	return e
}

func (e *gfP2) Triple(a *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &a.x)
	gfpAdd(&e.y, &a.y, &a.y)

	gfpAdd(&e.x, &e.x, &a.x)
	gfpAdd(&e.y, &e.y, &a.y)
	return e
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf
// The Karatsuba method
// (a0+a1*u)(b0+b1*u)=c0+c1*u, where
// c0 = a0*b0 - 2a1*b1
// c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	v0, v1 := &gfP{}, &gfP{}

	gfpMul(v0, &a.y, &b.y)
	gfpMul(v1, &a.x, &b.x)

	gfpAdd(tx, &a.x, &a.y)
	gfpAdd(ty, &b.x, &b.y)
	gfpMul(tx, tx, ty)
	gfpSub(tx, tx, v0)
	gfpSub(tx, tx, v1)

	gfpSub(ty, v0, v1)
	gfpSub(ty, ty, v1)

	gfp2Copy(e, tmp)
	return e
}

// MulU: a * b * u
// (a0+a1*u)(b0+b1*u)*u=c0+c1*u, where
// c1 = (a0*b0 - 2a1*b1)u
// c0 = -2 * ((a0 + a1)(b0 + b1) - a0*b0 - a1*b1) = -2 * (a0*b1 + a1*b0)
func (e *gfP2) MulU(a, b *gfP2) *gfP2 {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	v0, v1 := &gfP{}, &gfP{}

	gfpMul(v0, &a.y, &b.y)
	gfpMul(v1, &a.x, &b.x)

	gfpAdd(tx, &a.x, &a.y)
	gfpAdd(ty, &b.x, &b.y)

	gfpMul(ty, tx, ty)
	gfpSub(ty, ty, v0)
	gfpSub(ty, ty, v1)
	gfpAdd(ty, ty, ty)
	gfpNeg(ty, ty)

	gfpSub(tx, v0, v1)
	gfpSub(tx, tx, v1)

	gfp2Copy(e, tmp)
	return e
}

// MulU1: a  * u
// (a0+a1*u)u=c0+c1*u, where
// c1 = a0
// c0 = -2a1
func (e *gfP2) MulU1(a *gfP2) *gfP2 {
	t := &gfP{}
	gfpAdd(t, &a.x, &a.x)
	gfpNeg(t, t)

	gfpCopy(&e.x, &a.y)
	gfpCopy(&e.y, t)
	return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xu+y)² = y^2-2*x^2 + 2*u*x*y
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	gfpSqr(tx, &a.x, 1)
	gfpSqr(ty, &a.y, 1)
	gfpSub(ty, ty, tx)
	gfpSub(ty, ty, tx)

	gfpMul(tx, &a.x, &a.y)
	gfpAdd(tx, tx, tx)
	gfp2Copy(e, tmp)
	return e
}

func (e *gfP2) SquareU(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xu+y)²*u = (y^2-2*x^2)u - 4*x*y

	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	// tx = a0^2 - 2 * a1^2
	gfpSqr(ty, &a.x, 1)
	gfpSqr(tx, &a.y, 1)
	gfpAdd(ty, ty, ty)
	gfpSub(tx, tx, ty)

	// ty = -4 * a0 * a1
	gfpMul(ty, &a.x, &a.y)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, ty)
	gfpNeg(ty, ty)

	gfp2Copy(e, tmp)
	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
	gfpMul(&e.x, &a.x, b)
	gfpMul(&e.y, &a.y, b)
	return e
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2, t3 := &gfP{}, &gfP{}, &gfP{}
	gfpSqr(t1, &a.x, 1)
	gfpAdd(t3, t1, t1)
	gfpSqr(t2, &a.y, 1)
	gfpAdd(t3, t3, t2)

	inv := &gfP{}
	inv.Invert(t3) // inv = (2 * a.x ^ 2 + a.y ^ 2) ^ (-1)

	gfpNeg(t1, &a.x)

	gfpMul(&e.x, t1, inv)   // x = - a.x * inv
	gfpMul(&e.y, &a.y, inv) // y = a.y * inv
	return e
}

func (e *gfP2) Exp(f *gfP2, power *big.Int) *gfP2 {
	sum := (&gfP2{}).SetOne()
	t := &gfP2{}

	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum)
		if power.Bit(i) != 0 {
			sum.Mul(t, f)
		} else {
			sum.Set(t)
		}
	}

	e.Set(sum)
	return e
}

// （xu+y)^p = x * u^p + y
//
//	= x * u * u^(p-1) + y
//	= (-x)*u + y
//
// here u^(p-1) = -1
func (e *gfP2) Frobenius(a *gfP2) *gfP2 {
	e.Conjugate(a)
	return e
}

// Sqrt method is only required when we implement compressed format
// TODO: use addchain to improve performance for 3 exp operations.
func (ret *gfP2) Sqrt(a *gfP2) *gfP2 {
	// Algorithm 10 https://eprint.iacr.org/2012/685.pdf
	// TODO
	ret.SetZero()
	c := &twistGen.x
	b, b2, bq := &gfP2{}, &gfP2{}, &gfP2{}
	b = b.expPMinus1Over4(a)
	b2.Mul(b, b)
	bq = bq.expP(b)

	t := &gfP2{}
	x0 := &gfP{}
	/* ignore sqrt existing check
	a0 := &gfP2{}
	a0.Exp(b2, p)
	a0.Mul(a0, b2)
	a0 = gfP2Decode(a0)
	*/
	t.Mul(bq, b)
	if t.x == *zero && t.y == *one {
		t.Mul(b2, a)
		x0.Sqrt(&t.y)
		t.MulScalar(bq, x0)
		ret.Set(t)
	} else {
		d, e, f := &gfP2{}, &gfP2{}, &gfP2{}
		d = d.expPMinus1Over2(c)
		e.Mul(d, c)
		f.Square(e)
		e.Invert(e)
		t.Mul(b2, a)
		t.Mul(t, f)
		x0.Sqrt(&t.y)
		t.MulScalar(bq, x0)
		t.Mul(t, e)
		ret.Set(t)
	}
	return ret
}

// Select sets e to p1 if cond == 1, and to p2 if cond == 0.
func (e *gfP2) Select(p1, p2 *gfP2, cond int) *gfP2 {
	e.x.Select(&p1.x, &p2.x, cond)
	e.y.Select(&p1.y, &p2.y, cond)
	return e
}
