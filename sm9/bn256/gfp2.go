package bn256

import (
	"math/big"
)

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-2.
type gfP2 struct {
	x, y gfP // value is xi+y.
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
	e.x.Set(&a.x)
	e.y.Set(&a.y)
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
//(a0+a1*i)(b0+b1*i)=c0+c1*i, where
//c0 = a0*b0 - 2a1*b1
//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	tx, t := &gfP{}, &gfP{}
	gfpMul(tx, &a.x, &b.y)
	gfpMul(t, &b.x, &a.y)
	gfpAdd(tx, tx, t)

	ty := &gfP{}
	gfpMul(ty, &a.y, &b.y)
	gfpMul(t, &a.x, &b.x)
	gfpMul(t, t, two)
	gfpSub(ty, ty, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

// MulU: a * b * i
//(a0+a1*i)(b0+b1*i)*i=c0+c1*i, where
//c1 = (a0*b0 - 2a1*b1)i
//c0 = -2 * ((a0 + a1)(b0 + b1) - a0*b0 - a1*b1) = -2 * (a0*b1 + a1*b0)
func (e *gfP2) MulU(a, b *gfP2) *gfP2 {
	// ty = -2 * (a0 * b1 + a1 * b0)
	ty, t := &gfP{}, &gfP{}
	gfpMul(ty, &a.x, &b.y)
	gfpMul(t, &b.x, &a.y)
	gfpAdd(ty, ty, t)
	gfpAdd(ty, ty, ty)
	gfpNeg(ty, ty)

	// tx = a0 * b0 - 2 * a1 * b1
	tx := &gfP{}
	gfpMul(tx, &a.y, &b.y)
	gfpMul(t, &a.x, &b.x)
	gfpMul(t, t, two)
	gfpSub(tx, tx, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xi+y)² = y^2-2*x^2 + 2*i*x*y
	tx, ty := &gfP{}, &gfP{}
	gfpMul(tx, &a.x, &a.x)
	gfpMul(ty, &a.y, &a.y)
	gfpSub(ty, ty, tx)
	gfpSub(ty, ty, tx)

	gfpMul(tx, &a.x, &a.y)
	gfpAdd(tx, tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) SquareU(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xi+y)²*i = (y^2-2*x^2)i - 4*x*y

	tx, ty := &gfP{}, &gfP{}
	// tx = a0^2 - 2 * a1^2
	gfpMul(ty, &a.x, &a.x)
	gfpMul(tx, &a.y, &a.y)
	gfpAdd(ty, ty, ty)
	gfpSub(tx, tx, ty)

	// ty = -4 * a0 * a1
	gfpMul(ty, &a.x, &a.y)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, ty)
	gfpNeg(ty, ty)

	e.x.Set(tx)
	e.y.Set(ty)
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
	gfpMul(t1, &a.x, &a.x)
	gfpAdd(t3, t1, t1)
	gfpMul(t2, &a.y, &a.y)
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

// （xi+y)^p = x * i^p + y
//  = x * i * i^(p-1) + y
//  = (-x)*i + y
// here i^(p-1) = -1
func (e *gfP2) Frobenius(a *gfP2) *gfP2 {
	e.Conjugate(a)
	return e
}

// Sqrt method is only required when we implement compressed format
func (ret *gfP2) Sqrt(a *gfP2) *gfP2 {
	// Algorithm 10 https://eprint.iacr.org/2012/685.pdf
	// TODO
	ret.SetZero()
	c := &twistGen.x
	b, b2, bq := &gfP2{}, &gfP2{}, &gfP2{}
	b.Exp(a, pMinus1Over4)
	b2.Mul(b, b)
	bq.Exp(b, p)

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
		d.Exp(c, pMinus1Over2Big)
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

// Div2 e = f / 2, not used currently
func (e *gfP2) Div2(f *gfP2) *gfP2 {
	t := &gfP2{}
	t.x.Div2(&f.x)
	t.y.Div2(&f.y)

	e.Set(t)
	return e
}

// Select sets e to p1 if cond == 1, and to p2 if cond == 0.
func (e *gfP2) Select(p1, p2 *gfP2, cond int) *gfP2 {
	e.x.Select(&p1.x, &p2.x, cond)
	e.y.Select(&p1.y, &p2.y, cond)
	return e
}
