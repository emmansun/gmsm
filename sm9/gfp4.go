package sm9

import "math/big"

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.
//

// gfP4 implements the field of size p^4 as a quadratic extension of gfP2
// where u²=i.
type gfP4 struct {
	x, y gfP2 // value is xi+y.
}

func gfP4Decode(in *gfP4) *gfP4 {
	out := &gfP4{}
	out.x = *gfP2Decode(&in.x)
	out.y = *gfP2Decode(&in.y)
	return out
}

func (e *gfP4) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP4) Set(a *gfP4) *gfP4 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP4) SetZero() *gfP4 {
	e.x.SetZero()
	e.y.SetZero()
	return e
}

func (e *gfP4) SetOne() *gfP4 {
	e.x.SetZero()
	e.y.SetOne()
	return e
}

func (e *gfP4) SetV() *gfP4 {
	e.x.SetOne()
	e.y.SetZero()
	return e
}

func (e *gfP4) IsZero() bool {
	return e.x.IsZero() && e.y.IsZero()
}

func (e *gfP4) IsOne() bool {
	return e.x.IsZero() && e.y.IsOne()
}

func (e *gfP4) Conjugate(a *gfP4) *gfP4 {
	e.y.Set(&a.y)
	e.x.Neg(&a.x)
	return e
}

func (e *gfP4) Neg(a *gfP4) *gfP4 {
	e.x.Neg(&a.x)
	e.y.Neg(&a.y)
	return e
}

func (e *gfP4) Add(a, b *gfP4) *gfP4 {
	e.x.Add(&a.x, &b.x)
	e.y.Add(&a.y, &b.y)
	return e
}

func (e *gfP4) Sub(a, b *gfP4) *gfP4 {
	e.x.Sub(&a.x, &b.x)
	e.y.Sub(&a.y, &b.y)
	return e
}

func (e *gfP4) MulScalar(a *gfP4, b *gfP2) *gfP4 {
	e.x.Mul(&a.x, b)
	e.y.Mul(&a.y, b)
	return e
}

func (e *gfP4) MulGFP(a *gfP4, b *gfP) *gfP4 {
	e.x.MulScalar(&a.x, b)
	e.y.MulScalar(&a.y, b)
	return e
}

func (e *gfP4) Mul(a, b *gfP4) *gfP4 {
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	//(a0+a1*v)(b0+b1*v)=c0+c1*v, where
	//c0 = a0*b0 +a1*b1*u
	//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
	tx, t := &gfP2{}, &gfP2{}
	tx.Mul(&a.x, &b.y)
	t.Mul(&a.y, &b.x)
	tx.Add(tx, t)

	ty := &gfP2{}
	ty.Mul(&a.y, &b.y)
	t.MulU(&a.x, &b.x)
	ty.Add(ty, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

// MulV: a * b * v
//(a0+a1*v)(b0+b1*v)*v=c0+c1*v, where
// (a0*b0 + a0*b1v + a1*b0*v + a1*b1*u)*v
// a0*b0*v + a0*b1*u + a1*b0*u + a1*b1*u*v
// c0 = a0*b1*u + a1*b0*u
// c1 = a0*b0 + a1*b1*u
func (e *gfP4) MulV(a, b *gfP4) *gfP4 {
	tx, ty, t := &gfP2{}, &gfP2{}, &gfP2{}
	ty.MulU(&a.y, &b.x)
	t.MulU(&a.x, &b.y)
	ty.Add(ty, t)

	tx.Mul(&a.y, &b.y)
	t.MulU(&a.x, &b.x)
	tx.Add(tx, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP4) Square(a *gfP4) *gfP4 {
	// Complex squaring algorithm:
	// (xv+y)² = (x^2*u + y^2) + 2*x*y*v
	tx, ty := &gfP2{}, &gfP2{}
	tx.SquareU(&a.x)
	ty.Square(&a.y)
	ty.Add(tx, ty)

	tx.Mul(&a.x, &a.y)
	tx.Add(tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

// SquareV: (a^2) * v
// v*(xv+y)² = (x^2*u + y^2)v + 2*x*y*u
func (e *gfP4) SquareV(a *gfP4) *gfP4 {
	tx, ty := &gfP2{}, &gfP2{}
	tx.SquareU(&a.x)
	ty.Square(&a.y)
	tx.Add(tx, ty)

	ty.MulU(&a.x, &a.y)
	ty.Add(ty, ty)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP4) Invert(a *gfP4) *gfP4 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2, t3 := &gfP2{}, &gfP2{}, &gfP2{}

	t3.SquareU(&a.x)
	t1.Square(&a.y)
	t3.Sub(t3, t1)
	t3.Invert(t3)

	t1.Mul(&a.y, t3)
	t1.Neg(t1)

	t2.Mul(&a.x, t3)

	e.x.Set(t2)
	e.y.Set(t1)
	return e
}

func (e *gfP4) Exp(f *gfP4, power *big.Int) *gfP4 {
	sum := (&gfP4{}).SetOne()
	t := &gfP4{}

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

//  (y+x*v)^p
// = y^p + x^p*v^p
// = f(y) + f(x) * v^p
// = f(y) + f(x) * v * v^(p-1)
func (e *gfP4) Frobenius(a *gfP4) *gfP4 {
	x, y := &gfP2{}, &gfP2{}
	x.Conjugate(&a.x)
	y.Conjugate(&a.y)
	x.MulScalar(x, vToPMinus1)

	e.x.Set(x)
	e.y.Set(y)

	return e
}

//  (y+x*v)^(p^2)
// y + x*v * v^(p^2-1)
func (e *gfP4) FrobeniusP2(a *gfP4) *gfP4 {
	e.Conjugate(a)
	return e
}

//  (y+x*v)^(p^3)
// = ((y+x*v)^p)^(p^2)
func (e *gfP4) FrobeniusP3(a *gfP4) *gfP4 {
	x, y := &gfP2{}, &gfP2{}
	x.Conjugate(&a.x)
	y.Conjugate(&a.y)
	x.MulScalar(x, vToPMinus1)
	x.Neg(x)

	e.x.Set(x)
	e.y.Set(y)

	return e
}
