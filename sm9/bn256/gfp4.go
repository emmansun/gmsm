package bn256

import "math/big"

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.
//

// gfP4 implements the field of size p^4 as a quadratic extension of gfP2
// where v²=ξ and ξ=u.
type gfP4 struct {
	x, y gfP2 // value is xv+y.
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
	gfp4Copy(e, a)
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

func (e *gfP4) Double(a *gfP4) *gfP4 {
	e.x.Double(&a.x)
	e.y.Double(&a.y)
	return e
}

func (e *gfP4) Triple(a *gfP4) *gfP4 {
	e.x.Triple(&a.x)
	e.y.Triple(&a.y)
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
	tmp := &gfP4{}
	tmp.MulNC(a, b)
	gfp4Copy(e, tmp)
	return e
}

// Mul without value copy, will use e directly, so e can't be same as a and b.
func (e *gfP4) MulNC(a, b *gfP4) *gfP4 {
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	//(a0+a1*v)(b0+b1*v)=c0+c1*v, where
	//c0 = a0*b0 +a1*b1*u
	//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
	tx := &e.x
	ty := &e.y
	v0, v1 := &gfP2{}, &gfP2{}
	v0.Mul(&a.y, &b.y)
	v1.Mul(&a.x, &b.x)

	tx.Add(&a.x, &a.y)
	ty.Add(&b.x, &b.y)
	tx.Mul(tx, ty)
	tx.Sub(tx, v0)
	tx.Sub(tx, v1)

	ty.MulU1(v1)
	ty.Add(ty, v0)

	return e
}

// MulNC2 muls a with (xv+y), this method is used in mulLine function
// to avoid gfP4 instance construction. e can't be same as a.
func (e *gfP4) MulNC2(a *gfP4, x, y *gfP2) *gfP4 {
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	//(a0+a1*v)(b0+b1*v)=c0+c1*v, where
	//c0 = a0*b0 +a1*b1*u
	//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
	tx := &e.x
	ty := &e.y
	v0, v1 := &gfP2{}, &gfP2{}
	v0.Mul(&a.y, y)
	v1.Mul(&a.x, x)

	tx.Add(&a.x, &a.y)
	ty.Add(x, y)
	tx.Mul(tx, ty)
	tx.Sub(tx, v0)
	tx.Sub(tx, v1)

	ty.MulU1(v1)
	ty.Add(ty, v0)

	return e
}

// MulV: a * b * v
// (a0+a1*v)(b0+b1*v)*v=c0+c1*v, where
// (a0*b0 + a0*b1v + a1*b0*v + a1*b1*u)*v
// a0*b0*v + a0*b1*u + a1*b0*u + a1*b1*u*v
// c0 = a0*b1*u + a1*b0*u
// c1 = a0*b0 + a1*b1*u
func (e *gfP4) MulV(a, b *gfP4) *gfP4 {
	tmp := &gfP4{}
	tmp.MulVNC(a, b)
	gfp4Copy(e, tmp)
	return e
}

// MulV without value copy, will use e directly, so e can't be same as a and b.
func (e *gfP4) MulVNC(a, b *gfP4) *gfP4 {
	tx := &e.x
	ty := &e.y
	v0, v1 := &gfP2{}, &gfP2{}
	v0.Mul(&a.y, &b.y)
	v1.Mul(&a.x, &b.x)

	tx.Add(&a.x, &a.y)
	ty.Add(&b.x, &b.y)
	ty.Mul(tx, ty)
	ty.Sub(ty, v0)
	ty.Sub(ty, v1)
	ty.MulU1(ty)

	tx.MulU1(v1)
	tx.Add(tx, v0)

	return e
}

// MulV1: a * v
// (a0+a1*v)*v=c0+c1*v, where
// c0 = a1*u
// c1 = a0
func (e *gfP4) MulV1(a *gfP4) *gfP4 {
	tx := &gfP2{}
	gfp2Copy(tx, &a.y)

	e.y.MulU1(&a.x)
	gfp2Copy(&e.x, tx)
	return e
}

func (e *gfP4) Square(a *gfP4) *gfP4 {
	// Complex squaring algorithm:
	// (xv+y)² = (x^2*u + y^2) + 2*x*y*v
	tmp := &gfP4{}
	tmp.SquareNC(a)
	gfp4Copy(e, tmp)
	return e
}

// Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP4) SquareNC(a *gfP4) *gfP4 {
	// Complex squaring algorithm:
	// (xv+y)² = (x^2*u + y^2) + 2*x*y*v
	// = (xu + y)(x + y) -xy(1+u) + 2xy*v
	tx := &e.x
	ty := &e.y

	tx.SquareU(&a.x)
	ty.Square(&a.y)
	ty.Add(tx, ty)

	tx.Mul(&a.x, &a.y)
	tx.Add(tx, tx)

	return e
}

// SquareV without value copy, will use e directly, so e can't be same as a.
// SquareV: (a^2) * v
// v*(xv+y)² = (x^2*u + y^2)v + 2*x*y*u
func (e *gfP4) SquareV(a *gfP4) *gfP4 {
	tmp := &gfP4{}
	tmp.SquareVNC(a)
	gfp4Copy(e, tmp)
	return e
}

func (e *gfP4) SquareVNC(a *gfP4) *gfP4 {
	tx := &e.x
	ty := &e.y
	tx.SquareU(&a.x)
	ty.Square(&a.y)
	tx.Add(tx, ty)

	ty.MulU(&a.x, &a.y)
	ty.Add(ty, ty)

	return e
}

func (e *gfP4) Invert(a *gfP4) *gfP4 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	tmp := &gfP4{}
	t2 := &tmp.x
	t1 := &tmp.y

	t3 := &gfP2{}

	t3.SquareU(&a.x)
	t1.Square(&a.y)
	t3.Sub(t3, t1)
	t3.Invert(t3)

	t1.Mul(&a.y, t3)
	t1.Neg(t1)

	t2.Mul(&a.x, t3)

	gfp4Copy(e, tmp)
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

//	(y+x*v)^p
//
// = y^p + x^p*v^p
// = f(y) + f(x) * v^p
// = f(y) + f(x) * v * v^(p-1)
func (e *gfP4) Frobenius(a *gfP4) *gfP4 {
	tmp := &gfP4{}
	x := &tmp.x
	y := &tmp.y

	x.Conjugate(&a.x)
	y.Conjugate(&a.y)
	x.MulScalar(x, vToPMinus1)

	gfp4Copy(e, tmp)

	return e
}

//	(y+x*v)^(p^2)
//
// y + x*v * v^(p^2-1)
func (e *gfP4) FrobeniusP2(a *gfP4) *gfP4 {
	e.Conjugate(a)
	return e
}

//	(y+x*v)^(p^3)
//
// = ((y+x*v)^p)^(p^2)
func (e *gfP4) FrobeniusP3(a *gfP4) *gfP4 {
	tmp := &gfP4{}
	x := &tmp.x
	y := &tmp.y
	x.Conjugate(&a.x)
	y.Conjugate(&a.y)
	x.MulScalar(x, vToPMinus1)
	x.Neg(x)

	gfp4Copy(e, tmp)

	return e
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *gfP4) Select(p1, p2 *gfP4, cond int) *gfP4 {
	q.x.Select(&p1.x, &p2.x, cond)
	q.y.Select(&p1.y, &p2.y, cond)
	return q
}
