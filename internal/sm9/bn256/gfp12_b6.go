package bn256

import "math/big"

// gfP12b6 implements the field of size p¹² as a quadratic extension of gfP6
// where t²=s.
type gfP12b6 struct {
	x, y gfP6 // value is xt + y
}

func gfP12b6Decode(in *gfP12b6) *gfP12b6 {
	out := &gfP12b6{}
	out.x = *gfP6Decode(&in.x)
	out.y = *gfP6Decode(&in.y)
	return out
}

var gfP12b6Gen *gfP12b6 = &gfP12b6{
	x: gfP6{
		x: gfP2{
			x: *newGFpFromBytes([]byte{0x25, 0x69, 0x43, 0xfb, 0xdb, 0x2b, 0xf8, 0x7a, 0xb9, 0x1a, 0xe7, 0xfb, 0xea, 0xff, 0x14, 0xe1, 0x46, 0xcf, 0x7e, 0x22, 0x79, 0xb9, 0xd1, 0x55, 0xd1, 0x34, 0x61, 0xe0, 0x9b, 0x22, 0xf5, 0x23}),
			y: *newGFpFromBytes([]byte{0x01, 0x67, 0xb0, 0x28, 0x00, 0x51, 0x49, 0x5c, 0x6a, 0xf1, 0xec, 0x23, 0xba, 0x2c, 0xd2, 0xff, 0x1c, 0xdc, 0xde, 0xca, 0x46, 0x1a, 0x5a, 0xb0, 0xb5, 0x44, 0x9e, 0x90, 0x91, 0x30, 0x83, 0x10}),
		},
		y: gfP2{
			x: *newGFpFromBytes([]byte{0x8f, 0xfe, 0x1c, 0x0e, 0x9d, 0xe4, 0x5f, 0xd0, 0xfe, 0xd7, 0x90, 0xac, 0x26, 0xbe, 0x91, 0xf6, 0xb3, 0xf0, 0xa4, 0x9c, 0x08, 0x4f, 0xe2, 0x9a, 0x3f, 0xb6, 0xed, 0x28, 0x8a, 0xd7, 0x99, 0x4d}),
			y: *newGFpFromBytes([]byte{0x16, 0x64, 0xa1, 0x36, 0x6b, 0xeb, 0x31, 0x96, 0xf0, 0x44, 0x3e, 0x15, 0xf5, 0xf9, 0x04, 0x2a, 0x94, 0x73, 0x54, 0xa5, 0x67, 0x84, 0x30, 0xd4, 0x5b, 0xa0, 0x31, 0xcf, 0xf0, 0x6d, 0xb9, 0x27}),
		},
		z: gfP2{
			x: *newGFpFromBytes([]byte{0x7f, 0xc6, 0xeb, 0x2a, 0xa7, 0x71, 0xd9, 0x9c, 0x92, 0x34, 0xfd, 0xdd, 0x31, 0x75, 0x2e, 0xdf, 0xd6, 0x07, 0x23, 0xe0, 0x5a, 0x4e, 0xbf, 0xde, 0xb5, 0xc3, 0x3f, 0xbd, 0x47, 0xe0, 0xcf, 0x06}),
			y: *newGFpFromBytes([]byte{0x6f, 0xa6, 0xb6, 0xfa, 0x6d, 0xd6, 0xb6, 0xd3, 0xb1, 0x9a, 0x95, 0x9a, 0x11, 0x0e, 0x74, 0x81, 0x54, 0xee, 0xf7, 0x96, 0xdc, 0x0f, 0xc2, 0xdd, 0x76, 0x6e, 0xa4, 0x14, 0xde, 0x78, 0x69, 0x68}),
		},
	},
	y: gfP6{
		x: gfP2{
			x: *newGFpFromBytes([]byte{0x08, 0x2c, 0xde, 0x17, 0x30, 0x22, 0xda, 0x8c, 0xd0, 0x9b, 0x28, 0xa2, 0xd8, 0x0a, 0x8c, 0xee, 0x53, 0x89, 0x44, 0x36, 0xa5, 0x20, 0x07, 0xf9, 0x78, 0xdc, 0x37, 0xf3, 0x61, 0x16, 0xd3, 0x9b}),
			y: *newGFpFromBytes([]byte{0x3f, 0xa7, 0xed, 0x74, 0x1e, 0xae, 0xd9, 0x9a, 0x58, 0xf5, 0x3e, 0x3d, 0xf8, 0x2d, 0xf7, 0xcc, 0xd3, 0x40, 0x7b, 0xcc, 0x7b, 0x1d, 0x44, 0xa9, 0x44, 0x19, 0x20, 0xce, 0xd5, 0xfb, 0x82, 0x4f}),
		},
		y: gfP2{
			x: *newGFpFromBytes([]byte{0x5e, 0x7a, 0xdd, 0xad, 0xdf, 0x7f, 0xbf, 0xe1, 0x62, 0x91, 0xb4, 0xe8, 0x9a, 0xf5, 0x0b, 0x82, 0x17, 0xdd, 0xc4, 0x7b, 0xa3, 0xcb, 0xa8, 0x33, 0xc6, 0xe7, 0x7c, 0x3f, 0xb0, 0x27, 0x68, 0x5e}),
			y: *newGFpFromBytes([]byte{0x79, 0xd0, 0xc8, 0x33, 0x70, 0x72, 0xc9, 0x3f, 0xef, 0x48, 0x2b, 0xb0, 0x55, 0xf4, 0x4d, 0x62, 0x47, 0xcc, 0xac, 0x8e, 0x8e, 0x12, 0x52, 0x58, 0x54, 0xb3, 0x56, 0x62, 0x36, 0x33, 0x7e, 0xbe}),
		},
		z: gfP2{
			x: *newGFpFromBytes([]byte{0x7f, 0x7c, 0x6d, 0x52, 0xb4, 0x75, 0xe6, 0xaa, 0xa8, 0x27, 0xfd, 0xc5, 0xb4, 0x17, 0x5a, 0xc6, 0x92, 0x93, 0x20, 0xf7, 0x82, 0xd9, 0x98, 0xf8, 0x6b, 0x6b, 0x57, 0xcd, 0xa4, 0x2a, 0x04, 0x26}),
			y: *newGFpFromBytes([]byte{0x36, 0xa6, 0x99, 0xde, 0x7c, 0x13, 0x6f, 0x78, 0xee, 0xe2, 0xdb, 0xac, 0x4c, 0xa9, 0x72, 0x7b, 0xff, 0x0c, 0xee, 0x02, 0xee, 0x92, 0x0f, 0x58, 0x22, 0xe6, 0x5e, 0xa1, 0x70, 0xaa, 0x96, 0x69}),
		},
	},
}

func (e *gfP12b6) String() string {
	return "(" + e.x.String() + "," + e.y.String() + ")"
}

func (e *gfP12b6) ToGfP12() *gfP12 {
	ret := &gfP12{}

	ret.z.y.Set(&e.y.z)
	ret.x.y.Set(&e.y.y)
	ret.y.x.Set(&e.y.x)
	ret.y.y.Set(&e.x.z)
	ret.z.x.Set(&e.x.y)
	ret.x.x.Set(&e.x.x)

	return ret
}

func (e *gfP12b6) SetGfP12(a *gfP12) *gfP12b6 {
	e.y.z.Set(&a.z.y) //a
	e.y.y.Set(&a.x.y) //b
	e.y.x.Set(&a.y.x)
	e.x.z.Set(&a.y.y)
	e.x.y.Set(&a.z.x) //c
	e.x.x.Set(&a.x.x)

	return e
}

func (e *gfP12b6) Set(a *gfP12b6) *gfP12b6 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP12b6) SetZero() *gfP12b6 {
	e.x.SetZero()
	e.y.SetZero()
	return e
}

func (e *gfP12b6) SetOne() *gfP12b6 {
	e.x.SetZero()
	e.y.SetOne()
	return e
}

func (e *gfP12b6) IsZero() bool {
	return e.x.IsZero() && e.y.IsZero()
}

func (e *gfP12b6) IsOne() bool {
	return e.x.IsZero() && e.y.IsOne()
}

func (e *gfP12b6) Neg(a *gfP12b6) *gfP12b6 {
	e.x.Neg(&a.x)
	e.y.Neg(&a.y)
	return e
}

func (e *gfP12b6) Conjugate(a *gfP12b6) *gfP12b6 {
	e.x.Neg(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP12b6) Add(a, b *gfP12b6) *gfP12b6 {
	e.x.Add(&a.x, &b.x)
	e.y.Add(&a.y, &b.y)
	return e
}

func (e *gfP12b6) Sub(a, b *gfP12b6) *gfP12b6 {
	e.x.Sub(&a.x, &b.x)
	e.y.Sub(&a.y, &b.y)
	return e
}

func (e *gfP12b6) Mul(a, b *gfP12b6) *gfP12b6 {
	tmp := &gfP12b6{}
	tmp.MulNC(a, b)
	e.x.Set(&tmp.x)
	e.y.Set(&tmp.y)
	return e
}

// Mul without value copy, will use e directly, so e can't be same as a and b.
func (e *gfP12b6) MulNC(a, b *gfP12b6) *gfP12b6 {
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	//(a0+a1*t)(b0+b1*t)=c0+c1*t, where
	//c0 = a0*b0 +a1*b1*s
	//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
	tx := &e.x
	ty := &e.y
	v0, v1 := &gfP6{}, &gfP6{}
	v0.MulNC(&a.y, &b.y)
	v1.MulNC(&a.x, &b.x)

	tx.Add(&a.x, &a.y)
	ty.Add(&b.x, &b.y)
	tx.Mul(tx, ty)
	tx.Sub(tx, v0)
	tx.Sub(tx, v1)

	ty.MulS(v1)
	ty.Add(ty, v0)

	return e
}

func (e *gfP12b6) MulScalar(a *gfP12b6, b *gfP6) *gfP12b6 {
	e.x.Mul(&a.x, b)
	e.y.Mul(&a.y, b)
	return e
}

func (e *gfP12b6) MulGfP(a *gfP12b6, b *gfP) *gfP12b6 {
	e.x.MulGfP(&a.x, b)
	e.y.MulGfP(&a.y, b)
	return e
}

func (e *gfP12b6) MulGfP2(a *gfP12b6, b *gfP2) *gfP12b6 {
	e.x.MulScalar(&a.x, b)
	e.y.MulScalar(&a.y, b)
	return e
}

func (e *gfP12b6) Square(a *gfP12b6) *gfP12b6 {
	tmp := &gfP12b6{}
	tmp.SquareNC(a)
	e.x.Set(&tmp.x)
	e.y.Set(&tmp.y)
	return e
}

// Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP12b6) SquareNC(a *gfP12b6) *gfP12b6 {
	// Complex squaring algorithm
	// (xt+y)² = (x^2*s + y^2) + 2*x*y*t
	tx := &e.x
	ty := &e.y

	tx.SquareNC(&a.x).MulS(tx)
	ty.SquareNC(&a.y)
	ty.Add(tx, ty)

	tx.Mul(&a.x, &a.y)
	tx.Add(tx, tx)

	return e
}

// Cyclo6Square is used in final exponentiation after easy part(a ^ ((p^2 + 1)(p^6-1))).
// Note that after the easy part of the final exponentiation,
// the resulting element lies in cyclotomic subgroup.
// "New software speed records for cryptographic pairings"
// Section 3.3, Final exponentiation
// https://cryptojedi.org/papers/dclxvi-20100714.pdf
// The fomula reference:
// Granger/Scott (PKC2010).
// Section 3.2
// https://eprint.iacr.org/2009/565.pdf
func (e *gfP12b6) Cyclo6Square(a *gfP12b6) *gfP12b6 {
	tmp := &gfP12b6{}
	tmp.Cyclo6SquareNC(a)
	e.x.Set(&tmp.x)
	e.y.Set(&tmp.y)
	return e
}

// Special Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP12b6) Cyclo6SquareNC(a *gfP12b6) *gfP12b6 {
	f02 := &e.y.x
	f01 := &e.y.y
	f00 := &e.y.z
	f12 := &e.x.x
	f11 := &e.x.y
	f10 := &e.x.z

	t00, t01, t02, t10, t11, t12 := &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}

	gfP4Square(t11, t00, &a.x.y, &a.y.z)
	gfP4Square(t12, t01, &a.y.x, &a.x.z)
	gfP4Square(t02, t10, &a.x.x, &a.y.y)

	f00.MulU1(t02)
	t02.Set(t10)
	t10.Set(f00)

	f00.Add(t00, t00)
	t00.Add(f00, t00)
	f00.Add(t01, t01)
	t01.Add(f00, t01)
	f00.Add(t02, t02)
	t02.Add(f00, t02)
	f00.Add(t10, t10)
	t10.Add(f00, t10)
	f00.Add(t11, t11)
	t11.Add(f00, t11)
	f00.Add(t12, t12)
	t12.Add(f00, t12)

	f00.Add(&a.y.z, &a.y.z)
	f00.Neg(f00)
	f01.Add(&a.y.y, &a.y.y)
	f01.Neg(f01)
	f02.Add(&a.y.x, &a.y.x)
	f02.Neg(f02)
	f10.Add(&a.x.z, &a.x.z)
	f11.Add(&a.x.y, &a.x.y)
	f12.Add(&a.x.x, &a.x.x)

	f00.Add(f00, t00)
	f01.Add(f01, t01)
	f02.Add(f02, t02)
	f10.Add(f10, t10)
	f11.Add(f11, t11)
	f12.Add(f12, t12)

	return e
}

func (e *gfP12b6) Cyclo6Squares(a *gfP12b6, n int) *gfP12b6 {
	// Square first round
	in := &gfP12b6{}
	f02 := &in.y.x
	f01 := &in.y.y
	f00 := &in.y.z
	f12 := &in.x.x
	f11 := &in.x.y
	f10 := &in.x.z

	t00, t01, t02, t10, t11, t12 := &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}
	gfP4Square(t11, t00, &a.x.y, &a.y.z)
	gfP4Square(t12, t01, &a.y.x, &a.x.z)
	gfP4Square(t02, t10, &a.x.x, &a.y.y)

	f00.MulU1(t02)
	t02.Set(t10)
	t10.Set(f00)

	f00.Add(t00, t00)
	t00.Add(f00, t00)
	f00.Add(t01, t01)
	t01.Add(f00, t01)
	f00.Add(t02, t02)
	t02.Add(f00, t02)
	f00.Add(t10, t10)
	t10.Add(f00, t10)
	f00.Add(t11, t11)
	t11.Add(f00, t11)
	f00.Add(t12, t12)
	t12.Add(f00, t12)

	f00.Add(&a.y.z, &a.y.z)
	f00.Neg(f00)
	f01.Add(&a.y.y, &a.y.y)
	f01.Neg(f01)
	f02.Add(&a.y.x, &a.y.x)
	f02.Neg(f02)
	f10.Add(&a.x.z, &a.x.z)
	f11.Add(&a.x.y, &a.x.y)
	f12.Add(&a.x.x, &a.x.x)

	f00.Add(f00, t00)
	f01.Add(f01, t01)
	f02.Add(f02, t02)
	f10.Add(f10, t10)
	f11.Add(f11, t11)
	f12.Add(f12, t12)

	tmp := &gfP12b6{}
	var tmp2 *gfP12b6

	for i := 1; i < n; i++ {
		f02 = &tmp.y.x
		f01 = &tmp.y.y
		f00 = &tmp.y.z
		f12 = &tmp.x.x
		f11 = &tmp.x.y
		f10 = &tmp.x.z

		gfP4Square(t11, t00, &in.x.y, &in.y.z)
		gfP4Square(t12, t01, &in.y.x, &in.x.z)
		gfP4Square(t02, t10, &in.x.x, &in.y.y)

		f00.MulU1(t02)
		t02.Set(t10)
		t10.Set(f00)

		f00.Add(t00, t00)
		t00.Add(f00, t00)
		f00.Add(t01, t01)
		t01.Add(f00, t01)
		f00.Add(t02, t02)
		t02.Add(f00, t02)
		f00.Add(t10, t10)
		t10.Add(f00, t10)
		f00.Add(t11, t11)
		t11.Add(f00, t11)
		f00.Add(t12, t12)
		t12.Add(f00, t12)

		f00.Add(&in.y.z, &in.y.z)
		f00.Neg(f00)
		f01.Add(&in.y.y, &in.y.y)
		f01.Neg(f01)
		f02.Add(&in.y.x, &in.y.x)
		f02.Neg(f02)
		f10.Add(&in.x.z, &in.x.z)
		f11.Add(&in.x.y, &in.x.y)
		f12.Add(&in.x.x, &in.x.x)

		f00.Add(f00, t00)
		f01.Add(f01, t01)
		f02.Add(f02, t02)
		f10.Add(f10, t10)
		f11.Add(f11, t11)
		f12.Add(f12, t12)

		// Switch references
		tmp2 = in
		in = tmp
		tmp = tmp2
	}
	e.x.Set(&in.x)
	e.y.Set(&in.y)
	return e
}

func gfP4Square(retX, retY, x, y *gfP2) {
	retX.SquareU(x)
	retY.Square(y)
	retY.Add(retX, retY)

	retX.Mul(x, y)
	retX.Add(retX, retX)
}

func (c *gfP12b6) Exp(a *gfP12b6, power *big.Int) *gfP12b6 {
	sum := (&gfP12b6{}).SetOne()
	t := &gfP12b6{}

	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum)
		if power.Bit(i) != 0 {
			sum.Mul(t, a)
		} else {
			sum.Set(t)
		}
	}

	c.Set(sum)
	return c
}

func (e *gfP12b6) Invert(a *gfP12b6) *gfP12b6 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf

	t0, t1 := &gfP6{}, &gfP6{}

	t0.MulNC(&a.y, &a.y)
	t1.MulNC(&a.x, &a.x).MulS(t1)
	t0.Sub(t0, t1)
	t0.Invert(t0)

	e.x.Neg(&a.x)
	e.y.Set(&a.y)
	e.MulScalar(e, t0)

	return e
}

// Frobenius computes (xt+y)^p
// = x^p t^p + y^p
// = x^p t^(p-1) t + y^p
// = x^p s^((p-1)/2) t + y^p
// sToPMinus1Over2
func (e *gfP12b6) Frobenius(a *gfP12b6) *gfP12b6 {
	e.x.Frobenius(&a.x)
	e.y.Frobenius(&a.y)
	e.x.MulGfP(&e.x, sToPMinus1Over2)
	return e
}

// FrobeniusP2 computes (xt+y)^p² = x^p² t ·s^((p²-1)/2) + y^p²
func (e *gfP12b6) FrobeniusP2(a *gfP12b6) *gfP12b6 {
	e.x.FrobeniusP2(&a.x)
	e.y.FrobeniusP2(&a.y)
	e.x.MulGfP(&e.x, sToPSquaredMinus1Over2)
	return e
}

func (e *gfP12b6) FrobeniusP4(a *gfP12b6) *gfP12b6 {
	e.x.FrobeniusP4(&a.x)
	e.y.FrobeniusP4(&a.y)
	e.x.MulGfP(&e.x, sToPSquaredMinus1)
	return e
}

func (e *gfP12b6) FrobeniusP6(a *gfP12b6) *gfP12b6 {
	e.x.Neg(&a.x)
	e.y.Set(&a.y)
	return e
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *gfP12b6) Select(p1, p2 *gfP12b6, cond int) *gfP12b6 {
	q.x.Select(&p1.x, &p2.x, cond)
	q.y.Select(&p1.y, &p2.y, cond)
	return q
}
