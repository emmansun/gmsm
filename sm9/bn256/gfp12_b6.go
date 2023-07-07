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
			x: *fromBigInt(bigFromHex("256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f523")),
			y: *fromBigInt(bigFromHex("0167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e9091308310")),
		},
		y: gfP2{
			x: *fromBigInt(bigFromHex("8ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d")),
			y: *fromBigInt(bigFromHex("1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db927")),
		},
		z: gfP2{
			x: *fromBigInt(bigFromHex("7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf06")),
			y: *fromBigInt(bigFromHex("6fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de786968")),
		},
	},
	y: gfP6{
		x: gfP2{
			x: *fromBigInt(bigFromHex("082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b")),
			y: *fromBigInt(bigFromHex("3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f")),
		},
		y: gfP2{
			x: *fromBigInt(bigFromHex("5e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e")),
			y: *fromBigInt(bigFromHex("79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe")),
		},
		z: gfP2{
			x: *fromBigInt(bigFromHex("7f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a0426")),
			y: *fromBigInt(bigFromHex("36a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669")),
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

// Special squaring for use on elements in T_6(fp2) (after the
// easy part of the final exponentiation. Used in the hard part
// of the final exponentiation. Function uses formulas in
// Granger/Scott (PKC2010).
func (e *gfP12b6) SpecialSquare(a *gfP12b6) *gfP12b6 {
	tmp := &gfP12b6{}
	tmp.SpecialSquareNC(a)
	e.x.Set(&tmp.x)
	e.y.Set(&tmp.y)
	return e
}

// Special Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP12b6) SpecialSquareNC(a *gfP12b6) *gfP12b6 {
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

func (e *gfP12b6) SpecialSquares(a *gfP12b6, n int) *gfP12b6 {
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
	retX.SquareUNC(x)
	retY.SquareNC(y)
	retY.Add(retX, retY)

	retX.MulNC(x, y)
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
