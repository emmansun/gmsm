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
			x: *fromBigInt(bigFromHex("5f23b1ce3ac438e768411e843fea2a9be192c39d7c3e6440eb2aeaa2823d010c")),
			y: *fromBigInt(bigFromHex("61ebca2110d736bf0d4eba5c8c017781e2447d6d5edfdda6065c1ad6d376db4f")),
		},
		y: gfP2{
			x: *fromBigInt(bigFromHex("3b0fc03d5711c93dff31b23d5bc78184c4e4ad66027f8f55c219536a54552cae")),
			y: *fromBigInt(bigFromHex("254eb32dea84e64dfa196a2583564700074e1694c800c130290e1c8bdb9441aa")),
		},
		z: gfP2{
			x: *fromBigInt(bigFromHex("a3eec3cd6a795be8671d686fd9c9271dd32d71f71d7bd3de24fb5abe38626c9c")),
			y: *fromBigInt(bigFromHex("b101d668bfbf8ac8e546ccb8d6e1f9b89b988c0c238fb05e7b9c733c1f964b52")),
		},
	},
	y: gfP6{
		x: gfP2{
			x: *fromBigInt(bigFromHex("2efe33f18332bb77282c24f00c10930f7e2a3e36c6c822c7487ab1a6229d91f3")),
			y: *fromBigInt(bigFromHex("a6db7142e0ca24ae9ba7630e295a5ce7ed43ed38c0ce33e6346965f4dc5b5813")),
		},
		y: gfP2{
			x: *fromBigInt(bigFromHex("9ee43c7e3740bcd8e9d6067a4cf3c571441e074b4573390cfea0bce10965b32b")),
			y: *fromBigInt(bigFromHex("aa07010f9d42787cb0ebd9852fc780efb01ab631f2f10a180e06727b47ee6118")),
		},
		z: gfP2{
			x: *fromBigInt(bigFromHex("6a5fed210720de5844e199bee3498d4d2a72158dbf514e31be7381e2bce90a00")),
			y: *fromBigInt(bigFromHex("a0f422c35d7b6262796c802ec3f1370b9ef5d413e3176666b55d63ee8d7a8468")),
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
	e.y.z.Set(&a.z.y)
	e.y.y.Set(&a.x.y)
	e.y.x.Set(&a.y.x)
	e.x.z.Set(&a.y.y)
	e.x.y.Set(&a.z.x)
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
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	//(a0+a1*t)(b0+b1*t)=c0+c1*t, where
	//c0 = a0*b0 +a1*b1*s
	//c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
	tx, ty, v0, v1 := &gfP6{}, &gfP6{}, &gfP6{}, &gfP6{}
	v0.Mul(&a.y, &b.y)
	v1.Mul(&a.x, &b.x)

	tx.Add(&a.x, &a.y)
	ty.Add(&b.x, &b.y)
	tx.Mul(tx, ty)
	tx.Sub(tx, v0)
	tx.Sub(tx, v1)

	ty.MulS(v1)
	ty.Add(ty, v0)

	e.x.Set(tx)
	e.y.Set(ty)
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
	// Complex squaring algorithm
	// (xt+y)² = (x^2*s + y^2) + 2*x*y*t
	tx, ty := &gfP6{}, &gfP6{}
	tx.Square(&a.x).MulS(tx)
	ty.Square(&a.y)
	ty.Add(tx, ty)

	tx.Mul(&a.x, &a.y)
	tx.Add(tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
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

	t0.Mul(&a.y, &a.y)
	t1.Mul(&a.x, &a.x).MulS(t1)
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
