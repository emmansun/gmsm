package bn256

import (
	"crypto/subtle"
	"math/big"
)

// curvePoint implements the elliptic curve y²=x³+5. Points are kept in Jacobian
// form and t=z² when valid. G₁ is the set of points of this curve on GF(p).
type curvePoint struct {
	x, y, z, t gfP
}

var curveB = newGFp(5)

// curveGen is the generator of G₁.
var curveGen = &curvePoint{
	x: *fromBigInt(bigFromHex("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD")),
	y: *fromBigInt(bigFromHex("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616")),
	z: *one,
	t: *one,
}

func (c *curvePoint) String() string {
	c.MakeAffine()
	x, y := &gfP{}, &gfP{}
	montDecode(x, &c.x)
	montDecode(y, &c.y)
	return "(" + x.String() + ", " + y.String() + ")"
}

func (c *curvePoint) Set(a *curvePoint) {
	c.x.Set(&a.x)
	c.y.Set(&a.y)
	c.z.Set(&a.z)
	c.t.Set(&a.t)
}

func (c *curvePoint) polynomial(x *gfP) *gfP {
	x3 := &gfP{}
	gfpSqr(x3, x, 1)
	gfpMul(x3, x3, x)
	gfpAdd(x3, x3, curveB)
	return x3
}

// IsOnCurve returns true if c is on the curve.
func (c *curvePoint) IsOnCurve() bool {
	c.MakeAffine()
	if c.IsInfinity() { // TBC: This is not same as golang elliptic
		return true
	}

	y2 := &gfP{}
	gfpSqr(y2, &c.y, 1)

	x3 := c.polynomial(&c.x)

	return y2.Equal(x3) == 1
}

func NewCurvePoint() *curvePoint {
	c := &curvePoint{}
	c.SetInfinity()
	return c
}

func NewCurveGenerator() *curvePoint {
	c := &curvePoint{}
	c.Set(curveGen)
	return c
}

func (c *curvePoint) SetInfinity() {
	c.x.Set(zero)
	c.y.Set(one)
	c.z.Set(zero)
	c.t.Set(zero)
}

func (c *curvePoint) IsInfinity() bool {
	return c.z.Equal(zero) == 1
}

func (c *curvePoint) Add(a, b *curvePoint) {
	if a.IsInfinity() {
		c.Set(b)
		return
	}
	if b.IsInfinity() {
		c.Set(a)
		return
	}

	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

	// Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
	// by [u1:s1:z1·z2] and [u2:s2:z1·z2]
	// where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
	z12, z22 := &gfP{}, &gfP{}
	gfpSqr(z12, &a.z, 1)
	gfpSqr(z22, &b.z, 1)

	u1, u2 := &gfP{}, &gfP{}
	gfpMul(u1, &a.x, z22)
	gfpMul(u2, &b.x, z12)

	t, s1 := &gfP{}, &gfP{}
	gfpMul(t, &b.z, z22)
	gfpMul(s1, &a.y, t)

	s2 := &gfP{}
	gfpMul(t, &a.z, z12)
	gfpMul(s2, &b.y, t)

	// Compute x = (2h)²(s²-u1-u2)
	// where s = (s2-s1)/(u2-u1) is the slope of the line through
	// (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
	// This is also:
	// 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
	//                        = r² - j - 2v
	// with the notations below.
	h := &gfP{}
	gfpSub(h, u2, u1)

	gfpDouble(t, h)
	// i = 4h²
	i := &gfP{}
	gfpSqr(i, t, 1)
	// j = 4h³
	j := &gfP{}
	gfpMul(j, h, i)

	gfpSub(t, s2, s1)

	if h.Equal(zero) == 1 && t.Equal(one) == 1 {
		c.Double(a)
		return
	}
	r := &gfP{}
	gfpDouble(r, t)

	v := &gfP{}
	gfpMul(v, u1, i)

	// t4 = 4(s2-s1)²
	t4, t6 := &gfP{}, &gfP{}
	gfpSqr(t4, r, 1)
	gfpDouble(t, v)
	gfpSub(t6, t4, j)

	gfpSub(&c.x, t6, t)

	// Set y = -(2h)³(s1 + s*(x/4h²-u1))
	// This is also
	// y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
	gfpSub(t, v, &c.x) // t7
	gfpMul(t4, s1, j)  // t8
	gfpDouble(t6, t4) // t9
	gfpMul(t4, r, t)   // t10
	gfpSub(&c.y, t4, t6)

	// Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
	gfpAdd(t, &a.z, &b.z) // t11
	gfpSqr(t4, t, 1)      // t12
	gfpSub(t, t4, z12)    // t13
	gfpSub(t4, t, z22)    // t14
	gfpMul(&c.z, t4, h)
}

func (c *curvePoint) Double(a *curvePoint) {
	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
	A, B, C := &gfP{}, &gfP{}, &gfP{}
	gfpSqr(A, &a.x, 1)
	gfpSqr(B, &a.y, 1)
	gfpSqr(C, B, 1)

	t, t2 := &gfP{}, &gfP{}
	gfpAdd(t, &a.x, B)
	gfpSqr(t2, t, 1)
	gfpSub(t, t2, A)
	gfpSub(t2, t, C)

	d, e, f := &gfP{}, &gfP{}, &gfP{}
	gfpAdd(d, t2, t2)
	gfpDouble(t, A)
	gfpAdd(e, t, A)
	gfpSqr(f, e, 1)

	gfpDouble(t, d)
	gfpSub(&c.x, f, t)

	gfpMul(&c.z, &a.y, &a.z)
	gfpDouble(&c.z, &c.z)

	gfpDouble(t, C)
	gfpDouble(t2, t)
	gfpDouble(t, t2)
	gfpSub(&c.y, d, &c.x)
	gfpMul(t2, e, &c.y)
	gfpSub(&c.y, t2, t)
}

func (c *curvePoint) Mul(a *curvePoint, scalar *big.Int) {
	sum, t := &curvePoint{}, &curvePoint{}
	sum.SetInfinity()

	for i := scalar.BitLen(); i >= 0; i-- {
		t.Double(sum)
		if scalar.Bit(i) != 0 {
			sum.Add(t, a)
		} else {
			sum.Set(t)
		}
	}

	c.Set(sum)
}

func (c *curvePoint) MakeAffine() {
	if c.z.Equal(one) == 1 {
		return
	} else if c.z.Equal(zero) == 1 {
		c.x.Set(zero)
		c.y.Set(one)
		c.t.Set(zero)
		return
	}

	zInv := &gfP{}
	zInv.Invert(&c.z)

	t, zInv2 := &gfP{}, &gfP{}
	gfpMul(t, &c.y, zInv)
	gfpSqr(zInv2, zInv, 1)

	gfpMul(&c.x, &c.x, zInv2)
	gfpMul(&c.y, t, zInv2)

	c.z.Set(one)
	c.t.Set(one)
}

func (c *curvePoint) Neg(a *curvePoint) {
	c.x.Set(&a.x)
	gfpNeg(&c.y, &a.y)
	c.z.Set(&a.z)
	c.t.Set(zero)
}

// A curvePointTable holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type curvePointTable [15]*curvePoint

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *curvePointTable) Select(p *curvePoint, n uint8) {
	if n >= 16 {
		panic("sm9: internal error: curvePointTable called with out-of-bounds value")
	}
	p.SetInfinity()
	for i, f := range table {
		cond := subtle.ConstantTimeByteEq(uint8(i+1), n)
		curvePointMovCond(p, f, p, cond)
	}
}
