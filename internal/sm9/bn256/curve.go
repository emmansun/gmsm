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
var threeCurveB = newGFp(3 * 5)

// curveGen is the generator of G₁.
var curveGen = &curvePoint{
	x: *newGFpFromBytes([]byte{0x93, 0xDE, 0x05, 0x1D, 0x62, 0xBF, 0x71, 0x8F, 0xF5, 0xED, 0x07, 0x04, 0x48, 0x7D, 0x01, 0xD6, 0xE1, 0xE4, 0x08, 0x69, 0x09, 0xDC, 0x32, 0x80, 0xE8, 0xC4, 0xE4, 0x81, 0x7C, 0x66, 0xDD, 0xDD}),
	y: *newGFpFromBytes([]byte{0x21, 0xFE, 0x8D, 0xDA, 0x4F, 0x21, 0xE6, 0x07, 0x63, 0x10, 0x65, 0x12, 0x5C, 0x39, 0x5B, 0xBC, 0x1C, 0x1C, 0x00, 0xCB, 0xFA, 0x60, 0x24, 0x35, 0x0C, 0x46, 0x4C, 0xD7, 0x0A, 0x3E, 0xA6, 0x16}),
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

// MakeAffine reverses the Jacobian transform.
// the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³.
func (c *curvePoint) AffineFromJacobian() {
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
	gfpMul(t, &c.y, zInv) // t = y/z
	gfpSqr(zInv2, zInv, 1)

	gfpMul(&c.x, &c.x, zInv2) // x = x / z^2
	gfpMul(&c.y, t, zInv2)    // y = y / z^3

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

// Equal compare e and other
func (e *curvePoint) Equal(other *curvePoint) bool {
	return e.x.Equal(&other.x) == 1 &&
		e.y.Equal(&other.y) == 1 &&
		e.z.Equal(&other.z) == 1 &&
		e.t.Equal(&other.t) == 1
}

// Below methods are POC yet, the line add/double functions are still based on
// Jacobian coordination.
func (c *curvePoint) Add(p1, p2 *curvePoint) {
	curvePointAddComplete(c, p1, p2)
}

func (c *curvePoint) AddComplete(p1, p2 *curvePoint) {
	curvePointAddComplete(c, p1, p2)
}

func (c *curvePoint) Double(p *curvePoint) {
	curvePointDoubleComplete(c, p)
}

func (c *curvePoint) DoubleComplete(p *curvePoint) {
	curvePointDoubleComplete(c, p)
}

// MakeAffine reverses the Projective transform.
// A = 1/Z1
// X3 = A*X1
// Y3 = A*Y1
// Z3 = 1
func (c *curvePoint) MakeAffine() {
	// TODO: do we need to change it to constant-time implementation?
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
	gfpMul(&c.x, &c.x, zInv)
	gfpMul(&c.y, &c.y, zInv)
	c.z.Set(one)
	c.t.Set(one)
}

func (c *curvePoint) AffineFromProjective() {
	c.MakeAffine()
}

func curvePointDouble(c, a *curvePoint) {
	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
	A, B, C := &gfP{}, &gfP{}, &gfP{}
	gfpSqr(A, &a.x, 1)
	gfpSqr(B, &a.y, 1)
	gfpSqr(C, B, 1)

	t := &gfP{}
	gfpAdd(B, &a.x, B)
	gfpSqr(t, B, 1)
	gfpSub(B, t, A)
	gfpSub(t, B, C)

	d, e := &gfP{}, &gfP{}
	gfpDouble(d, t)
	gfpDouble(B, A)
	gfpAdd(e, B, A)
	gfpSqr(A, e, 1)

	gfpDouble(B, d)
	gfpSub(&c.x, A, B)

	gfpMul(&c.z, &a.y, &a.z)
	gfpDouble(&c.z, &c.z)

	gfpDouble(B, C)
	gfpDouble(t, B)
	gfpDouble(B, t)
	gfpSub(&c.y, d, &c.x)
	gfpMul(t, e, &c.y)
	gfpSub(&c.y, t, B)
}

func curvePointAdd(c, a, b *curvePoint) int {
	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
	var pointEq int
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

	pointEq = h.Equal(zero) & t.Equal(zero)

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
	gfpDouble(t6, t4)  // t9
	gfpMul(t4, r, t)   // t10
	gfpSub(&c.y, t4, t6)

	// Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
	gfpAdd(t, &a.z, &b.z) // t11
	gfpSqr(t4, t, 1)      // t12
	gfpSub(t, t4, z12)    // t13
	gfpSub(t4, t, z22)    // t14
	gfpMul(&c.z, t4, h)

	return pointEq
}
