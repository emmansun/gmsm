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
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §3.2.
	// Algorithm 7: Complete, projective point addition for prime order j-invariant 0 short Weierstrass curves.

	t0, t1, t2, t3, t4 := new(gfP), new(gfP), new(gfP), new(gfP), new(gfP)
	x3, y3, z3 := new(gfP), new(gfP), new(gfP)
	gfpMul(t0, &p1.x, &p2.x)    // t0 := X1X2
	gfpMul(t1, &p1.y, &p2.y)    // t1 := Y1Y2
	gfpMul(t2, &p1.z, &p2.z)    // t2 := Z1Z2
	gfpAdd(t3, &p1.x, &p1.y)    // t3 := X1 + Y1
	gfpAdd(t4, &p2.x, &p2.y)    // t4 := X2 + Y2
	gfpMul(t3, t3, t4)          // t3 := t3 * t4 = (X1 + Y1) * (X2 + Y2)
	gfpAdd(t4, t0, t1)          // t4 := t0 + t1
	gfpSub(t3, t3, t4)          // t3 := t3 - t4 = X1Y2 + X2Y1
	gfpAdd(t4, &p1.y, &p1.z)    // t4 := Y1 + Z1
	gfpAdd(x3, &p2.y, &p2.z)    // X3 := Y2 + Z2
	gfpMul(t4, t4, x3)          // t4 := t4 * X3 = (Y1 + Z1)(Y2 + Z2)
	gfpAdd(x3, t1, t2)          // X3 := t1 + t2
	gfpSub(t4, t4, x3)          // t4 := t4 - X3 = Y1Z2 + Y2Z1
	gfpAdd(x3, &p1.x, &p1.z)    // X3 := X1 + Z1
	gfpAdd(y3, &p2.x, &p2.z)    // Y3 := X2 + Z2
	gfpMul(x3, x3, y3)          // X3 := X3 * Y3
	gfpAdd(y3, t0, t2)          // Y3 := t0 + t2
	gfpSub(y3, x3, y3)          // Y3 := X3 - Y3 = X1Z2 + X2Z1
	gfpTriple(t0, t0)           // t0 := t0 + t0 + t0 = 3X1X2
	gfpMul(t2, threeCurveB, t2) // t2 := 3b * t2 = 3bZ1Z2
	gfpAdd(z3, t1, t2)          // Z3 := t1 + t2 = Y1Y2 + 3bZ1Z2
	gfpSub(t1, t1, t2)          // t1 := t1 - t2 = Y1Y2 - 3bZ1Z2
	gfpMul(y3, threeCurveB, y3) // Y3 = 3b * Y3 = 3b(X1Z2 + X2Z1)
	gfpMul(x3, t4, y3)          // X3 := t4 * Y3 = 3b(X1Z2 + X2Z1)(Y1Z2 + Y2Z1)
	gfpMul(t2, t3, t1)          // t2 := t3 * t1 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2)
	gfpSub(x3, t2, x3)          // X3 := t2 - X3 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2) - 3b(Y1Z2 + Y2Z1)(X1Z2 + X2Z1)
	gfpMul(y3, y3, t0)          // Y3 := Y3 * t0 = 9bX1X2(X1Z2 + X2Z1)
	gfpMul(t1, t1, z3)          // t1 := t1 * Z3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2)
	gfpAdd(y3, t1, y3)          // Y3 := t1 + Y3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2) + 9bX1X2(X1Z2 + X2Z1)
	gfpMul(t0, t0, t3)          // t0 := t0 * t3 = 3X1X2(X1Y2 + X2Y1)
	gfpMul(z3, z3, t4)          // Z3 := Z3 * t4 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2)
	gfpAdd(z3, z3, t0)          // Z3 := Z3 + t0 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2) + 3X1X2(X1Y2 + X2Y1)

	c.x.Set(x3)
	c.y.Set(y3)
	c.z.Set(z3)
}

func (c *curvePoint) AddComplete(p1, p2 *curvePoint) {
	c.Add(p1, p2)
}

func (c *curvePoint) Double(p *curvePoint) {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §3.2.
	// Algorithm 9: Exception-free point doubling for prime order j-invariant 0 short Weierstrass curves.
	t0, t1, t2 := new(gfP), new(gfP), new(gfP)
	x3, y3, z3 := new(gfP), new(gfP), new(gfP)

	gfpSqr(t0, &p.y, 1)         // t0 := Y^2
	gfpDouble(z3, t0)           // Z3 := t0 + t0
	gfpDouble(z3, z3)           // Z3 := Z3 + Z3
	gfpDouble(z3, z3)           // Z3 := Z3 + Z3
	gfpMul(t1, &p.y, &p.z)      // t1 := YZ
	gfpSqr(t2, &p.z, 1)         // t0 := Z^2
	gfpMul(t2, threeCurveB, t2) // t2 := 3b * t2 = 3bZ^2
	gfpMul(x3, t2, z3)          // X3 := t2 * Z3
	gfpAdd(y3, t0, t2)          // Y3 := t0 + t2
	gfpMul(z3, t1, z3)          // Z3 := t1 * Z3
	gfpTriple(t2, t2)           // t2 := t2 + t2 + t2
	gfpSub(t0, t0, t2)          // t0 := t0 - t2
	gfpMul(y3, t0, y3)          // t0 := t0 * Y3
	gfpAdd(y3, x3, y3)          // Y3 := X3 + Y3
	gfpMul(t1, &p.x, &p.y)      // t1 := XY
	gfpMul(x3, t0, t1)          // X3 := t0 * t1
	gfpDouble(x3, x3)           // X3 := X3 + X3

	c.x.Set(x3)
	c.y.Set(y3)
	c.z.Set(z3)
}

func (c *curvePoint) DoubleComplete(p *curvePoint) {
	c.Double(p)
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
