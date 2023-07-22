package bn256

import (
	"crypto/subtle"
	"math/big"
)

// twistPoint implements the elliptic curve y²=x³+5/ξ (y²=x³+5i) over GF(p²). Points are
// kept in Jacobian form and t=z² when valid. The group G₂ is the set of
// n-torsion points of this curve over GF(p²) (where n = Order)
type twistPoint struct {
	x, y, z, t gfP2
}

var twistB = &gfP2{
	*newGFp(5),
	*zero,
}

var threeTwistB = &gfP2{
	*newGFp(3 * 5),
	*zero,
}

// twistGen is the generator of group G₂.
var twistGen = &twistPoint{
	gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	},
	gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	},
	gfP2{*newGFp(0), *newGFp(1)},
	gfP2{*newGFp(0), *newGFp(1)},
}

func (c *twistPoint) String() string {
	c.MakeAffine()
	x, y := gfP2Decode(&c.x), gfP2Decode(&c.y)
	return "(" + x.String() + ", " + y.String() + ")"
}

func (c *twistPoint) Set(a *twistPoint) {
	c.x.Set(&a.x)
	c.y.Set(&a.y)
	c.z.Set(&a.z)
	c.t.Set(&a.t)
}

func NewTwistPoint() *twistPoint {
	c := &twistPoint{}
	c.SetInfinity()
	return c
}

func NewTwistGenerator() *twistPoint {
	c := &twistPoint{}
	c.Set(twistGen)
	return c
}

func (c *twistPoint) polynomial(x *gfP2) *gfP2 {
	x3 := &gfP2{}
	x3.Square(x).Mul(x3, x).Add(x3, twistB)
	return x3
}

// IsOnCurve returns true iff c is on the curve.
func (c *twistPoint) IsOnCurve() bool {
	c.MakeAffine()
	if c.IsInfinity() {
		return true
	}

	y2 := &gfP2{}
	y2.Square(&c.y)
	x3 := c.polynomial(&c.x)

	return y2.Equal(x3) == 1
}

func (c *twistPoint) SetInfinity() {
	c.x.SetZero()
	c.y.SetOne()
	c.z.SetZero()
	c.t.SetZero()
}

func (c *twistPoint) IsInfinity() bool {
	return c.z.IsZero()
}

func (c *twistPoint) Add(p1, p2 *twistPoint) {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §3.2.
	// Algorithm 7: Complete, projective point addition for prime order j-invariant 0 short Weierstrass curves.

	t0, t1, t2, t3, t4 := new(gfP2), new(gfP2), new(gfP2), new(gfP2), new(gfP2)
	x3, y3, z3 := new(gfP2), new(gfP2), new(gfP2)
	t0.Mul(&p1.x, &p2.x)    // t0 := X1X2
	t1.Mul(&p1.y, &p2.y)    // t1 := Y1Y2
	t2.Mul(&p1.z, &p2.z)    // t2 := Z1Z2
	t3.Add(&p1.x, &p1.y)    // t3 := X1 + Y1
	t4.Add(&p2.x, &p2.y)    // t4 := X2 + Y2
	t3.Mul(t3, t4)          // t3 := t3 * t4 = (X1 + Y1) * (X2 + Y2)
	t4.Add(t0, t1)          // t4 := t0 + t1
	t3.Sub(t3, t4)          // t3 := t3 - t4 = X1Y2 + X2Y1
	t4.Add(&p1.y, &p1.z)    // t4 := Y1 + Z1
	x3.Add(&p2.y, &p2.z)    // X3 := Y2 + Z2
	t4.Mul(t4, x3)          // t4 := t4 * X3 = (Y1 + Z1)(Y2 + Z2)
	x3.Add(t1, t2)          // X3 := t1 + t2
	t4.Sub(t4, x3)          // t4 := t4 - X3 = Y1Z2 + Y2Z1
	x3.Add(&p1.x, &p1.z)    // X3 := X1 + Z1
	y3.Add(&p2.x, &p2.z)    // Y3 := X2 + Z2
	x3.Mul(x3, y3)          // X3 := X3 * Y3
	y3.Add(t0, t2)          // Y3 := t0 + t2
	y3.Sub(x3, y3)          // Y3 := X3 - Y3 = X1Z2 + X2Z1
	t0.Triple(t0)           // t0 := t0 + t0 + t0 = 3X1X2
	t2.Mul(threeTwistB, t2) // t2 := 3b * t2 = 3bZ1Z2
	z3.Add(t1, t2)          // Z3 := t1 + t2 = Y1Y2 + 3bZ1Z2
	t1.Sub(t1, t2)          // t1 := t1 - t2 = Y1Y2 - 3bZ1Z2
	y3.Mul(threeTwistB, y3) // Y3 = 3b * Y3 = 3b(X1Z2 + X2Z1)
	x3.Mul(t4, y3)          // X3 := t4 * Y3 = 3b(X1Z2 + X2Z1)(Y1Z2 + Y2Z1)
	t2.Mul(t3, t1)          // t2 := t3 * t1 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2)
	x3.Sub(t2, x3)          // X3 := t2 - X3 = (X1Y2 + X2Y1)(Y1Y2 - 3bZ1Z2) - 3b(Y1Z2 + Y2Z1)(X1Z2 + X2Z1)
	y3.Mul(y3, t0)          // Y3 := Y3 * t0 = 9bX1X2(X1Z2 + X2Z1)
	t1.Mul(t1, z3)          // t1 := t1 * Z3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2)
	y3.Add(t1, y3)          // Y3 := t1 + Y3 = (Y1Y2 + 3bZ1Z2)(Y1Y2 - 3bZ1Z2) + 9bX1X2(X1Z2 + X2Z1)
	t0.Mul(t0, t3)          // t0 := t0 * t3 = 3X1X2(X1Y2 + X2Y1)
	z3.Mul(z3, t4)          // Z3 := Z3 * t4 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2)
	z3.Add(z3, t0)          // Z3 := Z3 + t0 = (Y1Z2 + Y2Z1)(Y1Y2 + 3bZ1Z2) + 3X1X2(X1Y2 + X2Y1)

	c.x.Set(x3)
	c.y.Set(y3)
	c.z.Set(z3)
}

func (c *twistPoint) Double(p *twistPoint) {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §3.2.
	// Algorithm 9: Exception-free point doubling for prime order j-invariant 0 short Weierstrass curves.
	t0, t1, t2 := new(gfP2), new(gfP2), new(gfP2)
	x3, y3, z3 := new(gfP2), new(gfP2), new(gfP2)

	t0.Square(&p.y)         // t0 := Y^2
	z3.Double(t0)           // Z3 := t0 + t0
	z3.Double(z3)           // Z3 := Z3 + Z3
	z3.Double(z3)           // Z3 := Z3 + Z3
	t1.Mul(&p.y, &p.z)      // t1 := YZ
	t2.Square(&p.z)         // t2 := Z^2
	t2.Mul(threeTwistB, t2) // t2 := 3b * t2 = 3bZ^2
	x3.Mul(t2, z3)          // X3 := t2 * Z3
	y3.Add(t0, t2)          // Y3 := t0 + t2
	z3.Mul(t1, z3)          // Z3 := t1 * Z3
	t2.Triple(t2)           // t2 := t2 + t2 + t2
	t0.Sub(t0, t2)          // t0 := t0 - t2
	y3.Mul(t0, y3)          // Y3 := t0 * Y3
	y3.Add(x3, y3)          // Y3 := X3 + Y3
	t1.Mul(&p.x, &p.y)      // t1 := XY
	x3.Mul(t0, t1)          // X3 := t0 * t1
	x3.Double(x3)           // X3 := X3 + X3

	c.x.Set(x3)
	c.y.Set(y3)
	c.z.Set(z3)
}

func (c *twistPoint) Mul(a *twistPoint, scalar *big.Int) {
	sum, t := &twistPoint{}, &twistPoint{}

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

// MakeAffine reverses the Projective transform.
// A = 1/Z1
// X3 = A*X1
// Y3 = A*Y1
// Z3 = 1
func (c *twistPoint) MakeAffine() {
	// TODO: do we need to change it to constant-time implementation?
	if c.z.IsOne() {
		return
	} else if c.z.IsZero() {
		c.x.SetZero()
		c.y.SetOne()
		c.t.SetZero()
		return
	}

	zInv := &gfP2{}
	zInv.Invert(&c.z)

	c.x.Mul(&c.x, zInv)
	c.y.Mul(&c.y, zInv)

	c.z.SetOne()
	c.t.SetOne()
}

// MakeAffine reverses the Jacobian transform.
// the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³.
func (c *twistPoint) AffineFromJacobian() {
	if c.z.IsOne() {
		return
	} else if c.z.IsZero() {
		c.x.SetZero()
		c.y.SetOne()
		c.t.SetZero()
		return
	}

	zInv := (&gfP2{}).Invert(&c.z)
	t := (&gfP2{}).Mul(&c.y, zInv)
	zInv2 := (&gfP2{}).Square(zInv)
	c.y.Mul(t, zInv2)
	t.Mul(&c.x, zInv2)
	c.x.Set(t)
	c.z.SetOne()
	c.t.SetOne()
}

func (c *twistPoint) Neg(a *twistPoint) {
	c.x.Set(&a.x)
	c.y.Neg(&a.y)
	c.z.Set(&a.z)
	c.t.SetZero()
}

// code logic is form https://github.com/guanzhi/GmSSL/blob/develop/src/sm9_alg.c
// the value is not same as [p]a
func (c *twistPoint) Frobenius(a *twistPoint) {
	c.x.Conjugate(&a.x)
	c.y.Conjugate(&a.y)
	c.z.Conjugate(&a.z)
	c.z.MulScalar(&a.z, frobConstant)
	c.t.Square(&a.z)
}

func (c *twistPoint) FrobeniusP2(a *twistPoint) {
	c.x.Set(&a.x)
	c.y.Set(&a.y)
	c.z.MulScalar(&a.z, wToP2Minus1)
	c.t.Square(&a.z)
}

func (c *twistPoint) NegFrobeniusP2(a *twistPoint) {
	c.x.Set(&a.x)
	c.y.Neg(&a.y)
	c.z.MulScalar(&a.z, wToP2Minus1)
	c.t.Square(&a.z)
}

// A twistPointTable holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type twistPointTable [15]*twistPoint

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *twistPointTable) Select(p *twistPoint, n uint8) {
	if n >= 16 {
		panic("sm9: internal error: twistPointTable called with out-of-bounds value")
	}
	p.SetInfinity()
	for i, f := range table {
		cond := subtle.ConstantTimeByteEq(uint8(i+1), n)
		twistPointMovCond(p, f, p, cond)
	}
}

/*
//code logic is from https://github.com/miracl/MIRACL/blob/master/source/curve/pairing/bn_pair.cpp
func (c *twistPoint) Frobenius(a *twistPoint) {
	w, r, frob := &gfP2{}, &gfP2{}, &gfP2{}
	frob.SetFrobConstant()
	w.Square(frob)

	r.Conjugate(&twistGen.x)
	r.Mul(r, w)
	c.x.Set(r)

	r.Conjugate(&twistGen.y)
	r.Mul(r, frob)
	r.Mul(r, w)
	c.y.Set(r)

	r.Conjugate(&twistGen.z)
	c.z.Set(r)

	r.Square(&c.z)
	c.t.Set(r)
}

func (c *twistPoint) FrobeniusP2(a *twistPoint) {
	ret := &twistPoint{}
	ret.Frobenius(a)
	c.Frobenius(ret)
}

*/
/*
// code logic from https://github.com/cloudflare/bn256/blob/master/optate.go
func (c *twistPoint) Frobenius(a *twistPoint) {
	r := &gfP2{}
	r.Conjugate(&a.x)
	r.MulScalar(r, xiToPMinus1Over3)
	c.x.Set(r)
	r.Conjugate(&a.y)
	r.MulScalar(r, xiToPMinus1Over2)
	c.y.Set(r)
	c.z.SetOne()
	c.t.SetOne()
}

func (c *twistPoint) FrobeniusP2(a *twistPoint) {
	c.x.MulScalar(&a.x, xiToPSquaredMinus1Over3)
	c.y.Neg(&a.y)
	c.z.SetOne()
	c.t.SetOne()
}

func (c *twistPoint) NegFrobeniusP2(a *twistPoint) {
	c.x.MulScalar(&a.x, xiToPSquaredMinus1Over3)
	c.y.Set(&a.y)
	c.z.SetOne()
	c.t.SetOne()
}
*/
