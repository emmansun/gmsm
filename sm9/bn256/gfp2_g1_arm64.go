//go:build arm64 && !purego
// +build arm64,!purego

package bn256

// gfP2 multiplication.
//
//go:noescape
func gfp2Mul(c, a, b *gfP2)

// gfP2 multiplication. c = a*b*u
//
//go:noescape
func gfp2MulU(c, a, b *gfP2)

// gfP2 square.
//
//go:noescape
func gfp2Square(c, a *gfP2)

// gfP2 square and mult u.
//
//go:noescape
func gfp2SquareU(c, a *gfP2)

// Point doubling. Sets res = in + in. in can be the point at infinity.
//
//go:noescape
func curvePointDoubleComplete(c, a *curvePoint)

func curvePointAddComplete(c, p1, p2 *curvePoint) {
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
