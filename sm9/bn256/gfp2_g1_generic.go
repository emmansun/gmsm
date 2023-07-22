//go:build (!amd64) || purego
// +build !amd64 purego

package bn256

func gfp2Mul(c, a, b *gfP2) {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	v0, v1 := &gfP{}, &gfP{}

	gfpMul(v0, &a.y, &b.y)
	gfpMul(v1, &a.x, &b.x)

	gfpAdd(tx, &a.x, &a.y)
	gfpAdd(ty, &b.x, &b.y)
	gfpMul(tx, tx, ty)
	gfpSub(tx, tx, v0)
	gfpSub(tx, tx, v1)

	gfpSub(ty, v0, v1)
	gfpSub(ty, ty, v1)

	gfp2Copy(c, tmp)
}

func gfp2MulU(c, a, b *gfP2) {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y
	v0, v1 := &gfP{}, &gfP{}

	gfpMul(v0, &a.y, &b.y)
	gfpMul(v1, &a.x, &b.x)

	gfpAdd(tx, &a.x, &a.y)
	gfpAdd(ty, &b.x, &b.y)

	gfpMul(ty, tx, ty)
	gfpSub(ty, ty, v0)
	gfpSub(ty, ty, v1)
	gfpDouble(ty, ty)
	gfpNeg(ty, ty)

	gfpSub(tx, v0, v1)
	gfpSub(tx, tx, v1)

	gfp2Copy(c, tmp)
}

func gfp2Square(c, a *gfP2) {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y

	gfpAdd(ty, &a.x, &a.y)
	gfpDouble(tx, &a.x)
	gfpSub(tx, &a.y, tx)
	gfpMul(ty, tx, ty)
	gfpMul(tx, &a.x, &a.y)
	gfpAdd(ty, tx, ty)
	gfpDouble(tx, tx)

	gfp2Copy(c, tmp)
}

func gfp2SquareU(c, a *gfP2) {
	tmp := &gfP2{}
	tx := &tmp.x
	ty := &tmp.y

	gfpAdd(tx, &a.x, &a.y)
	gfpDouble(ty, &a.x)
	gfpSub(ty, &a.y, ty)
	gfpMul(tx, tx, ty)
	gfpMul(ty, &a.x, &a.y)
	gfpAdd(tx, tx, ty)
	gfpDouble(ty, ty)
	gfpDouble(ty, ty)
	gfpNeg(ty, ty)

	gfp2Copy(c, tmp)
}

func curvePointDoubleComplete(c, p *curvePoint) {
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
	gfpSqr(t2, &p.z, 1)         // t2 := Z^2
	gfpMul(t2, threeCurveB, t2) // t2 := 3b * t2 = 3bZ^2
	gfpMul(x3, t2, z3)          // X3 := t2 * Z3
	gfpAdd(y3, t0, t2)          // Y3 := t0 + t2
	gfpMul(z3, t1, z3)          // Z3 := t1 * Z3
	gfpTriple(t2, t2)           // t2 := t2 + t2 + t2
	gfpSub(t0, t0, t2)          // t0 := t0 - t2
	gfpMul(y3, t0, y3)          // Y3 := t0 * Y3
	gfpAdd(y3, x3, y3)          // Y3 := X3 + Y3
	gfpMul(t1, &p.x, &p.y)      // t1 := XY
	gfpMul(x3, t0, t1)          // X3 := t0 * t1
	gfpDouble(x3, x3)           // X3 := X3 + X3

	c.x.Set(x3)
	c.y.Set(y3)
	c.z.Set(z3)
}
