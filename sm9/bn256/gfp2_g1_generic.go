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
