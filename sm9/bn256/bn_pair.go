// Package bn256 defines/implements ShangMi(SM) sm9's curves and pairing.
package bn256

func lineFunctionAdd(r, p, rOut *twistPoint, q *curvePoint, r2, a, b, c *gfP2) {
	// See the mixed addition algorithm from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	B := (&gfP2{}).Mul(&p.x, &r.t) // B = Xp * Zr^2

	D := (&gfP2{}).Add(&p.y, &r.z)                   // D = Yp + Zr
	D.Square(D).Sub(D, r2).Sub(D, &r.t).Mul(D, &r.t) // D = ((Yp + Zr)^2 - Zr^2 - Yp^2)*Zr^2 = 2Yp*Zr^3

	H := (&gfP2{}).Sub(B, &r.x) // H = Xp * Zr^2 - Xr
	I := (&gfP2{}).Square(H)  // I = (Xp * Zr^2 - Xr)^2 = Xp^2*Zr^4 + Xr^2 - 2Xr*Xp*Zr^2

	E := (&gfP2{}).Double(I) // E = 2*(Xp * Zr^2 - Xr)^2
	E.Double(E)              // E = 4*(Xp * Zr^2 - Xr)^2

	J := (&gfP2{}).Mul(H, E) // J =  4*(Xp * Zr^2 - Xr)^3

	L1 := (&gfP2{}).Sub(D, &r.y) // L1 = 2Yp*Zr^3 - Yr
	L1.Sub(L1, &r.y)             // L1 = 2Yp*Zr^3 - 2*Yr

	V := (&gfP2{}).Mul(&r.x, E) // V = 4 * Xr * (Xp * Zr^2 - Xr)^2

	rOut.x.Square(L1).Sub(&rOut.x, J).Sub(&rOut.x, V).Sub(&rOut.x, V) // rOut.x = L1^2 - J - 2V

	rOut.z.Add(&r.z, H).Square(&rOut.z).Sub(&rOut.z, &r.t).Sub(&rOut.z, I) // rOut.z = (Zr + H)^2 - Zr^2 - I

	t := (&gfP2{}).Sub(V, &rOut.x) // t = V - rOut.x
	t.Mul(t, L1)                   // t = L1*(V-rOut.x)
	t2 := (&gfP2{}).Mul(&r.y, J)
	t2.Double(t2)     // t2 = 2Yr * J
	rOut.y.Sub(t, t2) // rOut.y = L1*(V-rOut.x) - 2Yr*J

	rOut.t.Square(&rOut.z)

	// t = (Yp + rOut.Z)^2 - Yp^2 - rOut.Z^2 = 2Yp*rOut.Z
	t.Add(&p.y, &rOut.z).Square(t).Sub(t, r2).Sub(t, &rOut.t)

	t2.Mul(L1, &p.x)
	t2.Double(t2) // t2 = 2 L1 * Xp
	a.Sub(t2, t)  // a =  2 L1 * Xp - 2 Yp * rOut.z = 2 L1 * Xp - (Yp + rOut.Z)^2 + Yp^2 + rOut.Z^2

	c.MulScalar(&rOut.z, &q.y) // c = rOut.z * Yq
	c.Double(c)                // c = 2 * rOut.z * Yq

	b.Neg(L1)                      // b= -L1
	b.MulScalar(b, &q.x).Double(b) // b = -2 * L1 * Xq
}

func lineFunctionDouble(r, rOut *twistPoint, q *curvePoint, a, b, c *gfP2) {
	// See the doubling algorithm for a=0 from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	A := (&gfP2{}).Square(&r.x)
	B := (&gfP2{}).Square(&r.y)
	C := (&gfP2{}).Square(B) // C = Yr ^ 4

	D := (&gfP2{}).Add(&r.x, B)
	D.Square(D).Sub(D, A).Sub(D, C).Double(D)

	E := (&gfP2{}).Double(A) //
	E.Add(E, A)              // E = 3 * Xr ^ 2

	G := (&gfP2{}).Square(E) // G = 9 * Xr^4

	rOut.x.Sub(G, D).Sub(&rOut.x, D)

	rOut.z.Add(&r.y, &r.z).Square(&rOut.z).Sub(&rOut.z, B).Sub(&rOut.z, &r.t) // Z3 = (Yr + Zr)^2 - Yr^2 - Zr^2 = 2Yr*Zr

	rOut.y.Sub(D, &rOut.x).Mul(&rOut.y, E)
	t := (&gfP2{}).Double(C) // t = 2 * r.y ^ 4
	t.Double(t).Double(t)    // t = 8 * Yr ^ 4
	rOut.y.Sub(&rOut.y, t)

	rOut.t.Square(&rOut.z)

	t.Mul(E, &r.t).Double(t) // t = 2(E * Tr)
	b.Neg(t)                 // b = -2(E * Tr)
	b.MulScalar(b, &q.x)     // b = -2(E * Tr * Xq)

	a.Add(&r.x, E)                  // a = Xr + E
	a.Square(a).Sub(a, A).Sub(a, G) // a = (Xr + E) ^ 2 - A - G
	t.Double(B).Double(t)           // t = 4B
	a.Sub(a, t)                     // a = (Xr + E) ^ 2 - A - G - 4B

	c.Mul(&rOut.z, &r.t)           // c = rOut.z * Tr
	c.Double(c).MulScalar(c, &q.y) // c = 2 rOut.z * Tr * Yq
}

// (ret.z + ret.y*w + ret.x*w^2)* ((cv+a) + b*w^2)
func mulLine(ret *gfP12, a, b, c *gfP2) {
	tz, t := &gfP4{}, &gfP4{}
	tz.MulNC2(&ret.z, c, a)
	t.MulScalar(&ret.y, b).MulV1(t)
	tz.Add(tz, t)

	t.MulNC2(&ret.y, c, a)
	ret.y.MulScalar(&ret.x, b).MulV1(&ret.y)
	ret.y.Add(&ret.y, t)

	t.MulNC2(&ret.x, c, a)
	ret.x.MulScalar(&ret.z, b)
	ret.x.Add(&ret.x, t)

	gfp4Copy(&ret.z, tz)
}

// R-ate Pairing G2 x G1 -> GT
//
// P is a point of order q in G1. Q(x,y) is a point of order q in G2.
// Note that Q is a point on the sextic twist of the curve over Fp^2, P(x,y) is a point on the
// curve over the base field Fp
func miller(q *twistPoint, p *curvePoint) *gfP12 {
	ret := (&gfP12{}).SetOne()

	aAffine := &twistPoint{}
	aAffine.Set(q)
	aAffine.MakeAffine()

	minusA := &twistPoint{}
	minusA.Neg(aAffine)

	bAffine := &curvePoint{}
	bAffine.Set(p)
	bAffine.MakeAffine()

	r := &twistPoint{}
	r.Set(aAffine)

	r2 := (&gfP2{}).Square(&aAffine.y)

	a, b, c := &gfP2{}, &gfP2{}, &gfP2{}
	newR := &twistPoint{}
	var tmpR *twistPoint
	for i := len(sixUPlus2NAF) - 1; i > 0; i-- {
		lineFunctionDouble(r, newR, bAffine, a, b, c)
		if i != len(sixUPlus2NAF)-1 {
			ret.Square(ret)
		}
		mulLine(ret, a, b, c)
		tmpR = r
		r = newR
		newR = tmpR
		switch sixUPlus2NAF[i-1] {
		case 1:
			lineFunctionAdd(r, aAffine, newR, bAffine, r2, a, b, c)
		case -1:
			lineFunctionAdd(r, minusA, newR, bAffine, r2, a, b, c)
		default:
			continue
		}

		mulLine(ret, a, b, c)
		tmpR = r
		r = newR
		newR = tmpR
	}

	// In order to calculate Q1 we have to convert q from the sextic twist
	// to the full GF(p^12) group, apply the Frobenius there, and convert
	// back.
	//
	// The twist isomorphism is (x', y') -> (x*β^(-1/3), y*β^(-1/2)). If we consider just
	// x for a moment, then after applying the Frobenius, we have x̄*β^(-p/3)
	// where x̄ is the conjugate of x.	If we are going to apply the inverse
	// isomorphism we need a value with a single coefficient of β^(-1/3) so we
	// rewrite this as x̄*β^((-p+1)/3)*β^(-1/3).
	//
	// A similar argument can be made for the y value.
	q1 := &twistPoint{}
	q1.x.Conjugate(&aAffine.x)
	q1.x.MulScalar(&q1.x, betaToNegPPlus1Over3)
	q1.y.Conjugate(&aAffine.y)
	q1.y.MulScalar(&q1.y, betaToNegPPlus1Over2)
	q1.z.SetOne()
	q1.t.SetOne()

	minusQ2 := &twistPoint{}
	minusQ2.x.Set(&aAffine.x)
	minusQ2.x.MulScalar(&minusQ2.x, betaToNegP2Plus1Over3)
	minusQ2.y.Neg(&aAffine.y)
	minusQ2.y.MulScalar(&minusQ2.y, betaToNegP2Plus1Over2)
	minusQ2.z.SetOne()
	minusQ2.t.SetOne()

	r2.Square(&q1.y)
	lineFunctionAdd(r, q1, newR, bAffine, r2, a, b, c)
	mulLine(ret, a, b, c)
	tmpR = r
	r = newR
	newR = tmpR

	r2.Square(&minusQ2.y)
	lineFunctionAdd(r, minusQ2, newR, bAffine, r2, a, b, c)
	mulLine(ret, a, b, c)

	return ret
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT. https://eprint.iacr.org/2007/390.pdf
// http://cryptojedi.org/papers/dclxvi-20100714.pdf
func finalExponentiation(in *gfP12) *gfP12 {
	// This is the p^6-Frobenius
	t1 := (&gfP12{}).FrobeniusP6(in)

	inv := (&gfP12{}).Invert(in)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)            // t1 = in ^ ((p^6 - 1) * (p^2 + 1)), the first two parts of the exponentiation

	fp := (&gfP12{}).Frobenius(t1)
	fp2 := (&gfP12{}).FrobeniusP2(t1)
	fp3 := (&gfP12{}).Frobenius(fp2)

	y0 := &gfP12{}
	y0.MulNC(fp, fp2).Mul(y0, fp3) // y0 = (t1^p) * (t1^(p^2)) * (t1^(p^3))

	// reuse fp, fp2, fp3 local variables
	fu := fp.Cyclo6PowToU(t1)
	fu2 := fp2.Cyclo6PowToU(fu)
	fu3 := fp3.Cyclo6PowToU(fu2)

	fu2p := (&gfP12{}).Frobenius(fu2)
	fu3p := (&gfP12{}).Frobenius(fu3)

	y1 := (&gfP12{}).Conjugate(t1)    // y1 = 1 / t1
	y2 := (&gfP12{}).FrobeniusP2(fu2) // y2 = (t1^(u^2))^(p^2)
	y3 := (&gfP12{}).Frobenius(fu)    // y3 = (t1^u)^p
	y3.Conjugate(y3)                  // y3 = 1 / (t1^u)^p
	y4 := (&gfP12{}).MulNC(fu, fu2p)  // y4 = (t1^u) * ((t1^(u^2))^p)
	y4.Conjugate(y4)                  // y4 = 1 / ((t1^u) * ((t1^(u^2))^p))
	y5 := fu2p.Conjugate(fu2)         // y5 = 1 / t1^(u^2), reuse fu2p
	y6 := (&gfP12{}).MulNC(fu3, fu3p) // y6 = t1^(u^3) * (t1^(u^3))^p
	y6.Conjugate(y6)                  // y6 = 1 / (t1^(u^3) * (t1^(u^3))^p)

	// https://eprint.iacr.org/2008/490.pdf
	t0 := (&gfP12{}).Cyclo6SquareNC(y6)
	t0.Mul(t0, y4).Mul(t0, y5)
	t1.Mul(y3, y5).Mul(t1, t0)
	t0.Mul(t0, y2)
	t1.Cyclo6Square(t1).Mul(t1, t0).Cyclo6Square(t1)
	t0.Mul(t1, y1)
	t1.Mul(t1, y0)
	t0.Cyclo6Square(t0).Mul(t0, t1)

	return t0
}

func pairing(a *twistPoint, b *curvePoint) *gfP12 {
	e := miller(a, b)
	ret := finalExponentiation(e)

	if a.IsInfinity() || b.IsInfinity() {
		ret.SetOne()
	}
	return ret
}
