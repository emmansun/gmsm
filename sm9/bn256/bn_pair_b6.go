package bn256

// (ret.x t + ret.y) * ((cs)t + (bs+a))
//= ((ret.x * (bs+a))+ret.y*cs) t + (ret.y*(bs+a) + ret.x*cs*s)
//= (ret.x*bs + ret.x*a + ret.y*cs) t + (ret.y*bs + ret.x*cs*s + ret.y * a)
//ret.x = (ret.x + ret.y)(cs + bs + a) - ret.y(bs+a) - ret.x*cs
//ret.y = ret.y(bs+a) + ret.x*cs *s
func mulLineB6(ret *gfP12b6, a, b, c *gfP2) {
	a2 := &gfP6{}
	a2.y.Set(b)
	a2.z.Set(a)
	a2.Mul(&ret.y, a2)
	t3 := &gfP6{}
	t3.MulScalar(&ret.x, c).MulS(t3)

	t := (&gfP2{}).Add(b, c)
	t2 := &gfP6{}
	t2.y.Set(t)
	t2.z.Set(a)
	ret.x.Add(&ret.x, &ret.y)

	ret.y.Set(t3)

	ret.x.Mul(&ret.x, t2).Sub(&ret.x, a2).Sub(&ret.x, &ret.y)

	ret.y.MulS(&ret.y)
	ret.y.Add(&ret.y, a2)
}

// R-ate Pairing G2 x G1 -> GT
//
// P is a point of order q in G1. Q(x,y) is a point of order q in G2.
// Note that Q is a point on the sextic twist of the curve over Fp^2, P(x,y) is a point on the
// curve over the base field Fp
//
func millerB6(q *twistPoint, p *curvePoint) *gfP12b6 {
	ret := (&gfP12b6{}).SetOne()

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

	r2 := (&gfP2{}).SquareNC(&aAffine.y)

	a, b, c := &gfP2{}, &gfP2{}, &gfP2{}
	newR := &twistPoint{}
	var tmpR *twistPoint
	for i := len(sixUPlus2NAF) - 1; i > 0; i-- {
		lineFunctionDouble(r, newR, bAffine, a, b, c)
		if i != len(sixUPlus2NAF)-1 {
			ret.Square(ret)
		}
		mulLineB6(ret, a, b, c)
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

		mulLineB6(ret, a, b, c)
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
	mulLineB6(ret, a, b, c)
	tmpR = r
	r = newR
	newR = tmpR

	r2.Square(&minusQ2.y)
	lineFunctionAdd(r, minusQ2, newR, bAffine, r2, a, b, c)
	mulLineB6(ret, a, b, c)

	return ret
}

func pairingB6(a *twistPoint, b *curvePoint) *gfP12 {
	e := millerB6(a, b)
	ret := finalExponentiationB6(e)

	if a.IsInfinity() || b.IsInfinity() {
		ret.SetOne()
	}
	return ret.ToGfP12()
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT. https://eprint.iacr.org/2007/390.pdf
// http://cryptojedi.org/papers/dclxvi-20100714.pdf
func finalExponentiationB6(in *gfP12b6) *gfP12b6 {
	t1 := &gfP12b6{}

	// This is the p^6-Frobenius
	t1.x.Neg(&in.x)
	t1.y.Set(&in.y)

	inv := &gfP12b6{}
	inv.Invert(in)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)

	fp := (&gfP12b6{}).Frobenius(t1)
	fp2 := (&gfP12b6{}).FrobeniusP2(t1)
	fp3 := (&gfP12b6{}).Frobenius(fp2)

	y0 := &gfP12b6{}
	y0.MulNC(fp, fp2).Mul(y0, fp3)

	// reuse fp, fp2, fp3 local variables
	fu := fp.Cyclo6PowToU(t1)
	fu2 := fp2.Cyclo6PowToU(fu)
	fu3 := fp3.Cyclo6PowToU(fu2)

	y3 := (&gfP12b6{}).Frobenius(fu)
	fu2p := (&gfP12b6{}).Frobenius(fu2)
	fu3p := (&gfP12b6{}).Frobenius(fu3)
	y2 := (&gfP12b6{}).FrobeniusP2(fu2)

	y1 := (&gfP12b6{}).Conjugate(t1)
	y5 := (&gfP12b6{}).Conjugate(fu2)
	y3.Conjugate(y3)
	y4 := (&gfP12b6{}).MulNC(fu, fu2p)
	y4.Conjugate(y4)

	y6 := (&gfP12b6{}).MulNC(fu3, fu3p)
	y6.Conjugate(y6)

	t0 := (&gfP12b6{}).Cyclo6SquareNC(y6)
	t0.Mul(t0, y4).Mul(t0, y5)
	t1.Mul(y3, y5).Mul(t1, t0)
	t0.Mul(t0, y2)
	t1.Cyclo6Square(t1).Mul(t1, t0).Cyclo6Square(t1)
	t0.Mul(t1, y1)
	t1.Mul(t1, y0)
	t0.Cyclo6Square(t0).Mul(t0, t1)

	return t0
}
