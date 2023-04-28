package bn256

func pairingB6(a *twistPoint, b *curvePoint) *gfP12 {
	e := miller(a, b)
	eb6 := (&gfP12b6{}).SetGfP12(e)
	ret := finalExponentiationB6(eb6)

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

	t2 := (&gfP12b6{}).FrobeniusP2(t1)
	t1.Mul(t1, t2)

	fp := (&gfP12b6{}).Frobenius(t1)
	fp2 := (&gfP12b6{}).FrobeniusP2(t1)
	fp3 := (&gfP12b6{}).Frobenius(fp2)

	fu := (&gfP12b6{}).Exp(t1, u)
	fu2 := (&gfP12b6{}).Exp(fu, u)
	fu3 := (&gfP12b6{}).Exp(fu2, u)

	y3 := (&gfP12b6{}).Frobenius(fu)
	fu2p := (&gfP12b6{}).Frobenius(fu2)
	fu3p := (&gfP12b6{}).Frobenius(fu3)
	y2 := (&gfP12b6{}).FrobeniusP2(fu2)

	y0 := &gfP12b6{}
	y0.Mul(fp, fp2).Mul(y0, fp3)

	y1 := (&gfP12b6{}).Conjugate(t1)
	y5 := (&gfP12b6{}).Conjugate(fu2)
	y3.Conjugate(y3)
	y4 := (&gfP12b6{}).Mul(fu, fu2p)
	y4.Conjugate(y4)

	y6 := (&gfP12b6{}).Mul(fu3, fu3p)
	y6.Conjugate(y6)

	t0 := (&gfP12b6{}).Square(y6)
	t0.Mul(t0, y4).Mul(t0, y5)
	t1.Mul(y3, y5).Mul(t1, t0)
	t0.Mul(t0, y2)
	t1.Square(t1).Mul(t1, t0).Square(t1)
	t0.Mul(t1, y1)
	t1.Mul(t1, y0)
	t0.Square(t0).Mul(t0, t1)

	return t0
}
