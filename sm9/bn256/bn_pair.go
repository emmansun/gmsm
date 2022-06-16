package bn256

import (
	"math/big"
)

func lineFunctionAdd(r, p *twistPoint, q *curvePoint, r2 *gfP2) (a, b, c, d *gfP2, rOut *twistPoint) {
	// See the mixed addition algorithm from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	B := (&gfP2{}).Mul(&p.x, &r.t) // B = Xp * Zr^2

	d = (&gfP2{}).Mul(B, &r.z) // d =  Xp * Zr^3
	D := (&gfP2{}).Mul(&r.z, &r.x)
	d.Sub(D, d) // d = Xr*Zr - Xp * Zr^3

	D = (&gfP2{}).Add(&p.y, &r.z)                    // D = Yp + Zr
	D.Square(D).Sub(D, r2).Sub(D, &r.t).Mul(D, &r.t) // D = ((Yp + Zr)^2 - Zr^2 - Yp^2)*Zr^2 = 2Yp*Zr^3

	H := (&gfP2{}).Sub(B, &r.x) // H = Xp * Zr^2 - Xr
	I := (&gfP2{}).Square(H)    // I = (Xp * Zr^2 - Xr)^2 = Xp^2*Zr^4 + Xr^2 - 2Xr*Xp*Zr^2

	E := (&gfP2{}).Add(I, I) // E = 2*(Xp * Zr^2 - Xr)^2
	E.Add(E, E)              // E = 4*(Xp * Zr^2 - Xr)^2

	J := (&gfP2{}).Mul(H, E) // J =  4*(Xp * Zr^2 - Xr)^3

	L1 := (&gfP2{}).Sub(D, &r.y) // L1 = 2Yp*Zr^3 - Yr
	L1.Sub(L1, &r.y)             // L1 = 2Yp*Zr^3 - 2*Yr

	V := (&gfP2{}).Mul(&r.x, E) // V = 4 * Xr * (Xp * Zr^2 - Xr)^2

	rOut = &twistPoint{}
	rOut.x.Square(L1).Sub(&rOut.x, J).Sub(&rOut.x, V).Sub(&rOut.x, V) // rOut.x = L1^2 - J - 2V

	rOut.z.Add(&r.z, H).Square(&rOut.z).Sub(&rOut.z, &r.t).Sub(&rOut.z, I) // rOut.z = (Zr + H)^2 - Zr^2 - I

	t := (&gfP2{}).Sub(V, &rOut.x) // t = V - rOut.x
	t.Mul(t, L1)                   // t = L1*(V-rOut.x)
	t2 := (&gfP2{}).Mul(&r.y, J)
	t2.Add(t2, t2)    // t2 = 2Yr * J
	rOut.y.Sub(t, t2) // rOut.y = L1*(V-rOut.x) - 2Yr*J

	rOut.t.Square(&rOut.z)

	t.Add(&p.y, &rOut.z).Square(t).Sub(t, r2).Sub(t, &rOut.t) // t = (Yp + rOut.Z)^2 - Yp^2 - rOut.Z^2 = 2Yp*rOut.Z

	t2.Mul(L1, &p.x)
	t2.Add(t2, t2)           // t2 = 2 L1 * Xp
	a = (&gfP2{}).Sub(t2, t) // a =  2 L1 * Xp - 2 Yp * rOut.z

	c = (&gfP2{}).MulScalar(&rOut.z, &q.y)
	c.Add(c, c)

	b = (&gfP2{}).Neg(L1)
	b.MulScalar(b, &q.x).Add(b, b)

	return
}

func lineFunctionDouble(r *twistPoint, q *curvePoint) (a, b, c, d *gfP2, rOut *twistPoint) {
	// See the doubling algorithm for a=0 from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	A := (&gfP2{}).Square(&r.x)
	B := (&gfP2{}).Square(&r.y)
	C := (&gfP2{}).Square(B) // C = Yr ^ 4

	D := (&gfP2{}).Add(&r.x, B)
	D.Square(D).Sub(D, A).Sub(D, C).Add(D, D)

	E := (&gfP2{}).Add(A, A) //
	E.Add(E, A)              // E = 3 * Xr ^ 2

	G := (&gfP2{}).Square(E) // G = 9 * Xr^4

	rOut = &twistPoint{}
	rOut.x.Sub(G, D).Sub(&rOut.x, D)

	rOut.z.Add(&r.y, &r.z).Square(&rOut.z).Sub(&rOut.z, B).Sub(&rOut.z, &r.t) // Z3 = (Yr + Zr)^2 - Yr^2 - Zr^2 = 2Yr*Zr

	rOut.y.Sub(D, &rOut.x).Mul(&rOut.y, E)
	t := (&gfP2{}).Add(C, C) // t = 2 * r.y ^ 4
	t.Add(t, t).Add(t, t)    // t = 8 * Yr ^ 4
	rOut.y.Sub(&rOut.y, t)

	rOut.t.Square(&rOut.z)

	d = (&gfP2{}).Mul(&rOut.z, &rOut.t) // d = 2Yr*Zr^3

	t.Mul(E, &r.t).Add(t, t)
	b = (&gfP2{}).Neg(t)
	b.MulScalar(b, &q.x)

	a = (&gfP2{}).Add(&r.x, E)
	a.Square(a).Sub(a, A).Sub(a, G)
	t.Add(B, B).Add(t, t)
	a.Sub(a, t)

	c = (&gfP2{}).Mul(&rOut.z, &r.t)
	c.Add(c, c).MulScalar(c, &q.y)

	return
}

func mulLine(ret *gfP12, retDen *gfP4, a, b, c, d *gfP2) {
	l := &gfP12{}
	l.y.SetZero()
	l.x.x.SetZero()
	l.x.y.Set(b)
	l.z.x.Set(c)
	l.z.y.Set(a)

	ret.Mul(ret, l)

	lDen := &gfP4{}
	lDen.x.Set(d)
	lDen.y.SetZero()
	retDen.Mul(retDen, lDen)
}

//
// R-ate Pairing G2 x G1 -> GT
//
// P is a point of order q in G1. Q(x,y) is a point of order q in G2.
// Note that Q is a point on the sextic twist of the curve over Fp^2, P(x,y) is a point on the
// curve over the base field Fp
//
func miller(q *twistPoint, p *curvePoint) *gfP12 {
	ret := (&gfP12{}).SetOne()
	retDen := (&gfP4{}).SetOne() // denominator

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

	for i := len(sixUPlus2NAF) - 1; i > 0; i-- {
		a, b, c, d, newR := lineFunctionDouble(r, bAffine)
		if i != len(sixUPlus2NAF)-1 {
			ret.Square(ret)
			retDen.Square(retDen)
		}
		mulLine(ret, retDen, a, b, c, d)
		r = newR
		switch sixUPlus2NAF[i-1] {
		case 1:
			a, b, c, d, newR = lineFunctionAdd(r, aAffine, bAffine, r2)
		case -1:
			a, b, c, d, newR = lineFunctionAdd(r, minusA, bAffine, r2)
		default:
			continue
		}

		mulLine(ret, retDen, a, b, c, d)
		r = newR
	}
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
	a, b, c, d, newR := lineFunctionAdd(r, q1, bAffine, r2)
	mulLine(ret, retDen, a, b, c, d)
	r = newR

	r2.Square(&minusQ2.y)
	a, b, c, d, _ = lineFunctionAdd(r, minusQ2, bAffine, r2)
	mulLine(ret, retDen, a, b, c, d)

	retDen.Invert(retDen)
	ret.MulScalar(ret, retDen)

	return ret
}

func finalExponentiationHardPart(in *gfP12) *gfP12 {
	a, b, t0, t1 := &gfP12{}, &gfP12{}, &gfP12{}, &gfP12{}

	a.Exp(in, sixUPlus5)
	a.Invert(a)
	b.Frobenius(a)
	b.Mul(a, b) // b = ab

	a.Mul(a, b)
	t0.Frobenius(in)
	t1.Mul(t0, in) // t1 = in ^(p+1)
	t1.Exp(t1, big.NewInt(9))
	a.Mul(a, t1)

	t1.Square(in)
	t1.Square(t1)
	a.Mul(a, t1)

	t0.Square(t0) // (in^p)^2
	t0.Mul(t0, b) // b*(in^p)^2
	b.FrobeniusP2(in)
	t0.Mul(b, t0) // b*(in^p)^2 * in^(p^2)
	t0.Exp(t0, sixU2Plus1)
	a.Mul(a, t0)

	b.FrobeniusP3(in)
	b.Mul(a, b)
	return b
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT. https://eprint.iacr.org/2007/390.pdf
func finalExponentiation(in *gfP12) *gfP12 {
	t0, t1 := &gfP12{}, &gfP12{}

	t0.FrobeniusP6(in)
	t1.Invert(in)
	t0.Mul(t0, t1)
	t1.FrobeniusP2(t0)
	t0.Mul(t0, t1)

	return finalExponentiationHardPart(t0)
}

func pairing(a *twistPoint, b *curvePoint) *gfP12 {
	e := miller(a, b)
	ret := finalExponentiation(e)

	if a.IsInfinity() || b.IsInfinity() {
		ret.SetOne()
	}
	return ret
}
