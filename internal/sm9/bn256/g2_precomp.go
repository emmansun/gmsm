package bn256

// g2LineEval stores precomputed line function evaluation coefficients for a fixed G2 point.
// For each step of the Miller loop:
//   - a is fully evaluated (depends only on G2 twist point coordinates)
//   - b is the G2-dependent factor of the b coefficient; scale by P.x at pairing time
//   - c is the G2-dependent factor of the c coefficient; scale by P.y at pairing time
//
// At pairing time: b_final = b * P.x, c_final = c * P.y, then call mulLine(ret, a, b_final, c_final).
type g2LineEval struct {
	a, b, c gfP2
}

// G2Precomputed holds precomputed Miller loop line evaluations for a fixed G2 twist point.
// It can be used with PairPrecomp to compute pairings faster when the G2 point (e.g., a
// public key) is fixed across multiple pairings.
//
// The 77 entries correspond to:
//   - 65 doubling steps (one per bit of the NAF representation of 6u+2)
//   - 10 addition steps within the NAF loop (for nonzero NAF digits)
//   - 2 post-loop addition steps (Frobenius endomorphism corrections)
type G2Precomputed [77]g2LineEval

// Precompute computes the Miller loop line function coefficients for this G2 point.
// The result can be passed to PairPrecomp for repeated pairings with different G1 points.
func (g *G2) Precompute() *G2Precomputed {
	return PrecomputeG2(g.p)
}

// PrecomputeG2 computes line function coefficients for all steps of the R-ate Miller loop
// for a fixed G2 twist point q. The result can be used with MillerWithPrecomp and PairPrecomp.
func PrecomputeG2(q *twistPoint) *G2Precomputed {
	precomp := new(G2Precomputed)
	idx := 0

	aAffine := &twistPoint{}
	aAffine.Set(q)
	aAffine.MakeAffine()

	minusA := &twistPoint{}
	minusA.Neg(aAffine)

	r := &twistPoint{}
	r.Set(aAffine)

	r2 := (&gfP2{}).Square(&aAffine.y)

	newR := &twistPoint{}
	var tmpR *twistPoint

	for i := len(sixUPlus2NAF) - 1; i > 0; i-- {
		lineFunctionDoublePrecomp(r, newR, &precomp[idx])
		idx++
		tmpR = r
		r = newR
		newR = tmpR

		switch sixUPlus2NAF[i-1] {
		case 1:
			lineFunctionAddPrecomp(r, aAffine, newR, r2, &precomp[idx])
			idx++
			tmpR = r
			r = newR
			newR = tmpR
		case -1:
			lineFunctionAddPrecomp(r, minusA, newR, r2, &precomp[idx])
			idx++
			tmpR = r
			r = newR
			newR = tmpR
		}
	}

	// Post-loop Frobenius endomorphism correction steps, matching miller().
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
	lineFunctionAddPrecomp(r, q1, newR, r2, &precomp[idx])
	idx++
	tmpR = r
	r = newR
	newR = tmpR

	r2.Square(&minusQ2.y)
	lineFunctionAddPrecomp(r, minusQ2, newR, r2, &precomp[idx])

	return precomp
}

// lineFunctionDoublePrecomp is the precomputation variant of lineFunctionDouble.
// It evolves the twist point r → rOut (same as lineFunctionDouble) but instead of
// applying G1 scaling, it stores the G2-only factors in out:
//   out.b = -2*E*r.t    (scale by P.x at pairing time to get b_final)
//   out.c = 2*rOut.z*r.t (scale by P.y at pairing time to get c_final)
//   out.a = a            (fully computed, no G1 dependence)
func lineFunctionDoublePrecomp(r, rOut *twistPoint, out *g2LineEval) {
	// See the doubling algorithm for a=0 from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	A := (&gfP2{}).Square(&r.x)
	B := (&gfP2{}).Square(&r.y)
	C := (&gfP2{}).Square(B)

	D := (&gfP2{}).Add(&r.x, B)
	D.Square(D).Sub(D, A).Sub(D, C).Double(D)

	E := (&gfP2{}).Double(A)
	E.Add(E, A) // E = 3 * Xr^2

	G := (&gfP2{}).Square(E)

	rOut.x.Sub(G, D).Sub(&rOut.x, D)

	rOut.z.Add(&r.y, &r.z).Square(&rOut.z).Sub(&rOut.z, B).Sub(&rOut.z, &r.t)

	rOut.y.Sub(D, &rOut.x).Mul(&rOut.y, E)
	t := (&gfP2{}).Double(C)
	t.Double(t).Double(t) // t = 8*C
	rOut.y.Sub(&rOut.y, t)

	rOut.t.Square(&rOut.z)

	t.Mul(E, &r.t).Double(t) // t = 2*E*r.t
	out.b.Neg(t)             // b_coeff = -2*E*r.t

	out.a.Add(&r.x, E)
	out.a.Square(&out.a).Sub(&out.a, A).Sub(&out.a, G)
	t.Double(B).Double(t) // t = 4B
	out.a.Sub(&out.a, t)

	// c_coeff = 2*rOut.z*r.t (uses old r.t, not rOut.t)
	out.c.Mul(&rOut.z, &r.t)
	out.c.Double(&out.c)
}

// lineFunctionAddPrecomp is the precomputation variant of lineFunctionAdd.
// It evolves the twist point r → rOut and stores the G2-only factors in out:
//   out.b = -2*L1     (scale by P.x at pairing time to get b_final)
//   out.c = 2*rOut.z  (scale by P.y at pairing time to get c_final)
//   out.a = a         (fully computed, no G1 dependence)
func lineFunctionAddPrecomp(r, p, rOut *twistPoint, r2 *gfP2, out *g2LineEval) {
	// See the mixed addition algorithm from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	B := (&gfP2{}).Mul(&p.x, &r.t)

	D := (&gfP2{}).Add(&p.y, &r.z)
	D.Square(D).Sub(D, r2).Sub(D, &r.t).Mul(D, &r.t)

	H := (&gfP2{}).Sub(B, &r.x)
	I := (&gfP2{}).Square(H)

	E := (&gfP2{}).Double(I)
	E.Double(E)

	J := (&gfP2{}).Mul(H, E)

	L1 := (&gfP2{}).Sub(D, &r.y)
	L1.Sub(L1, &r.y)

	V := (&gfP2{}).Mul(&r.x, E)

	rOut.x.Square(L1).Sub(&rOut.x, J).Sub(&rOut.x, V).Sub(&rOut.x, V)

	rOut.z.Add(&r.z, H).Square(&rOut.z).Sub(&rOut.z, &r.t).Sub(&rOut.z, I)

	t := (&gfP2{}).Sub(V, &rOut.x)
	t.Mul(t, L1)
	t2 := (&gfP2{}).Mul(&r.y, J)
	t2.Double(t2)
	rOut.y.Sub(t, t2)

	rOut.t.Square(&rOut.z)

	// t = 2*Yp*rOut.z (G2 twist point p's y-coordinate, not G1)
	t.Add(&p.y, &rOut.z).Square(t).Sub(t, r2).Sub(t, &rOut.t)

	t2.Mul(L1, &p.x)
	t2.Double(t2)    // t2 = 2*L1*Xp (G2 coords, Fp2)
	out.a.Sub(t2, t) // a = 2*L1*Xp - 2*Yp*rOut.z

	// c_coeff = 2*rOut.z; online: c = c_coeff * P.y
	out.c.Set(&rOut.z)
	out.c.Double(&out.c)

	// b_coeff = -2*L1; online: b = b_coeff * P.x
	out.b.Neg(L1)
	out.b.Double(&out.b)
}

// millerWithPrecomp computes the Miller loop using precomputed G2 line coefficients.
// For each line evaluation, it applies only 2 gfP2×gfP MulScalar operations (for
// the G1 point coordinates) and then calls mulLine, replacing all G2 point arithmetic.
func millerWithPrecomp(precomp *G2Precomputed, p *curvePoint) *gfP12 {
	ret := (&gfP12{}).SetOne()

	bAffine := &curvePoint{}
	bAffine.Set(p)
	bAffine.MakeAffine()

	b, c := &gfP2{}, &gfP2{}
	idx := 0

	for i := len(sixUPlus2NAF) - 1; i > 0; i-- {
		if i != len(sixUPlus2NAF)-1 {
			ret.Square(ret)
		}

		line := &(*precomp)[idx]
		b.MulScalar(&line.b, &bAffine.x)
		c.MulScalar(&line.c, &bAffine.y)
		mulLine(ret, &line.a, b, c)
		idx++

		switch sixUPlus2NAF[i-1] {
		case 1, -1:
			line = &(*precomp)[idx]
			b.MulScalar(&line.b, &bAffine.x)
			c.MulScalar(&line.c, &bAffine.y)
			mulLine(ret, &line.a, b, c)
			idx++
		}
	}

	// Post-loop: two Frobenius correction additions.
	line := &(*precomp)[idx]
	b.MulScalar(&line.b, &bAffine.x)
	c.MulScalar(&line.c, &bAffine.y)
	mulLine(ret, &line.a, b, c)
	idx++

	line = &(*precomp)[idx]
	b.MulScalar(&line.b, &bAffine.x)
	c.MulScalar(&line.c, &bAffine.y)
	mulLine(ret, &line.a, b, c)

	return ret
}

// MillerPrecomp applies the Miller loop using a precomputed G2 point, returning the
// intermediate result before final exponentiation. Call Finalize() on the result.
func MillerPrecomp(g1 *G1, precomp *G2Precomputed) *GT {
	return &GT{millerWithPrecomp(precomp, g1.p)}
}

// PairPrecomp calculates the R-Ate pairing e(g1, g2) using precomputed G2 line evaluations.
// It is equivalent to Pair but faster when the G2 point is fixed across multiple calls.
func PairPrecomp(g1 *G1, precomp *G2Precomputed) *GT {
	e := millerWithPrecomp(precomp, g1.p)
	ret := finalExponentiation(e)
	if g1.p.IsInfinity() {
		ret.SetOne()
	}
	return &GT{ret}
}
