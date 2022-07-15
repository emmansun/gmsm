package bn256

import (
	"testing"
)

func TestIsOnCurve(t *testing.T) {
	if !twistGen.IsOnCurve() {
		t.Errorf("twist gen point should be on curve")
	}
	a := &twistPoint{}
	a.SetInfinity()
	if !a.IsOnCurve() {
		t.Errorf("infinity zero point should be on curve")
	}
}

func TestAddNeg(t *testing.T) {
	neg := &twistPoint{}
	neg.Neg(twistGen)
	res := &twistPoint{}
	res.Add(twistGen, neg)
	if !res.IsInfinity() {
		t.Errorf("a add its neg should be zero")
	}
}

func Test_TwistFrobeniusP(t *testing.T) {
	ret1, ret2 := &twistPoint{}, &twistPoint{}
	ret1.Frobenius(twistGen)
	ret1.MakeAffine()

	ret2.x.Conjugate(&twistGen.x)
	ret2.x.MulScalar(&ret2.x, betaToNegPPlus1Over3)

	ret2.y.Conjugate(&twistGen.y)
	ret2.y.MulScalar(&ret2.y, betaToNegPPlus1Over2)
	ret2.z.SetOne()
	ret2.t.SetOne()
	if !ret2.IsOnCurve() {
		t.Errorf("point should be on curve")
	}

	if ret1.x != ret2.x || ret1.y != ret2.y || ret1.z != ret2.z || ret1.t != ret2.t {
		t.Errorf("not same")
	}
}

func Test_TwistFrobeniusP2(t *testing.T) {
	ret1, ret2 := &twistPoint{}, &twistPoint{}
	ret1.Frobenius(twistGen)
	ret1.Frobenius(ret1)
	if !ret1.IsOnCurve() {
		t.Errorf("point should be on curve")
	}

	ret2.FrobeniusP2(twistGen)
	if !ret2.IsOnCurve() {
		t.Errorf("point should be on curve")
	}
	if ret1.x != ret2.x || ret1.y != ret2.y || ret1.z != ret2.z || ret1.t != ret2.t {
		t.Errorf("not same")
	}
}

func Test_TwistFrobeniusP2_Case2(t *testing.T) {
	ret1, ret2 := &twistPoint{}, &twistPoint{}
	ret1.x.Set(&twistGen.x)
	ret1.x.MulScalar(&ret1.x, betaToNegP2Plus1Over3)

	ret1.y.Set(&twistGen.y)
	ret1.y.MulScalar(&ret1.y, betaToNegP2Plus1Over2)
	ret1.z.SetOne()
	ret1.t.SetOne()
	if !ret1.IsOnCurve() {
		t.Errorf("point should be on curve")
	}

	ret2.FrobeniusP2(twistGen)
	ret2.MakeAffine()
	if !ret2.IsOnCurve() {
		t.Errorf("point should be on curve")
	}
	if ret1.x != ret2.x || ret1.y != ret2.y || ret1.z != ret2.z || ret1.t != ret2.t {
		t.Errorf("not same")
	}
}

func Test_TwistNegFrobeniusP2_Case2(t *testing.T) {
	ret1, ret2 := &twistPoint{}, &twistPoint{}
	ret1.x.Set(&twistGen.x)
	ret1.x.MulScalar(&ret1.x, betaToNegP2Plus1Over3)

	ret1.y.Neg(&twistGen.y)
	ret1.y.MulScalar(&ret1.y, betaToNegP2Plus1Over2)
	ret1.z.SetOne()
	ret1.t.SetOne()
	if !ret1.IsOnCurve() {
		t.Errorf("point should be on curve")
	}

	ret2.NegFrobeniusP2(twistGen)
	ret2.MakeAffine()
	if !ret2.IsOnCurve() {
		t.Errorf("point should be on curve")
	}
	if ret1.x != ret2.x || ret1.y != ret2.y || ret1.z != ret2.z || ret1.t != ret2.t {
		t.Errorf("not same")
	}
}
