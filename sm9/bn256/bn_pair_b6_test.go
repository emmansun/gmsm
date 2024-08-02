package bn256

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestToGfP12_1(t *testing.T) {
	x := &gfP12b6{}
	x.SetGfP12(expected1)
	fmt.Printf("%v\n", gfP12b6Decode(x))
	x.SetGfP12(expected_b2)
	fmt.Printf("%v\n", gfP12b6Decode(x))
	x.SetGfP12(expected_b2_2)
	fmt.Printf("%v\n", gfP12b6Decode(x))
}

func Test_finalExponentiationB6(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	got := finalExponentiationB6(x)

	exp := new(big.Int).Exp(p, big.NewInt(12), nil)
	exp.Sub(exp, big.NewInt(1))
	exp.Div(exp, Order)
	expected := (&gfP12b6{}).Exp(x, exp)

	if *got != *expected {
		t.Errorf("got %v, expected %v\n", got, expected)
	}
}

func Test_PairingB6_A2(t *testing.T) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	ret := pairingB6(g2.p, curveGen)
	if *ret != *expected1 {
		t.Errorf("not expected")
	}
}

func Test_PairingB6_B2(t *testing.T) {
	deB := &twistPoint{}
	deB.x.x = *fromBigInt(bigFromHex("74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"))
	deB.x.y = *fromBigInt(bigFromHex("01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"))
	deB.y.x = *fromBigInt(bigFromHex("44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"))
	deB.y.y = *fromBigInt(bigFromHex("8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"))
	deB.z.SetOne()
	deB.t.SetOne()

	rA := &curvePoint{}
	rA.x = *fromBigInt(bigFromHex("7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"))
	rA.y = *fromBigInt(bigFromHex("A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"))
	rA.z = *one
	rA.t = *one

	ret := pairingB6(deB, rA)
	if ret.x != expected_b2.x || ret.y != expected_b2.y || ret.z != expected_b2.z {
		t.Errorf("not expected")
	}
}

func Test_PairingB6_B2_2(t *testing.T) {
	pubE := &curvePoint{}
	pubE.x = *fromBigInt(bigFromHex("9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"))
	pubE.y = *fromBigInt(bigFromHex("54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210"))
	pubE.z = *one
	pubE.t = *one

	ret := pairingB6(twistGen, pubE)
	ret.Exp(ret, bigFromHex("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE"))
	if ret.x != expected_b2_2.x || ret.y != expected_b2_2.y || ret.z != expected_b2_2.z {
		t.Errorf("not expected")
	}
}

func TestBilinearityB6(t *testing.T) {
	for i := 0; i < 2; i++ {
		a, p1, _ := RandomG1(rand.Reader)
		b, p2, _ := RandomG2(rand.Reader)
		e1 := pairingB6(p2.p, p1.p)

		e2 := pairingB6(twistGen, curveGen)
		e2.Exp(e2, a)
		e2.Exp(e2, b)

		if *e1 != *e2 {
			t.Fatalf("bad pairing result: %s", e1)
		}
	}
}

func BenchmarkFinalExponentiationB6(b *testing.B) {
	x := &gfP12b6{
		p6,
		p6,
	}
	exp := new(big.Int).Exp(p, big.NewInt(12), nil)
	exp.Sub(exp, big.NewInt(1))
	exp.Div(exp, Order)
	expected := (&gfP12b6{}).Exp(x, exp)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := finalExponentiationB6(x)
		if *got != *expected {
			b.Errorf("got %v, expected %v\n", got, expected)
		}
	}
}

func BenchmarkPairingB6(b *testing.B) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ret := pairingB6(g2.p, curveGen)
		if *ret != *expected1 {
			b.Errorf("not expected")
		}
	}
}
