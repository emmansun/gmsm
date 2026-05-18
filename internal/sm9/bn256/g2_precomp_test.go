package bn256

import (
	"crypto/rand"
	"testing"
)

func TestPairPrecomp_A2(t *testing.T) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	precomp := g2.Precompute()

	g1 := &G1{curveGen}
	got := PairPrecomp(g1, precomp)
	want := Pair(g1, g2)

	if *got.p != *want.p {
		t.Errorf("PairPrecomp mismatch: got %v, want %v", got, want)
	}
}

func TestPairPrecomp_B2(t *testing.T) {
	deB := &twistPoint{}
	deB.x.x = *newGFpFromHex("74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7")
	deB.x.y = *newGFpFromHex("01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2")
	deB.y.x = *newGFpFromHex("44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1")
	deB.y.y = *newGFpFromHex("8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539")
	deB.z.SetOne()
	deB.t.SetOne()

	rA := &curvePoint{}
	rA.x = *newGFpFromHex("7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265")
	rA.y = *newGFpFromHex("A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599")
	rA.z = *one
	rA.t = *one

	g2 := &G2{deB}
	g1 := &G1{rA}
	precomp := g2.Precompute()

	got := PairPrecomp(g1, precomp)
	want := Pair(g1, g2)

	if *got.p != *want.p {
		t.Errorf("PairPrecomp mismatch")
	}
}

func TestPairPrecompBilinearity(t *testing.T) {
	for i := 0; i < 2; i++ {
		a, p1, _ := RandomG1(rand.Reader)
		b, p2, _ := RandomG2(rand.Reader)

		precomp := p2.Precompute()

		e1 := PairPrecomp(p1, precomp)
		e2 := Pair(p1, p2)
		if *e1.p != *e2.p {
			t.Fatalf("PairPrecomp does not match Pair: %s vs %s", e1, e2)
		}

		// Bilinearity: e(a*G1, b*G2) == e(G1,G2)^(ab)
		e3 := Pair(&G1{curveGen}, &G2{twistGen})
		e3.ScalarMult(e3, a)
		e3.ScalarMult(e3, b)
		if *e1.p != *e3.p {
			t.Fatalf("bilinearity failed")
		}
	}
}

func TestMillerPrecomp_EquivalentToMiller(t *testing.T) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	precomp := g2.Precompute()
	g1 := &G1{curveGen}

	gotMiller := MillerPrecomp(g1, precomp)
	wantMiller := Miller(g1, g2)

	if *gotMiller.p != *wantMiller.p {
		t.Errorf("MillerPrecomp mismatch")
	}
}

func BenchmarkPrecomputeG2(b *testing.B) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g2.Precompute()
	}
}

func BenchmarkPairPrecomp(b *testing.B) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		b.Fatal(err)
	}
	precomp := g2.Precompute()
	g1 := &G1{curveGen}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ret := PairPrecomp(g1, precomp)
		if *ret.p != *expected1 {
			b.Errorf("not expected")
		}
	}
}

func BenchmarkMillerWithPrecomp(b *testing.B) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	_, err := g2.ScalarBaseMult(NormalizeScalar(pk.Bytes()))
	if err != nil {
		b.Fatal(err)
	}
	precomp := g2.Precompute()
	g1 := &G1{curveGen}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = millerWithPrecomp(precomp, g1.p)
	}
}
