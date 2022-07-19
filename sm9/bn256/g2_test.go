package bn256

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestG2(t *testing.T) {
	k, Ga, err := RandomG2(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ma := Ga.Marshal()

	Gb := new(G2).ScalarBaseMult(k)
	mb := Gb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Errorf("bytes are different, expected %v, got %v", hex.EncodeToString(ma), hex.EncodeToString(mb))
	}
}

func TestG2Marshal(t *testing.T) {
	_, Ga, err := RandomG2(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ma := Ga.Marshal()

	Gb := new(G2)
	_, err = Gb.Unmarshal(ma)
	if err != nil {
		t.Fatal(err)
	}
	mb := Gb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Errorf("bytes are different, expected %v, got %v", hex.EncodeToString(ma), hex.EncodeToString(mb))
	}
}

func Test_G2MarshalCompressed(t *testing.T) {
	e, e2 := &G2{}, &G2{}
	ret := e.MarshalCompressed()
	_, err := e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if !e2.p.IsInfinity() {
		t.Errorf("not same")
	}
	e.p.Set(twistGen)
	ret = e.MarshalCompressed()
	_, err = e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if e2.p.x != e.p.x || e2.p.y != e.p.y || e2.p.z != e.p.z {
		t.Errorf("not same")
	}
	e.p.Neg(e.p)
	ret = e.MarshalCompressed()
	_, err = e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if e2.p.x != e.p.x || e2.p.y != e.p.y || e2.p.z != e.p.z {
		t.Errorf("not same")
	}
	if e2.p.x == twistGen.x && e2.p.y == twistGen.y && e2.p.z == twistGen.z {
		t.Errorf("not expected")
	}
}

func TestScaleMult(t *testing.T) {
	k, e, err := RandomG2(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.p.MakeAffine()

	e2, e3 := &G2{}, &G2{}
	e3.p = &twistPoint{}
	e3.p.Mul(twistGen, k)
	e3.p.MakeAffine()

	e2.ScalarMult(Gen2, k)
	e2.p.MakeAffine()
	if !e.Equal(e2) {
		t.Errorf("not same")
	}
}

func BenchmarkG2(b *testing.B) {
	x, _ := rand.Int(rand.Reader, Order)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(G2).ScalarBaseMult(x)
	}
}
