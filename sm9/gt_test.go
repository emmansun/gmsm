package sm9

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGT(t *testing.T) {
	k, Ga, err := RandomGT(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ma := Ga.Marshal()

	Gb := new(GT)
	_, err = Gb.Unmarshal((&GT{gfP12Gen}).Marshal())
	if err != nil {
		t.Fatal("unmarshal not ok")
	}
	Gb.ScalarMult(Gb, k)
	mb := Gb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func BenchmarkGT(b *testing.B) {
	x, _ := rand.Int(rand.Reader, Order)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(GT).ScalarBaseMult(x)
	}
}

func BenchmarkPairing(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Pair(&G1{curveGen}, &G2{twistGen})
	}
}
