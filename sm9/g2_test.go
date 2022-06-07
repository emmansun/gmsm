package sm9

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

func BenchmarkG2(b *testing.B) {
	x, _ := rand.Int(rand.Reader, Order)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		new(G2).ScalarBaseMult(x)
	}
}
