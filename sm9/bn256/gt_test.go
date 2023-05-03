package bn256

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestGTMarshal(t *testing.T) {
	expected, _ := hex.DecodeString("256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f5230167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e90913083105e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf066fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de7869688ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db9277f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a042636a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669")
	x := &GT{gfP12Gen}
	ret := x.Marshal()
	if !bytes.Equal(expected, ret) {
		t.Errorf("expected %x, got %x\n", expected, ret)
	}
}

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

	_, err = Gb.Unmarshal((&GT{gfP12Gen}).Marshal())
	if err != nil {
		t.Fatal("unmarshal not ok")
	}
	Gc, err := ScalarMultGT(Gb, k.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	mc := Gc.Marshal()
	if !bytes.Equal(ma, mc) {
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
