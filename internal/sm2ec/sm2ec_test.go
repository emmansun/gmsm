package sm2ec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// r = 2^256
var r = bigFromHex("010000000000000000000000000000000000000000000000000000000000000000")
var r0 = bigFromHex("010000000000000000")
var sm2Prime = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
var sm2n = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
var nistP256Prime = bigFromDecimal("115792089210356248762697446949407573530086143415290314195533631308867097853951")
var nistP256N = bigFromDecimal("115792089210356248762697446949407573529996955224135760342422259061068512044369")

func generateMontgomeryDomain(in *big.Int, p *big.Int) *big.Int {
	tmp := new(big.Int)
	tmp = tmp.Mul(in, r)
	return tmp.Mod(tmp, p)
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2ec: internal error: invalid encoding")
	}
	return b
}

func bigFromDecimal(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("sm2ec: internal error: invalid encoding")
	}
	return b
}

func TestSM2P256MontgomeryDomain(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{ // One
			"01",
			"0000000100000000000000000000000000000000ffffffff0000000000000001",
		},
		{ // Gx
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
			"91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e",
		},
		{ // Gy
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
			"63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd",
		},
		{ // B
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
			"240fe188ba20e2c8527981505ea51c3c71cf379ae9b537ab90d230632bc0dd42",
		},
		{ // R
			"010000000000000000000000000000000000000000000000000000000000000000",
			"0400000002000000010000000100000002ffffffff0000000200000003",
		},
	}
	for _, test := range tests {
		out := generateMontgomeryDomain(bigFromHex(test.in), sm2Prime)
		if out.Cmp(bigFromHex(test.out)) != 0 {
			t.Errorf("expected %v, got %v", test.out, hex.EncodeToString(out.Bytes()))
		}
	}
}

func TestSM2P256MontgomeryDomainN(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{ // One
			"01",
			"010000000000000000000000008dfc2094de39fad4ac440bf6c62abedd",
		},
		{ // R
			"010000000000000000000000000000000000000000000000000000000000000000",
			"1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20",
		},
	}
	for _, test := range tests {
		out := generateMontgomeryDomain(bigFromHex(test.in), sm2n)
		if out.Cmp(bigFromHex(test.out)) != 0 {
			t.Errorf("expected %v, got %v", test.out, hex.EncodeToString(out.Bytes()))
		}
	}
}

func TestSM2P256MontgomeryK0(t *testing.T) {
	tests := []struct {
		in  *big.Int
		out string
	}{
		{
			sm2n,
			"327f9e8872350975",
		},
		{
			sm2Prime,
			"0000000000000001",
		},
	}
	for _, test := range tests {
		// k0 = -in^(-1) mod 2^64
		k0 := new(big.Int).ModInverse(test.in, r0)
		k0.Neg(k0)
		k0.Mod(k0, r0)
		if k0.Cmp(bigFromHex(test.out)) != 0 {
			t.Errorf("expected %v, got %v", test.out, hex.EncodeToString(k0.Bytes()))
		}
	}
}

func TestNISTP256MontgomeryDomain(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{ // One
			"01",
			"fffffffeffffffffffffffffffffffff000000000000000000000001",
		},
		{ // Gx
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
			"18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c",
		},
		{ // Gy
			"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
			"8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a",
		},
		{ // B
			"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
			"dc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf",
		},
		{ // R
			"010000000000000000000000000000000000000000000000000000000000000000",
			"04fffffffdfffffffffffffffefffffffbffffffff0000000000000003",
		},
	}
	for _, test := range tests {
		out := generateMontgomeryDomain(bigFromHex(test.in), nistP256Prime)
		if out.Cmp(bigFromHex(test.out)) != 0 {
			t.Errorf("expected %v, got %v", test.out, hex.EncodeToString(out.Bytes()))
		}
	}
}

func TestForSqrt(t *testing.T) {
	mod4 := new(big.Int).Mod(sm2Prime, big.NewInt(4))
	if mod4.Cmp(big.NewInt(3)) != 0 {
		t.Fatal("sm2 prime is not fulfill 3 mod 4")
	}

	exp := new(big.Int).Add(sm2Prime, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
}

func TestEquivalents(t *testing.T) {
	p := NewSM2P256Point().SetGenerator()

	elementSize := 32
	two := make([]byte, elementSize)
	two[len(two)-1] = 2
	nPlusTwo := make([]byte, elementSize)
	new(big.Int).Add(sm2n, big.NewInt(2)).FillBytes(nPlusTwo)

	p1 := NewSM2P256Point().Double(p)
	p2 := NewSM2P256Point().Add(p, p)
	p3, err := NewSM2P256Point().ScalarMult(p, two)
	fatalIfErr(t, err)
	p4, err := NewSM2P256Point().ScalarBaseMult(two)
	fatalIfErr(t, err)
	p5, err := NewSM2P256Point().ScalarMult(p, nPlusTwo)
	fatalIfErr(t, err)
	p6, err := NewSM2P256Point().ScalarBaseMult(nPlusTwo)
	fatalIfErr(t, err)

	if !bytes.Equal(p1.Bytes(), p2.Bytes()) {
		t.Error("P+P != 2*P")
	}
	if !bytes.Equal(p1.Bytes(), p3.Bytes()) {
		t.Error("P+P != [2]P")
	}
	if !bytes.Equal(p1.Bytes(), p4.Bytes()) {
		t.Error("G+G != [2]G")
	}
	if !bytes.Equal(p1.Bytes(), p5.Bytes()) {
		t.Error("P+P != [N+2]P")
	}
	if !bytes.Equal(p1.Bytes(), p6.Bytes()) {
		t.Error("G+G != [N+2]G")
	}
}

func TestBasicScalarMult(t *testing.T) {
	testvector := []struct {
		name     string
		scalar   *big.Int
		expected string
	}{
		{
			"32",
			big.NewInt(32),
			"0425d3debd0950d180a6d5c2b5817f2329791734cd03e5565ca32641e56024666c92d99a70679d61efb938c406dd5cb0e10458895120e208b4d39e100303fa10a2",
		},
		{
			"N-3",
			new(big.Int).Sub(sm2n, big.NewInt(3)),
			"04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebfacf4a2267397710a333a313f758deaf083bff11932fbad6e555322fc8ba70919",
		},
	}
	p := NewSM2P256Point().SetGenerator()

	for _, test := range testvector {
		scalar := make([]byte, 32)
		test.scalar.FillBytes(scalar)
		p1, err := NewSM2P256Point().ScalarBaseMult(scalar)
		fatalIfErr(t, err)
		p2, err := NewSM2P256Point().ScalarMult(p, scalar)
		fatalIfErr(t, err)
		if hex.EncodeToString(p1.Bytes()) != test.expected {
			t.Errorf("%s ScalarBaseMult fail, got %x", test.name, p1.Bytes())
		}
		if hex.EncodeToString(p2.Bytes()) != test.expected {
			t.Errorf("%s ScalarMult fail, got %x", test.name, p2.Bytes())
		}
	}
}

func TestScalarMult(t *testing.T) {
	G := NewSM2P256Point().SetGenerator()
	checkScalar := func(t *testing.T, scalar []byte) {
		p1, err := NewSM2P256Point().ScalarBaseMult(scalar)
		fatalIfErr(t, err)
		p2, err := NewSM2P256Point().ScalarMult(G, scalar)
		fatalIfErr(t, err)
		if !bytes.Equal(p1.Bytes(), p2.Bytes()) {
			t.Errorf("[k]G != ScalarBaseMult(k), k=%x, p1=%x, p2=%x", scalar, p1.Bytes(), p2.Bytes())
		}

		d := new(big.Int).SetBytes(scalar)
		d.Sub(sm2n, d)
		d.Mod(d, sm2n)
		g1, err := NewSM2P256Point().ScalarBaseMult(d.FillBytes(make([]byte, len(scalar))))
		fatalIfErr(t, err)
		g1.Add(g1, p1)
		if !bytes.Equal(g1.Bytes(), NewSM2P256Point().Bytes()) {
			t.Errorf("[N - k]G + [k]G != ∞, k=%x, g1=%x", scalar, g1.Bytes())
		}
	}

	byteLen := len(sm2n.Bytes())
	bitLen := sm2n.BitLen()
	t.Run("0", func(t *testing.T) { checkScalar(t, make([]byte, byteLen)) })
	t.Run("1", func(t *testing.T) {
		checkScalar(t, big.NewInt(1).FillBytes(make([]byte, byteLen)))
	})
	t.Run("N-6", func(t *testing.T) {
		checkScalar(t, new(big.Int).Sub(sm2n, big.NewInt(6)).Bytes())
	})
	t.Run("N-1", func(t *testing.T) {
		checkScalar(t, new(big.Int).Sub(sm2n, big.NewInt(1)).Bytes())
	})
	t.Run("N", func(t *testing.T) { checkScalar(t, sm2n.Bytes()) })
	t.Run("N+1", func(t *testing.T) {
		checkScalar(t, new(big.Int).Add(sm2n, big.NewInt(1)).Bytes())
	})
	t.Run("N+58", func(t *testing.T) {
		checkScalar(t, new(big.Int).Add(sm2n, big.NewInt(58)).Bytes())
	})
	t.Run("all1s", func(t *testing.T) {
		s := new(big.Int).Lsh(big.NewInt(1), uint(bitLen))
		s.Sub(s, big.NewInt(1))
		checkScalar(t, s.Bytes())
	})
	if testing.Short() {
		return
	}
	for i := 0; i < bitLen; i++ {
		t.Run(fmt.Sprintf("1<<%d", i), func(t *testing.T) {
			s := new(big.Int).Lsh(big.NewInt(1), uint(i))
			checkScalar(t, s.FillBytes(make([]byte, byteLen)))
		})
	}
	for i := 0; i <= 64; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			checkScalar(t, big.NewInt(int64(i)).FillBytes(make([]byte, byteLen)))
		})
	}

	// Test N-64...N+64 since they risk overlapping with precomputed table values
	// in the final additions.
	for i := int64(-64); i <= 64; i++ {
		t.Run(fmt.Sprintf("N%+d", i), func(t *testing.T) {
			checkScalar(t, new(big.Int).Add(sm2n, big.NewInt(i)).Bytes())
		})
	}

}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	p := NewSM2P256Point().SetGenerator()
	scalar := make([]byte, 32)
	rand.Read(scalar)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ScalarBaseMult(scalar)
	}
}

func BenchmarkScalarMult(b *testing.B) {
	p := NewSM2P256Point().SetGenerator()
	scalar := make([]byte, 32)
	rand.Read(scalar)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ScalarMult(p, scalar)
	}
}
