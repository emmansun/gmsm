package sm2ec

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// r = 2^256
var r = bigFromHex("010000000000000000000000000000000000000000000000000000000000000000")
var r0 = bigFromHex("010000000000000000")
var sm2Prime = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
var sm2n = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
var nistP256Prime = bigFromDecimal("115792089210356248762697446949407573530086143415290314195533631308867097853951")

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
