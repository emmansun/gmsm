package sm9

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

var secp256k1Params = &CurveParams{
	Name:    "secp256k1",
	BitSize: 256,
	P:       bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
	N:       bigFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
	B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000007"),
	Gx:      bigFromHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
	Gy:      bigFromHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
}

var sm9CurveParams = &CurveParams{
	Name:    "sm9",
	BitSize: 256,
	P:       bigFromHex("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D"),
	N:       bigFromHex("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"),
	B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000005"),
	Gx:      bigFromHex("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD"),
	Gy:      bigFromHex("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616"),
}

type baseMultTest struct {
	k    string
	x, y string
}

var s256BaseMultTests = []baseMultTest{
	{
		"AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
		"34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
		"B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
	},
	{
		"7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
		"D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
		"131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
	},
	{
		"6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
		"E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
		"C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
	},
	{
		"376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
		"14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
		"297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
	},
	{
		"1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
		"F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
		"F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
	},
}

func TestBaseMult(t *testing.T) {
	for i, e := range s256BaseMultTests {
		k, ok := new(big.Int).SetString(e.k, 16)
		if !ok {
			t.Errorf("%d: bad value for k: %s", i, e.k)
		}
		x, y := secp256k1Params.ScalarBaseMult(k.Bytes())
		if fmt.Sprintf("%X", x) != e.x || fmt.Sprintf("%X", y) != e.y {
			t.Errorf("%d: bad output for k=%s: got (%X, %X), want (%s, %s)", i, e.k, x, y, e.x, e.y)
		}
	}
}

func TestOnCurve(t *testing.T) {
	if !secp256k1Params.IsOnCurve(secp256k1Params.Gx, secp256k1Params.Gy) {
		t.Errorf("point is not on curve")
	}
	if !sm9CurveParams.IsOnCurve(sm9CurveParams.Gx, sm9CurveParams.Gy) {
		t.Errorf("point is not on curve")
	}
}

func TestPMode4And8(t *testing.T) {
	res := new(big.Int).Mod(sm9CurveParams.P, big.NewInt(4))
	if res.Int64() != 1 {
		t.Errorf("p mod 4 != 1")
	}
	res = new(big.Int).Mod(sm9CurveParams.P, big.NewInt(6))
	if res.Int64() != 1 {
		t.Errorf("p mod 6 != 1")
	}
	res = new(big.Int).Mod(sm9CurveParams.P, big.NewInt(8))
	if res.Int64() != 5 {
		t.Errorf("p mod 8 != 5")
	}
	res = new(big.Int).Sub(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(2))
	if hex.EncodeToString(res.Bytes()) != "5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be" {
		t.Errorf("expected %v, got %v\n", "5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Add(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(2))
	if hex.EncodeToString(res.Bytes()) != "5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2bf" {
		t.Errorf("expected %v, got %v\n", "5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2bf", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Add(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(3))
	if hex.EncodeToString(res.Bytes()) != "3cc0000000e137a5f201391aa72f97c1b5fb866e5e28fa494c7a890d4bc5c1d4" {
		t.Errorf("expected %v, got %v\n", "3cc0000000e137a5f201391aa72f97c1b5fb866e5e28fa494c7a890d4bc5c1d4", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Sub(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(4))
	if hex.EncodeToString(res.Bytes()) != "2d90000000a8e9bc7580ead3fd63b1d1487ca4d2c69ebbb6f95be6c9f8d4515f" {
		t.Errorf("expected %v, got %v\n", "2d90000000a8e9bc7580ead3fd63b1d1487ca4d2c69ebbb6f95be6c9f8d4515f", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Sub(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(6))
	if hex.EncodeToString(res.Bytes()) != "1e60000000709bd2f9009c8d5397cbe0dafdc3372f147d24a63d4486a5e2e0ea" {
		t.Errorf("expected %v, got %v\n", "1e60000000709bd2f9009c8d5397cbe0dafdc3372f147d24a63d4486a5e2e0ea", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Sub(sm9CurveParams.P, big.NewInt(1))
	res.Div(res, big.NewInt(3))
	if hex.EncodeToString(res.Bytes()) != "3cc0000000e137a5f201391aa72f97c1b5fb866e5e28fa494c7a890d4bc5c1d4" {
		t.Errorf("expected %v, got %v\n", "3cc0000000e137a5f201391aa72f97c1b5fb866e5e28fa494c7a890d4bc5c1d4", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Mul(sm9CurveParams.P, sm9CurveParams.P)
	res.Sub(res, big.NewInt(1))
	res.Div(res, big.NewInt(3))
	if hex.EncodeToString(res.Bytes()) != "2b3fb0000140abbbc71510370c6fa2b194d4665ff95c18014568b07bbd19fb54f0b9aded6fea5b670c35d6b4e3b966415456a4a8503c6361c90d41b4e8a78a58" {
		t.Errorf("expected %v, got %v\n", "2b3fb0000140abbbc71510370c6fa2b194d4665ff95c18014568b07bbd19fb54f0b9aded6fea5b670c35d6b4e3b966415456a4a8503c6361c90d41b4e8a78a58", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Mul(sm9CurveParams.P, sm9CurveParams.P)
	res.Sub(res, big.NewInt(1))
	res.Div(res, big.NewInt(2))
	if hex.EncodeToString(res.Bytes()) != "40df880001e10199aa9f985292a7740a5f3e998ff60a2401e81d08b99ba6f8ff691684e427df891a9250c20f55961961fe81f6fc785a9512ad93e28f5cfb4f84" {
		t.Errorf("expected %v, got %v\n", "40df880001e10199aa9f985292a7740a5f3e998ff60a2401e81d08b99ba6f8ff691684e427df891a9250c20f55961961fe81f6fc785a9512ad93e28f5cfb4f84", hex.EncodeToString(res.Bytes()))
	}

	res = new(big.Int).Sub(sm9CurveParams.P, big.NewInt(5))
	res.Div(res, big.NewInt(8))
	if hex.EncodeToString(res.Bytes()) != "16c80000005474de3ac07569feb1d8e8a43e5269634f5ddb7cadf364fc6a28af" {
		t.Errorf("expected %v, got %v\n", "16c80000005474de3ac07569feb1d8e8a43e5269634f5ddb7cadf364fc6a28af", hex.EncodeToString(res.Bytes()))
	}

	res.Exp(big.NewInt(2), res, sm9CurveParams.P)
	if hex.EncodeToString(res.Bytes()) != "800db90d149e875b5b564505fe88efba5223f2bf170cc61fea968b3df63edd75" {
		t.Errorf("expected %v, got %v\n", "800db90d149e875b5b564505fe88efba5223f2bf170cc61fea968b3df63edd75", hex.EncodeToString(res.Bytes()))
	}

	res.Mul(u, big.NewInt(6))
	res.Add(res, big.NewInt(5))
	if hex.EncodeToString(res.Bytes()) != "02400000000215d941" {
		t.Errorf("expected %v, got %v\n", "02400000000215d941", hex.EncodeToString(res.Bytes()))
	}
	res.Mul(u, big.NewInt(6))
	res.Mul(res, u)
	res.Add(res, big.NewInt(1))
	if hex.EncodeToString(res.Bytes()) != "d8000000019062ed0000b98b0cb27659" {
		t.Errorf("expected %v, got %v\n", "d8000000019062ed0000b98b0cb27659", hex.EncodeToString(res.Bytes()))
	}
}
