package bn256

import (
	"math/big"
	"testing"
)

func TestMulS(t *testing.T) {
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	s := &gfP6{}
	s.SetS()

	xmuls1, xmuls2 := &gfP6{}, &gfP6{}
	xmuls1.MulS(x)
	xmuls1 = gfP6Decode(xmuls1)
	xmuls2.Mul(x, s)
	xmuls2 = gfP6Decode(xmuls2)

	if *xmuls1 != *xmuls2 {
		t.Errorf("xmulx=%v, x2=%v", xmuls1, xmuls2)
	}
}

func testGfP6Square(t *testing.T, x *gfP6) {
	xmulx := &gfP6{}
	xmulx.Mul(x, x)
	xmulx = gfP6Decode(xmulx)

	x2 := &gfP6{}
	x2.Square(x)
	x2 = gfP6Decode(x2)

	if xmulx.x != x2.x || xmulx.y != x2.y {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
}

func Test_gfP6Square(t *testing.T) {
	gfp2Zero := (&gfP2{}).SetZero()
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	testGfP6Square(t, x)
	x = &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		*gfp2Zero,
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	testGfP6Square(t, x)
}

func testGfP6Invert(t *testing.T, x *gfP6) {
	xInv := &gfP6{}
	xInv.Invert(x)

	y := &gfP6{}
	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
}

func Test_gfP6Invert(t *testing.T) {
	gfp2Zero := (&gfP2{}).SetZero()
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	testGfP6Invert(t, x)

	x = &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		*gfp2Zero,
	}
	testGfP6Invert(t, x)

	x = &gfP6{
		*gfp2Zero,
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
	}
	testGfP6Invert(t, x)

	
	x = &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		*gfp2Zero,
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
	}
	testGfP6Invert(t, x)
}

// sToPMinus1 = s^(p-1) = u ^ ((p-1) / 3)
// sToPMinus1 ^ 3 = -1
// sToPMinus1 = 0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334
func TestSToPMinus1(t *testing.T) {
	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
	expected.x.Set(zero)

	s := &gfP6{}
	s.SetS()
	s.Exp(s, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))
	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		t.Error("not same as expected")
	}
}

// s2ToPMinus1 = (s^2)^(p-1) = sToPMinus1 ^ 2
// s2ToPMinus1 = sToPMinus1^2
// s2ToPMinus1 = 0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333
func TestS2ToPMinus1(t *testing.T) {
	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
	expected.x.Set(zero)

	s := &gfP6{}
	s.SetS()
	s.Square(s)
	s.Exp(s, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))
	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		t.Error("not same as expected")
	}

	s2 := &gfP2{}
	s2.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
	s2.x.Set(zero)
	s2.Square(s2)

	if *s2 != *expected {
		t.Errorf("not same as expected")
	}
}

func Test_gfP6Frobenius(t *testing.T) {
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP6{}
	expected.Exp(x, p)
	got := &gfP6{}
	got.Frobenius(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func TestSToPSquaredMinus1(t *testing.T) {
	s := &gfP6{}
	s.SetS()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	s.Exp(s, p2)

	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
	expected.x.Set(zero)

	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		t.Error("not same as expected")
	}
}

func TestSTo2PSquaredMinus2(t *testing.T) {
	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249")))
	expected.x.Set(zero)

	s2 := &gfP2{}
	s2.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
	s2.x.Set(zero)
	s2.Square(s2)

	if *s2 != *expected {
		s2 = gfP2Decode(s2)
		t.Errorf("not same as expected: %v", s2)
	}
}

func Test_gfP6FrobeniusP2(t *testing.T) {
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP6{}
	p2 := new(big.Int).Mul(p, p)
	expected.Exp(x, p2)
	got := &gfP6{}
	got.FrobeniusP2(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP6FrobeniusP4(t *testing.T) {
	x := &gfP6{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP6{}
	p4 := new(big.Int).Mul(p, p)
	p4.Mul(p4, p4)
	expected.Exp(x, p4)
	got := &gfP6{}
	got.FrobeniusP4(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}
