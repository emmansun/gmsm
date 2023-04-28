package bn256

import (
	"math/big"
	"testing"
)

func Test_gfP4Square(t *testing.T) {
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	xmulx := &gfP4{}
	xmulx.Mul(x, x)
	xmulx = gfP4Decode(xmulx)

	x2 := &gfP4{}
	x2.Square(x)
	x2 = gfP4Decode(x2)

	if xmulx.x != x2.x || xmulx.y != x2.y {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
}

func Test_gfP4Invert(t *testing.T) {
	gfp2Zero := (&gfP2{}).SetZero()
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}

	xInv := &gfP4{}
	xInv.Invert(x)

	y := &gfP4{}
	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}

	x = &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		*gfp2Zero,
	}

	xInv.Invert(x)

	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}

	x = &gfP4{
		*gfp2Zero,
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}

	xInv.Invert(x)

	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
}

func Test_gfP4Frobenius(t *testing.T) {
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP4{}
	expected.Exp(x, p)
	got := &gfP4{}
	got.Frobenius(x)
	if expected.x != got.x || expected.y != got.y {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

// Generate vToPMinus1
func Test_gfP4Frobenius_Case1(t *testing.T) {
	expected := &gfP4{}
	i := &gfP4{}
	i.SetV()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	i.Exp(i, pMinus1)
	i = gfP4Decode(i)
	expected.y.x.Set(zero)
	expected.y.y.Set(fromBigInt(bigFromHex("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011")))
	expected.x.SetZero()
	expected = gfP4Decode(expected)
	if expected.x != i.x || expected.y != i.y {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

func Test_gfP4FrobeniusP2(t *testing.T) {
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP4{}
	p2 := new(big.Int).Mul(p, p)
	expected.Exp(x, p2)
	got := &gfP4{}
	got.FrobeniusP2(x)
	if expected.x != got.x || expected.y != got.y {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP4FrobeniusP2_Case1(t *testing.T) {
	expected := &gfP4{}
	i := &gfP4{}
	i.SetV()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	i.Exp(i, p2)
	i = gfP4Decode(i)
	expected.y.x.Set(zero)
	expected.y.y.Set(newGFp(-1))
	expected.x.SetZero()
	expected = gfP4Decode(expected)
	if expected.x != i.x || expected.y != i.y {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

func Test_gfP4FrobeniusP3(t *testing.T) {
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	expected := &gfP4{}
	p3 := new(big.Int).Mul(p, p)
	p3 = p3.Mul(p3, p)
	expected.Exp(x, p3)
	got := &gfP4{}
	got.FrobeniusP3(x)
	if expected.x != got.x || expected.y != got.y {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func BenchmarkGfP4Mul(b *testing.B) {
	x := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
	}
	y := &gfP4{
		gfP2{
			*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
			*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
		},
		gfP2{
			*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
			*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := &gfP4{}
		t.Mul(x, y)
	}
}
