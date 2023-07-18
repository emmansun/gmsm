package bn256

import (
	"math/big"
	"testing"
)

var p6 = gfP6{
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

func testGfP12b6Square(t *testing.T, x *gfP12b6) {
	xmulx := &gfP12b6{}
	xmulx.Mul(x, x)
	xmulx = gfP12b6Decode(xmulx)

	x2 := &gfP12b6{}
	x2.Square(x)
	x2 = gfP12b6Decode(x2)

	if *xmulx != *x2 {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
}

func Test_gfP12b6Square(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	testGfP12b6Square(t, x)

	x = &gfP12b6{
		p6,
		*(&gfP6{}).SetOne(),
	}
	testGfP12b6Square(t, x)

	x = &gfP12b6{
		*(&gfP6{}).SetOne(),
		p6,
	}
	testGfP12b6Square(t, x)

	x = &gfP12b6{
		*(&gfP6{}).SetZero(),
		p6,
	}
	testGfP12b6Square(t, x)

	x = &gfP12b6{
		p6,
		*(&gfP6{}).SetZero(),
	}
	testGfP12b6Square(t, x)
}

func testGfP12b6Invert(t *testing.T, x *gfP12b6) {
	xInv := &gfP12b6{}
	xInv.Invert(x)

	y := &gfP12b6{}
	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
}

func TestToGfP12(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}

	p12 := x.ToGfP12()

	x1 := &gfP12b6{}
	x1.SetGfP12(p12)

	if *x1 != *x {
		t.Errorf("not same")
	}

	// after add
	x2 := (&gfP12b6{}).Add(x, x)
	p12_1 := (&gfP12{}).Add(p12, p12)
	x3 := (&gfP12b6{}).SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after double, %v\n%v\n", x3, x2)
	}

	// after sub
	x2 = (&gfP12b6{}).Sub(x, x)
	p12_1 = (&gfP12{}).Sub(p12, p12)
	x3 = (&gfP12b6{}).SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after double, %v\n%v\n", x3, x2)
	}

	// after neg
	x2 = (&gfP12b6{}).Neg(x)
	p12_1 = (&gfP12{}).Neg(p12)
	x3 = (&gfP12b6{}).SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after double, %v\n%v\n", x3, x2)
	}

	// after mul gfp
	x2.MulGfP(x, fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")))
	p12_1.MulGFP(p12, fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")))
	x3.SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after mul gfp, %v\n%v\n", x3, x2)
	}

	// after mul gfp2
	gfp2 := &gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	}

	x2.MulGfP2(x, gfp2)
	p12_1.MulGFP2(p12, gfp2)
	x3.SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after mul gfp2, %v\n%v\n", x3, x2)
	}

	// after squre
	x2.Square(x)
	p12_1.Square(p12)
	x3.SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after square, %v\n%v\n", x3, x2)
	}

	// after mul
	x2.Mul(x, x)
	p12_1.Mul(p12, p12)
	x3.SetGfP12(p12_1)
	if *x2 != *x3 {
		x3 = gfP12b6Decode(x3)
		x2 = gfP12b6Decode(x2)
		t.Errorf("not same after mul, %v\n%v\n", x3, x2)
	}
}

func Test_gfP12b6Invert(t *testing.T) {
	x := &gfP12b6{
		*(&gfP6{}).SetZero(),
		p6,
	}
	testGfP12b6Invert(t, x)
	x = &gfP12b6{
		*(&gfP6{}).SetOne(),
		p6,
	}
	testGfP12b6Invert(t, x)
}

func TestSToPMinus1Over2(t *testing.T) {
	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b")))
	expected.x.Set(zero)

	s := &gfP6{}
	s.SetS()
	s.Exp(s, pMinus1Over2Big)
	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		s = gfP6Decode(s)
		t.Errorf("not same as expected %v\n", s)
	}
}

func Test_gfP12b6Frobenius(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	expected := &gfP12b6{}
	expected.Exp(x, p)
	got := &gfP12b6{}
	got.Frobenius(x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func TestSToPSquaredMinus1Over2(t *testing.T) {
	s := &gfP6{}
	s.SetS()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	p2.Rsh(p2, 1)
	s.Exp(s, p2)

	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
	expected.x.Set(zero)

	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		s = gfP6Decode(s)
		t.Errorf("not same as expected %v\n", s)
	}
}

func Test_gfP12b6FrobeniusP2(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	expected := &gfP12b6{}
	p2 := new(big.Int).Mul(p, p)
	expected.Exp(x, p2)
	got := &gfP12b6{}
	got.FrobeniusP2(x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func TestSToP4Minus1Over2(t *testing.T) {
	s := &gfP6{}
	s.SetS()
	p4 := new(big.Int).Mul(p, p)
	p4.Mul(p4, p4)
	p4 = new(big.Int).Sub(p4, big.NewInt(1))
	p4.Rsh(p4, 1)
	s.Exp(s, p4)

	expected := &gfP2{}
	expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
	expected.x.Set(zero)

	if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
		s = gfP6Decode(s)
		t.Errorf("not same as expected %v\n", s)
	}
}

func Test_gfP12b6FrobeniusP4(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	expected := &gfP12b6{}
	p4 := new(big.Int).Mul(p, p)
	p4.Mul(p4, p4)
	expected.Exp(x, p4)
	got := &gfP12b6{}
	got.FrobeniusP4(x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12b6FrobeniusP6(t *testing.T) {
	x := &gfP12b6{
		p6,
		p6,
	}
	expected := &gfP12b6{}
	p6 := new(big.Int).Mul(p, p)
	p6.Mul(p6, p)
	p6.Mul(p6, p6)
	expected.Exp(x, p6)
	got := &gfP12b6{}
	got.FrobeniusP6(x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func BenchmarkGfP12b6Frobenius(b *testing.B) {
	x := &gfP12b6{
		p6,
		p6,
	}
	expected := &gfP12b6{}
	expected.Exp(x, p)
	got := &gfP12b6{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Frobenius(x)
		if *expected != *got {
			b.Errorf("got %v, expected %v", got, expected)
		}
	}
}

func TestGfP12b6SpecialSquare(t *testing.T) {
	in := &gfP12b6{
		p6,
		p6,
	}
	t1 := &gfP12b6{}
	t1.x.Neg(&in.x)
	t1.y.Set(&in.y)

	inv := &gfP12b6{}
	inv.Invert(in)
	t1.Mul(t1, inv)

	t2 := (&gfP12b6{}).FrobeniusP2(t1)
	t1.Mul(t1, t2)

	got := &gfP12b6{}
	expected := &gfP12b6{}
	got.Cyclo6Square(t1)
	expected.Square(t1)
	if *got != *expected {
		t.Errorf("not same got=%v, expected=%v", got, expected)
	}
}
