package bn256

import (
	"math/big"
	"testing"
)

var testdataP4 = gfP4{
	gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	},
	gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	},
}

func Test_gfP12Square(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}
	xmulx := &gfP12{}
	xmulx.Mul(x, x)
	xmulx = gfP12Decode(xmulx)

	x2 := &gfP12{}
	x2.Square(x)
	x2 = gfP12Decode(x2)

	if xmulx.x != x2.x || xmulx.y != x2.y || xmulx.z != x2.z {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
}

func TestSpecialSquare(t *testing.T) {
	in := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}

	// This is the p^6-Frobenius
	t1 := (&gfP12{}).FrobeniusP6(in)

	inv := (&gfP12{}).Invert(in)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)            // t1 = in ^ ((p^6 - 1) * (p^2 + 1)), the first two parts of the exponentiation

	got := &gfP12{}
	expected := &gfP12{}
	got.SpecialSquare(t1)
	expected.Square(t1)
	if *got != *expected {
		t.Errorf("not same got=%v, expected=%v", got, expected)
	}
}

func BenchmarkGfP12Square(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}
	x2 := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x2.Square(x)
	}
}

func BenchmarkGfP12SpecialSquare(b *testing.B) {
	in := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}

	// This is the p^6-Frobenius
	t1 := (&gfP12{}).FrobeniusP6(in)

	inv := (&gfP12{}).Invert(in)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)            // t1 = in ^ ((p^6 - 1) * (p^2 + 1)), the first two parts of the exponentiation
	x2 := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x2.Square(t1)
	}
}

func BenchmarkGfP12SpecialSqures(b *testing.B) {
	in := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}

	// This is the p^6-Frobenius
	t1 := (&gfP12{}).FrobeniusP6(in)

	inv := (&gfP12{}).Invert(in)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)            // t1 = in ^ ((p^6 - 1) * (p^2 + 1)), the first two parts of the exponentiation
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.SpecialSquares(in, 61)
	}
}

func testGfP12Invert(t *testing.T, x *gfP12) {
	xInv := &gfP12{}
	xInv.Invert(x)

	y := &gfP12{}
	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
}

func Test_gfP12Invert(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}
	testGfP12Invert(t, x)
	x = &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetZero(),
	}
	testGfP12Invert(t, x)
	x = &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	testGfP12Invert(t, x)
}

// Generate wToPMinus1
func Test_gfP12Frobenius_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	i.Exp(i, pMinus1)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b")))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToPMinus1
func Test_gfP12Frobenius_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	i.Exp(i, pMinus1)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate wToP2Minus1
func Test_gfP12FrobeniusP2_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	i.Exp(i, p2)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToP2Minus1
func Test_gfP12FrobeniusP2_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	i.Exp(i, p2)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate wToP3Minus1
func Test_gfP12FrobeniusP3_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	p3 = new(big.Int).Sub(p3, big.NewInt(1))
	i.Exp(i, p3)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011")))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToP3minus1
func Test_gfP12FrobeniusP3_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	p3 = new(big.Int).Sub(p3, big.NewInt(1))
	i.Exp(i, p3)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(fromBigInt(bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))) // -1
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

func Test_gfP12Frobenius(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	expected := &gfP12{}
	expected.Exp(x, p)
	got := &gfP12{}
	got.Frobenius(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP2(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	expected := &gfP12{}
	p2 := new(big.Int).Mul(p, p)
	expected.Exp(x, p2)
	got := &gfP12{}
	got.FrobeniusP2(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP3(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	expected := &gfP12{}
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	expected.Exp(x, p3)
	got := &gfP12{}
	got.FrobeniusP3(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP6(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	expected := &gfP12{}
	p6 := new(big.Int).Mul(p, p)
	p6.Mul(p6, p)
	p6.Mul(p6, p6)
	expected.Exp(x, p6)
	got := &gfP12{}
	got.FrobeniusP6(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_W3(t *testing.T) {
	w1 := (&gfP12{}).SetW()
	w2 := (&gfP12{}).SetW2()

	w1.Mul(w2, w1)
	w1 = gfP12Decode(w1)
	gfp4zero := (&gfP4{}).SetZero()
	gfp4v := (&gfP4{}).SetV()
	gfp4v = gfP4Decode(gfp4v)
	if w1.x != *gfp4zero || w1.y != *gfp4zero || w1.z != *gfp4v {
		t.Errorf("not expected")
	}
}

func BenchmarkGfP12Invert(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Invert(x)
	}
}

func BenchmarkGfP12Frobenius(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	expected := &gfP12{}
	expected.Exp(x, p)
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Frobenius(x)
		if *expected != *got {
			b.Errorf("got %v, expected %v", got, expected)
		}
	}
}

func BenchmarkGfP12Mul(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Mul(x, x)
	}
}

func BenchmarkGfP12Squre(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Square(x)
	}
}

func BenchmarkGfP12Squres(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Squares(x, 61)
	}
}

func BenchmarkGfP12ExpU(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.gfP12ExpU(x)
		got.gfP12ExpU(x)
		got.gfP12ExpU(x)
	}
}

func BenchmarkGfP12ExpU2(b *testing.B) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		testdataP4,
	}
	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Exp(x, u)
		got.Exp(x, u)
		got.Exp(x, u)
	}
}
