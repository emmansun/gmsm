package bn256

import (
	"math/big"
	"testing"
)

var testdataP4 = gfP4{
	gfP2{
		*newGFpFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"),
		*newGFpFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"),
	},
	gfP2{
		*newGFpFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96"),
		*newGFpFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7"),
	},
}

func TestGfp12BasicOperations(t *testing.T) {
	x := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}
	y := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetZero(),
	}

	t.Parallel()
	t.Run("Add", func(t *testing.T) {
		expectedAdd := "(((6a6225e56e1acd7c5ae45b0f1b63733de799936987c8f38dd16bcddc6b500bcf, 0db9e03175ebe2b21be74db56d03e143dbd835729d7291fa6694b22536746fa1), (4d8891878c3113b4665011d7b24f278d4c1b54a22ec093840a00c030b5c239f9, 21092bc181ec5d9c488aac3c5feef9b725f7568b42b4794f807e271f22e38494)), ((6a6225e56e1acd7c5ae45b0f1b63733de799936987c8f38dd16bcddc6b500bcf, 0db9e03175ebe2b21be74db56d03e143dbd835729d7291fa6694b22536746fa1), (4d8891878c3113b4665011d7b24f278d4c1b54a22ec093840a00c030b5c239f9, 21092bc181ec5d9c488aac3c5feef9b725f7568b42b4794f807e271f22e38494)), ((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83)))"
		got := &gfP12{}
		got.Set(x)
		got.Add(got, y)

		if got.String() != expectedAdd {
			t.Errorf("got %v, expected %v", got, expectedAdd)
		}
	})

	t.Run("Sub", func(t *testing.T) {
		expectedSub := "(((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000)), ((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000)), ((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83)))"
		got := &gfP12{}
		got.Set(x)
		got.Sub(got, y)

		if got.String() != expectedSub {
			t.Errorf("got %v, expected %v", got, expectedSub)
		}
	})

	t.Run("Mul", func(t *testing.T) {
		expectedMul := "(((2302538ca37ab5cf8c253b56ece9734f92e31f026e5bea5f178828769a8e2322, 96fe2ddc0dda2779d93b9d8560eebd91bb61e659c81a9936dac9a2bcc3f8ab86), (2c371ba768b6f660eaba367b2c444295e529efc2a5ad95d8f80265235ad4c6c9, 4f24d79c798eb4d8c2005bf43cb955f5420baf40650c750f4f0f1c0a11882a1c)), ((3aa3e5d659abd344e5045b16e0ce686e32e90f265231c5dddbb7ebf9359bafb4, a09d31d474e04adc96b08258be0b2d5e2df568599fa8f8d2b4d22f210cf94261), (00a5868716591909286c54468e0599715190e2a67646ab1fc7100e9aa04e4b35, 34e214ace81b90ab66df3a7f7188097a54cf00aa4c6b5b77629a907ec7a587d5)), ((0ae5a5c7453cd90d6f245b1ea6395d9e7e388ae31c9a982de6040a15ffe75399, 7d40837771310c153b760bac1983b2335e2007f5876470cf1da010f5002ccfa4), (6a027b86a324c54fc08c42055f4ad29a78f903f5d847b197698ef82c6e2ba1ee, 48bafd984e4ac3ba8533c8c28321193d83a6aac956223d9f44b6f9de6c678b16)))"
		got := &gfP12{}
		got.Set(x)
		got.Mul(got, y)

		if got.String() != expectedMul {
			t.Errorf("got %v, expected %v", got, expectedMul)
		}
	})

	t.Run("Square", func(t *testing.T) {
		got := &gfP12{}
		got.Set(x)
		got.Square(got)

		expected := (&gfP12{}).Mul(x, x)

		if *expected != *got {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})
}

func TestGfp12Order(t *testing.T) {
	in := &gfP12{
		testdataP4,
		testdataP4,
		*(&gfP4{}).SetOne(),
	}

	p6 := (&gfP12{}).FrobeniusP6(in)
	p12 := (&gfP12{}).FrobeniusP6(p6)
	if *p12 != *in {
		t.Errorf("in^(p^12) not equal with in")
	}

	p2 := (&gfP12{}).FrobeniusP2(in)
	p4 := (&gfP12{}).FrobeniusP2(p2)
	p6_1 := (&gfP12{}).FrobeniusP2(p4)
	p8 := (&gfP12{}).FrobeniusP2(p6_1)
	p10 := (&gfP12{}).FrobeniusP2(p8)
	p12_1 := (&gfP12{}).FrobeniusP2(p10)
	if *p12_1 != *in {
		t.Errorf("in^(p^12) not equal with in")
	}

	p3 := (&gfP12{}).FrobeniusP3(in)
	p6_2 := (&gfP12{}).FrobeniusP3(p3)
	p9 := (&gfP12{}).FrobeniusP3(p6_2)
	p12_2 := (&gfP12{}).FrobeniusP3(p9)
	if *p12_2 != *in {
		t.Errorf("in^(p^12) not equal with in")
	}
}

func TestCyclo6Square(t *testing.T) {
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

	one := (&gfP12{}).SetOne()
	t3 := (&gfP12{}).FrobeniusP2(t1)
	t4 := (&gfP12{}).FrobeniusP2(t3)
	t5 := (&gfP12{}).Invert(t3)
	t5.Mul(t4, t5).Mul(t1, t5)
	if *t5 != *one {
		t.Errorf("t1 should be in Cyclotomic Subgroup")
	}

	got := &gfP12{}
	expected := &gfP12{}
	got.Cyclo6Square(t1)
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

func BenchmarkGfP12Cyclo6Square(b *testing.B) {
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
		x2.Cyclo6Square(t1)
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
		got.Cyclo6Squares(in, 61)
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
	expected.z.y.y.Set(newGFpFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b"))
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
	expected.z.y.y.Set(newGFpFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))
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
	expected.z.y.y.Set(newGFpFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))
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
	expected.z.y.y.Set(newGFpFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333"))
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
	expected.z.y.y.Set(newGFpFromHex("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011"))
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
	expected.z.y.y.Set(newGFpFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c")) // -1
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
	// This is the p^6-Frobenius
	t1 := (&gfP12{}).FrobeniusP6(x)

	inv := (&gfP12{}).Invert(x)
	t1.Mul(t1, inv)

	t2 := inv.FrobeniusP2(t1) // reuse inv
	t1.Mul(t1, t2)            // t1 = in ^ ((p^6 - 1) * (p^2 + 1)), the first two parts of the exponentiation

	got := &gfP12{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got.Cyclo6PowToU(t1)
		got.Cyclo6PowToU(t1)
		got.Cyclo6PowToU(t1)
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
