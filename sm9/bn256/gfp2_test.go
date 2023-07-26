package bn256

import (
	"math/big"
	"testing"
)

func TestGfp2BasicOperations(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	y := &gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	}
	expectedAdd := "(5bf55bb67d25f098609a367366d94d6599da7405db44c388edb64706908922e4, 728185f97d3df3a01d3ad2a0e140d12011e10fa47d50fd12e6413a361e549cd9)"
	expectedSub := "(0e6cca2ef0f4dce3fa4a249bb48a25d84dbf1f63ac843004e3b586d5dac6e8eb, 51785a37fb519603d4b026648151d768ebe9b9193a9c83c365c31316fb711845)"
	expectedMul := "(7f98a04cf83164be0fdc4763a7c6f24c2901191f2917eb71037cd5221cf002bb, 75a09ee1aa1b04ccdb24e629529a18492f378aa3034f63d3cd1b8b9f0d338b3a)"
	expectedMulU := "(75a09ee1aa1b04ccdb24e629529a18492f378aa3034f63d3cd1b8b9f0d338b3a, 6d4ebf6614e484678c4ec7d89b8fa9f1f1e2f457e2c606d5c3e58c0b8cc28584)"
	t.Run("Add", func(t *testing.T) {
		ret := &gfP2{}
		ret.Add(x, y)
		if ret.String() != expectedAdd {
			t.Errorf("expected %v, got %v", expectedAdd, ret)
		}
		ret.Set(x)
		ret.Add(ret, y)
		if ret.String() != expectedAdd {
			t.Errorf("add self fail, expected %v, got %v", expectedAdd, ret)
		}
		ret.Set(y)
		ret.Add(x, ret)
		if ret.String() != expectedAdd {
			t.Errorf("add self fail, expected %v, got %v", expectedAdd, ret)
		}
	})

	t.Run("Sub", func(t *testing.T) {
		ret := &gfP2{}
		ret.Sub(x, y)
		if ret.String() != expectedSub {
			t.Errorf("expected %v, got %v", expectedSub, ret)
		}
		ret.Set(x)
		ret.Sub(ret, y)
		if ret.String() != expectedSub {
			t.Errorf("sub self fail, expected %v, got %v", expectedSub, ret)
		}
		ret.Set(y)
		ret.Sub(x, ret)
		if ret.String() != expectedSub {
			t.Errorf("sub self fail, expected %v, got %v", expectedSub, ret)
		}
	})

	t.Run("Double", func(t *testing.T) {
		expected := &gfP2{}
		expected.Set(x)
		expected.Add(expected, expected)

		got := &gfP2{}
		got.Set(x)
		got.Double(got)
		if got.Equal(expected) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("Triple", func(t *testing.T) {
		expected := &gfP2{}
		expected.Set(x)
		expected.Add(expected, expected)
		expected.Add(expected, x)
		got := &gfP2{}
		got.Set(x)
		got.Triple(got)
		if got.Equal(expected) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("Mul", func(t *testing.T) {
		got := &gfP2{}
		got.Set(x)
		got.Mul(got, y)
		if got.String() != expectedMul {
			t.Errorf("got %v, expected %v", got, expectedMul)
		}
	})

	t.Run("MulU", func(t *testing.T) {
		got := &gfP2{}
		got.Set(x)
		got.MulU(got, y)
		if got.String() != expectedMulU {
			t.Errorf("got %v, expected %v", got, expectedMulU)
		}
	})

	t.Run("Square", func(t *testing.T) {
		expected := &gfP2{}
		expected.Mul(x, x)
		got := &gfP2{}
		got.Set(x)
		got.Square(got)
		if got.Equal(expected) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("SquareU", func(t *testing.T) {
		expected := &gfP2{}
		expected.MulU(x, x)
		got := &gfP2{}
		got.Set(x)
		got.SquareU(got)
		if got.Equal(expected) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})
}

func Test_gfP2Invert(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}

	xInv := &gfP2{}
	xInv.Invert(x)

	y := &gfP2{}
	y.Mul(x, xInv)
	expected := (&gfP2{}).SetOne()

	if y.x != expected.x || y.y != expected.y {
		t.Errorf("got %v, expected %v", y, expected)
	}

	x = &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*zero,
	}

	xInv.Invert(x)

	y.Mul(x, xInv)

	if y.x != expected.x || y.y != expected.y {
		t.Errorf("got %v, expected %v", y, expected)
	}

	x = &gfP2{
		*zero,
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}

	xInv.Invert(x)

	y.Mul(x, xInv)

	if y.x != expected.x || y.y != expected.y {
		t.Errorf("got %v, expected %v", y, expected)
	}
}

func Test_gfP2Exp(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	}
	got := &gfP2{}
	got.Exp(x, big.NewInt(1))
	if x.x != got.x || x.y != got.y {
		t.Errorf("got %v, expected %v", got, x)
	}
}

func Test_gfP2Frobenius(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	expected := &gfP2{}
	expected.Exp(x, p)
	got := &gfP2{}
	got.Frobenius(x)
	if expected.x != got.x || expected.y != got.y {
		t.Errorf("got %v, expected %v", got, x)
	}

	// make sure i^(p-1) = -1
	i := &gfP2{}
	i.SetU()
	i.Exp(i, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))
	i = gfP2Decode(i)
	expected.y.Set(newGFp(-1))
	expected.x.Set(zero)
	expected = gfP2Decode(expected)
	if expected.x != i.x || expected.y != i.y {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

func Test_gfP2Sqrt(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	x2, x3, sqrt, sqrtNeg := &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}
	x2.Mul(x, x)
	sqrt.Sqrt(x2)
	sqrtNeg.Neg(sqrt)
	x3.Mul(sqrt, sqrt)

	if *x3 != *x2 {
		t.Errorf("not correct")
	}

	if *sqrt != *x && *sqrtNeg != *x {
		t.Errorf("sqrt not expected")
	}
}

func BenchmarkGfP2Mul(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	y := &gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	}
	t := &gfP2{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Mul(x, y)
	}
}

func BenchmarkGfP2MulU(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	y := &gfP2{
		*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
		*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
	}

	t := &gfP2{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.MulU(x, y)
	}
}

func BenchmarkGfP2Square(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Square(x)
	}
}

func BenchmarkGfP2SquareU(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.SquareU(x)
	}
}

func BenchmarkGfP2Neg(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gfpNeg(&x.x, &x.x)
		gfpNeg(&x.y, &x.y)
	}
}

func BenchmarkGfP2Neg2(b *testing.B) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gfpSub(&x.x, zero, &x.x)
		gfpSub(&x.y, zero, &x.y)
	}
}

/*
func Test_gfP2QuadraticResidue(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}
	n := bigFromHex("40df880001e10199aa9f985292a7740a5f3e998ff60a2401e81d08b99ba6f8ff691684e427df891a9250c20f55961961fe81f6fc785a9512ad93e28f5cfb4f84")
	y := &gfP2{}
	x2 := &gfP2{}
	x2.Exp(x, n)
	x2 = gfP2Decode(x2)
	fmt.Printf("%v\n", x2)
	for {
		k, err := randomK(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		x2.Exp(x, k)
		y.Exp(x2, n)
		if y.x == *zero && y.y == *one {
			break
		}
	}
	x2 = gfP2Decode(x2)
	fmt.Printf("%v\n", x2)
}
*/
