package bn256

import (
	"math/big"
	"testing"
)

func TestGfp4BasicOperations(t *testing.T) {
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
	y := &gfP4{}
	y.x.Set(&x.y)
	y.y.Set(&x.x)

	expectedAdd := "((5bf55bb67d25f098609a367366d94d6599da7405db44c388edb64706908922e4, 728185f97d3df3a01d3ad2a0e140d12011e10fa47d50fd12e6413a361e549cd9), (5bf55bb67d25f098609a367366d94d6599da7405db44c388edb64706908922e4, 728185f97d3df3a01d3ad2a0e140d12011e10fa47d50fd12e6413a361e549cd9))"
	expectedSub := "((0e6cca2ef0f4dce3fa4a249bb48a25d84dbf1f63ac843004e3b586d5dac6e8eb, 51785a37fb519603d4b026648151d768ebe9b9193a9c83c365c31316fb711845), (a7d335d111aeca0ddbb986b44104a16cd43373e76df6bed701ba1452088a5c92, 64c7a5c8075210ee015384eb743cefdc3608da31dfde6b187fac8810e7e02d38))"
	expectedMul := "((5f318c234b817377df2179ff82a0759c6b926330853e5abd919e45a6a93e658e, 3c9db0f3bbdb89a9a407dfec4f8f4d6b8ef35b2a3f05e7bcc9bb6a956876faf7), (3ef93f2e9fa8c29914fd823d04d243503646107711ec6068eb28c59946d24878, 2caf5e47bc5be242917002b1f89afaf5ff27ebafcb9a7bcdab917c82b6a4cb41))"
	expectedMulV := "((3ef93f2e9fa8c29914fd823d04d243503646107711ec6068eb28c59946d24878, 2caf5e47bc5be242917002b1f89afaf5ff27ebafcb9a7bcdab917c82b6a4cb41), (3c9db0f3bbdb89a9a407dfec4f8f4d6b8ef35b2a3f05e7bcc9bb6a956876faf7, ae1ce7b96e4466f3edc462a0e5dca3516cc060352a79283ca7a2ab027425bfde))"

	t.Parallel()
	t.Run("Add", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Add(got, y)
		if got.String() != expectedAdd {
			t.Errorf("got %v, expected %v", got, expectedAdd)
		}
	})

	t.Run("Sub", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Sub(got, y)
		if got.String() != expectedSub {
			t.Errorf("got %v, expected %v", got, expectedSub)
		}
	})

	t.Run("Mul", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Mul(got, y)
		if got.String() != expectedMul {
			t.Errorf("got %v, expected %v", got, expectedMul)
		}
	})

	t.Run("MulV", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.MulV(got, y)
		if got.String() != expectedMulV {
			t.Errorf("got %v, expected %v", got, expectedMulV)
		}
	})

	t.Run("Double", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Double(got)

		expected := &gfP4{}
		expected.Add(x, x)
		if got.x.Equal(&expected.x) != 1 || got.y.Equal(&expected.y) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("Triple", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Triple(got)

		expected := &gfP4{}
		expected.Add(x, x)
		expected.Add(expected, x)
		if got.x.Equal(&expected.x) != 1 || got.y.Equal(&expected.y) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("Square", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.Square(got)

		expected := &gfP4{}
		expected.Mul(x, x)
		if got.x.Equal(&expected.x) != 1 || got.y.Equal(&expected.y) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})

	t.Run("SquareV", func(t *testing.T) {
		got := &gfP4{}
		got.Set(x)
		got.SquareV(got)

		expected := &gfP4{}
		expected.MulV(x, x)
		if got.x.Equal(&expected.x) != 1 || got.y.Equal(&expected.y) != 1 {
			t.Errorf("got %v, expected %v", got, expected)
		}
	})
}

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
	t := &gfP4{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Mul(x, y)
	}
}

func BenchmarkGfP4Square(b *testing.B) {
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
	t := &gfP4{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Square(x)
	}
}
