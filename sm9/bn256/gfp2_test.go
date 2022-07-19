package bn256

import (
	"math/big"
	"testing"
)

func Test_gfP2Square(t *testing.T) {
	x := &gfP2{
		*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
		*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
	}

	xmulx := &gfP2{}
	xmulx.Mul(x, x)
	xmulx = gfP2Decode(xmulx)

	x2 := &gfP2{}
	x2.Square(x)
	x2 = gfP2Decode(x2)

	if xmulx.x != x2.x || xmulx.y != x2.y {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
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
