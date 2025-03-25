package bn256

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func fromBigInt(x *big.Int) (out *gfP) {
	var buf [32]byte
	x.FillBytes(buf[:])
	return newGFpFromBytes(buf[:])
}

func newGFpFromHex(x string) (out *gfP) {
	return fromBigInt(bigFromHex(x))
}

func TestGfpBasicOperations(t *testing.T) {
	x := newGFpFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")
	y := newGFpFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")
	expectedAdd := newGFpFromHex("0691692307d370af56226e57920199fbbe10f216c67fbc9468c7f225a4b1f21f")
	expectedDouble := newGFpFromHex("551de7a0ee24723edcf314ff72f478fac1c7c4e7044238acc3913cfbcdaf7d05")
	expectedSub := newGFpFromHex("67b381821c52a5624f3304a8149be8461e3bc07adcb872c38aa65051ba53ba97")
	expectedNeg := newGFpFromHex("7f1d8aad70909be90358f1d02240062433cc3a0248ded72febb879ec33ce6f22")
	expectedMul := newGFpFromHex("3d08bbad376584e4f74bd31f78f716372b96ba8c3f939c12b8d54e79b6489e76")
	expectedMul2 := newGFpFromHex("1df94a9e05a559ff38e0ab50cece734dc058d33738ceacaa15986a67cbff1ef6")

	t.Parallel()
	t.Run("add", func(t *testing.T) {
		ret := &gfP{}
		gfpAdd(ret, x, y)
		if *expectedAdd != *ret {
			t.Errorf("add not same")
		}
		x1 := &gfP{}
		x1.Set(x)
		gfpAdd(x1, x1, y)
		if *expectedAdd != *x1 {
			t.Errorf("add not same when add self")
		}
	})

	t.Run("double", func(t *testing.T) {
		ret := &gfP{}
		gfpDouble(ret, x)
		if ret.Equal(expectedDouble) != 1 {
			t.Errorf("double not same, got %v, expected %v", ret, expectedDouble)
		}
		ret.Set(x)
		gfpDouble(ret, ret)
		if ret.Equal(expectedDouble) != 1 {
			t.Errorf("double not same, got %v, expected %v", ret, expectedDouble)
		}
	})

	t.Run("triple", func(t *testing.T) {
		expected := &gfP{}
		gfpAdd(expected, x, expectedDouble)
		ret := &gfP{}
		ret.Set(x)
		gfpTriple(ret, ret)
		if ret.Equal(expected) != 1 {
			t.Errorf("expected %v, got %v", expected, ret)
		}
	})

	t.Run("sub", func(t *testing.T) {
		ret := &gfP{}
		gfpSub(ret, y, x)
		if *expectedSub != *ret {
			t.Errorf("sub not same")
		}
		x1 := &gfP{}
		x1.Set(x)
		gfpSub(x1, y, x1)
		if *expectedSub != *x1 {
			t.Errorf("sub not same when sub self")
		}
	})

	t.Run("neg", func(t *testing.T) {
		ret := &gfP{}
		gfpNeg(ret, y)
		if *expectedNeg != *ret {
			t.Errorf("neg not same")
		}
		ret.Set(y)
		gfpNeg(ret, ret)
		if *expectedNeg != *ret {
			t.Errorf("neg not same when neg self")
		}
	})

	t.Run("mul", func(t *testing.T) {
		ret := &gfP{}
		gfpMul(ret, x, y)
		if *expectedMul != *ret {
			t.Errorf("mul not same")
		}
		ret.Set(x)
		gfpMul(ret, ret, y)
		if *expectedMul != *ret {
			t.Errorf("mul not same when mul self")
		}
	})

	t.Run("square", func(t *testing.T) {
		ret, ret1, ret2 := &gfP{}, &gfP{}, &gfP{}
		gfpMul(ret, x, y)
		gfpMul(ret1, ret, ret)
		if *ret1 != *expectedMul2 {
			t.Errorf("mul not same")
		}
		gfpMul(ret1, ret1, ret1)
		gfpSqr(ret2, ret, 2)
		if *ret1 != *ret2 {
			t.Errorf("mul/sqr not same")
		}
		ret2.Set(ret)
		gfpSqr(ret2, ret2, 2)
		if *ret1 != *ret2 {
			t.Errorf("mul/sqr not same when square self")
		}
	})
}

func TestGfpSqr(t *testing.T) {
	t.Run("p-1", func(t *testing.T) {
		pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
		x := fromBigInt(pMinusOne)
		ret := &gfP{}
		gfpSqr(ret, x, 1)
		pMinusOne.Mul(pMinusOne, pMinusOne)
		pMinusOne.Mod(pMinusOne, p)
		expected := fromBigInt(pMinusOne)
		if *ret != *expected {
			t.Errorf("bad sqr")
		}
	})
	t.Run("p+1", func(t *testing.T) {
		pPlusOne := new(big.Int).Add(p, big.NewInt(1))
		x := fromBigInt(pPlusOne)
		ret := &gfP{}
		gfpSqr(ret, x, 1)
		pPlusOne.Mul(pPlusOne, pPlusOne)
		pPlusOne.Mod(pPlusOne, p)
		if *ret != *fromBigInt(pPlusOne) {
			t.Errorf("bad sqr")
		}
	})
}

func TestFromMont(t *testing.T) {
	x := newGFpFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")
	ret1, ret2 := &gfP{}, &gfP{}
	gfpFromMont(ret1, x)
	gfpMul(ret2, x, &gfP{1})
	if *ret1 != *ret2 {
		t.Errorf("mul/fromMont not same")
	}
}

func TestGfpExp(t *testing.T) {
	xI := bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	x := fromBigInt(xI)
	ret, ret3 := &gfP{}, &gfP{}
	ret.exp(x, pMinus2)

	gfpMul(ret3, x, ret)
	if *ret3 != *one {
		t.Errorf("got %v, expected %v\n", ret3, one)
	}
	montDecode(ret, ret)

	ret2 := new(big.Int).Exp(xI, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b"), p)
	if hex.EncodeToString(ret2.Bytes()) != ret.String() {
		t.Errorf("exp not same, got %v, expected %v\n", ret, hex.EncodeToString(ret2.Bytes()))
	}

	xInv := new(big.Int).ModInverse(xI, p)
	if hex.EncodeToString(ret2.Bytes()) != hex.EncodeToString(xInv.Bytes()) {
		t.Errorf("exp not same, got %v, expected %v\n", hex.EncodeToString(ret2.Bytes()), hex.EncodeToString(xInv.Bytes()))
	}

	x2 := new(big.Int).Mul(xI, xInv)
	x2.Mod(x2, p)
	if big.NewInt(1).Cmp(x2) != 0 {
		t.Errorf("not same")
	}

	xInvGfp := fromBigInt(xInv)
	gfpMul(ret, x, xInvGfp)
	if *ret != *one {
		t.Errorf("got %v, expected %v", ret, one)
	}
}

func TestSqrt(t *testing.T) {
	tests := []string{
		"9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596",
		"92fe90b700fbd4d8cc177d300ed16e4e15471a681b2c9e3728c1b82c885e49c2",
	}
	for i, test := range tests {
		y2 := bigFromHex(test)
		y21 := new(big.Int).ModSqrt(y2, p)

		y3 := new(big.Int).Mul(y21, y21)
		y3.Mod(y3, p)
		if y2.Cmp(y3) != 0 {
			t.Error("Invalid sqrt")
		}

		tmp := fromBigInt(y2)
		tmp.Sqrt(tmp)
		montDecode(tmp, tmp)
		var res [32]byte
		tmp.Marshal(res[:])
		if hex.EncodeToString(res[:]) != hex.EncodeToString(y21.Bytes()) {
			t.Errorf("case %v, got %v, expected %v\n", i, hex.EncodeToString(res[:]), hex.EncodeToString(y21.Bytes()))
		}
	}
}

func TestGeneratedSqrt(t *testing.T) {
	tests := []string{
		"9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596",
		"92fe90b700fbd4d8cc177d300ed16e4e15471a681b2c9e3728c1b82c885e49c2",
	}
	for i, test := range tests {
		y2 := bigFromHex(test)
		y21 := new(big.Int).ModSqrt(y2, p)

		y3 := new(big.Int).Mul(y21, y21)
		y3.Mod(y3, p)
		if y2.Cmp(y3) != 0 {
			t.Error("Invalid sqrt")
		}

		tmp := fromBigInt(y2)
		e := &gfP{}
		Sqrt(e, tmp)
		montDecode(e, e)
		var res [32]byte
		e.Marshal(res[:])
		if hex.EncodeToString(res[:]) != hex.EncodeToString(y21.Bytes()) {
			t.Errorf("case %v, got %v, expected %v\n", i, hex.EncodeToString(res[:]), hex.EncodeToString(y21.Bytes()))
		}
	}
}

func TestInvert(t *testing.T) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	xInv := &gfP{}
	xInv.Invert(x)
	y := &gfP{}
	gfpMul(y, x, xInv)
	if *y != *one {
		t.Errorf("got %v, expected %v", y, one)
	}
}

func TestGfpNeg(t *testing.T) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	got := &gfP{}
	gfpSub(got, zero, x)
	expected := &gfP{}
	gfpNeg(expected, x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
	gfpSub(got, zero, zero)
	gfpNeg(expected, zero)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func BenchmarkGfPUnmarshal(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	var out [32]byte
	x.Marshal(out[:])
	for i := 0; i < b.N; i++ {
		x.Unmarshal(out[:])
	}
}

func BenchmarkGfPMul(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpMul(ret, x, x)
	}
}

func BenchmarkGfPSqr(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpSqr(ret, x, 1)
	}
}

func BenchmarkGfPTriple(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpTriple(ret, x)
	}
}

func BenchmarkGfPTriple2(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpAdd(ret, x, x)
		gfpAdd(ret, ret, x)
	}
}

func BenchmarkGfPDouble(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpDouble(ret, x)
	}
}

func BenchmarkGfPDouble2(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpAdd(ret, x, x)
	}
}

func BenchmarkGfPNeg(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpNeg(ret, x)
	}
}

func BenchmarkGfPNeg2(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpSub(ret, zero, x)
	}
}

func BenchmarkGfPInvert(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		ret.Invert(x)
	}
}

func BenchmarkGfPInvert2(b *testing.B) {
	x := newGFpFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		ret.exp(x, pMinus2)
	}
}
