package bn256

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func Test_gfpBasicOperations(t *testing.T) {
	x := fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"))
	y := fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"))
	expectedAdd := fromBigInt(bigFromHex("0691692307d370af56226e57920199fbbe10f216c67fbc9468c7f225a4b1f21f"))
	expectedSub := fromBigInt(bigFromHex("67b381821c52a5624f3304a8149be8461e3bc07adcb872c38aa65051ba53ba97"))
	expectedNeg := fromBigInt(bigFromHex("7f1d8aad70909be90358f1d02240062433cc3a0248ded72febb879ec33ce6f22"))
	expectedMul := fromBigInt(bigFromHex("3d08bbad376584e4f74bd31f78f716372b96ba8c3f939c12b8d54e79b6489e76"))
	expectedMul2 := fromBigInt(bigFromHex("1df94a9e05a559ff38e0ab50cece734dc058d33738ceacaa15986a67cbff1ef6"))

	ret := &gfP{}
	gfpAdd(ret, x, y)
	if *expectedAdd != *ret {
		t.Errorf("add not same")
	}

	gfpSub(ret, y, x)
	if *expectedSub != *ret {
		t.Errorf("sub not same")
	}

	gfpNeg(ret, y)
	if *expectedNeg != *ret {
		t.Errorf("neg not same")
	}

	gfpMul(ret, x, y)
	if *expectedMul != *ret {
		t.Errorf("mul not same")
	}

	ret1, ret2 := &gfP{}, &gfP{}
	gfpMul(ret1, ret, ret)
	if *ret1 != *expectedMul2 {
		t.Errorf("mul not same")
	}
	gfpMul(ret1, ret1, ret1)
	gfpSqr(ret2, ret, 2)
	if *ret1 != *ret2 {
		t.Errorf("mul/sqr not same")
	}
}

func Test_gfpSqr(t *testing.T) {
	// p - 1
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	x := fromBigInt(pMinusOne)
	ret := &gfP{}
	gfpSqr(ret, x, 1)
	pMinusOne.Mul(pMinusOne, pMinusOne)
	pMinusOne.Mod(pMinusOne, p)
	if *ret != *fromBigInt(pMinusOne) {
		t.Errorf("bad sqr")
	}
	// p + 1
	pPlusOne := new(big.Int).Add(p, big.NewInt(1))
	x = fromBigInt(pPlusOne)
	gfpSqr(ret, x, 1)
	pPlusOne.Mul(pPlusOne, pPlusOne)
	pPlusOne.Mod(pPlusOne, p)
	if *ret != *fromBigInt(pPlusOne) {
		t.Errorf("bad sqr")
	}
}

func TestFromMont(t *testing.T) {
	x := fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"))
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
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	xInv := &gfP{}
	xInv.Invert(x)
	y := &gfP{}
	gfpMul(y, x, xInv)
	if *y != *one {
		t.Errorf("got %v, expected %v", y, one)
	}
}

func BenchmarkGfPMul(b *testing.B) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpMul(ret, x, x)
	}
}

func BenchmarkGfPSqr(b *testing.B) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	b.ReportAllocs()
	b.ResetTimer()
	ret := &gfP{}
	for i := 0; i < b.N; i++ {
		gfpSqr(ret, x, 1)
	}
}
