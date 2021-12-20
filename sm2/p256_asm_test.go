//go:build amd64 || arm64
// +build amd64 arm64

package sm2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func toBigInt(in []uint64) *big.Int {
	var valBytes = make([]byte, 32)
	p256LittleToBig(valBytes, in)
	return new(big.Int).SetBytes(valBytes)
}

func Test_p256NegCond(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	var val = []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	bigVal := toBigInt(val)

	p256NegCond(val, 0)
	bigVal1 := toBigInt(val)
	if bigVal.Cmp(bigVal1) != 0 {
		t.Fatal("should be same")
	}
	p256NegCond(val, 1)
	bigVal1 = toBigInt(val)
	if bigVal.Cmp(bigVal1) == 0 {
		t.Fatal("should be different")
	}
	bigVal2 := new(big.Int).Sub(p, bigVal)
	if bigVal2.Cmp(bigVal1) != 0 {
		t.Fatal("should be same")
	}
}

func Test_p256FromMont(t *testing.T) {
	res := make([]uint64, 4)
	p256FromMont(res, []uint64{0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000})
	res1 := (res[0] ^ 0x0000000000000001) | res[1] | res[2] | res[3]
	if res1 != 0 {
		t.FailNow()
	}
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	x1 := make([]uint64, 4)
	p256BigToLittle(x1, x.Bytes())

	p256FromMont(res, []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05})
	if (res[0]^x1[0])|(res[1]^x1[1])|(res[2]^x1[2])|(res[3]^x1[3]) != 0 {
		t.FailNow()
	}
}

func Test_p256Sqr(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	one := []uint64{0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000}
	res := make([]uint64, 4)
	p256Sqr(res, one, 2)
	if (res[0]^one[0])|(res[1]^one[1])|(res[2]^one[2])|(res[3]^one[3]) != 0 {
		t.FailNow()
	}
	gx := []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	p256Sqr(res, gx, 2)
	resInt := toBigInt(res)
	fmt.Printf("1=%s\n", hex.EncodeToString(resInt.Bytes()))
	gxsqr := new(big.Int).Mul(x, x)
	gxsqr = new(big.Int).Mod(gxsqr, p)
	gxsqr = new(big.Int).Mul(gxsqr, gxsqr)
	gxsqr = new(big.Int).Mod(gxsqr, p)
	gxsqr = new(big.Int).Mul(gxsqr, r)
	gxsqr = new(big.Int).Mod(gxsqr, p)
	fmt.Printf("2=%s\n", hex.EncodeToString(gxsqr.Bytes()))
	if resInt.Cmp(gxsqr) != 0 {
		t.FailNow()
	}
}

func Test_p256Mul(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	res := make([]uint64, 4)
	gx := []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	gy := []uint64{0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd}

	p256Mul(res, gx, gy)
	resInt := toBigInt(res)
	fmt.Printf("1=%s\n", hex.EncodeToString(resInt.Bytes()))
	xmy := new(big.Int).Mul(x, y)
	xmy = new(big.Int).Mod(xmy, p)
	xmy = new(big.Int).Mul(xmy, r)
	xmy = new(big.Int).Mod(xmy, p)
	fmt.Printf("2=%s\n", hex.EncodeToString(xmy.Bytes()))
	if resInt.Cmp(xmy) != 0 {
		t.FailNow()
	}
}

func Test_p256MulSqr(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	res := make([]uint64, 4)
	gx := []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}

	p256Sqr(res, gx, 32)
	resInt := toBigInt(res)
	fmt.Printf("0=%s\n", hex.EncodeToString(resInt.Bytes()))

	p256Mul(res, gx, gx)
	for i := 0; i < 31; i++ {
		p256Mul(res, res, res)
	}
	resInt1 := toBigInt(res)
	fmt.Printf("1=%s\n", hex.EncodeToString(resInt1.Bytes()))

	resInt2 := new(big.Int).Mod(x, p)

	for i := 0; i < 32; i++ {
		resInt2 = new(big.Int).Mul(resInt2, resInt2)
		resInt2 = new(big.Int).Mod(resInt2, p)
	}
	resInt2 = new(big.Int).Mul(resInt2, r)
	resInt2 = new(big.Int).Mod(resInt2, p)
	fmt.Printf("2=%s\n", hex.EncodeToString(resInt2.Bytes()))

	if resInt.Cmp(resInt2) != 0 || resInt1.Cmp(resInt2) != 0 {
		t.FailNow()
	}
}

func Test_p256OrdSqr(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	n, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	gx := make([]uint64, 4)
	res := make([]uint64, 4)
	xm := new(big.Int).Mul(x, r)
	xm = new(big.Int).Mod(xm, n)
	p256BigToLittle(gx, xm.Bytes())
	p256OrdMul(res, gx, gx)
	resInt := toBigInt(res)
	fmt.Printf("p256OrdMul=%s\n", hex.EncodeToString(resInt.Bytes()))
	gxsqr := new(big.Int).Mul(x, x)
	gxsqr = new(big.Int).Mod(gxsqr, n)
	gxsqr = new(big.Int).Mul(gxsqr, r)
	gxsqr = new(big.Int).Mod(gxsqr, n)
	fmt.Printf("2=%s\n", hex.EncodeToString(gxsqr.Bytes()))
	if resInt.Cmp(gxsqr) != 0 {
		t.FailNow()
	}
	p256OrdSqr(res, gx, 1)
	resInt = toBigInt(res)
	fmt.Printf("p256OrdSqr=%s\n", hex.EncodeToString(resInt.Bytes()))
	if resInt.Cmp(gxsqr) != 0 {
		t.FailNow()
	}
}

func Test_p256Inverse(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	gx := []uint64{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	res := make([]uint64, 4)
	p256Inverse(res, gx)
	resInt := toBigInt(res)
	fmt.Printf("p256Inverse=%s\n", hex.EncodeToString(resInt.Bytes()))
	xInv := new(big.Int).ModInverse(x, p)
	xInv = new(big.Int).Mul(xInv, r)
	xInv = new(big.Int).Mod(xInv, p)
	fmt.Printf("expected=%s\n", hex.EncodeToString(xInv.Bytes()))
	if resInt.Cmp(xInv) != 0 {
		t.FailNow()
	}
}

func Test_p256PointAddAsm_basepoint(t *testing.T) {
	curve1 := P256()
	params := curve1.Params()
	basePoint := []uint64{
		0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05,
		0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd,
		0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000,
	}
	in := make([]uint64, 12)
	res := make([]uint64, 12)
	copy(in, basePoint)
	p256PointDoubleAsm(res, in)
	n := p256PointAddAsm(res, res, in)
	fmt.Printf("n=%d\n", n)
	var r p256Point
	copy(r.xyz[:], res)
	x1, y1 := r.p256PointToAffine()
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x1.Bytes()), hex.EncodeToString(y1.Bytes()))

	x2, y2 := params.Double(params.Gx, params.Gy)
	x2, y2 = params.Add(params.Gx, params.Gy, x2, y2)
	fmt.Printf("x2=%s, y2=%s\n", hex.EncodeToString(x2.Bytes()), hex.EncodeToString(y2.Bytes()))
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.FailNow()
	}
}

func Test_p256PointDoubleAsm(t *testing.T) {
	basePoint := []uint64{
		0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05,
		0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd,
		0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000,
	}
	t1 := make([]uint64, 12)
	copy(t1, basePoint)
	for i := 0; i < 16; i++ {
		p256PointDoubleAsm(t1, t1)
	}
	var r p256Point
	copy(r.xyz[:], t1)
	x1, y1 := r.p256PointToAffine()
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x1.Bytes()), hex.EncodeToString(y1.Bytes()))
	curve1 := P256()
	params := curve1.Params()
	x2, y2 := params.Double(params.Gx, params.Gy)
	for i := 0; i < 15; i++ {
		x2, y2 = params.Double(x2, y2)
	}
	fmt.Printf("x2=%s, y2=%s\n", hex.EncodeToString(x2.Bytes()), hex.EncodeToString(y2.Bytes()))
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.FailNow()
	}
}

func Test_ScalarBaseMult(t *testing.T) {
	scalar := big.NewInt(0xffffffff)
	curve1 := P256()
	x1, y1 := curve1.ScalarBaseMult(scalar.Bytes())
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x1.Bytes()), hex.EncodeToString(y1.Bytes()))
	params := curve1.Params()
	x2, y2 := params.ScalarBaseMult(scalar.Bytes())
	fmt.Printf("x2=%s, y2=%s\n", hex.EncodeToString(x2.Bytes()), hex.EncodeToString(y2.Bytes()))
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.FailNow()
	}
}

func Test_p256PointAddAsm(t *testing.T) {
	curve1 := P256()
	params := curve1.Params()
	k1, _ := randFieldElement(params, rand.Reader)
	x1, y1 := params.ScalarBaseMult(k1.Bytes())
	k2, _ := randFieldElement(params, rand.Reader)
	x2, y2 := params.ScalarBaseMult(k2.Bytes())
	x3, y3 := params.Add(x1, y1, x2, y2)
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x3.Bytes()), hex.EncodeToString(y3.Bytes()))
	var in1, in2, rp p256Point
	fromBig(in1.xyz[0:4], maybeReduceModP(x1))
	fromBig(in1.xyz[4:8], maybeReduceModP(y1))
	fromBig(in2.xyz[0:4], maybeReduceModP(x2))
	fromBig(in2.xyz[4:8], maybeReduceModP(y2))
	in1.xyz[8] = 0x0000000000000001
	in1.xyz[9] = 0x00000000ffffffff
	in1.xyz[10] = 0x0000000000000000
	in1.xyz[11] = 0x0000000100000000
	in2.xyz[8] = 0x0000000000000001
	in2.xyz[9] = 0x00000000ffffffff
	in2.xyz[10] = 0x0000000000000000
	in2.xyz[11] = 0x0000000100000000
	p256Mul(in1.xyz[0:4], in1.xyz[0:4], rr[:])
	p256Mul(in1.xyz[4:8], in1.xyz[4:8], rr[:])
	p256Mul(in2.xyz[0:4], in2.xyz[0:4], rr[:])
	p256Mul(in2.xyz[4:8], in2.xyz[4:8], rr[:])
	res := make([]uint64, 12)
	n := p256PointAddAsm(res, in1.xyz[:], in2.xyz[:])
	fmt.Printf("n=%d\n", n)
	copy(rp.xyz[:], res)
	x4, y4 := rp.p256PointToAffine()
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x4.Bytes()), hex.EncodeToString(y4.Bytes()))
	if n == 0 && (x3.Cmp(x4) != 0 || y3.Cmp(y4) != 0) {
		t.FailNow()
	}
}

func Test_ScalarMult_basepoint(t *testing.T) {
	scalar := big.NewInt(0xffffffff)
	curve1 := P256()
	x1, y1 := curve1.ScalarMult(curve1.Params().Gx, curve1.Params().Gy, scalar.Bytes())
	fmt.Printf("x1=%s, y1=%s\n", hex.EncodeToString(x1.Bytes()), hex.EncodeToString(y1.Bytes()))
	params := curve1.Params()
	x2, y2 := params.ScalarMult(curve1.Params().Gx, curve1.Params().Gy, scalar.Bytes())
	fmt.Printf("x2=%s, y2=%s\n", hex.EncodeToString(x2.Bytes()), hex.EncodeToString(y2.Bytes()))
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.FailNow()
	}
}

func Test_Inverse(t *testing.T) {
	n, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	nm2 := new(big.Int).Sub(n, big.NewInt(2))
	nm2a := make([]uint64, 4)
	fromBig(nm2a, nm2)
	fmt.Printf("%0b, %0b, %b, %b\n", nm2a[0], nm2a[1], nm2a[2], nm2a[3])
	xInv1 := fermatInverse(x, n)
	fmt.Printf("expect=%s\n", hex.EncodeToString(xInv1.Bytes()))
	_ = P256()
	xInv2 := p256.Inverse(x)
	fmt.Printf("result=%s\n", hex.EncodeToString(xInv2.Bytes()))

	if xInv1.Cmp(xInv2) != 0 {
		t.FailNow()
	}
}
