// +build amd64

package sm2

import (
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
	p256Sqr(res, gx, 1)
	//p256FromMont(res, res)
	resInt := toBigInt(res)
	fmt.Printf("1=%s\n", hex.EncodeToString(resInt.Bytes()))
	gxsqr := new(big.Int).Mul(x, x)
	gxsqr = new(big.Int).Mod(gxsqr, p)
	gxsqr = new(big.Int).Mul(gxsqr, r)
	gxsqr = new(big.Int).Mod(gxsqr, p)
	fmt.Printf("2=%s\n", hex.EncodeToString(gxsqr.Bytes()))
	if resInt.Cmp(gxsqr) != 0 {
		t.FailNow()
	}

}
